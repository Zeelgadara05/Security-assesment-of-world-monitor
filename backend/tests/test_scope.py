"""Scope enforcement: authorization to scan is granted only for declared
project scope entries or already-discovered assets.

Negative checks go through the live API (403, no scan starts).  Positive
containment (subdomains, CIDR, exact) is asserted on the enforcement function
directly to avoid launching expensive simulated scans for each case.
"""

from database.connection import SessionLocal
from database.models import Asset, Project, Scan, User
from app.core.auth import is_target_in_scope
from tests.conftest import add_scope


def _project(scope, assets=None):
    return Project(id=1, user_id="u", scope_json=scope, name="P"), assets or []


def _asset(value, atype="domain"):
    return Asset(id=1, project_id=1, type=atype, value=value, metadata_json={})


def test_domain_exact_match():
    project, assets = _project(["example.com"])
    assert is_target_in_scope("example.com", project, assets)


def test_subdomain_of_scoped_domain_allowed():
    project, assets = _project(["example.com"])
    assert is_target_in_scope("api.example.com", project, assets)
    assert is_target_in_scope("deep.api.example.com", project, assets)


def test_unrelated_domain_denied():
    project, assets = _project(["example.com"])
    assert not is_target_in_scope("example.org", project, assets)
    assert not is_target_in_scope("notexample.com", project, assets)  # suffix, not a subdomain


def test_cidr_contains_ip():
    project, assets = _project(["10.0.0.0/8"])
    assert is_target_in_scope("10.1.2.3", project, assets)
    assert not is_target_in_scope("11.1.2.3", project, assets)


def test_ip_exact_match():
    project, assets = _project(["203.0.113.42"])
    assert is_target_in_scope("203.0.113.42", project, assets)
    assert not is_target_in_scope("203.0.113.43", project, assets)


def test_empty_scope_denies_everything():
    project, assets = _project([])
    assert not is_target_in_scope("example.com", project, assets)


def test_discovered_assets_count_as_scope():
    project, assets = _project([], assets=[_asset("host.internal.example")])
    assert is_target_in_scope("host.internal.example", project, assets)
    # Rescanning a subdomain of a discovered asset is also in scope.
    assert is_target_in_scope("api.host.internal.example", project, assets)


def test_invalid_target_returns_false():
    project, assets = _project(["example.com"])
    assert not is_target_in_scope("javascript:alert(1)", project, assets)


# ---------------------------------------------------------------------------
# API-level enforcement
# ---------------------------------------------------------------------------
def test_out_of_scope_trigger_denied(client, auth_headers):
    add_scope(client, auth_headers, "authorized.example.com")
    resp = client.post("/scans/trigger", json={"target": "rogue.example.org"}, headers=auth_headers)
    assert resp.status_code == 403
    assert "scope" in resp.json()["detail"].lower()


def test_in_scope_trigger_allowed(client, auth_headers):
    add_scope(client, auth_headers, "inscope.example.com")
    resp = client.post("/scans/trigger", json={"target": "inscope.example.com"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["target"] == "inscope.example.com"
    # Wait for completion to avoid stray background writer during later tests.
    import time
    deadline = time.time() + 90
    while time.time() < deadline:
        details = client.get(f"/scans/{resp.json()['scan_id']}/details", headers=auth_headers).json()
        if details["status"] in ("Completed", "Failed"):
            break
        time.sleep(2)


def test_scope_add_and_list(client, auth_headers):
    add_scope(client, auth_headers, "scoped-api.example.com")
    body = client.get("/scans/scope", headers=auth_headers).json()
    assert "scoped-api.example.com" in body["scope"]
    # Protocol/port normalization applies to scope entries too.
    add_scope(client, auth_headers, "https://normalized.example.com:8443")
    body = client.get("/scans/scope", headers=auth_headers).json()
    assert "normalized.example.com" in body["scope"]
    assert body["project_id"]


def test_scope_is_per_user(client, session, auth_headers, other_auth_headers):
    add_scope(client, auth_headers, "mine.example.com")
    other_scope = client.get("/scans/scope", headers=other_auth_headers).json()["scope"]
    assert "mine.example.com" not in other_scope
    # Other user cannot trigger against my scope either.
    resp = client.post("/scans/trigger", json={"target": "mine.example.com"}, headers=other_auth_headers)
    assert resp.status_code == 403