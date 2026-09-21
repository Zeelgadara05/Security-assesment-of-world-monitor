"""World Monitor API endpoints (Phase 8): auth, ownership isolation, and the
real health/discovery flow against a localhost HTTP fixture.

No HTTP mocking: target checks and discovery hit a real local server, and the
persisted health/discovery JSON is compared against what that server actually
served.
"""
from __future__ import annotations

import socket

import pytest

from tests.test_phase8_world_monitor_provider import OPENAPI_DOC, _make_server

ROUTES_FULL = {
    "/": (200, {"Server": "WM-Server/2.0"}, "<html>World Monitor</html>"),
    "/api": (200, {"Content-Type": "application/json"}, {"ok": True}),
    "/openapi.json": (200, {"Content-Type": "application/json"}, OPENAPI_DOC),
}


@pytest.fixture()
def wm_base():
    base, server = _make_server(ROUTES_FULL)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _closed_port_url():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def _create(client, headers, base, **extra):
    payload = {"base_url": base, **extra}
    return client.post("/world-monitor/targets", json=payload, headers=headers)


# ---------------------------------------------------------------------------
# auth + validation
# ---------------------------------------------------------------------------
def test_requires_authentication(client):
    resp = client.post("/world-monitor/targets", json={"base_url": "http://example.com"})
    assert resp.status_code == 401


def test_rejects_invalid_url(client, auth_headers):
    for bad in ("ftp://example.com", "not a url", "example.com", "http://", ""):
        resp = _create(client, auth_headers, bad)
        assert resp.status_code in (401, 422), bad


def test_rejects_cross_host_extra_urls(client, auth_headers, wm_base):
    resp = _create(client, auth_headers, wm_base, api_base_url="http://other.example/api")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# CRUD + project isolation
# ---------------------------------------------------------------------------
def test_create_list_get_delete_flow(client, auth_headers, wm_base):
    created = _create(client, auth_headers, wm_base)
    assert created.status_code == 200, created.text
    target = created.json()
    assert target["status"] == "not_configured"
    assert target["api_endpoints_total"] == 0

    listed = client.get("/world-monitor/targets", headers=auth_headers).json()
    assert [t["id"] for t in listed] == [target["id"]]

    detail = client.get(f"/world-monitor/targets/{target['id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["api_endpoints"] == []

    gone = client.delete(f"/world-monitor/targets/{target['id']}", headers=auth_headers)
    assert gone.status_code == 200
    assert client.get("/world-monitor/targets", headers=auth_headers).json() == []


def test_ownership_isolation_404(client, auth_headers, other_auth_headers, wm_base):
    created = _create(client, auth_headers, wm_base).json()
    tid = created["id"]
    for method in ("GET", "DELETE", "POST"):
        url = f"/world-monitor/targets/{tid}"
        if method == "POST":
            url += "/check"
        resp = client.request(method, url, headers=other_auth_headers)
        assert resp.status_code == 404, (method, resp.text)


# ---------------------------------------------------------------------------
# real check / discover flows
# ---------------------------------------------------------------------------
def test_check_persists_reachable_facts(client, auth_headers, wm_base):
    target = _create(client, auth_headers, wm_base).json()
    resp = client.post(f"/world-monitor/targets/{target['id']}/check", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "reachable"
    assert body["last_checked_at"] is not None
    health = body["health"]
    assert health["reachable"] is True
    assert health["http_status"] == 200
    assert "WM-Server/2.0" in (health["server"] or "")
    assert health["error"] is None


def test_check_unreachable_target_status(client, auth_headers):
    url = _closed_port_url()
    target = _create(client, auth_headers, url).json()
    resp = client.post(f"/world-monitor/targets/{target['id']}/check", headers=auth_headers)
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["health"]["reachable"] is False
    assert body["health"]["error"]


def test_discover_full_inventory(client, auth_headers, wm_base):
    target = _create(client, auth_headers, wm_base,
                     api_base_url=f"{wm_base}/api",
                     openapi_url=f"{wm_base}/openapi.json").json()
    resp = client.post(f"/world-monitor/targets/{target['id']}/discover", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "discovered"
    assert body["discovered_version"] == "1.2.3"
    assert body["last_discovery_at"] is not None
    assert body["api_endpoints_total"] == 3

    inventory = client.get(f"/world-monitor/targets/{target['id']}/inventory", headers=auth_headers).json()
    assert len(inventory["endpoints"]) == 3
    methods = {e["method"] for e in inventory["endpoints"]}
    assert methods == {"GET", "POST"}
    get_health = next(e for e in inventory["endpoints"] if e["operation_id"] == "getHealth")
    assert get_health["source"] == "openapi"
    assert get_health["authentication_hint"]


def test_discover_honest_without_openapi(client, auth_headers, wm_base):
    target = _create(client, auth_headers, wm_base, api_base_url=f"{wm_base}/api").json()
    resp = client.post(f"/world-monitor/targets/{target['id']}/discover", headers=auth_headers)
    body = resp.json()
    assert body["status"] in ("partially_discovered", "reachable")
    assert body["api_endpoints_total"] == 0
    assert body["discovered_version"] is None
    assert body["discovery"]["openapi_status"] == "unconfigured"
    assert any(s["status"] == "unsupported" for s in body["discovery"]["steps"])


def test_discover_unreachable_base(client, auth_headers):
    url = _closed_port_url()
    target = _create(client, auth_headers, url,
                     api_base_url=f"{url}/api").json()
    resp = client.post(f"/world-monitor/targets/{target['id']}/discover", headers=auth_headers)
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["api_endpoints_total"] == 0
    assert body["discovery"]["target_status"] == "unavailable"


# ---------------------------------------------------------------------------
# global monitor assessments do not require a separate scope entry
# ---------------------------------------------------------------------------
def test_wm_assessment_uses_registered_host_without_scope_entry(client, auth_headers, wm_base):
    """A registered World Monitor deployment host is already authorized: the
    scan may start without additionally declaring the host in custom scope."""
    target = _create(client, auth_headers, wm_base,
                     api_base_url=f"{wm_base}/api",
                     openapi_url=f"{wm_base}/openapi.json").json()
    tid = target["id"]
    try:
        resp = client.post("/scans", headers=auth_headers, json={
            "target": "127.0.0.1",
            "assessment_type": "world_monitor",
            "authorization_acknowledged": True,
            "world_monitor": {"target_id": tid},
        })
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["assessment_type"] == "world_monitor"
        assert body["status"] == "Pending"
    finally:
        client.delete(f"/world-monitor/targets/{tid}", headers=auth_headers)


def test_wm_assessment_unrelated_host_still_403(client, auth_headers, wm_base):
    """The world_monitor allowance only authorizes the registered host: an
    unregistered target on the WM path is still refused with 403."""
    target = _create(client, auth_headers, wm_base).json()
    tid = target["id"]
    try:
        resp = client.post("/scans", headers=auth_headers, json={
            "target": "unrelated.example",
            "assessment_type": "world_monitor",
            "authorization_acknowledged": True,
            "world_monitor": {"target_id": tid},
        })
        assert resp.status_code == 403, resp.text
    finally:
        client.delete(f"/world-monitor/targets/{tid}", headers=auth_headers)