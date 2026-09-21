"""Phase 8.5 assessment taxonomy + authorization acknowledgement.

The two authorized assessment paths (world_monitor / custom_target) are
resolved and validated at creation time; the authorization acknowledgement is
persisted as an audit record.  Legacy clients that omit ``assessment_type``
keep working (the path is inferred) so the Phase 7/8 API contract is preserved.
"""
from __future__ import annotations

from tests.conftest import add_scope
def _create(client, headers, target, **extra):
    payload = {"target": target, **extra}
    return client.post("/scans", json=payload, headers=headers)


# ---------------------------------------------------------------------------
# custom_target path
# ---------------------------------------------------------------------------
def test_explicit_custom_target_requires_acknowledgement(client, auth_headers):
    add_scope(client, auth_headers, "example.com")
    resp = _create(client, auth_headers, "example.com", assessment_type="custom_target")
    assert resp.status_code == 422, resp.text
    assert "authorization_acknowledged" in resp.text


def test_explicit_custom_target_with_acknowledgement(client, auth_headers):
    add_scope(client, auth_headers, "custom.example.com")
    resp = _create(client, auth_headers, "custom.example.com",
                   assessment_type="custom_target", authorization_acknowledged=True)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["assessment_type"] == "custom_target"
    assert data["authorization_acknowledged"] is True

    detail = client.get(f"/scans/{data['scan_id']}", headers=auth_headers).json()
    assert detail["assessment_type"] == "custom_target"
    assert detail["authorization_acknowledged"] is True


def test_legacy_payload_still_works(client, auth_headers):
    add_scope(client, auth_headers, "legacy.example.com")
    resp = _create(client, auth_headers, "legacy.example.com")
    assert resp.status_code == 200, resp.text
    assert resp.json()["assessment_type"] == "custom_target"
    assert resp.json()["authorization_acknowledged"] is None


def test_rejects_unknown_assessment_type(client, auth_headers):
    add_scope(client, auth_headers, "badtype.example.com")
    resp = _create(client, auth_headers, "badtype.example.com",
                   assessment_type="whatever", authorization_acknowledged=True)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# world_monitor path
# ---------------------------------------------------------------------------
def test_world_monitor_requires_configuration(client, auth_headers):
    add_scope(client, auth_headers, "wm-missing.example.com")
    resp = _create(client, auth_headers, "wm-missing.example.com",
                   assessment_type="world_monitor", authorization_acknowledged=True)
    assert resp.status_code == 422, resp.text


def test_world_monitor_rejects_unowned_target(client, auth_headers):
    add_scope(client, auth_headers, "wm-unowned.example.com")
    resp = _create(client, auth_headers, "wm-unowned.example.com",
                   assessment_type="world_monitor", authorization_acknowledged=True,
                   world_monitor={"target_id": 999999})
    assert resp.status_code == 404, resp.text


def test_world_monitor_with_owned_target(client, auth_headers, session):
    """A WM assessment referencing an owned deployment is accepted and tagged.

    The deployment row is inserted directly and removed afterwards so this test
    never pollutes the shared owner's World Monitor target list.
    """
    from database.models import WorldMonitorTarget

    project_id = client.get("/scans/scope", headers=auth_headers).json()["project_id"]
    wm = WorldMonitorTarget(project_id=project_id, base_url="http://127.0.0.1:9001",
                            status="not_configured")
    session.add(wm)
    session.commit()
    session.refresh(wm)
    try:
        add_scope(client, auth_headers, "127.0.0.1")
        resp = _create(client, auth_headers, "127.0.0.1",
                       assessment_type="world_monitor", authorization_acknowledged=True,
                       world_monitor={"target_id": wm.id})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["assessment_type"] == "world_monitor"
        assert data["authorization_acknowledged"] is True
    finally:
        session.delete(wm)
        session.commit()
