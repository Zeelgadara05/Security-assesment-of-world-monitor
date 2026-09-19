"""RBAC: admin-only endpoints reject regular users with 403 and accept admins."""

from tests.conftest import register_user, login_user, add_scope


def test_admin_can_list_users(client, admin_headers):
    resp = client.get("/auth/users", headers=admin_headers)
    assert resp.status_code == 200
    emails = {u["email"] for u in resp.json()}
    assert "admin@test.local" in emails


def test_admin_can_read_overview(client, admin_headers):
    resp = client.get("/auth/admin/overview", headers=admin_headers)
    assert resp.status_code == 200
    overview = resp.json()["overview"]
    for key in ("users", "projects", "scans", "assets", "reports", "chat_messages"):
        assert key in overview


def test_regular_user_forbidden_from_admin_endpoints(client, admin_headers):
    email = "rbac-user@test.local"
    register_user(client, email)
    headers = login_user(client, email)

    assert client.get("/auth/users", headers=headers).status_code == 403
    assert client.get("/auth/admin/overview", headers=headers).status_code == 403
    # An authenticated non-admin also cannot reach profile data of others.
    resp = client.get("/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["role"] == "user"


def test_profile_reports_role_token_for_regular_user(client, auth_headers):
    resp = client.get("/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["role"] in ("admin", "user")
    assert resp.json()["email"] == "owner@test.local"


def test_admin_must_still_be_authenticated(client):
    assert client.get("/auth/users").status_code == 401
    assert client.get("/auth/admin/overview").status_code == 401


def test_admin_rbac_does_not_leak_into_scan_scope(client, admin_headers):
    # RBAC path is independent of the cooperative editing bug class: an admin
    # still needs an explicitly-authorized scope to run a scan.
    add_scope(client, admin_headers, "rbac.example.com")
    resp = client.post("/scans/trigger", json={"target": "not-in-scope.example.com"}, headers=admin_headers)
    assert resp.status_code == 403