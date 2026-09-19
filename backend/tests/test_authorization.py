"""Authorization: per-user isolation enforced through the owning project.

The conftest ``auth_headers`` fixture owns ``owner@test.local`` and
``other_auth_headers`` owns ``other@test.local``.  Every scan, report, chat
and asset is reachable only through the project belonging to the requesting
user.  Foreign data is indistinguishable from missing data (404s, never 200s
or data-leaking 403s).
"""

from database.connection import SessionLocal
from database.models import Asset, ChatHistory, Project, Report, Scan, User, Vulnerability

OWNER_EMAIL = "owner@test.local"
OTHER_EMAIL = "other@test.local"


def _ensure_owned_scan(session, email, target="isolation.example.com"):
    """Create (once) a fully populated scan for the given user's project."""
    user = session.query(User).filter(User.email == email).first()
    assert user is not None, f"{email} must be created by conftest fixtures"
    project = session.query(Project).filter(Project.user_id == user.id).first()
    if project is None:
        project = Project(name="Proj", user_id=user.id, scope_json=[target])
        session.add(project)
        session.flush()
    existing = session.query(Scan).filter(Scan.project_id == project.id).first()
    if existing is not None:
        return existing
    scan = Scan(project_id=project.id, target=target, status="Completed", security_score=70, logs="logs")
    session.add(scan)
    session.flush()
    session.add(Vulnerability(scan_id=scan.id, title="Test Issue", severity="Low", description="d"))
    session.add(Report(scan_id=scan.id, title="Record", markdown_content="# MD", json_content={}, html_content="<html/>"))
    session.add(ChatHistory(scan_id=scan.id, role="user", message="hello"))
    session.add(ChatHistory(scan_id=scan.id, role="assistant", message="hi"))
    session.add(Asset(project_id=project.id, type="domain", value=target, metadata_json={}))
    session.commit()
    session.refresh(scan)
    return scan


def test_owner_can_read_own_scan_assets_chat_reports(client, session, auth_headers):
    _ensure_owned_scan(session, OWNER_EMAIL)
    mine = client.get("/scans/list", headers=auth_headers).json()
    scan_id = mine[0]["id"]

    assert client.get(f"/scans/{scan_id}/details", headers=auth_headers).status_code == 200
    assert client.get(f"/reports/{scan_id}/markdown", headers=auth_headers).status_code == 200
    assert client.get(f"/reports/{scan_id}/json", headers=auth_headers).status_code == 200
    assert client.get(f"/reports/{scan_id}/html", headers=auth_headers).status_code == 200
    assert client.get(f"/reports/{scan_id}/pdf", headers=auth_headers).status_code == 200
    assert client.get(f"/chat/history/{scan_id}", headers=auth_headers).status_code == 200
    assert client.get(f"/scans/{scan_id}/stream", headers=auth_headers).status_code == 200


def test_other_user_cannot_read_owner_data(client, session, auth_headers, other_auth_headers):
    _ensure_owned_scan(session, OWNER_EMAIL)
    scan_id = client.get("/scans/list", headers=auth_headers).json()[0]["id"]

    for method, url in [
        ("GET", f"/scans/{scan_id}/details"),
        ("GET", f"/reports/{scan_id}/markdown"),
        ("GET", f"/reports/{scan_id}/json"),
        ("GET", f"/reports/{scan_id}/html"),
        ("GET", f"/reports/{scan_id}/pdf"),
        ("GET", f"/chat/history/{scan_id}"),
        ("GET", f"/scans/{scan_id}/stream"),
        ("POST", f"/chat/query"),
    ]:
        kwargs = {"headers": other_auth_headers}
        if method == "POST":
            kwargs["json"] = {"scan_id": scan_id, "message": "hi"}
        resp = client.request(method, url, **kwargs)
        assert resp.status_code == 404, f"{method} {url} -> {resp.status_code}"


def test_list_scan_ids_are_isolated(client, auth_headers, other_auth_headers):
    mine = {s["id"] for s in client.get("/scans/list", headers=auth_headers).json()}
    theirs = {s["id"] for s in client.get("/scans/list", headers=other_auth_headers).json()}
    assert mine.isdisjoint(theirs)


def test_report_lists_are_isolated(client, session, auth_headers, other_auth_headers):
    _ensure_owned_scan(session, OWNER_EMAIL)
    mine = {r["scan_id"] for r in client.get("/reports/list", headers=auth_headers).json()}
    theirs = {r["scan_id"] for r in client.get("/reports/list", headers=other_auth_headers).json()}
    assert mine.isdisjoint(theirs)
    assert mine  # owner must actually see reports


def test_assets_are_scoped_to_owner(client, session, auth_headers, other_auth_headers):
    _ensure_owned_scan(session, OWNER_EMAIL)
    owner_ids = {a["id"] for a in client.get("/auth/assets", headers=auth_headers).json()}
    other_ids = {a["id"] for a in client.get("/auth/assets", headers=other_auth_headers).json()}
    assert owner_ids
    assert owner_ids.isdisjoint(other_ids)
    # Owner's project assets are visible only to the owner.
    owner_values = {a["value"] for a in client.get("/auth/assets", headers=auth_headers).json()}
    assert "isolation.example.com" in owner_values


def test_chat_query_is_isolated(client, session, auth_headers, other_auth_headers):
    _ensure_owned_scan(session, OWNER_EMAIL)
    scan_id = client.get("/scans/list", headers=auth_headers).json()[0]["id"]

    ok = client.post("/chat/query", json={"scan_id": scan_id, "message": "sql injection"}, headers=auth_headers)
    assert ok.status_code == 200
    denial = client.post("/chat/query", json={"scan_id": scan_id, "message": "sql injection"}, headers=other_auth_headers)
    assert denial.status_code == 404
    # Owner's chat history contains the newly written message.
    history = client.get(f"/chat/history/{scan_id}", headers=auth_headers).json()
    assert any(m["role"] == "user" and m["message"] == "sql injection" for m in history)