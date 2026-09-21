"""Phase 8.5 cross-assessment findings list (ownership-scoped, honest filters)."""
from __future__ import annotations

from database.models import Scan, Vulnerability


def _project_id(client, headers):
    return client.get("/scans/scope", headers=headers).json()["project_id"]


def _seed_finding(session, project_id, **overrides):
    scan = Scan(project_id=project_id, target="scope.example.com", status="Completed")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    finding = Vulnerability(
        scan_id=scan.id,
        title=overrides.get("title", "Reflected XSS"),
        severity=overrides.get("severity", "High"),
        description="A real seeded finding.",
        status=overrides.get("status", "confirmed"),
        state="NEW",
        category=overrides.get("category", "xss"),
        endpoint="/search",
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def test_list_findings_returns_owned_only(client, auth_headers, session):
    project_id = _project_id(client, auth_headers)
    finding = _seed_finding(session, project_id)

    resp = client.get("/findings", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] >= 1
    row = next((f for f in body["findings"] if f["id"] == finding.id), None)
    assert row is not None
    assert row["category"] == "xss"
    assert set(row["sih_areas"]) == {"input_validation", "client_side"}


def test_list_findings_isolation(client, auth_headers, other_auth_headers, session):
    project_id = _project_id(client, auth_headers)
    finding = _seed_finding(session, project_id)

    resp = client.get("/findings", headers=other_auth_headers)
    assert resp.status_code == 200
    assert all(f["id"] != finding.id for f in resp.json()["findings"])


def test_list_findings_filters_and_sih_area(client, auth_headers, session):
    project_id = _project_id(client, auth_headers)
    _seed_finding(session, project_id, title="SQLi", severity="Critical", category="sqli")
    _seed_finding(session, project_id, title="TLS", severity="Medium", category="tls")

    crit = client.get("/findings?severity=Critical", headers=auth_headers).json()
    assert crit["findings"] and all(f["severity"] == "Critical" for f in crit["findings"])

    crypto = client.get("/findings?sih_area=secure_communication", headers=auth_headers).json()
    assert any(f["category"] == "tls" for f in crypto["findings"])
    assert all("secure_communication" in f["sih_areas"] for f in crypto["findings"])


def test_list_findings_rejects_unknown_sih_area(client, auth_headers):
    resp = client.get("/findings?sih_area=bogus", headers=auth_headers)
    assert resp.status_code == 422


def test_list_findings_requires_auth(client):
    assert client.get("/findings").status_code == 401
