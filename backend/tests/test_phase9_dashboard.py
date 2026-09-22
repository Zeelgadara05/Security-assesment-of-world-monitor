"""Phase 9: dashboard aggregation endpoint.

``GET /dashboard/summary`` must derive every number from persisted rows owned
by the authenticated user.  No sample figures, no cross-user leakage, no
invented coverage: the lifecycle buckets, evidence chain and coverage trend are
asserted against rows seeded in this test.
"""

import uuid

from database.models import Asset, FindingObservationLink, Observation, Project, Scan, User, Vulnerability


def _seed(db, email):
    from database.models import User

    user = db.query(User).filter(User.email == email).first()
    assert user is not None
    project = Project(name="p9d", user_id=user.id, scope_json=["r.example"])
    db.add(project)
    db.commit()
    scan = Scan(project_id=project.id, target="r.example", status="Completed",
                state="completed", coverage=86.0)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    obs = Observation(scan_id=scan.id, kind="http_response", subject="https://r.example/",
                      tool_name="native_http", data_json={"status": 200}, raw_output="{}")
    db.add(obs)
    db.commit()
    db.refresh(obs)

    finding = Vulnerability(
        scan_id=scan.id, title="Header check", severity="Medium", description="d",
        state="NEW", category="headers", endpoint="https://r.example/",
        http_method="GET", source_test="http.security_headers",
        source_tool="native_http", status="confirmed",
        rule_id="missing-security-header", evidence_observation_ids=[obs.id])
    db.add(finding)
    db.add(Vulnerability(
        scan_id=scan.id, title="Candidate X", severity="Low", description="d",
        state="NEW", category="misc", endpoint="https://r.example/x",
        http_method="GET", source_test="ext.candidate",
        source_tool="external", status="candidate"))
    db.add(Asset(project_id=project.id, type="host", value="r.example", metadata_json={"state": "up"}))
    db.add(Asset(project_id=project.id, type="port", value="443/tcp", metadata_json={"state": "open"}))
    db.commit()
    db.refresh(finding)
    db.add(FindingObservationLink(finding_id=finding.id, observation_id=obs.id))
    db.commit()
    return scan.id


def test_dashboard_summary_derives_from_persisted_rows(client, session):
    email = f"p9d-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    try:
        scan_id = _seed(session, email)
    except Exception:
        session.rollback()
        raise

    resp = client.get("/dashboard/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["scans_total"] == 1
    assert data["confirmed_findings"] == 1
    assert data["candidate_findings"] == 1
    assert data["findings_lifecycle"].get("confirmed") == 1
    assert data["findings_lifecycle"].get("candidate") == 1
    assert data["findings_by_severity"].get("Medium") == 1
    assert data["findings_by_rule"].get("missing-security-header") == 1
    assert data["observation_count"] == 1
    assert data["observations_by_scan"].get(str(scan_id)) == 1
    assert data["assets_total"] == 2
    assert data["assets_by_type"].get("port") == 1
    assert data["coverage_trend"] and data["coverage_trend"][0]["coverage"] == 86.0

    # recent findings include a real evidence note from the persisted observation
    recent = data["recent_findings"]
    assert {r["title"] for r in recent} == {"Header check", "Candidate X"}
    header = next(r for r in recent if r["title"] == "Header check")
    assert header["evidence_note"] == "http_response by native_http on https://r.example/"
    assert header["status"] == "confirmed"
    assert header["severity"] == "Medium"

    # lifecycle buckets are exhaustive and match seeded rows
    assert sum(data["findings_lifecycle"].values()) == 2


def test_dashboard_summary_empty_for_other_user(client, session):
    email_a = f"p9d-a-{uuid.uuid4().hex[:8]}@test.local"
    email_b = f"p9d-b-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email_a)
    register_user(client, email_b)
    try:
        _seed(session, email_a)
    except Exception:
        session.rollback()
        raise
    head_b = login_user(client, email_b)

    resp = client.get("/dashboard/summary", headers=head_b)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scans_total"] == 0
    assert data["confirmed_findings"] == 0
    assert data["observation_count"] == 0
    assert data["assets_total"] == 0
    assert data["recent_findings"] == []