"""Phase 6 reporting + lifecycle API tests.

End-to-end: build a deterministic report (JSON + Markdown) from persisted scan
state, verify the assessment endpoint, the finding detail/evidence endpoints,
triage-driven lifecycle transitions, and multi-user isolation of all new
reporting endpoints.
"""
import uuid

from app.assess import finding_lifecycle as lifecycle
from app.assess.evidence import evidence_to_kwargs
from app.assess.models import EvidenceData
from database.models import (
    AssessmentTest,
    FindingEvidence,
    Project,
    ReportExport,
    Scan,
    ToolResult,
    Vulnerability,
)


def _seed_scan(db, email, *, candidate=False):
    import json
    import datetime

    from database.models import User

    user = db.query(User).filter(User.email == email).first()
    project = Project(name="p6-report", user_id=user.id, scope_json=["t.example"])
    db.add(project)
    db.commit()
    scan = Scan(project_id=project.id, target="t.example", status="Completed", stage="completed",
                completed_at=datetime.datetime.utcnow())
    db.add(scan)
    db.commit()

    confirmed = Vulnerability(
        scan_id=scan.id, title="Reflected XSS", severity="Medium", description="d",
        state="NEW", category="xss", endpoint="http://t.example/search", http_method="GET",
        parameter="q", source_test="injection.xss.reflected", source_tool="native_http",
        confidence="HIGH", status=lifecycle.STATUS_CONFIRMED,
        affected_component="backend/api",
    )
    db.add(confirmed)
    db.commit()
    lifecycle.record_initial(db, confirmed, reason="validated by injection.xss.reflected")
    cand = Vulnerability(
        scan_id=scan.id, title="nuclei candidate", severity="High", description="ext",
        state="NEW", category="ssl", endpoint="http://t.example/", source_tool="nuclei",
        confidence="MEDIUM", status=lifecycle.STATUS_CANDIDATE,
    )
    db.add(cand)
    db.commit()
    lifecycle.record_initial(db, cand, reason="candidate from external tool nuclei")

    evidence = EvidenceData(
        evidence_type="comparison", expected="encoded output", actual="raw script injection",
        security_boundary="browser script execution",
        request={"method": "GET", "url": "http://t.example/search?q=%3Cscript%3E", "headers": {}},
        response={"status": 200, "headers": {"Content-Type": "text/html"}, "body": "ok"},
    )
    db.add(FindingEvidence(**evidence_to_kwargs(confirmed.id, evidence, None)))
    db.add(AssessmentTest(
        scan_id=scan.id, test_id="injection.xss.reflected", name="XSS", category="xss",
        status="executed", reason="", active=True, finding_ids=[confirmed.id],
    ))
    db.add(AssessmentTest(
        scan_id=scan.id, test_id="http.security_headers", name="Security headers", category="headers",
        status="skipped", reason="no http response observations", active=False,
    ))
    db.add(ToolResult(
        scan_id=scan.id, tool_name="native_assessment", status="Completed",
        raw_output=json.dumps({
            "registry_fingerprint": "abcdef1234567890",
            "tests_total": 2, "tests_applicable": 1, "tests_executed": 1,
            "tests_failed": 0, "tests_not_applicable": 0, "tests_skipped": 1,
            "testcases_planned": 3, "testcases_executed": 2, "observations": 1,
            "findings_confirmed": 1, "coverage_percent": 100.0,
            "not_executed": [{"test_id": "http.security_headers", "reason": "no observations"}],
            "tools_missing": [],
        }),
    ))
    db.commit()

    from app.assess import summary as summary_mod
    summary_mod.snapshot(db, scan, {
        "active_testing": False, "assessment_engine": True, "installed_tools": ["nmap"],
        "tools_missing": [],
    }, coverage={"tests_applicable": 1, "tests_executed": 1, "tests_skipped": 1,
                 "tests_failed": 0, "coverage_percent": 100.0})
    db.commit()
    return scan.id, confirmed.id, cand.id


def test_assessment_endpoint_aggregates_without_vulnerability_claim(client, session):
    import uuid as _uuid

    email = f"p6-asset-{_uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, _c, _x = _seed_scan(session, email)

    resp = client.get(f"/scans/{scan_id}/assessment", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["assessment_status"] in ("completed", "completed_with_gaps")
    assert data["coverage"]["coverage_percent"] == 100.0
    assert data["aggregate"]["total_confirmed"] == 1
    assert data["aggregate"]["total_candidates"] == 1
    assert "0 vulnerabilities" not in data["headline"]


def test_report_json_preserves_ids_and_never_leaks_secrets(client, session):
    email = f"p6-json-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, confirmed_id, cand_id = _seed_scan(session, email)

    resp = client.get(f"/scans/{scan_id}/report?format=json", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["format"] == "json"
    assert data["content_hash"]
    report = data["report"]
    assert report["scan_id"] == scan_id
    assert report["registry_fingerprint"] == "abcdef1234567890"
    finding_ids = [f["id"] for f in report["findings"]]
    assert confirmed_id in finding_ids and cand_id in finding_ids
    statuses = {f["id"]: f["status"] for f in report["findings"]}
    assert statuses[confirmed_id] == "confirmed"
    assert statuses[cand_id] == "candidate"
    assert report["evidence"]
    assert any(e["evidence_id"] for e in report["evidence"])
    assert report["limitations"]
    assert report["generated_at"]
    # Secrets must not appear anywhere in the exported report.
    blob = str(data).lower()
    for secret in ("authorization: bearer", "set-cookie", "<script>"):
        assert secret not in blob


def test_report_markdown_has_sections_and_is_stable(client, session):
    email = f"p6-md-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, _, _ = _seed_scan(session, email)

    r1 = client.get(f"/scans/{scan_id}/report?format=markdown", headers=headers)
    assert r1.status_code == 200
    md = r1.json()["report"]
    assert "# Assessment report" in md
    assert "Assessment Completeness" in md
    assert "Coverage statement" in md
    assert "Limitations" in md
    assert "F-" in md

    r2 = client.get(f"/scans/{scan_id}/report?format=markdown", headers=headers)
    assert r2.json()["report"] == md  # deterministic


def test_report_export_row_is_persisted_with_content_hash(client, session):
    email = f"p6-export-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, _, _ = _seed_scan(session, email)
    client.get(f"/scans/{scan_id}/report?format=json", headers=headers)
    client.get(f"/scans/{scan_id}/report?format=markdown", headers=headers)
    rows = session.query(ReportExport).filter(ReportExport.scan_id == scan_id).order_by(ReportExport.format).all()
    assert {r.format for r in rows} == {"json", "markdown"}
    assert all(r.content_hash and r.content_length for r in rows)
    assert all(r.registry_fingerprint == "abcdef1234567890" for r in rows)


def test_finding_detail_and_evidence_endpoints(client, session):
    email = f"p6-detail-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    _scan_id, confirmed_id, _cand = _seed_scan(session, email)

    detail = client.get(f"/findings/{confirmed_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    d = detail.json()
    assert d["status"] == "confirmed"
    assert d["affected_component"] == "backend/api"
    assert d["cvss"]["consistency"]["status"] == "n/a"  # no fabricated vector
    assert d["proof_of_concept"]["request"]["method"] == "GET"
    assert d["evidence"][0]["integrity"] == {"request_ok": True, "response_ok": True}
    assert d["history"][0]["to_status"] == "confirmed"

    ev = client.get(f"/findings/{confirmed_id}/evidence", headers=headers)
    assert ev.status_code == 200
    record = ev.json()["evidence"][0]
    assert record["request_hash"] and record["response_hash"]
    assert record["request"]["method"] == "GET"  # redacted proof is surfaced
    assert "Authorization" not in str(record["request"])


def test_triage_drives_lifecycle_and_rejects_illegal_transitions(client, session):
    email = f"p6-triage-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    _scan_id, confirmed_id, cand_id = _seed_scan(session, email)

    # remediated -> can no longer be "confirmed".
    r = client.post(f"/findings/{confirmed_id}/triage", json={"action": "resolve", "reason": "patched"},
                    headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "remediated"
    blocked = client.post(f"/findings/{confirmed_id}/triage", json={"action": "confirm"}, headers=headers)
    assert blocked.status_code == 400
    blocked2 = client.post(f"/findings/{confirmed_id}/triage", json={"action": "false_positive"}, headers=headers)
    assert blocked2.status_code == 400

    # candidate -> confirmed is legal (operator validations).
    promote = client.post(f"/findings/{cand_id}/triage", json={"action": "confirm", "reason": "validated"},
                          headers=headers)
    assert promote.status_code == 200 and promote.json()["status"] == "confirmed"

    from database.models import FindingStatusHistory
    rows = session.query(FindingStatusHistory).filter(FindingStatusHistory.finding_id == confirmed_id).all()
    assert [h.to_status for h in rows] == ["confirmed", "remediated"]


def test_reporting_endpoints_are_isolated_between_users(client, session):
    email_a = f"p6-iso-a-{uuid.uuid4().hex[:8]}@test.local"
    email_b = f"p6-iso-b-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email_a)
    register_user(client, email_b)
    head_a = login_user(client, email_a)
    head_b = login_user(client, email_b)
    scan_id, confirmed_id, _c = _seed_scan(session, email_a)

    for url in (f"/scans/{scan_id}/assessment", f"/scans/{scan_id}/report?format=json",
                f"/findings/{confirmed_id}", f"/findings/{confirmed_id}/evidence"):
        assert client.get(url, headers=head_b).status_code == 404, url


def test_unsupported_report_format_is_rejected(client, session):
    email = f"p6-fmt-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, _, _ = _seed_scan(session, email)
    assert client.get(f"/scans/{scan_id}/report?format=pdf", headers=headers).status_code in (200, 400)
    assert client.get(f"/scans/{scan_id}/report?format=docx", headers=headers).status_code == 400