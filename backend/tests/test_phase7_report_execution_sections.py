"""Phase 7 report execution sections.

The report builder extends the stable Phase 6 payload with an execution
platform/ledger trail.  These tests pin that behaviour: the new sections must
appear at deterministic positions, carry only real persisted artifacts, keep
the fixed F- markers, and leave the overall build deterministic (two builds of
the same state are byte-identical).
"""

import datetime
import uuid

from app.assess import finding_lifecycle as flc
from app.reporting import builder
from database.models import (
    FindingValidation,
    MLInference,
    Project,
    Scan,
    ScanStage,
    ToolExecution,
    ToolReadiness,
    User,
    Vulnerability,
)


def _seed(db):
    owner = User(id=f"p7rep-{uuid.uuid4().hex[:8]}", email=f"p7rep-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    db.add(owner)
    db.commit()
    project = Project(name="p7rep", user_id=owner.id, scope_json=["r.example"])
    db.add(project)
    db.commit()
    scan = Scan(project_id=project.id, target="r.example", status="Completed", stage="completed",
                completed_at=datetime.datetime.utcnow())
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Vulnerability(
        scan_id=scan.id, title="Header check", severity="Medium", description="d",
        state="NEW", category="headers", endpoint="https://r.example/", http_method="GET",
        source_test="http.security_headers", source_tool="native_http",
        status=flc.STATUS_CONFIRMED, rule_id="missing-security-header",
        evidence_observation_ids=[10],
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    scan.preflight_json = {
        "runnable": True,
        "installed": ["subfinder", "nmap"],
        "missing": ["assetfinder"],
        "disabled": ["ffuf", "nikto", "sqlmap", "testssl"],
    }
    db.add(ScanStage(scan_id=scan.id, name="PRECHECK", order=1, status="completed",
                     tools=["real_dns", "real_tcp"], tests_executed=0, observations=2,
                     duration_ms=10))
    db.add(ScanStage(scan_id=scan.id, name="REPORTING", order=13, status="completed",
                     tools=[], duration_ms=4))
    db.add(ToolReadiness(scan_id=scan.id, tool="subfinder", status="installed",
                         executable="/bin/subfinder", version="v2.6.5", adapter="legacy",
                         category="recon", enabled=True))
    db.add(ToolReadiness(scan_id=scan.id, tool="assetfinder", status="missing",
                         executable=None, version=None, adapter="legacy", category="recon",
                         enabled=True, reason="binary not found"))
    db.add(ToolExecution(scan_id=scan.id, stage="PASSIVE_RECON", tool="subfinder",
                         adapter="legacy", attempt=1, status="completed",
                         target=scan.target, parsed_observations=0, duration_ms=40))
    db.add(ToolExecution(scan_id=scan.id, stage="DNS_DISCOVERY", tool="dnsx",
                         adapter="legacy", attempt=2, status="timeout",
                         target=scan.target, parsed_observations=0, duration_ms=30000,
                         termination_reason="stub timeout"))
    db.add(ToolExecution(scan_id=scan.id, stage="PORT_SERVICE_DISCOVERY", tool="nmap",
                         adapter="external", attempt=1, status="parse_failed",
                         target=scan.target, parsed_observations=0, duration_ms=80,
                         error_code="parse_failed"))
    db.add(FindingValidation(
        scan_id=scan.id, finding_id=finding.id,
        validator_id="http.security_headers",
        status="confirmed", condition="security headers present",
        reason="deterministic validator confirmed the finding", duration_ms=0))
    db.add(FindingValidation(
        scan_id=scan.id, finding_id=None, validator_id="nuclei",
        status="rejected", condition="external candidate without native confirmation",
        reason="no native deterministic validator applied", observation_id=11))
    db.add(MLInference(
        scan_id=scan.id, status="advisory_only", model_name=None, model_version=None,
        training_status="none", feature_schema_version="phase7-v1",
        advisory_json={"tool_gaps": ["nuclei_missing"], "recommendation": "advisory only"}))
    db.commit()
    return scan.id


def _build(db, scan_id):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    report = builder.build(db, scan)
    db.commit()
    json_text = json_dumps(report.json_content)
    return report, json_text


def json_dumps(obj):
    import json

    return json.dumps(obj, sort_keys=True, default=str)


def test_execution_sections_are_deterministic_and_honest(session):
    scan_id = _seed(session)
    r1, j1 = _build(session, scan_id)
    r2, j2 = _build(session, scan_id)
    assert j1 == j2, "two builds of identical state must be byte-identical"
    assert r1.markdown == r2.markdown

    payload = r1.json_content
    assert payload["assessment_version"] == "phase6"
    assert payload["execution_platform_version"] == "phase7"
    trail = payload["execution_trail"]

    execution = trail["execution"]
    stages = execution["stages"]
    assert [s["name"] for s in stages] == ["PRECHECK", "REPORTING"]
    assert execution["stage_status_bucket"] == {"completed": 2}
    pre = execution["preflight"]
    assert pre["runnable"] is True
    assert "assetfinder" in pre["missing"]
    assert pre["disabled"] == ["ffuf", "nikto", "sqlmap", "testssl"]
    readiness = {r["tool"]: r for r in execution["readiness"]}
    assert readiness["subfinder"]["status"] == "installed"
    assert readiness["assetfinder"]["status"] == "missing"
    assert readiness["assetfinder"]["reason"] == "binary not found"

    ledger = trail["ledger"]
    assert ledger["execution_status_bucket"] == {
        "completed": 1, "timeout": 1, "parse_failed": 1}
    assert ledger["validation_status_bucket"] == {"confirmed": 1, "rejected": 1}
    confirmed = [v for v in ledger["validations"] if v["status"] == "confirmed"]
    assert confirmed and confirmed[0]["validator_id"] == "http.security_headers"
    assert ledger["advisory"]["status"] == "advisory_only"

    # section order is pinned: coverage → execution_platform → … →
    # reproducibility → execution_ledger
    ids = [s.id for s in r1.sections]
    assert ids.index("execution_platform") > ids.index("coverage")
    assert ids.index("execution_ledger") > ids.index("reproducibility")

    assert "Execution Platform & Stage Ledger" in r1.markdown
    assert "Execution Ledger & Validations" in r1.markdown
    assert "Validator verdicts: confirmed:1 • rejected:1" in r1.markdown
    assert "F-" in r1.markdown