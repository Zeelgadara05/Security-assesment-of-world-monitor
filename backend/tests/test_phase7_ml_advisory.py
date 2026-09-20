"""Phase 7 ML advisory tests.

The platform ships no model, so the advisory record must always be
``advisory_only`` with a null model, a stamped feature schema version, and a
deterministic coverage-gap payload derived only from persisted state.
"""

import uuid

from app.ml import advisory
from database.connection import SessionLocal
from database.models import (AssessmentTest, FindingValidation, MLInference,
                             Project, Scan, ToolExecution, User, Vulnerability)


def _seed(session, *, preflight=None, findings=1, unvalidated=0, executions=None):
    owner = User(id=f"p7ml-{uuid.uuid4().hex[:8]}", email=f"p7ml-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7ml", user_id=owner.id, scope_json=["m.example"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="m.example", status="Completed",
                coverage=88.0, preflight_json=preflight)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    for i in range(findings):
        session.add(Vulnerability(scan_id=scan.id, title=f"f{i}", severity="High",
                                  state="NEW", description="d", rule_id="r", dedup_key=f"k{i}"))
    for i in range(unvalidated):
        session.add(FindingValidation(
            scan_id=scan.id, validator_id="nuclei", status="rejected", finding_id=None))
    session.add(AssessmentTest(scan_id=scan.id, test_id="t1", name="t", category="c",
                               status="executed"))
    session.add(AssessmentTest(scan_id=scan.id, test_id="t2", name="t", category="c",
                               status="executed"))
    for ex in executions or []:
        session.add(ToolExecution(scan_id=scan.id, stage="PRECHECK", tool=ex, adapter="legacy",
                                  attempt=1, status="not_installed"))
    session.commit()
    session.refresh(scan)
    return scan.id


def test_generate_is_advisory_only_with_no_model(session):
    scan_id = _seed(session, preflight={"installed": [], "missing": ["nuclei"], "disabled": []})
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        payload = advisory.generate(db, scan, tracking_rows={"updated": 1})
        db.commit()
        assert payload["status"] == "advisory_only"
        assert payload["model_name"] is None
        row = db.query(MLInference).filter(MLInference.scan_id == scan_id).one()
        assert row.status == "advisory_only"
        assert row.model_name is None
        assert row.feature_schema_version == advisory.FEATURE_SCHEMA_VERSION
        assert row.advisory_json["scope"] == "coverage-gap advisory"
    finally:
        db.close()


def test_advisory_quotes_real_coverage_and_gaps(session):
    scan_id = _seed(session, preflight={"installed": ["subfinder"], "missing": ["nuclei"],
                                        "disabled": []}, executions=["nuclei"])
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        payload = advisory.generate(db, scan)
        db.commit()
        data = payload["advisory_json"]
        assert data["execution"]["coverage_percent"] == 88.0
        assert data["tool_gaps"] == ["nuclei"]
        assert "nuclei" in data["recommendation"]
        assert data["execution"]["tool_statuses"] == {"not_installed": 1}
    finally:
        db.close()


def test_advisory_counts_unvalidated_candidates(session):
    scan_id = _seed(session, preflight={"installed": [], "missing": [], "disabled": []},
                    findings=1, unvalidated=2)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        data = advisory.generate(db, scan)["advisory_json"]
        assert data["findings"]["confirmed_findings"] == 1
        assert data["findings"]["unvalidated_candidates"] == 2
        assert data["findings"]["validation_rows"] == 2
    finally:
        db.close()


def test_advisory_without_gaps_still_refuses_absence_claims(session):
    scan_id = _seed(session, preflight={"installed": [], "missing": [], "disabled": []})
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        data = advisory.generate(db, scan)["advisory_json"]
        assert data["tool_gaps"] == []
        assert "absence of vulnerabilities" in data["recommendation"]
    finally:
        db.close()