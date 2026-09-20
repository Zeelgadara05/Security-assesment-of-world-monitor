"""Phase 7 deterministic validation ledger tests.

Every confirming/rejecting verdict the pipeline records must be an auditable
FindingValidation row; every confirmed finding must be linked to its evidence
observations via FindingObservationLink.
"""

import uuid

from app.assess import finding_lifecycle as flc
from app.observations import types as obs_types
from app.orchestration import pipeline
from database.connection import SessionLocal
from database.models import (FindingObservationLink, FindingValidation,
                             Observation, Project, Scan, User, Vulnerability)


def _seed(session, *, confirmed=True, candidate=False, vuln_obs=False):
    owner = User(id=f"p7val-{uuid.uuid4().hex[:8]}", email=f"p7val-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7val", user_id=owner.id, scope_json=["v.example"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="v.example", status="Pending")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    if confirmed:
        f = Vulnerability(
            scan_id=scan.id, title="XSS", severity="High", description="d", state="NEW",
            category="xss", endpoint="http://v.example/", source_test="injection.xss.reflected",
            source_tool="native_http", status=flc.STATUS_CONFIRMED, validation_reason="payload reflected",
            rule_id="injection.xss.reflected", evidence_observation_ids=[11, 12],
        )
        session.add(f)
    if candidate:
        c = Vulnerability(
            scan_id=scan.id, title="nuclei hit", severity="Medium", description="ext",
            state="NEW", category="ssl", endpoint="http://v.example/", source_tool="nuclei",
            status=flc.STATUS_CANDIDATE,
        )
        session.add(c)
    if vuln_obs:
        session.add(Observation(
            scan_id=scan.id, tool_name="nuclei", kind="nuclei_finding", subject="http://v.example/",
            data_json={"title": "x"}, observation_type=obs_types.OBS_VULNERABILITY,
        ))
    session.commit()
    session.refresh(scan)
    return scan.id


def test_confirmed_finding_records_confirming_validation(session):
    scan_id = _seed(session, confirmed=True)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        db.query(Observation).filter(Observation.scan_id == scan_id).delete()
        db.commit()
        pipeline._record_validations(db, scan)
        db.commit()
        rows = db.query(FindingValidation).filter(FindingValidation.scan_id == scan_id).all()
        assert len(rows) == 1
        assert rows[0].status == "confirmed"
        assert rows[0].finding_id is not None
        assert rows[0].validator_id == "injection.xss.reflected"
    finally:
        db.close()


def test_candidate_without_native_confirmation_is_rejected(session):
    scan_id = _seed(session, confirmed=False, candidate=True)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        pipeline._record_validations(db, scan)
        db.commit()
        rows = db.query(FindingValidation).filter(FindingValidation.scan_id == scan_id).all()
        assert len(rows) == 1
        assert rows[0].status == "rejected"
        cand = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).first()
        assert rows[0].finding_id == cand.id
    finally:
        db.close()


def test_external_vulnerability_observation_is_unvalidated_candidate(session):
    scan_id = _seed(session, confirmed=False, vuln_obs=True)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        pipeline._record_validations(db, scan)
        db.commit()
        rows = db.query(FindingValidation).filter(FindingValidation.scan_id == scan_id).all()
        assert len(rows) == 1
        assert rows[0].finding_id is None  # candidate without any native confirmation
        assert rows[0].observation_id is not None
        assert rows[0].status == "rejected"
    finally:
        db.close()


def test_link_observations_creates_provenance_edges(session):
    scan_id = _seed(session, confirmed=True)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        pipeline._record_validations(db, scan)
        pipeline._link_observations(db, scan)
        db.commit()
        f = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).first()
        links = db.query(FindingObservationLink).filter(FindingObservationLink.finding_id == f.id).all()
        assert {l.observation_id for l in links} == {11, 12}
    finally:
        db.close()