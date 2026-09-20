"""Phase 6 evidence-integrity tests.

Evidence records carry SHA-256 hashes over the redacted payload and bounded
capture metadata (original vs captured size, truncation).  Mutation of a stored
payload must be detectable by re-verifying the hash.
"""
from app.assess.evidence import capture_metrics, payload_hash, verify_evidence_integrity
from app.assess.models import EvidenceData
from database.models import FindingEvidence


def test_payload_hash_is_deterministic_over_canonical_json():
    left = payload_hash({"b": 2, "a": [1, 2], "nested": {"z": "z", "y": "y"}})
    right = payload_hash({"a": [1, 2], "b": 2, "nested": {"y": "y", "z": "z"}})
    assert left == right
    assert len(left) == 64
    assert payload_hash(None) is None
    assert payload_hash("a") != payload_hash("b")


def test_capture_metrics_within_limit_not_truncated():
    body = "x" * 100
    metrics = capture_metrics({"status": 200, "body": body})
    assert metrics == {"original_size": 100, "captured_size": 100, "truncated": False}


def test_capture_metrics_over_limit_are_truncated():
    body = "x" * 50000
    metrics = capture_metrics({"status": 200, "body": body})
    assert metrics["truncated"] is True
    assert metrics["original_size"] == 50000
    assert metrics["captured_size"] <= 50000
    assert metrics["captured_size"] < metrics["original_size"]


def test_capture_metrics_missing_body_not_measured():
    metrics = capture_metrics({"status": 204})
    assert metrics == {"original_size": None, "captured_size": None, "truncated": None}


def test_evidence_row_carries_hashes_and_integrity_ok(session):
    from database.models import Project, Scan, User

    user = User(id="ev-b25c1afdb0", email="ev-integrity@test.local", role="user")
    session.add(user)
    session.commit()
    project = Project(name="ev", user_id=user.id, scope_json=[])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="ev.example.com", status="Completed", stage="completed")
    session.add(scan)
    session.commit()
    from database.models import Vulnerability

    finding = Vulnerability(scan_id=scan.id, title="f", severity="Low", description="d",
                            category="headers", status="confirmed")
    session.add(finding)
    session.commit()

    evidence = EvidenceData(
        evidence_type="comparison", expected="CSP present", actual="CSP absent",
        security_boundary="client-side execution",
        request={"method": "GET", "url": "https://ev.example.com/", "headers": {}},
        response={"status": 200, "headers": {}, "body": "ok"},
    )
    from app.assess.evidence import evidence_to_kwargs

    row = FindingEvidence(**evidence_to_kwargs(finding.id, evidence, None))
    session.add(row)
    session.commit()
    session.refresh(row)

    assert row.request_hash and len(row.request_hash) == 64
    assert row.response_hash and len(row.response_hash) == 64
    assert row.original_size == 2  # "ok"
    assert row.captured_size == 2
    assert row.truncated is False
    verified = verify_evidence_integrity(row)
    assert verified == {"request_ok": True, "response_ok": True}


def test_mutated_payload_is_detected(session):
    from database.models import Project, Scan, User, Vulnerability

    user = User(id="ev-mut-9991", email="ev-mutate@test.local", role="user")
    session.add(user)
    session.commit()
    project = Project(name="evm", user_id=user.id, scope_json=[])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="evm.example.com", status="Completed", stage="completed")
    session.add(scan)
    session.commit()
    finding = Vulnerability(scan_id=scan.id, title="f", severity="Low", description="d",
                            category="headers", status="confirmed")
    session.add(finding)
    session.commit()

    row = FindingEvidence(finding_id=finding.id, evidence_type="comparison",
                          request_json={"headers": {}}, response_json={"body": "a"})
    session.add(row)
    session.commit()
    session.refresh(row)
    # Tamper with the stored payload after the hash was recorded.
    row.response_json = {"body": "HACKED"}
    session.commit()
    verified = verify_evidence_integrity(row)
    assert verified["response_ok"] is False