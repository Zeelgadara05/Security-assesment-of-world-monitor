"""Phase 7 cross-scan finding tracking tests.

Same-fingerprint findings are linked across scans and diffed into
added/removed/retained/reintroduced sets deterministically.
"""

import uuid

from app.assess import tracking
from database.connection import SessionLocal
from database.models import Project, Scan, User, Vulnerability


def _make(session, target="t.example") -> int:
    owner = User(id=f"p7tr-{uuid.uuid4().hex[:8]}", email=f"p7tr-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7tr", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Completed")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def _add_finding(session, scan_id, key, title="XSS", severity="High"):
    f = Vulnerability(scan_id=scan_id, title=title, severity=severity, state="NEW",
                      description="d", dedup_key=key, evidence_observation_ids=[1])
    session.add(f)
    session.commit()
    session.refresh(f)
    return f.id


def test_fingerprint_fallback_is_deterministic():
    class F:
        fingerprint = None
        dedup_key = None
        rule_id = "r1"
        target = "a.example"
        title = "  Title  "

    assert tracking.fingerprint_of(F()) == "r1|a.example|Title"
    F.fingerprint = "fp-9"
    assert tracking.fingerprint_of(F()) == "fp-9"


def test_update_cross_scan_stamps_first_last_count(session):
    scan1 = _make(session)
    scan2 = _make(session)
    _add_finding(session, scan1, "fp-a", title="a")
    _add_finding(session, scan2, "fp-a", title="a")
    _add_finding(session, scan1, "fp-b", title="b")
    db = SessionLocal()
    try:
        s2 = db.query(Scan).filter(Scan.id == scan2).first()
        summary = tracking.update_cross_scan(db, s2)
        db.commit()
        assert summary["updated"] == 1
        rows = db.query(Vulnerability).filter(Vulnerability.scan_id == scan2).all()
        assert len(rows) == 1
        f = rows[0]
        assert f.occurrence_count == 2
        assert f.first_scan_id == scan1  # earliest scan with the same fingerprint
        assert f.last_scan_id == scan2
    finally:
        db.close()


def test_compare_buckets(session):
    a = _make(session)
    b = _make(session)
    c = _make(session)
    _add_finding(session, c, "fp-rein")   # historically present, gone in a
    _add_finding(session, a, "fp-keep")
    _add_finding(session, a, "fp-gone")
    _add_finding(session, b, "fp-new")
    _add_finding(session, b, "fp-keep")   # retained (both a and b)
    _add_finding(session, b, "fp-rein")   # reintroduced (in c, absent in a, back in b)
    db = SessionLocal()
    try:
        diff = tracking.compare(db, a, b)
        assert diff["added"] == ["fp-new"]
        assert diff["removed"] == ["fp-gone"]
        assert diff["retained"] == ["fp-keep"]
        assert diff["reintroduced"] == ["fp-rein"]
    finally:
        db.close()


def test_compare_same_scan_is_all_retained(session):
    scan = _make(session)
    _add_finding(session, scan, "fp-1")
    _add_finding(session, scan, "fp-2")
    db = SessionLocal()
    try:
        diff = tracking.compare(db, scan, scan)
        assert diff["retained"] == ["fp-1", "fp-2"]
        assert diff["added"] == [] and diff["removed"] == [] and diff["reintroduced"] == []
    finally:
        db.close()