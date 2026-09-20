"""Phase 7 typed event stream tests.

``ScanEvent`` rows are append-only with a monotonic per-scan ``seq``.
``replay`` returns real rows only, from any cursor, never invented events.
"""

import uuid

import pytest

from app.orchestration import events
from database.connection import SessionLocal
from database.models import Project, Scan, ScanEvent, User


def _make_scan(session, target="p7ev.example"):
    owner = User(id=f"p7ev-{uuid.uuid4().hex[:8]}", email=f"p7ev-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7ev", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def test_unknown_event_type_is_rejected(session):
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        with pytest.raises(ValueError):
            events.emit(db, scan_id, "fabricated", {})
    finally:
        db.close()


def test_seq_is_monotonic_per_scan(session):
    a = _make_scan(session)
    b = _make_scan(session)
    db = SessionLocal()
    try:
        events.emit_state(db, a, "created", "created")
        events.emit_state(db, a, "queued", "queued")
        events.emit_state(db, b, "created", "created")
        seqs_a = [e.seq for e in db.query(ScanEvent).filter(ScanEvent.scan_id == a).all()]
        seqs_b = [e.seq for e in db.query(ScanEvent).filter(ScanEvent.scan_id == b).all()]
        assert seqs_a == [1, 2]
        assert seqs_b == [1]  # independent per scan
    finally:
        db.close()


def test_all_helpers_persist_real_rows(session):
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        events.emit_state(db, scan_id, "created", "reason")
        events.emit_stage(db, scan_id, "PRECHECK", "started")
        events.emit_tool(db, scan_id, "nmap", "started", stage="PORT_SERVICE_DISCOVERY", attempt=1)
        events.emit_finding(db, scan_id, finding_id=7, title="XSS", severity="High",
                            status="confirmed", fingerprint="fp-1")
        events.emit_validation(db, scan_id, finding_id=7, validator_id="xss", status="confirmed",
                               reason="payload reflected")
        page = events.replay(db, scan_id)
        assert page["has_more"] is False
        types = [e["type"] for e in page["events"]]
        assert types == ["state", "stage", "tool", "finding", "validation"]
    finally:
        db.close()


def test_replay_cursor_pagination(session):
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        for i in range(5):
            events.emit(db, scan_id, "state", {"state": "s", "n": i})
        page1 = events.replay(db, scan_id, cursor=0, limit=2)
        assert len(page1["events"]) == 2
        assert page1["has_more"] is True
        page2 = events.replay(db, scan_id, cursor=page1["cursor"], limit=10)
        assert len(page2["events"]) == 3
        assert page2["has_more"] is False
        assert [e["seq"] for e in page1["events"]] == [1, 2]
        assert [e["seq"] for e in page2["events"]] == [3, 4, 5]
    finally:
        db.close()


def test_replay_returns_nothing_for_unsent_cursor(session):
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        events.emit(db, scan_id, "state", {"state": "created"})
        page = events.replay(db, scan_id, cursor=10 ** 6)
        assert page["events"] == []
        assert page["has_more"] is False
    finally:
        db.close()