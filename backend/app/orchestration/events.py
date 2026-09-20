"""Typed, append-only scan event stream (Phase 7).

The pipeline emits a ScanEvent row for every substantive thing that really
happened: state transitions, stage lifecycle, tool start/finish/skip, preflight
outcomes, coverage/progress changes, findings and their validations, and the
terminal resolution.  Rows are id-ordered with a per-scan ``seq`` so a client
can replay the stream from any cursor (``/scans/{id}/typed-events``).

Nothing invents events: an emit is only called after the described artifact was
persisted by the caller.
"""
from __future__ import annotations

from database.models import ScanEvent

EVENT_STATE = "state"
EVENT_STAGE = "stage"
EVENT_TOOL = "tool"
EVENT_PREFLIGHT = "preflight"
EVENT_PROGRESS = "progress"
EVENT_COVERAGE = "coverage"
EVENT_FINDING = "finding"
EVENT_VALIDATION = "validation"
EVENT_DONE = "done"
EVENT_ERROR = "error"

KNOWN_EVENT_TYPES = frozenset({
    EVENT_STATE, EVENT_STAGE, EVENT_TOOL, EVENT_PREFLIGHT, EVENT_PROGRESS,
    EVENT_COVERAGE, EVENT_FINDING, EVENT_VALIDATION, EVENT_DONE, EVENT_ERROR,
})


def next_seq(db, scan_id: int) -> int:
    from sqlalchemy import func

    current = (
        db.query(func.max(ScanEvent.seq))
        .filter(ScanEvent.scan_id == scan_id)
        .scalar()
    )
    return int(current or 0) + 1


def emit(db, scan_id: int, event_type: str, data: dict | None = None) -> int:
    """Append one event (caller commits).  Returns the row id."""
    if event_type not in KNOWN_EVENT_TYPES:
        raise ValueError(f"unknown scan event type: {event_type!r}")
    event = ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        data=data or {},
        seq=next_seq(db, scan_id),
    )
    db.add(event)
    db.flush()
    return event.id


def emit_state(db, scan_id: int, state: str, reason: str = "") -> int:
    return emit(db, scan_id, EVENT_STATE, {
        "state": state,
        "reason": reason,
    })


def emit_stage(db, scan_id: int, name: str, status: str,
               reason: str | None = None) -> int:
    return emit(db, scan_id, EVENT_STAGE, {
        "stage": name,
        "status": status,
        "reason": reason or "",
    })


def emit_tool(db, scan_id: int, tool: str, status: str,
              stage: str | None = None, attempt: int = 1,
              detail: dict | None = None) -> int:
    data = {"tool": tool, "status": status, "attempt": attempt}
    if stage:
        data["stage"] = stage
    if detail:
        data.update(detail)
    return emit(db, scan_id, EVENT_TOOL, data)


def emit_finding(db, scan_id: int, finding_id: int, title: str,
                 severity: str, status: str, fingerprint: str | None = None) -> int:
    return emit(db, scan_id, EVENT_FINDING, {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": status,
        "fingerprint": fingerprint,
    })


def emit_validation(db, scan_id: int, finding_id: int | None,
                    validator_id: str, status: str, reason: str = "") -> int:
    return emit(db, scan_id, EVENT_VALIDATION, {
        "finding_id": finding_id,
        "validator_id": validator_id,
        "status": status,
        "reason": reason,
    })


def replay(db, scan_id: int, cursor: int = 0, limit: int = 500) -> list[dict]:
    """Replay persisted events after ``cursor`` (exclusive by event id)."""
    rows = (
        db.query(ScanEvent)
        .filter(ScanEvent.scan_id == scan_id, ScanEvent.id > cursor)
        .order_by(ScanEvent.id.asc())
        .limit(limit)
        .all()
    )
    last = rows[-1].id if rows else cursor
    return {
        "cursor": last,
        "has_more": len(rows) == limit,
        "events": [
            {
                "id": e.id,
                "seq": e.seq,
                "type": e.event_type,
                "data": e.data or {},
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in rows
        ],
    }


__all__ = [
    "emit", "emit_state", "emit_stage", "emit_tool", "emit_finding",
    "emit_validation", "replay", "next_seq",
    "EVENT_STATE", "EVENT_STAGE", "EVENT_TOOL", "EVENT_PREFLIGHT",
    "EVENT_PROGRESS", "EVENT_COVERAGE", "EVENT_FINDING", "EVENT_VALIDATION",
    "EVENT_DONE", "EVENT_ERROR",
]