"""Phase 7 scan state machine.

``Scan.state`` is the execution-platform state (created/queued/preflight/
running/validating/finalizing/...).  It is a superset of the legacy
``Scan.stage`` (queued/starting/recon/.../reporting) which remains populated so
all Phase 4 consumers, SSE and tests keep working unchanged.

Transitions are explicit and guarded: a pipeline step can only move a scan to a
state reachable from its current one.  Terminal states (completed,
completed_with_gaps, blocked, failed, cancelled) are immutable.
"""
from __future__ import annotations

CREATED = "created"
QUEUED = "queued"
PREFLIGHT = "preflight"
RUNNING = "running"
VALIDATING = "validating"
FINALIZING = "finalizing"
COMPLETED = "completed"
COMPLETED_WITH_GAPS = "completed_with_gaps"
BLOCKED = "blocked"
FAILED = "failed"
CANCELLED = "cancelled"

ALL = (
    CREATED, QUEUED, PREFLIGHT, RUNNING, VALIDATING, FINALIZING,
    COMPLETED, COMPLETED_WITH_GAPS, BLOCKED, FAILED, CANCELLED,
)

# Active (non-terminal) states.
ACTIVE = (CREATED, QUEUED, PREFLIGHT, RUNNING, VALIDATING, FINALIZING)

TERMINAL = frozenset({COMPLETED, COMPLETED_WITH_GAPS, BLOCKED, FAILED, CANCELLED})

# Explicit transition table.  Anything not listed is an illegal transition.
_TRANSITIONS: dict[str, frozenset] = {
    CREATED: frozenset({QUEUED, CANCELLED}),
    QUEUED: frozenset({PREFLIGHT, CANCELLED, FAILED, BLOCKED}),
    PREFLIGHT: frozenset({RUNNING, BLOCKED, CANCELLED, FAILED}),
    RUNNING: frozenset({VALIDATING, BLOCKED, COMPLETED_WITH_GAPS, CANCELLED, FAILED}),
    VALIDATING: frozenset({FINALIZING, CANCELLED, FAILED, BLOCKED}),
    FINALIZING: frozenset({COMPLETED, COMPLETED_WITH_GAPS, CANCELLED, FAILED}),
    COMPLETED: frozenset(),
    COMPLETED_WITH_GAPS: frozenset(),
    BLOCKED: frozenset(),
    FAILED: frozenset(),
    CANCELLED: frozenset(),
}

# Terminal stable order used when persisting a *final* state machine summary.
TERMINAL_ORDER = (COMPLETED, COMPLETED_WITH_GAPS, BLOCKED, FAILED, CANCELLED)


def is_terminal(state: str) -> bool:
    return (state or "") in TERMINAL


def is_active(state: str) -> bool:
    return (state or "") in ACTIVE


def can_transition(current: str, target: str) -> bool:
    return target in _TRANSITIONS.get(current, frozenset())


def validate_transition(current: str, target: str) -> None:
    """Raise ValueError for an illegal state transition."""
    if current not in _TRANSITIONS:
        raise ValueError(f"unknown scan state: {current!r}")
    if target not in _TRANSITIONS:
        raise ValueError(f"unknown scan state: {target!r}")
    if not can_transition(current, target):
        raise ValueError(
            f"illegal scan state transition: {current!r} -> {target!r}")


def coarse_completion(state: str) -> str:
    """Map a Phase 7 terminal state onto the legacy Partially Completed/Failed
    vocabulary used by existing progress consumers."""
    if state == COMPLETED:
        return "Completed"
    if state == COMPLETED_WITH_GAPS:
        return "Partially Completed"
    if state == BLOCKED:
        return "Blocked"
    if state == FAILED:
        return "Failed"
    if state == CANCELLED:
        return "Cancelled"
    return "Running"


__all__ = [
    "ALL", "ACTIVE", "TERMINAL", "TERMINAL_ORDER",
    "CREATED", "QUEUED", "PREFLIGHT", "RUNNING", "VALIDATING", "FINALIZING",
    "COMPLETED", "COMPLETED_WITH_GAPS", "BLOCKED", "FAILED", "CANCELLED",
    "is_terminal", "is_active", "can_transition", "validate_transition",
    "coarse_completion",
]