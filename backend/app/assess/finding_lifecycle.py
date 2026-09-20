"""Finding lifecycle (Phase 6).

An explicit, persisted state machine distinguishes candidate from confirmed from
rejected/duplicate/accepted/remediated/reopened.  Every transition appends an
immutable row to ``finding_status_history``; historical state is never
overwritten or deleted.  ``candidate == vulnerability`` is explicitly false.
"""
from __future__ import annotations

import datetime

# Finding statuses (spec 7).
STATUS_CANDIDATE = "candidate"
STATUS_VALIDATED = "validated"
STATUS_CONFIRMED = "confirmed"
STATUS_REJECTED = "rejected"
STATUS_DUPLICATE = "duplicate"
STATUS_ACCEPTED = "accepted"
STATUS_REMEDIATED = "remediated"
STATUS_REOPENED = "reopened"

STATUSES = (
    STATUS_CANDIDATE, STATUS_VALIDATED, STATUS_CONFIRMED, STATUS_REJECTED,
    STATUS_DUPLICATE, STATUS_ACCEPTED, STATUS_REMEDIATED, STATUS_REOPENED,
)

# Deterministic transition graph: status -> allowed next statuses.
_TRANSITIONS = {
    STATUS_CANDIDATE: {STATUS_VALIDATED, STATUS_REJECTED, STATUS_DUPLICATE,
                       STATUS_ACCEPTED, STATUS_CONFIRMED},
    STATUS_VALIDATED: {STATUS_CONFIRMED, STATUS_REJECTED, STATUS_DUPLICATE,
                       STATUS_ACCEPTED},
    STATUS_CONFIRMED: {STATUS_ACCEPTED, STATUS_REMEDIATED, STATUS_DUPLICATE,
                       STATUS_REOPENED},
    STATUS_ACCEPTED: {STATUS_REMEDIATED, STATUS_REOPENED, STATUS_DUPLICATE},
    STATUS_REMEDIATED: {STATUS_REOPENED},
    STATUS_REJECTED: {STATUS_REOPENED},
    STATUS_DUPLICATE: {STATUS_REOPENED},
    STATUS_REOPENED: {STATUS_CANDIDATE, STATUS_CONFIRMED, STATUS_REJECTED},
}

_INITIAL_ACTOR = "assessment_engine"


def allowed_transitions(from_status: str) -> set[str]:
    return set(_TRANSITIONS.get(from_status, set()))


def is_terminal(status: str) -> bool:
    return status in (STATUS_ACCEPTED, STATUS_REMEDIATED)


def record_initial(db, finding, *, actor: str = _INITIAL_ACTOR, reason: str = "",
                   from_status: str = "none") -> None:
    """Record the initial creation of a finding (no prior status)."""
    from database.models import FindingStatusHistory

    now = datetime.datetime.utcnow()
    db.add(FindingStatusHistory(
        finding_id=finding.id,
        from_status=from_status,
        to_status=finding.status or STATUS_CONFIRMED,
        actor=actor,
        reason=reason or f"finding created as {finding.status or STATUS_CONFIRMED}",
        created_at=now,
    ))
    finding.created_at = finding.created_at or now
    finding.first_seen = finding.first_seen or now
    finding.last_seen = now
    if not finding.fingerprint:
        finding.fingerprint = finding.dedup_key or None


def transition(db, finding, to_status: str, *, actor: str = _INITIAL_ACTOR,
               reason: str = "") -> str:
    """Transition a finding to ``to_status``, recording history immutably.

    Returns the effective status (the requested one) and raises
    :class:`InvalidTransition` for illegal jumps or unknown statuses.
    """
    from database.models import FindingStatusHistory

    if to_status not in STATUSES:
        raise InvalidTransition(f"unknown finding status {to_status!r}")
    from_status = finding.status or STATUS_CANDIDATE
    if from_status == to_status:
        return from_status
    if to_status not in _TRANSITIONS.get(from_status, set()):
        raise InvalidTransition(
            f"illegal transition {from_status} -> {to_status} "
            f"(allowed: {sorted(_TRANSITIONS.get(from_status, set()))})")
    now = datetime.datetime.utcnow()
    finding.status = to_status
    finding.updated_at = now
    finding.last_seen = now
    if to_status in (STATUS_REMEDIATED,):
        finding.resolved_at = now
    db.add(FindingStatusHistory(
        finding_id=finding.id,
        from_status=from_status,
        to_status=to_status,
        actor=actor,
        reason=reason or f"transition {to_status}",
        created_at=now,
    ))
    return to_status


class InvalidTransition(ValueError):
    """Raised when a finding transition is not allowed by the state graph."""


def apply_external_status(db, finding, requested: str, *, actor: str = "system") -> str:
    """Public API entry for manual status changes with a whitelist."""
    aliases = {
        "FALSE_POSITIVE": STATUS_REJECTED,
        "DUPLICATE": STATUS_DUPLICATE,
        "ACCEPTED_RISK": STATUS_ACCEPTED,
        "RESOLVED": STATUS_REMEDIATED,
    }
    normalized = aliases.get(requested.upper(), requested.lower())
    return transition(db, finding, normalized, actor=actor,
                      reason=f"operator triage to {normalized}")


__all__ = [
    "STATUS_ACCEPTED", "STATUS_CANDIDATE", "STATUS_CONFIRMED", "STATUS_DUPLICATE",
    "STATUS_REJECTED", "STATUS_REMEDIATED", "STATUS_REOPENED", "STATUS_VALIDATED",
    "STATUSES", "InvalidTransition", "allowed_transitions", "apply_external_status",
    "is_terminal", "record_initial", "transition",
]