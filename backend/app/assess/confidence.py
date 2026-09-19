"""Deterministic confidence model (Phase 5).

Confidence reflects evidence quality only.  It is never inflated because
multiple tools agree, and the validator can never silently upgrade a candidate.
"""
from __future__ import annotations

from app.observations import types

_RANK = {
    types.CONFIDENCE_LOW: 0,
    types.CONFIDENCE_MEDIUM: 1,
    types.CONFIDENCE_HIGH: 2,
    types.CONFIDENCE_CONFIRMED: 3,
}


def rank(level: str) -> int:
    return _RANK.get((level or "").upper(), 0)


def at_least(level: str, minimum: str) -> bool:
    return rank(level) >= rank(minimum)


def downgrade(level: str) -> str:
    """Return the next-lower confidence level (never below LOW)."""
    current = rank(level)
    return types.CONFIDENCE_LOW if current <= 0 else [types.CONFIDENCE_LOW, types.CONFIDENCE_MEDIUM, types.CONFIDENCE_HIGH, types.CONFIDENCE_CONFIRMED][current - 1]


def from_evidence(
    *,
    reflected: bool = False,
    consistent_differential: bool = False,
    boundary_violation: bool = False,
    independently_reproduced: bool = False,
) -> str:
    """Map evidence quality signals to a confidence level."""
    if independently_reproduced and boundary_violation:
        return types.CONFIDENCE_CONFIRMED
    if boundary_violation:
        return types.CONFIDENCE_HIGH
    if consistent_differential:
        return types.CONFIDENCE_MEDIUM
    if reflected:
        return types.CONFIDENCE_LOW
    return types.CONFIDENCE_LOW
