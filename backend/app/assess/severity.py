"""Deterministic severity model (Phase 5).

Severity is derived from documented impact factors, never copied from a raw
scanner string.  The calculation is pure and testable: the same inputs always
produce the same level.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.observations.types import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

# Baseline impact by vulnerability category.
_CATEGORY_BASE = {
    "sqli": 3,
    "ssti": 3,
    "ssrf": 3,
    "authorization": 3,
    "idor": 3,
    "bola": 3,
    "xss": 2,
    "jwt": 2,
    "oauth": 2,
    "graphql": 2,
    "authentication": 2,
    "disclosure": 2,
    "tls": 2,
    "cors": 1,
    "redirects": 1,
    "methods": 1,
    "http": 0,
    "headers": 0,
}

_LEVELS = [SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]


@dataclass
class SeverityInput:
    category: str
    unauthenticated: bool = False
    requires_auth: bool = False
    boundary_crossed: bool = False
    data_exposure: bool = False
    repeatable: bool = True
    scope_limited: bool = False


def compute_severity(factors: SeverityInput) -> str:
    """Return a deterministic severity level for the given impact factors."""
    score = _CATEGORY_BASE.get((factors.category or "").lower(), 1)

    if factors.unauthenticated:
        score += 1
    if factors.requires_auth:
        score -= 1
    if factors.boundary_crossed:
        score += 1
    if factors.data_exposure:
        score += 1
    if not factors.repeatable:
        score -= 1
    if factors.scope_limited:
        score -= 1

    if score <= 0:
        return SEVERITY_INFO
    return _LEVELS[min(score, len(_LEVELS) - 1)]
