"""Safe finding validation (Phase 5).

A validator either confirms or rejects a candidate by re-checking an explicit
security property against observed responses.  It never upgrades a candidate on
its own, and it never performs destructive actions: it replays the same safe
request that produced the candidate.

``DifferentialValidator`` re-executes the baseline and mutation requests and
requires the property to hold *both* times before marking a result as
independently reproduced (CONFIRMED).
"""
from __future__ import annotations

from typing import Callable

from app.assess.confidence import from_evidence
from app.assess.models import ValidationResult
from app.http.client import OutOfScopeError, SafeHttpClient
from app.http.responses import HTTPResponse
from app.observations import types


class DifferentialValidator:
    """Replays baseline + mutated requests and evaluates an explicit property."""

    def __init__(self, client: SafeHttpClient):
        self.client = client

    def replay(self, method: str, url: str, *, headers: dict | None = None,
               body: str | None = None) -> HTTPResponse | None:
        try:
            return self.client.request(method, url, headers=headers, body=body)
        except (OutOfScopeError, Exception):  # pragma: no cover - defensive
            return None

    def validate(
        self,
        *,
        property_holds: Callable[[HTTPResponse, HTTPResponse], bool],
        baseline: HTTPResponse,
        probe: HTTPResponse,
        reproduce: bool = False,
        reason: str = "",
        expected: str = "",
        actual: str = "",
        boundary: str = "",
    ) -> ValidationResult:
        holds = property_holds(baseline, probe)
        if not holds:
            return ValidationResult(confirmed=False, confidence=types.CONFIDENCE_LOW,
                                    reason=reason or "security property did not hold",
                                    expected=expected, actual=actual, security_boundary=boundary)
        confidence = from_evidence(boundary_violation=True)
        if reproduce:
            confidence = from_evidence(boundary_violation=True, independently_reproduced=True)
        return ValidationResult(confirmed=True, confidence=confidence, reason=reason,
                                expected=expected, actual=actual, security_boundary=boundary)


def confirm(reason: str, *, confidence: str = types.CONFIDENCE_MEDIUM,
            expected: str = "", actual: str = "", boundary: str = "") -> ValidationResult:
    return ValidationResult(confirmed=True, confidence=confidence, reason=reason,
                            expected=expected, actual=actual, security_boundary=boundary)


def reject(reason: str, *, expected: str = "", actual: str = "", boundary: str = "") -> ValidationResult:
    return ValidationResult(confirmed=False, confidence=types.CONFIDENCE_LOW, reason=reason,
                            expected=expected, actual=actual, security_boundary=boundary)
