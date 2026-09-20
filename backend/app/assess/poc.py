"""Structured proof-of-concept representation (Phase 6).

A PoC is a safe, deterministic retelling of how a finding was validated: the
request, the expected vs observed behavior, the validation logic, the evidence
records that prove it, and the safety constraints that bound it.  It never
contains destructive steps and never invents requests that were not performed.
"""
from __future__ import annotations

from typing import Any

SAFETY_CONSTRAINTS = (
    "Authorized target only (project scope guard).",
    "Minimal request count and payloads.",
    "No data destruction, credential harvesting, persistence, or post-exploitation.",
    "SSRF validation uses only the configured ssrf_validation_url callback.",
    "Request count bounded by the assessment limits.",
)


def _evidence_entry(evidence) -> dict[str, Any]:
    return {
        "evidence_id": getattr(evidence, "id", None),
        "evidence_type": getattr(evidence, "evidence_type", None) or "comparison",
        "expected": getattr(evidence, "expected", None),
        "actual": getattr(evidence, "actual", None),
        "security_boundary": getattr(evidence, "security_boundary", None),
        "request_hash": getattr(evidence, "request_hash", None),
        "response_hash": getattr(evidence, "response_hash", None),
        "truncated": getattr(evidence, "truncated", None),
    }


def build_poc(db, finding) -> dict[str, Any]:
    """Deterministic PoC derived from the finding + its first evidence records."""
    from database.models import FindingEvidence

    evidential = (
        db.query(FindingEvidence)
        .filter(FindingEvidence.finding_id == finding.id)
        .order_by(FindingEvidence.id.asc())
        .all()
        if finding.id else []
    )
    first = evidential[0] if evidential else None
    method = finding.http_method or "GET"
    endpoint = finding.endpoint or finding.target or ""
    return {
        "setup": (
            "Establish the authorized test identity and the authorized target scope "
            "for this scan; all requests are scope-guarded."
        ),
        "request": {
            "method": method,
            "endpoint": endpoint,
            "parameter": finding.parameter,
            "request_hash": getattr(first, "request_hash", None) if first else None,
        },
        "expected_behavior": getattr(first, "expected", None) or finding.validation_reason,
        "observed_behavior": getattr(first, "actual", None) or "see evidence records",
        "validation_logic": finding.validation_reason or "deterministic validator",
        "evidence": [_evidence_entry(e) for e in evidential],
        "safety_constraints": list(SAFETY_CONSTRAINTS),
        "steps_to_reproduce": (
            f"1. Establish the authorized test identity.\n"
            f"2. Send the observed baseline request: {method} {endpoint}\n"
            f"3. Modify the controlled input (parameter: {finding.parameter or 'n/a'}).\n"
            f"4. Send the request within the authorized target scope.\n"
            f"5. Observe the response.\n"
            f"6. Compare baseline and test response.\n"
            f"7. Confirm the deterministic validation condition ({finding.validation_reason or 'validated'})."
        ),
    }


__all__ = ["SAFETY_CONSTRAINTS", "build_poc"]