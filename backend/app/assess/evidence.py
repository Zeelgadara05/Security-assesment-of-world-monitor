"""Structured evidence construction + persistence helpers (Phase 5).

Every finding must retain enough redacted information to reproduce the
reasoning: the request, the response, the expected vs actual security property,
and the boundary that was crossed.
"""
from __future__ import annotations

from typing import Any

from app.assess.models import CandidateData, EvidenceData
from app.observations.normalize import redact_headers, redact_mapping, redact_text

REDACTION_STATUS = "redacted"


def evidence_to_kwargs(finding_id: int, evidence: EvidenceData, observation_id: int | None = None) -> dict[str, Any]:
    """Map an :class:`EvidenceData` to ``FindingEvidence`` ORM kwargs (redacted)."""
    request = redact_mapping(evidence.request) if evidence.request else None
    if isinstance(request, dict) and isinstance(evidence.request, dict) and "headers" in evidence.request:
        request["headers"] = redact_headers(evidence.request.get("headers") or {})
    response = redact_mapping(evidence.response) if evidence.response else None
    if isinstance(response, dict) and isinstance(evidence.response, dict) and "headers" in evidence.response:
        response["headers"] = redact_headers(evidence.response.get("headers") or {})
    return {
        "finding_id": finding_id,
        "observation_id": observation_id,
        "evidence_type": evidence.evidence_type,
        "request_json": request,
        "response_json": response,
        "expected": redact_text(evidence.expected or ""),
        "actual": redact_text(evidence.actual or ""),
        "security_boundary": redact_text(evidence.security_boundary or ""),
        "redaction_status": REDACTION_STATUS,
    }


def summary(candidate: CandidateData) -> str:
    """Deterministic human-readable evidence chain for a candidate."""
    lines = [
        f"Test: {candidate.source_test}",
        f"Category: {candidate.category}",
        f"Endpoint: {candidate.method} {candidate.endpoint}",
    ]
    if candidate.parameter:
        lines.append(f"Parameter: {candidate.parameter}")
    if candidate.security_boundary:
        lines.append(f"Security boundary: {candidate.security_boundary}")
    if candidate.expected:
        lines.append(f"Expected: {candidate.expected}")
    if candidate.actual:
        lines.append(f"Actual: {candidate.actual}")
    lines.append(f"Source tool: {candidate.source_tool}")
    if candidate.observation_ids:
        lines.append("Observations: " + ", ".join(f"#{i}" for i in candidate.observation_ids))
    return "\n".join(lines)
