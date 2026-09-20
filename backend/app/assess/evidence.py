"""Structured evidence construction + persistence helpers (Phase 5/6).

Every finding must retain enough redacted information to reproduce the
reasoning: the request, the response, the expected vs actual security property,
and the boundary that was crossed.  Phase 6 adds integrity hashes over the
redacted payload so accidental mutation of stored evidence is detectable, and
bounded-capture metadata (original vs captured size, truncation flag) so
response bodies are never stored unbounded.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from app.assess.models import CandidateData, EvidenceData
from app.observations.normalize import redact_headers, redact_mapping, redact_text

REDACTION_STATUS = "redacted"

_MAX_EVIDENCE_BODY = 20000  # bounded capture: mirror the HTTP body store limit


def payload_hash(payload: Any) -> str | None:
    """SHA-256 over the canonical JSON of a payload (None in -> None out)."""
    if payload is None:
        return None
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def capture_metrics(payload: Any) -> dict[str, Any]:
    """Bounded-capture metadata for a response payload.

    ``original_size`` is the observed body size; ``captured_size`` is what was
    persisted (never larger); ``truncated`` is True when data was dropped.  When
    the body is not a plain string both sizes are None and ``truncated`` is None
    (nothing was truncated).
    """
    body = payload.get("body") if isinstance(payload, dict) else None
    if not isinstance(body, str):
        return {"original_size": None, "captured_size": None, "truncated": None}
    total = len(body.encode("utf-8"))
    if total <= _MAX_EVIDENCE_BODY:
        return {"original_size": total, "captured_size": total, "truncated": False}
    return {"original_size": total, "captured_size": _MAX_EVIDENCE_BODY, "truncated": True}


def evidence_to_kwargs(finding_id: int, evidence: EvidenceData, observation_id: int | None = None) -> dict[str, Any]:
    """Map an :class:`EvidenceData` to ``FindingEvidence`` ORM kwargs (redacted)."""
    request = redact_mapping(evidence.request) if evidence.request else None
    if isinstance(request, dict) and isinstance(evidence.request, dict) and "headers" in evidence.request:
        request["headers"] = redact_headers(evidence.request.get("headers") or {})
    response = redact_mapping(evidence.response) if evidence.response else None
    if isinstance(response, dict) and isinstance(evidence.response, dict) and "headers" in evidence.response:
        response["headers"] = redact_headers(evidence.response.get("headers") or {})
    metrics = capture_metrics(response)
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
        "request_hash": payload_hash(request),
        "response_hash": payload_hash(response),
        "original_size": metrics["original_size"],
        "captured_size": metrics["captured_size"],
        "truncated": metrics["truncated"],
    }


def verify_evidence_integrity(row) -> dict[str, bool]:
    """Recompute the payload hashes of a persisted evidence row.

    Returns ``{"request_ok": bool, "response_ok": bool}`` where False means the
    stored payload no longer matches its stored hash (accidental mutation).
    """
    current_request = payload_hash(row.request_json)
    current_response = payload_hash(row.response_json)
    return {
        "request_ok": current_request is None or current_request == row.request_hash,
        "response_ok": current_response is None or current_response == row.response_hash,
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
