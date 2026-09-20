"""Report redaction guards (Phase 6).

The report must never embed raw command output or raw headers; only the
``redacted`` projections produced by the observation normalizers and the
sanitized configuration snapshot are assembled.  These helpers re-apply the
project-wide redaction so defence-in-depth holds even for fields that did not
flow through the normalizers.
"""
from __future__ import annotations

from app.observations.normalize import redact_headers, redact_mapping, redact_text


def safe_text(value) -> str:
    """Redact any secrets-shaped content in free-form text."""
    text = str(value or "").strip()
    return redact_text(text)[:4000]


def safe_mapping(value) -> dict:
    """Redact any mapping-shaped payload (e.g. evidence request/response)."""
    if not isinstance(value, dict):
        return {}
    out = redact_mapping(value)
    if "headers" in value and isinstance(value["headers"], dict):
        out["headers"] = redact_headers(value["headers"])
    return out


__all__ = ["safe_mapping", "safe_text"]