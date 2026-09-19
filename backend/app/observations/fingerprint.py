"""Deterministic observation fingerprinting (Phase 5).

Two observations with the same security-relevant identity must hash to the same
fingerprint so duplicate evidence is suppressed deterministically.  The
fingerprint is a SHA-256 over a canonical, ordered set of fields -- never over
volatile data such as timestamps or response byte counts.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_WS = re.compile(r"\s+")


def _canonical(value: Any) -> Any:
    """Reduce a value to a stable, comparable primitive."""
    if value is None:
        return ""
    if isinstance(value, str):
        return _WS.sub(" ", value.strip()).lower()
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k).strip().lower(): _canonical(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_canonical(v) for v in value]
    return str(value)


def observation_fingerprint(
    observation_type: str,
    subject: str,
    *,
    asset: str | None = None,
    discriminator: Any = None,
) -> str:
    """Stable SHA-256 hex digest of an observation's identity.

    ``discriminator`` should carry only security-relevant, stable data (e.g. the
    normalized endpoint + method for an HTTP response).  Timestamps, response
    times and body sizes must never be included.
    """
    payload = {
        "type": (observation_type or "").strip().lower(),
        "subject": (subject or "").strip().lower(),
        "asset": (asset or "").strip().lower(),
        "discriminator": _canonical(discriminator),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def finding_fingerprint(category: str, host: str, endpoint: str, parameter: str | None, evidence_signature: str | None = None) -> str:
    """Deterministic dedup identity for a finding candidate.

    Mirrors ``observation_fingerprint`` but is tuned for findings: category +
    normalized host + normalized endpoint + parameter (+ optional evidence
    signature).  Two scanners reporting the same underlying issue collapse onto
    the same key.
    """
    payload = {
        "category": (category or "").strip().lower(),
        "host": (host or "").strip().lower(),
        "endpoint": _normalize_endpoint(endpoint),
        "parameter": (parameter or "").strip().lower(),
        "evidence_signature": _canonical(evidence_signature),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _normalize_endpoint(endpoint: str | None) -> str:
    """Normalize an endpoint for dedup: drop query values, collapse slashes."""
    if not endpoint:
        return ""
    value = endpoint.strip()
    if "?" in value:
        value = value.split("?", 1)[0]
    value = re.sub(r"/{2,}", "/", value)
    if len(value) > 1:
        value = value.rstrip("/")
    return value.lower()
