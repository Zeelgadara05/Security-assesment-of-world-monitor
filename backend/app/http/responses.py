"""Structured HTTP response value object + deterministic differential helpers.

Phase 5 never treats a bare difference as proof of a vulnerability.  These
comparison primitives produce neutral, structured facts (what changed) that a
security test then interprets against an explicit security property.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from app.observations.normalize import redact_headers, redact_text

_MAX_BODY_STORE = 20000


@dataclass
class HTTPResponse:
    status: int
    url: str
    headers: dict[str, Any] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    content_type: str | None = None
    tls: dict[str, Any] | None = None
    request: dict[str, Any] | None = None
    error: str | None = None

    # -- convenience ---------------------------------------------------------
    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, value in self.headers.items():
            if str(key).lower() == target:
                if isinstance(value, (list, tuple)):
                    return ", ".join(str(v) for v in value)
                return str(value)
        return None

    @property
    def body_size(self) -> int:
        return len(self.body or "")

    @property
    def json_body(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        body = self.body or ""
        if len(body) > _MAX_BODY_STORE:
            body = body[:_MAX_BODY_STORE]
        headers: Mapping[str, Any] = redact_headers(self.headers) if redact else self.headers
        return {
            "status": self.status,
            "url": self.url,
            "headers": dict(headers),
            "body": redact_text(body) if redact else body,
            "body_size": self.body_size,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "content_type": self.content_type,
            "redirect_chain": list(self.redirect_chain),
            "tls": self.tls,
            "error": self.error,
        }

    def fingerprint_fields(self) -> dict[str, Any]:
        """Stable identity used for observation fingerprints (no volatile data)."""
        return {
            "status": self.status,
            "content_type": self.content_type,
            "headers": sorted(
                (str(k).lower(), str(v)) for k, v in self.headers.items()
                if str(k).lower() in _FINGERPRINT_HEADERS
            ),
        }


_FINGERPRINT_HEADERS = {"server", "content-type", "x-powered-by", "location", "allow"}


# ---------------------------------------------------------------------------
# Deterministic comparison primitives
# ---------------------------------------------------------------------------
def compare_status(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    return {"equal": baseline.status == observed.status, "baseline": baseline.status, "observed": observed.status}


def compare_headers(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    b = {str(k).lower(): _as_str(v) for k, v in baseline.headers.items()}
    o = {str(k).lower(): _as_str(v) for k, v in observed.headers.items()}
    added = {k: o[k] for k in o if k not in b}
    removed = {k: b[k] for k in b if k not in o}
    changed = {k: {"baseline": b[k], "observed": o[k]} for k in b if k in o and b[k] != o[k]}
    return {"equal": not (added or removed or changed), "added": added, "removed": removed, "changed": changed}


def compare_body(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    b, o = baseline.body or "", observed.body or ""
    return {
        "equal": b == o,
        "length_delta": len(o) - len(b),
        "baseline_length": len(b),
        "observed_length": len(o),
        "contains_marker": None,  # filled by callers with an explicit marker
    }


def compare_length(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    return {
        "baseline": baseline.body_size,
        "observed": observed.body_size,
        "delta": observed.body_size - baseline.body_size,
        "equal": baseline.body_size == observed.body_size,
    }


def compare_structure(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    b, o = baseline.json_body, observed.json_body
    if isinstance(b, dict) and isinstance(o, dict):
        return {
            "json": True,
            "equal_keys": set(b.keys()) == set(o.keys()),
            "added_keys": sorted(set(o.keys()) - set(b.keys())),
            "removed_keys": sorted(set(b.keys()) - set(o.keys())),
        }
    return {"json": False, "equal": (baseline.body or "") == (observed.body or "")}


def compare_timing(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    return {
        "baseline_ms": round(baseline.elapsed_ms, 2),
        "observed_ms": round(observed.elapsed_ms, 2),
        "delta_ms": round(observed.elapsed_ms - baseline.elapsed_ms, 2),
        "note": "timing is never sufficient on its own",
    }


def compare_redirect(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    return {
        "equal": baseline.redirect_chain == observed.redirect_chain,
        "baseline": list(baseline.redirect_chain),
        "observed": list(observed.redirect_chain),
    }


def compare_content_type(baseline: HTTPResponse, observed: HTTPResponse) -> dict[str, Any]:
    return {
        "equal": baseline.content_type == observed.content_type,
        "baseline": baseline.content_type,
        "observed": observed.content_type,
    }


def _as_str(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)
