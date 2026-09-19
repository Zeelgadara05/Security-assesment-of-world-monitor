"""Observation normalization and redaction (Phase 5).

Everything persisted as evidence flows through here.  The two guarantees are:

  * normalization -- structured observations always carry a consistent shape
    (type, subject, asset, target, source, status, fingerprint), regardless of
    which tool produced them; and
  * redaction -- credentials (cookies, Authorization headers, API keys, tokens,
    passwords, session identifiers) are replaced with ``<REDACTED>`` before an
    observation or evidence record is written to the database.

Normalization is deterministic and side-effect free so it can be unit tested
without a database or a network.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from app.observations import types
from app.observations.fingerprint import observation_fingerprint

REDACTED = "<REDACTED>"

# Header names whose values must never be persisted in cleartext.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-amz-security-token",
}

# JSON/form/query keys whose values must never be persisted in cleartext.
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "x_api_key",
    "auth",
    "authorization",
    "cookie",
    "set_cookie",
    "session",
    "session_id",
    "sessionid",
    "private_key",
    "jwt",
    "bearer",
}

_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}\b")
_QUERY_SECRET_RE = re.compile(
    r"(?i)\b(" + "|".join(sorted(SENSITIVE_KEYS)) + r")=([^&\s]+)"
)


def redact_text(value: str) -> str:
    """Redact inline credential material from a free-text string."""
    if not value:
        return value
    value = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", value)
    value = _JWT_RE.sub(REDACTED, value)
    value = _QUERY_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", value)
    return value


def redact_headers(headers: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> dict[str, Any]:
    """Return a copy of ``headers`` with sensitive values replaced."""
    out: dict[str, Any] = {}
    if not headers:
        return out
    items = headers.items() if isinstance(headers, Mapping) else headers
    for key, value in items:
        name = str(key)
        if name.strip().lower() in SENSITIVE_HEADERS:
            out[name] = REDACTED
        elif isinstance(value, (list, tuple)):
            out[name] = [redact_text(str(v)) for v in value]
        else:
            out[name] = redact_text(str(value)) if value is not None else ""
    return out


def redact_mapping(value: Any) -> Any:
    """Recursively redact sensitive keys/values from a JSON-like structure."""
    if isinstance(value, Mapping):
        return {
            str(k): (REDACTED if str(k).strip().lower() in SENSITIVE_KEYS else redact_mapping(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_mapping(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def normalize_endpoint(url: str) -> str:
    """Return a stable ``scheme://host[:port]/path`` with query string removed."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.scheme:
        return url
    netloc = parts.netloc.lower()
    path = re.sub(r"/{2,}", "/", parts.path) or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), netloc, path, "", ""))


def observation_discriminator(*, endpoint: str | None = None, method: str | None = None,
                              parameter: str | None = None, extra: Any = None) -> dict:
    """Build the stable, security-relevant discriminator used for fingerprinting."""
    disc: dict[str, Any] = {}
    if endpoint:
        disc["endpoint"] = normalize_endpoint(endpoint)
    if method:
        disc["method"] = method.upper()
    if parameter:
        disc["parameter"] = parameter
    if extra is not None:
        disc["extra"] = extra
    return disc


def build_observation(
    *,
    scan_id: int,
    observation_type: str,
    subject: str,
    tool_name: str,
    source: str = types.SOURCE_ASSESSOR,
    user_id: str | None = None,
    target: str | None = None,
    asset: str | None = None,
    tool_version: str | None = None,
    data: Mapping[str, Any] | None = None,
    raw_output: str = "",
    request: Mapping[str, Any] | None = None,
    response: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    status: str = types.STATUS_OBSERVED,
    discriminator: Any = None,
    observed_at: datetime | None = None,
) -> dict:
    """Normalize an observation into kwargs suitable for the ORM model.

    Request/response headers are redacted; request/response/metadata bodies are
    recursively redacted; the fingerprint is computed from the stable identity.
    """
    if observation_type not in types.OBSERVATION_TYPES:
        raise ValueError(f"unknown observation_type: {observation_type!r}")

    redacted_request = redact_mapping(request) if request else None
    redacted_response = redact_mapping(response) if response else None
    if isinstance(redacted_request, Mapping) and "headers" in redacted_request:
        redacted_request = dict(redacted_request)
        redacted_request["headers"] = redact_headers(dict(request or {}).get("headers"))
    if isinstance(redacted_response, Mapping) and "headers" in redacted_response:
        redacted_response = dict(redacted_response)
        redacted_response["headers"] = redact_headers(dict(response or {}).get("headers"))

    fingerprint = observation_fingerprint(
        observation_type,
        subject,
        asset=asset,
        discriminator=discriminator,
    )

    return {
        "scan_id": scan_id,
        "tool_name": tool_name,
        "kind": observation_type,  # legacy Phase 3 column mirrors the type
        "subject": subject,
        "data_json": redact_mapping(dict(data)) if data else {},
        "raw_output": redact_text(raw_output or ""),
        "user_id": user_id,
        "target": target,
        "asset": asset,
        "observation_type": observation_type,
        "source": source,
        "tool_version": tool_version,
        "request_json": redacted_request,
        "response_json": redacted_response,
        "metadata_json": redact_mapping(dict(metadata)) if metadata else None,
        "fingerprint": fingerprint,
        "status": status,
        "observed_at": observed_at or datetime.utcnow(),
    }
