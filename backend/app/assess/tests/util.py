"""Shared helpers for security tests (Phase 5)."""
from __future__ import annotations

from typing import Any


def observation_headers(observation: dict) -> dict[str, str]:
    """Lower-cased header map from a persisted observation dict."""
    response = observation.get("response_json") or {}
    headers = response.get("headers") or {}
    if not headers:
        headers = (observation.get("data_json") or {}).get("headers") or {}
    return {str(k).lower(): _as_str(v) for k, v in headers.items()}


def observation_body(observation: dict) -> str:
    response = observation.get("response_json") or {}
    body = response.get("body")
    if body is None:
        body = observation.get("raw_output")
    if isinstance(body, (dict, list)):
        import json
        return json.dumps(body)
    return body or ""


def observation_status(observation: dict) -> int | None:
    response = observation.get("response_json") or {}
    status = response.get("status")
    if status is None:
        status = (observation.get("data_json") or {}).get("status")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def observation_url(observation: dict) -> str:
    response = observation.get("response_json") or {}
    return response.get("url") or observation.get("subject") or ""


def _as_str(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def iter_parameters(context) -> list[dict]:
    """Enumerate injectable parameters from explicit config or endpoint queries.

    Returns dicts of {endpoint, method, parameter, value}.  Tests only ever act
    on parameters that were actually observed/declared -- never guessed.
    """
    from urllib.parse import parse_qsl, urlsplit

    found: list[dict] = []

    explicit = (context.config or {}).get("parameters") or (context.metadata or {}).get("parameters")
    if isinstance(explicit, list):
        for item in explicit:
            if isinstance(item, dict) and item.get("endpoint") and item.get("parameter"):
                found.append({
                    "endpoint": item["endpoint"],
                    "method": (item.get("method") or "GET").upper(),
                    "parameter": item["parameter"],
                    "value": item.get("value", ""),
                })

    for endpoint in context.endpoints:
        parts = urlsplit(endpoint)
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            candidate = {"endpoint": endpoint, "method": "GET", "parameter": name, "value": value}
            if candidate not in found:
                found.append(candidate)
    return found


def with_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` replaced by ``value``."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


