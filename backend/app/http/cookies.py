"""Cookie *attribute* capture (Phase 8, check 17.2).

``Set-Cookie`` values are credentials and are redacted everywhere before they
are persisted (see ``app.observations.normalize.redact_headers``).  What the
assessment does need -- and what this module provides -- is the attribute
surface of every cookie the target set: name, HttpOnly, Secure, SameSite,
Domain, Path, expiration semantics.  Values are parsed out and discarded here,
at capture time, so they never reach a persisted structure by any path.
"""
from __future__ import annotations

from typing import Any

FLAG_KEYS = {
    "httponly": "HttpOnly",
    "secure": "Secure",
}


def extract_cookie_attributes(set_cookie_values: Any) -> list[dict[str, Any]]:
    """Return attribute-only records for each ``Set-Cookie`` header value.

    ``set_cookie_values`` may be a single header string or a list/tuple of
    them (multiple Set-Cookie headers).  Cookie values are never included in
    the result.
    """
    if set_cookie_values is None:
        return []
    if isinstance(set_cookie_values, str):
        raw_values = [set_cookie_values]
    elif isinstance(set_cookie_values, (list, tuple)):
        raw_values = [str(v) for v in set_cookie_values]
    else:
        return []

    cookies: list[dict[str, Any]] = []
    for raw in raw_values:
        parts = [p.strip() for p in (raw or "").split(";")]
        if not parts or not parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        if not name:
            continue

        entry: dict[str, Any] = {
            "name": name,
            "httponly": False,
            "secure": False,
            "samesite": None,
            "domain": None,
            "path": None,
            "max_age": None,
            "expires": False,
        }
        for part in parts[1:]:
            key, _, value = part.partition("=")
            key = key.strip()
            value = value.strip().strip('"')
            if key.lower() in FLAG_KEYS:
                entry[key.lower()] = True
            elif key.lower() == "samesite":
                entry["samesite"] = value or "True"
            elif key.lower() == "domain":
                entry["domain"] = value or None
            elif key.lower() == "path":
                entry["path"] = value or None
            elif key.lower() == "max-age":
                try:
                    entry["max_age"] = int(value)
                except (TypeError, ValueError):
                    entry["max_age"] = None
            elif key.lower() == "expires":
                entry["expires"] = True
        entry["session"] = entry["max_age"] is None and not entry["expires"]
        cookies.append(entry)
    return cookies


__all__ = ["extract_cookie_attributes"]