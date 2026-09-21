"""Real World Monitor health/connectivity check (Phase 8).

A health check issues one real, scope-guarded GET against the configured base
URL and records whatever the deployment actually returned: HTTP status,
response timing, detected server/application metadata and TLS information when
HTTPS is used.  The result is *reachability*, never a security verdict -- HTTP
200 only means the request returned successfully.

Scope is enforced before the request and again on every redirect hop (the
reused ``SafeHttpClient`` does both).  An out-of-scope destination is recorded
as a blocked step, not probed.
"""
from __future__ import annotations

import datetime
import urllib.parse

from app.http.client import HttpLimits, OutOfScopeError, SafeHttpClient
from app.http.fingerprints import technology_hints
from app.integrations.world_monitor.models import HealthResult

_TIMEOUT_SECONDS = 8.0


def _valid_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url or "")
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def check_health(url: str, scope_guard, client: SafeHttpClient | None = None) -> HealthResult:
    """Probe ``url`` with one real request. Returns a HealthResult (never raises
    for network conditions; raises only for internal misuse)."""
    url = (url or "").strip().rstrip("/") or ""
    now = datetime.datetime.utcnow().isoformat()

    if not _valid_url(url):
        return HealthResult(url=url, reachable=False, http_status=0, error="invalid or unsupported URL",
                            checked_at=now)

    if not scope_guard(url):
        return HealthResult(url=url, reachable=False, http_status=0,
                            error="blocked: destination outside authorized scope", checked_at=now)

    if client is None:
        client = SafeHttpClient(
            scope_guard,
            HttpLimits(active_testing=False, request_timeout=_TIMEOUT_SECONDS),
            capture_tls=url.startswith("https://"),
        )

    try:
        resp = client.get(url)
    except OutOfScopeError as exc:
        return HealthResult(url=url, reachable=False, http_status=0,
                            error=f"blocked: {exc}", checked_at=now)
    if resp.error and resp.status == 0:
        return HealthResult(url=url, reachable=False, http_status=0, elapsed_ms=resp.elapsed_ms,
                            error=str(resp.error), checked_at=now)

    headers = {str(k): (", ".join(str(x) for x in v) if isinstance(v, list) else str(v))
               for k, v in (resp.headers or {}).items()}
    server = headers.get("Server") or headers.get("server")
    metadata = technology_hints(headers)
    metadata_payload = {
        "content_type": resp.content_type,
        "technology_hints": metadata,
        "redirect_chain": list(resp.redirect_chain or []),
    }

    return HealthResult(
        url=url,
        reachable=resp.status > 0,
        http_status=resp.status,
        elapsed_ms=resp.elapsed_ms,
        server=server,
        version_hint=metadata[0]["value"] if metadata and metadata[0]["kind"] == "server" else None,
        detected_metadata=metadata_payload,
        tls=resp.tls,
        error=None,
        checked_at=now,
    )


__all__ = ["check_health"]