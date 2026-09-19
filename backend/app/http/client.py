"""Scope-safe, rate-limited native HTTP client (Phase 5).

Built on the standard library only (urllib), so the assessment engine remains
useful even when every external scanner is absent.  Hard guarantees:

  * every request (including each redirect hop) passes the scope guard before
    a socket is opened;
  * global and per-test request budgets, redirect limits, timeouts and response
    size limits are enforced;
  * 4xx/5xx are captured as observations, not raised (they are evidence);
  * no state-changing method is ever sent unless the caller explicitly asks.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from app.http.requests import HTTPRequest
from app.http.responses import HTTPResponse


class OutOfScopeError(RuntimeError):
    """Raised when a request would leave the authorized scope."""


class RequestLimitExceeded(RuntimeError):
    """Raised when the per-test or per-scan request budget is exhausted."""


@dataclass
class HttpLimits:
    max_requests_per_scan: int = 200
    max_requests_per_test: int = 40
    request_timeout: float = 8.0
    redirect_limit: int = 5
    response_size_limit: int = 200_000
    concurrency_limit: int = 4
    test_depth_limit: int = 3
    user_agent: str = "CyberAgent-Assessment/1.0 (authorized)"
    user_agent_suffix: str = ""
    active_testing: bool = True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class SafeHttpClient:
    """A minimal, deterministic HTTP client bound to an authorized scope."""

    def __init__(
        self,
        scope_guard: Callable[[str], bool],
        limits: HttpLimits | None = None,
        *,
        capture_tls: bool = False,
    ) -> None:
        self.scope_guard = scope_guard
        self.limits = limits or HttpLimits()
        self.capture_tls = capture_tls
        self.requests_made = 0
        self.request_log: list[str] = []
        self._test_requests = 0
        self._history: list[HTTPRequest] = []
        self._opener = urllib.request.build_opener(_NoRedirect)

    # -- budget helpers ------------------------------------------------------
    def reset_test_counter(self) -> None:
        self._test_requests = 0

    def _check_scope(self, url: str) -> None:
        if not self.scope_guard(url):
            raise OutOfScopeError(f"URL outside authorized scope: {url}")

    def _check_budget(self) -> None:
        if self.requests_made >= self.limits.max_requests_per_scan:
            raise RequestLimitExceeded("per-scan request budget exhausted")
        if self._test_requests >= self.limits.max_requests_per_test:
            raise RequestLimitExceeded("per-test request budget exhausted")

    # -- core ----------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        allow_redirects: bool = True,
    ) -> HTTPResponse:
        method = method.upper()
        self._check_scope(url)
        self._check_budget()

        sent_headers = {
            "User-Agent": (self.limits.user_agent + (" " + self.limits.user_agent_suffix if self.limits.user_agent_suffix else "")).strip(),
            "Accept": "*/*",
        }
        if headers:
            sent_headers.update({str(k): str(v) for k, v in headers.items()})
        data = body.encode("utf-8") if body is not None else None

        self.requests_made += 1
        self._test_requests += 1
        self.request_log.append(f"{method} {url}")

        chain: list[str] = []
        current_url = url
        current_method = method
        current_data = data
        redirects = 0

        while True:
            req = urllib.request.Request(current_url, data=current_data, headers=sent_headers, method=current_method)
            record = HTTPRequest(method=current_method, url=current_url,
                                 headers=dict(sent_headers), body=body if current_data else None)
            self._history.append(record)
            start = time.monotonic()
            try:
                with self._opener.open(req, timeout=self.limits.request_timeout) as resp:
                    raw = resp.read(self.limits.response_size_limit + 1)
                    elapsed = (time.monotonic() - start) * 1000.0
                    return self._build_response(resp, raw, current_url, elapsed, chain, record)
            except urllib.error.HTTPError as exc:
                raw = exc.read(self.limits.response_size_limit + 1)
                elapsed = (time.monotonic() - start) * 1000.0
                if allow_redirects and exc.code in (301, 302, 303, 307, 308):
                    location = exc.headers.get("Location")
                    if location and redirects < self.limits.redirect_limit:
                        nxt = urllib.parse.urljoin(current_url, location)
                        self._check_scope(nxt)
                        self._check_budget()
                        self.requests_made += 1
                        self._test_requests += 1
                        self.request_log.append(f"=> {nxt}")
                        chain.append(nxt)
                        redirects += 1
                        current_url = nxt
                        if exc.code == 303:
                            current_method, current_data = "GET", None
                        elif exc.code in (301, 302) and current_method not in ("GET", "HEAD"):
                            current_method, current_data = "GET", None
                        continue
                return self._build_response(exc, raw, current_url, elapsed, chain, record)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                elapsed = (time.monotonic() - start) * 1000.0
                reason = getattr(exc, "reason", exc)
                return HTTPResponse(status=0, url=current_url, headers={}, body="", elapsed_ms=elapsed,
                                    redirect_chain=list(chain), request=record.to_dict(), error=str(reason))

    def _build_response(self, raw_resp, raw: bytes, url: str, elapsed: float, chain: list[str],
                        record: HTTPRequest) -> HTTPResponse:
        headers: dict[str, object] = {}
        for key, value in raw_resp.headers.items():
            if key in headers:
                existing = headers[key]
                headers[key] = [existing, value] if isinstance(existing, str) else [*existing, value]  # type: ignore[list-item]
            else:
                headers[key] = value
        truncated = len(raw) > self.limits.response_size_limit
        if truncated:
            raw = raw[: self.limits.response_size_limit]
        try:
            body = raw.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - decode fallback
            body = ""
        content_type = None
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                content_type = str(value)
                break
        tls = None
        if self.capture_tls and url.lower().startswith("https://"):
            from app.http.fingerprints import fetch_tls_info

            tls = fetch_tls_info(url, timeout=self.limits.request_timeout)
        return HTTPResponse(
            status=int(getattr(raw_resp, "status", getattr(raw_resp, "code", 0)) or 0),
            url=url,
            headers=headers,
            body=body,
            elapsed_ms=elapsed,
            redirect_chain=list(chain),
            content_type=content_type,
            tls=tls,
            request=record.to_dict(),
        )

    # -- verb helpers --------------------------------------------------------
    def get(self, url: str, **kw) -> HTTPResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, body: str | None = None, **kw) -> HTTPResponse:
        return self.request("POST", url, body=body, **kw)

    def put(self, url: str, body: str | None = None, **kw) -> HTTPResponse:
        return self.request("PUT", url, body=body, **kw)

    def patch(self, url: str, body: str | None = None, **kw) -> HTTPResponse:
        return self.request("PATCH", url, body=body, **kw)

    def delete(self, url: str, **kw) -> HTTPResponse:
        return self.request("DELETE", url, **kw)

    def options(self, url: str, **kw) -> HTTPResponse:
        return self.request("OPTIONS", url, **kw)

    def head(self, url: str, **kw) -> HTTPResponse:
        return self.request("HEAD", url, **kw)

    def trace(self, url: str, **kw) -> HTTPResponse:
        return self.request("TRACE", url, **kw)

    # -- SSRF-safe callback probe -------------------------------------------
    def probe_callback(self, url: str, *, timeout: float | None = None) -> HTTPResponse:
        """Issue a GET to an explicitly configured validation URL (SSRF proof)."""
        old_timeout = self.limits.request_timeout
        if timeout is not None:
            self.limits.request_timeout = timeout
        try:
            return self.request("GET", url)
        finally:
            self.limits.request_timeout = old_timeout
