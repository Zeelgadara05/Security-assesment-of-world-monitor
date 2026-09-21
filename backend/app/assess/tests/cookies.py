"""Cookie security-attribute analysis (Phase 8, check 17.2).

Passive review of the cookies a target actually sets.  Only previously
captured *attributes* are evaluated (name, HttpOnly, Secure, SameSite --
values were discarded at capture time), so this test never persists a cookie
value and never leaks session material.

A cookie is scored against the standard hardening properties only:
  * HttpOnly absent      -> Low
  * Secure absent (HTTPS) -> Low
  * SameSite absent      -> Info

The test is passive (active=False): it consumes observed http_response
observations and never issues a request of its own.
"""
from __future__ import annotations

from typing import Any

from app.assess.models import AssessmentContext, CandidateData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import observation_url
from app.assess.validators import confirm
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

_SESSION_COOKIE_HINTS = (
    "auth", "session", "sess", "token", "jwt", "sid", "csrf", "user", "login",
)


def _url_scheme(url: str) -> str:
    return (url or "").split("://", 1)[0].lower()


def _cookie_attributes(observation: dict) -> list[dict[str, Any]]:
    data = observation.get("data_json") or {}
    cookies = data.get("cookies") or []
    if not cookies:
        response = observation.get("response_json") or {}
        cookies = response.get("cookies") or data.get("cookies") or []
    if isinstance(cookies, (list, tuple)):
        return [c for c in cookies if isinstance(c, dict)]
    return []


class CookiesSecurityTest(BaseSecurityTest):
    id = "cookies.security_attributes"
    name = "Weak cookie security attributes"
    category = "cookies"
    description = "Cookies are set without HttpOnly, Secure (over HTTPS) or SameSite hardening."
    active = False
    required_observations = (types.OBS_HTTP_RESPONSE,)

    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        seen: set[str] = set()
        for obs in context.observations_of(types.OBS_HTTP_RESPONSE):
            url = observation_url(obs)
            scheme = _url_scheme(url)
            https = scheme == "https"
            for cookie in _cookie_attributes(obs):
                name = cookie.get("name") or ""
                if not name:
                    continue
                session_like = any(h in name.lower() for h in _SESSION_COOKIE_HINTS)
                lower_name = name.lower()
                issues = []
                if not cookie.get("httponly"):
                    issues.append(("cookie-no-httponly", "Cookie without HttpOnly",
                                   types.SEVERITY_LOW,
                                   "HttpOnly attribute present", "HttpOnly absent"))
                if https and not cookie.get("secure"):
                    issues.append(("cookie-no-secure", f"Cookie without Secure over {scheme.upper()}",
                                   types.SEVERITY_LOW,
                                   "Secure attribute present", "Secure absent"))
                if not cookie.get("samesite"):
                    issues.append(("cookie-no-samesite", "Cookie without SameSite",
                                   types.SEVERITY_INFO,
                                   "SameSite attribute present", "SameSite absent"))
                for suffix, title, severity, expected, actual in issues:
                    key = finding_fingerprint(self.category, url, url, f"{suffix}:{name}")
                    if key in seen:
                        continue
                    seen.add(key)
                    outcome.executed += 1
                    result = confirm(f"{title} ({name})", confidence=types.CONFIDENCE_MEDIUM,
                                     expected=expected, actual=actual, boundary="cookie integrity")
                    outcome.candidates.append(CandidateData(
                        category=self.category, title=title, severity=severity,
                        confidence=result.confidence, description=self.description,
                        endpoint=url, method="GET", target=url, source_test=self.id,
                        source_tool="native_http", security_boundary=result.security_boundary,
                        expected=result.expected, actual=f"{actual} ({name})",
                        impact="Cookie-bound sessions are easier to steal or misuse cross-site.",
                        proof_of_concept=f"Set-Cookie observed at {url} (attribute-only capture)",
                        dedup_key=key,
                        parameter="cookie:" + name,
                    ))
            if session_like and not issues:
                outcome.executed += 1
        return outcome


TEST = CookiesSecurityTest()