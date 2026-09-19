"""Security-header analysis (Phase 5).

Passive: consumes observed HTTP responses and reports only genuinely weak
configuration.  A missing header is not automatically a vulnerability, so the
baseline severity is Low (Info for referrer policy) and the finding records the
exact header and expected value.  No header absence is ever escalated to High.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import observation_headers, observation_url
from app.assess.validators import confirm
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

_HSTS_MIN_AGE = 15552000  # 180 days


class SecurityHeadersTest(BaseSecurityTest):
    id = "http.security_headers"
    name = "Weak HTTP security headers"
    category = "headers"
    description = "Security-related response headers are missing or misconfigured."
    required_observations = (types.OBS_HTTP_RESPONSE,)
    active = False

    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        seen: set[str] = set()
        for obs in context.observations_of(types.OBS_HTTP_RESPONSE):
            url = observation_url(obs)
            headers = observation_headers(obs)
            if not headers:
                continue
            outcome.executed += 1
            for candidate in self._analyze(url, headers, obs.get("id")):
                if candidate.dedup_key not in seen:
                    seen.add(candidate.dedup_key)
                    outcome.candidates.append(candidate)
        return outcome

    def _analyze(self, url: str, headers: dict[str, str], observation_id):
        results: list[CandidateData] = []
        https = url.lower().startswith("https://")

        if https and "strict-transport-security" not in headers:
            results.append(self._candidate(
                url, "Missing HTTP Strict-Transport-Security (HSTS)", types.SEVERITY_LOW,
                "transport security", "Strict-Transport-Security present",
                "header absent", observation_id, "hsts-missing"))
        elif https and "strict-transport-security" in headers:
            max_age = self._max_age(headers["strict-transport-security"])
            if max_age is not None and max_age < _HSTS_MIN_AGE:
                results.append(self._candidate(
                    url, "HSTS max-age below 180 days", types.SEVERITY_LOW,
                    "transport security", f"max-age >= {_HSTS_MIN_AGE}",
                    f"max-age={max_age}", observation_id, "hsts-short"))

        if "x-content-type-options" not in headers:
            results.append(self._candidate(
                url, "Missing X-Content-Type-Options: nosniff", types.SEVERITY_LOW,
                "MIME sniffing", "X-Content-Type-Options: nosniff",
                "header absent", observation_id, "xcto-missing"))

        csp = headers.get("content-security-policy")
        xfo = headers.get("x-frame-options")
        if not csp and not xfo:
            results.append(self._candidate(
                url, "No clickjacking protection (CSP frame-ancestors / X-Frame-Options)",
                types.SEVERITY_LOW, "frame embedding",
                "frame-ancestors or X-Frame-Options", "neither present",
                observation_id, "frame-missing"))
        elif csp and "unsafe-inline" in csp:
            results.append(self._candidate(
                url, "CSP allows unsafe-inline", types.SEVERITY_LOW,
                "content execution", "no unsafe-inline in script-src",
                "unsafe-inline present", observation_id, "csp-unsafe-inline"))

        if "referrer-policy" not in headers:
            results.append(self._candidate(
                url, "Missing Referrer-Policy", types.SEVERITY_INFO,
                "referrer leakage", "Referrer-Policy present", "header absent",
                observation_id, "referrer-missing"))
        return results

    @staticmethod
    def _max_age(value: str) -> int | None:
        for part in value.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    return int(part.split("=", 1)[1].strip())
                except ValueError:
                    return None
        return None

    def _candidate(self, url, title, severity, boundary, expected, actual, observation_id, suffix) -> CandidateData:
        result = confirm(f"{title}: {actual}", confidence=types.CONFIDENCE_MEDIUM,
                         expected=expected, actual=actual, boundary=boundary)
        candidate = CandidateData(
            category=self.category, title=title, severity=severity, confidence=result.confidence,
            description=self.description, endpoint=url, method="GET", target=url,
            source_test=self.id, source_tool="native_http",
            security_boundary=boundary, expected=expected, actual=actual,
            impact=f"Observed weakness: {actual}.", proof_of_concept=f"GET {url}",
            observation_ids=[observation_id] if observation_id else [],
            dedup_key=finding_fingerprint(self.category, url, url, suffix),
        )
        return candidate


TEST = SecurityHeadersTest()
