"""Authentication hardening analysis (Phase 5).

Two deterministic checks:
  * passive session-cookie attribute review (HttpOnly / Secure / SameSite);
  * optional unauthenticated-access probe against declared protected endpoints.

No credential guessing, no brute force.  Missing attributes are Low/Info; the
unauthenticated-access probe is only run when the operator declares the
endpoints it expects to be protected.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import observation_url
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class AuthenticationTest(BaseSecurityTest):
    id = "auth.session_hardening"
    name = "Weak authentication/session configuration"
    category = "auth"
    description = "Session cookies lack security attributes or protected endpoints are reachable anonymously."
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
            response = obs.get("response_json") or {}
            for cookie in _set_cookies(response):
                name = cookie.split("=", 1)[0].strip()
                lower = cookie.lower()
                https = url.lower().startswith("https://")
                issues = []
                if "httponly" not in lower:
                    issues.append(("cookie-no-httponly", "Session cookie without HttpOnly",
                                   types.SEVERITY_LOW, "HttpOnly attribute present", "HttpOnly absent"))
                if https and "secure" not in lower:
                    issues.append(("cookie-no-secure", "Session cookie without Secure flag",
                                   types.SEVERITY_LOW, "Secure attribute present", "Secure absent"))
                if "samesite" not in lower:
                    issues.append(("cookie-no-samesite", "Session cookie without SameSite",
                                   types.SEVERITY_INFO, "SameSite attribute present", "SameSite absent"))
                for suffix, title, severity, expected, actual in issues:
                    key = finding_fingerprint(self.category, url, url, f"{suffix}:{name}")
                    if key in seen:
                        continue
                    seen.add(key)
                    outcome.executed += 1
                    result = confirm(f"{title} ({name})", confidence=types.CONFIDENCE_MEDIUM,
                                     expected=expected, actual=actual, boundary="session integrity")
                    outcome.candidates.append(CandidateData(
                        category=self.category, title=title, severity=severity,
                        confidence=result.confidence, description=self.description,
                        endpoint=url, method="GET", target=url, source_test=self.id,
                        source_tool="native_http", security_boundary=result.security_boundary,
                        expected=expected, actual=f"{actual} ({cookie[:80]})",
                        impact="Session cookies are more exposed to theft or cross-site use.",
                        proof_of_concept=f"Set-Cookie at {url}",
                        dedup_key=key,
                    ))
        outcome.candidates.extend(self._protected_probe(context, outcome))
        return outcome

    def _protected_probe(self, context: AssessmentContext, outcome: TestOutcome) -> list[CandidateData]:
        endpoints = (context.config or {}).get("protected_endpoints") or []
        if not endpoints or context.client is None:
            return []
        found: list[CandidateData] = []
        client = context.client
        for endpoint in endpoints:
            client.reset_test_counter()
            try:
                response = client.get(endpoint)
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                data={"anonymous": True, "response": response.to_dict()},
                request=response.request, response=response.to_dict(),
                discriminator={"endpoint": endpoint, "test": self.id},
            ))
            if response.status == 200 and len(response.body or "") > 0:
                result = confirm("protected endpoint returned content anonymously",
                                 confidence=types.CONFIDENCE_MEDIUM,
                                 expected="401/403 without credentials", actual=f"HTTP {response.status}",
                                 boundary="authentication boundary")
                found.append(CandidateData(
                    category=self.category, title="Protected endpoint reachable without authentication",
                    severity=types.SEVERITY_MEDIUM, confidence=result.confidence,
                    description=self.description, endpoint=endpoint, method="GET", target=endpoint,
                    source_test=self.id, source_tool="native_http",
                    security_boundary=result.security_boundary, expected=result.expected,
                    actual=result.actual,
                    impact="Anonymous visitors can reach functionality that should require login.",
                    proof_of_concept=f"GET {endpoint} (no credentials)",
                    dedup_key=finding_fingerprint(self.category, endpoint, endpoint, "anonymous"),
                ))
        return found


def _set_cookies(response: dict) -> list[str]:
    headers = response.get("headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "set-cookie":
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)]
    return []


TEST = AuthenticationTest()
