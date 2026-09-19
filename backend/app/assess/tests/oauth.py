"""OAuth/OIDC misconfiguration analysis (Phase 5).

Config-driven: the operator declares an authorization endpoint, a client id and
an attacker-controlled redirect target.  A finding is confirmed only when the
server redirects to (or reflects) the attacker redirect target without an
allow-list rejection.
"""
from __future__ import annotations

from urllib.parse import urlencode

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

ATTACKER_REDIRECT = "https://evil.example/callback"


class OAuthTest(BaseSecurityTest):
    id = "oauth.redirect"
    name = "OAuth redirect_uri not validated"
    category = "oauth"
    description = "The authorization endpoint accepts an attacker-controlled redirect_uri."
    active = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        checks = (context.config or {}).get("oauth_checks") or []
        if not checks:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE,
                               reason="no OAuth checks were configured")
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for check in checks:
            authorize_url = check.get("authorize_url")
            client_id = check.get("client_id", "test")
            redirect = check.get("attacker_redirect", ATTACKER_REDIRECT)
            if not authorize_url:
                continue
            query = urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                               "state": "cyberagent"})
            url = f"{authorize_url}{'&' if '?' in authorize_url else '?'}{query}"
            client.reset_test_counter()
            try:
                response = client.get(url, allow_redirects=False)
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=authorize_url,
                data={"attacker_redirect": redirect, "response": response.to_dict()},
                request=response.request, response=response.to_dict(),
                discriminator={"endpoint": authorize_url, "test": self.id},
            ))
            location = (response.header("Location") or "")
            if redirect in location or redirect in (response.body or ""):
                result = confirm("authorization endpoint accepted an untrusted redirect_uri",
                                 confidence=types.CONFIDENCE_HIGH,
                                 expected="redirect_uri rejected or allow-listed",
                                 actual=f"redirected toward {redirect}", boundary="redirect trust")
                outcome.candidates.append(CandidateData(
                    category=self.category, title=self.name, severity=types.SEVERITY_HIGH,
                    confidence=result.confidence, description=self.description, endpoint=authorize_url,
                    method="GET", target=authorize_url, source_test=self.id, source_tool="native_http",
                    security_boundary=result.security_boundary, expected=result.expected, actual=result.actual,
                    impact="Authorization codes or tokens can be delivered to an attacker-controlled endpoint.",
                    proof_of_concept=f"GET {url}",
                    dedup_key=finding_fingerprint(self.category, authorize_url, authorize_url, None),
                ))
        return outcome


TEST = OAuthTest()
