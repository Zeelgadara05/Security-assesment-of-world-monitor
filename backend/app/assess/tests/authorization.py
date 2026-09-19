"""Broken authorization validation (Phase 5).

Config-driven and deterministic: the operator supplies protected resources and
the identity that must *not* be able to read them.  A finding is confirmed only
when a non-owner identity receives an authenticated success response containing
the protected resource's marker.  Without an explicit check there is nothing to
prove, so the test is not applicable.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm, reject
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class AuthorizationTest(BaseSecurityTest):
    id = "access.authorization"
    name = "Missing function-level authorization"
    category = "authorization"
    description = "A protected resource is reachable by an identity that should be denied."
    active = True
    authentication_required = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        checks = (context.config or {}).get("authorization_checks") or []
        if not checks:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE,
                               reason="no authorization checks were configured")
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for check in checks:
            endpoint = check.get("endpoint")
            identity = check.get("identity")
            marker = check.get("marker")
            if not (endpoint and identity and marker):
                continue
            headers = self._identity_headers(context, identity)
            client.reset_test_counter()
            try:
                response = client.get(endpoint, headers=headers)
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                data={"identity": identity, "marker": marker, "response": response.to_dict()},
                request=response.request, response=response.to_dict(),
                discriminator={"endpoint": endpoint, "identity": identity, "test": self.id},
            ))
            if response.status == 200 and marker in (response.body or ""):
                result = confirm(
                    f"identity '{identity}' received protected content",
                    confidence=types.CONFIDENCE_HIGH,
                    expected=f"access denied for '{identity}'", actual=f"HTTP 200 with {marker!r}",
                    boundary="authorization boundary")
                outcome.candidates.append(self._candidate(check, endpoint, identity, result))
            else:
                reject(f"identity '{identity}' was denied or received no marker")
        return outcome

    @staticmethod
    def _identity_headers(context: AssessmentContext, identity: str) -> dict[str, str]:
        entry = (context.auth_identities or {}).get(identity) or {}
        return dict(entry.get("headers") or {})

    def _candidate(self, check, endpoint, identity, result) -> CandidateData:
        description = check.get("description") or self.description
        return CandidateData(
            category=self.category, title=self.name, severity=types.SEVERITY_HIGH,
            confidence=result.confidence, description=description, endpoint=endpoint,
            method="GET", target=endpoint, source_test=self.id, source_tool="native_http",
            security_boundary=result.security_boundary, expected=result.expected, actual=result.actual,
            impact="An unauthorized user can access functionality or data reserved for another role.",
            proof_of_concept=f"GET {endpoint} as '{identity}'",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, identity),
        )


TEST = AuthorizationTest()
