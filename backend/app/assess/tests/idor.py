"""Insecure direct object reference validation (Phase 5).

Config-driven: the operator declares an object, its owner identity and a marker
that uniquely identifies the owner's object.  A finding is confirmed only when a
*non-owner* identity fetches the endpoint and the response contains the owner's
marker.  This is the strongest deterministic IDOR signal available without
guessing object identifiers.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class IdorTest(BaseSecurityTest):
    id = "access.idor"
    name = "Insecure direct object reference"
    category = "idor"
    description = "An object belonging to one user is readable by another user."
    active = True
    authentication_required = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        checks = (context.config or {}).get("idor_checks") or []
        if not checks:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE,
                               reason="no IDOR checks were configured")
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for check in checks:
            endpoint = check.get("endpoint")
            owner = check.get("owner_identity")
            marker = check.get("owner_marker")
            attackers = check.get("as_identities") or [
                name for name in (context.auth_identities or {}) if name != owner]
            if not (endpoint and owner and marker):
                continue
            for identity in attackers:
                headers = dict(((context.auth_identities or {}).get(identity) or {}).get("headers") or {})
                client.reset_test_counter()
                try:
                    response = client.get(endpoint, headers=headers)
                except (OutOfScopeError, RequestLimitExceeded):
                    outcome.skipped += 1
                    continue
                outcome.executed += 1
                outcome.observations.append(ObservationData(
                    observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                    data={"identity": identity, "owner_identity": owner, "marker": marker,
                          "response": response.to_dict()},
                    request=response.request, response=response.to_dict(),
                    discriminator={"endpoint": endpoint, "identity": identity, "test": self.id},
                ))
                if response.status == 200 and marker in (response.body or ""):
                    result = confirm(
                        f"non-owner '{identity}' read a resource owned by '{owner}'",
                        confidence=types.CONFIDENCE_HIGH,
                        expected=f"access denied for '{identity}'",
                        actual=f"HTTP 200 containing {marker!r}",
                        boundary="object-level authorization")
                    outcome.candidates.append(self._candidate(check, endpoint, identity, owner, result))
        return outcome

    def _candidate(self, check, endpoint, identity, owner, result) -> CandidateData:
        return CandidateData(
            category=self.category, title=self.name, severity=types.SEVERITY_HIGH,
            confidence=result.confidence,
            description=check.get("description") or self.description,
            endpoint=endpoint, method="GET", target=endpoint, source_test=self.id,
            source_tool="native_http", security_boundary=result.security_boundary,
            expected=result.expected, actual=result.actual,
            impact="Any authenticated user can read other users' objects by changing an identifier.",
            proof_of_concept=f"GET {endpoint} as '{identity}' (owner: '{owner}')",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, identity),
        )


TEST = IdorTest()
