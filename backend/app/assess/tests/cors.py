"""CORS misconfiguration analysis (Phase 5).

Active but read-only: sends a cross-origin ``Origin`` header (an attacker-chosen
origin) and inspects the access-control response headers.  A finding requires
the server to reflect the untrusted origin -- merely emitting ``*`` is reported
at most as informational.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

ATTACKER_ORIGIN = "https://evil.example"


class CorsTest(BaseSecurityTest):
    id = "http.cors"
    name = "Permissive CORS policy"
    category = "cors"
    description = "The server reflects an attacker-controlled Origin, allowing cross-origin reads."
    active = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for endpoint in context.endpoints:
            client.reset_test_counter()
            try:
                probe = client.get(endpoint, headers={"Origin": ATTACKER_ORIGIN})
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                data={"cors_origin": ATTACKER_ORIGIN},
                request=probe.request, response=probe.to_dict(),
                discriminator={"endpoint": endpoint, "method": "GET", "test": self.id},
            ))
            acao = (probe.header("Access-Control-Allow-Origin") or "").strip()
            acac = (probe.header("Access-Control-Allow-Credentials") or "").strip().lower()
            if acao == ATTACKER_ORIGIN and acac == "true":
                outcome.candidates.append(self._candidate(
                    endpoint, types.SEVERITY_HIGH, "cross-origin data access",
                    "only trusted origins reflected with credentials",
                    f"reflected origin={acao}, credentials={acac}", types.CONFIDENCE_HIGH))
            elif acao == ATTACKER_ORIGIN:
                outcome.candidates.append(self._candidate(
                    endpoint, types.SEVERITY_MEDIUM, "cross-origin data access",
                    "only trusted origins reflected",
                    f"reflected origin={acao}", types.CONFIDENCE_MEDIUM))
        return outcome

    def _candidate(self, endpoint, severity, boundary, expected, actual, confidence) -> CandidateData:
        result = confirm(f"CORS reflects untrusted origin at {endpoint}",
                         confidence=confidence, expected=expected, actual=actual, boundary=boundary)
        return CandidateData(
            category=self.category, title=self.name, severity=severity,
            confidence=result.confidence, description=self.description,
            endpoint=endpoint, method="GET", target=endpoint, source_test=self.id,
            source_tool="native_http", security_boundary=boundary,
            expected=expected, actual=actual,
            impact="A malicious site can read authenticated responses from this endpoint.",
            proof_of_concept=f"GET {endpoint} with Origin: {ATTACKER_ORIGIN}",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, None),
        )


TEST = CorsTest()
