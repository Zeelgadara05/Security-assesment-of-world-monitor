"""SSRF validation (Phase 5).

Only runs when the operator supplies an out-of-band validation URL and the
unique token that URL echoes back.  A finding is confirmed only when that token
appears in the *target's* response, which is the standard non-destructive proof
of server-side request forgery.  Without a validation URL the test is not
applicable and no SSRF guess is made.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import iter_parameters, with_query_param
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class SsrfTest(BaseSecurityTest):
    id = "injection.ssrf"
    name = "Server-side request forgery"
    category = "ssrf"
    description = "The server fetches a user-controlled URL, reaching internal or callback resources."
    active = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        validation_url = context.ssrf_validation_url or (context.metadata or {}).get("ssrf_validation_url")
        token = (context.metadata or {}).get("ssrf_token")
        if not validation_url or not token:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE,
                               reason="no SSRF validation URL/token configured")
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for item in iter_parameters(context):
            client.reset_test_counter()
            url = with_query_param(item["endpoint"], item["parameter"], validation_url)
            try:
                response = client.get(url)
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=item["endpoint"],
                data={"payload": validation_url, "parameter": item["parameter"],
                      "response": response.to_dict()},
                request=response.request, response=response.to_dict(),
                discriminator={"endpoint": item["endpoint"], "parameter": item["parameter"], "test": self.id},
            ))
            if token in (response.body or ""):
                result = confirm("target server fetched the out-of-band validation URL",
                                 confidence=types.CONFIDENCE_HIGH,
                                 expected="user-supplied URL not fetched server-side",
                                 actual=f"validation token {token!r} returned",
                                 boundary="network boundary")
                outcome.candidates.append(CandidateData(
                    category=self.category, title=self.name, severity=types.SEVERITY_HIGH,
                    confidence=result.confidence, description=self.description,
                    endpoint=item["endpoint"], method=item["method"], target=item["endpoint"],
                    source_test=self.id, source_tool="native_http", parameter=item["parameter"],
                    security_boundary=result.security_boundary, expected=result.expected, actual=result.actual,
                    impact="The server can be coerced into making requests to internal or attacker services.",
                    proof_of_concept=f"GET {url}",
                    dedup_key=finding_fingerprint(self.category, item["endpoint"], item["endpoint"], item["parameter"]),
                ))
        return outcome


TEST = SsrfTest()
