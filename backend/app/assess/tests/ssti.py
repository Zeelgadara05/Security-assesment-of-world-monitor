"""Server-side template injection validation (Phase 5).

Confirmation requires the engine to *evaluate* an arithmetic expression: the
response must contain the computed value (49) while not containing the literal
payload.  A template-shaped reflection is not enough.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import iter_parameters, with_query_param
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

PAYLOADS = ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>")
_EXPECTED = "49"


class SstiTest(BaseSecurityTest):
    id = "injection.ssti"
    name = "Server-side template injection"
    category = "ssti"
    description = "User input is evaluated as a server-side template expression."
    active = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for item in iter_parameters(context):
            for payload in PAYLOADS:
                client.reset_test_counter()
                url = with_query_param(item["endpoint"], item["parameter"], payload)
                try:
                    probe = client.get(url)
                except (OutOfScopeError, RequestLimitExceeded):
                    outcome.skipped += 1
                    continue
                outcome.executed += 1
                outcome.observations.append(ObservationData(
                    observation_type=types.OBS_HTTP_RESPONSE, subject=item["endpoint"],
                    data={"probe": probe.to_dict(), "payload": payload, "parameter": item["parameter"]},
                    request=probe.request, response=probe.to_dict(),
                    discriminator={"endpoint": item["endpoint"], "parameter": item["parameter"],
                                   "payload": payload, "test": self.id},
                ))
                body = probe.body or ""
                if payload in body:
                    continue
                if _EXPECTED in body:
                    result = confirm(f"payload {payload} evaluated to {_EXPECTED}",
                                     confidence=types.CONFIDENCE_HIGH,
                                     expected="input not evaluated as a template",
                                     actual=f"{payload} -> {_EXPECTED}",
                                     boundary="server-side code execution")
                    outcome.candidates.append(self._candidate(item, payload, result, probe))
        return outcome

    def _candidate(self, item, payload, result, probe) -> CandidateData:
        endpoint = item["endpoint"]
        return CandidateData(
            category=self.category, title=self.name, severity=types.SEVERITY_HIGH,
            confidence=result.confidence, description=self.description, endpoint=endpoint,
            method=item["method"], target=endpoint, source_test=self.id, source_tool="native_http",
            parameter=item["parameter"], security_boundary=result.security_boundary,
            expected=result.expected, actual=f"{payload} evaluated to {_EXPECTED} (HTTP {probe.status})",
            impact="Template evaluation on the server can lead to remote code execution.",
            proof_of_concept=f"GET {with_query_param(endpoint, item['parameter'], payload)}",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, item["parameter"]),
        )


TEST = SstiTest()
