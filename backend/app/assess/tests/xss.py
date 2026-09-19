"""Reflected XSS validation (Phase 5).

The classic false positive is "the marker was reflected, therefore XSS".  This
test only confirms when the *unsafe characters* of the payload survive into an
executable HTML context unescaped.  An escaped reflection is explicitly
rejected and recorded.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestCase, ValidationResult
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import iter_parameters, with_query_param
from app.assess.validators import confirm, reject
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

MARKER = "cyberxss7q"
PAYLOAD = f"{MARKER}'\"\"><b>z"
_UNSAFE_FRAGMENTS = (f"{MARKER}'\"\"><b>z", "\"><b>z")


class ReflectedXssTest(BaseSecurityTest):
    id = "injection.xss.reflected"
    name = "Reflected cross-site scripting"
    category = "xss"
    description = "A request parameter is reflected into HTML without encoding, allowing script injection."
    active = True

    def plan(self, context: AssessmentContext) -> list[TestCase]:
        cases = []
        for item in iter_parameters(context):
            cases.append(TestCase(
                endpoint=item["endpoint"], method=item["method"], parameter=item["parameter"],
                marker=PAYLOAD, rationale=f"parameter '{item['parameter']}' reflected into response"))
        return cases

    def execute(self, testcase: TestCase, context: AssessmentContext) -> ObservationData | None:
        client = context.client
        assert client is not None
        baseline = client.get(testcase.endpoint)
        probe_url = with_query_param(testcase.endpoint, testcase.parameter, testcase.marker or PAYLOAD)
        probe = client.get(probe_url)
        if probe.error:
            return None
        return ObservationData(
            observation_type=types.OBS_HTTP_RESPONSE, subject=testcase.endpoint,
            data={"baseline": baseline.to_dict(), "probe": probe.to_dict(),
                  "parameter": testcase.parameter},
            request=probe.request, response=probe.to_dict(),
            discriminator={"endpoint": testcase.endpoint, "parameter": testcase.parameter,
                           "method": testcase.method, "test": self.id},
        )

    def validate(self, baseline, probe, context: AssessmentContext) -> ValidationResult:
        body = (probe or {}).get("body") or ""
        if MARKER not in body:
            return reject("payload was not reflected in the response")
        for fragment in _UNSAFE_FRAGMENTS:
            if fragment in body:
                return confirm("payload reflected with unescaped HTML metacharacters",
                               confidence=types.CONFIDENCE_HIGH,
                               expected="HTML metacharacters encoded", actual=fragment,
                               boundary="script execution")
        return reject("payload reflected but HTML metacharacters were encoded")

    def build_candidate(self, testcase, observation, result, severity=None) -> CandidateData:
        endpoint = testcase.endpoint
        return CandidateData(
            category=self.category, title=self.name, severity=types.SEVERITY_MEDIUM,
            confidence=result.confidence, description=self.description, endpoint=endpoint,
            method=testcase.method, target=endpoint, source_test=self.id, source_tool="native_http",
            parameter=testcase.parameter, security_boundary=result.security_boundary,
            expected=result.expected, actual=result.actual,
            impact="An attacker can execute arbitrary script in a victim's browser session.",
            proof_of_concept=f"GET {with_query_param(endpoint, testcase.parameter or '', PAYLOAD)}",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, testcase.parameter),
        )


TEST = ReflectedXssTest()
