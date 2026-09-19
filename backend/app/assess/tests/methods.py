"""HTTP method analysis (Phase 5).

Active but read-only-safe: probes ``OPTIONS`` and, only when advertised, a
single harmless ``TRACE``.  TRACE being enabled is a real (if lower severity)
weakness; the mere presence of PUT/DELETE in an Allow header is not reported.
"""
from __future__ import annotations

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class HttpMethodsTest(BaseSecurityTest):
    id = "http.methods"
    name = "Verbose or unsafe HTTP methods enabled"
    category = "methods"
    description = "The server advertises or allows unsafe/verbose HTTP methods."
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
                options = client.options(endpoint)
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            allow = (options.header("Allow") or options.header("Access-Control-Allow-Methods") or "").upper()
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                data={"allow": allow}, request=options.request, response=options.to_dict(),
                discriminator={"endpoint": endpoint, "method": "OPTIONS", "test": self.id},
            ))
            if "TRACE" not in allow:
                continue
            try:
                trace = client.trace(endpoint)
            except (OutOfScopeError, RequestLimitExceeded):
                continue
            if trace.status == 200 and "TRACE" in (trace.body or "").upper():
                result = confirm("TRACE method is enabled and echoes the request",
                                 confidence=types.CONFIDENCE_MEDIUM,
                                 expected="TRACE disabled", actual=f"Allow: {allow}",
                                 boundary="cross-site tracing")
                outcome.candidates.append(CandidateData(
                    category=self.category, title=self.name, severity=types.SEVERITY_LOW,
                    confidence=result.confidence, description=self.description,
                    endpoint=endpoint, method="TRACE", target=endpoint, source_test=self.id,
                    source_tool="native_http", security_boundary="cross-site tracing",
                    expected="TRACE disabled", actual=f"TRACE returned {trace.status}",
                    impact="TRACE can aid cross-site tracing attacks.",
                    proof_of_concept=f"TRACE {endpoint}", dedup_key=finding_fingerprint(self.category, endpoint, endpoint, "trace"),
                ))
        return outcome


TEST = HttpMethodsTest()
