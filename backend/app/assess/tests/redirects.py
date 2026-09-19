"""Redirect analysis (Phase 5).

Active, read-only: checks whether a cleartext HTTP endpoint upgrades to HTTPS.
Only the absence of an upgrade is reported (Low), with the observed redirect
chain as evidence.  No open-redirect guessing is performed.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class RedirectTest(BaseSecurityTest):
    id = "http.redirects"
    name = "Cleartext endpoint does not enforce HTTPS"
    category = "redirects"
    description = "An HTTP endpoint serves content without redirecting to HTTPS."
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
            if not endpoint.lower().startswith("http://"):
                continue
            client.reset_test_counter()
            try:
                response = client.get(endpoint)
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            final_scheme = urlsplit(response.url).scheme.lower()
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                data={"final_scheme": final_scheme, "chain": response.redirect_chain},
                request=response.request, response=response.to_dict(),
                discriminator={"endpoint": endpoint, "method": "GET", "test": self.id},
            ))
            if final_scheme == "http" and response.status < 400:
                result = confirm("HTTP endpoint did not upgrade to HTTPS",
                                 confidence=types.CONFIDENCE_MEDIUM,
                                 expected="301/308 redirect to https://",
                                 actual=f"status={response.status}, chain={response.redirect_chain}",
                                 boundary="transport confidentiality")
                outcome.candidates.append(CandidateData(
                    category=self.category, title=self.name, severity=types.SEVERITY_LOW,
                    confidence=result.confidence, description=self.description,
                    endpoint=endpoint, method="GET", target=endpoint, source_test=self.id,
                    source_tool="native_http", security_boundary="transport confidentiality",
                    expected="redirect to HTTPS", actual=f"served over HTTP ({response.status})",
                    impact="Traffic can be intercepted or modified in transit.",
                    proof_of_concept=f"GET {endpoint}", dedup_key=finding_fingerprint(self.category, endpoint, endpoint, None),
                ))
        return outcome


TEST = RedirectTest()
