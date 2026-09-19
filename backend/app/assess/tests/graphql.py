"""GraphQL configuration analysis (Phase 5).

Applicable only when a GraphQL endpoint was observed or declared.  Sends a
read-only introspection query; if the schema is returned, introspection is
reported as a Low information-exposure finding (not a breach on its own).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

_INTROSPECTION = '{"query":"{ __schema { queryType { name } } }"}'


class GraphqlTest(BaseSecurityTest):
    id = "graphql.introspection"
    name = "GraphQL introspection enabled"
    category = "graphql"
    description = "The GraphQL endpoint exposes its schema to unauthenticated clients."
    active = True

    def run(self, context: AssessmentContext) -> TestOutcome:
        endpoints = self._targets(context)
        if not endpoints:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE,
                               reason="no GraphQL endpoint observed or configured")
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        client = context.client
        assert client is not None
        for endpoint in endpoints:
            client.reset_test_counter()
            try:
                response = client.post(endpoint, body=_INTROSPECTION,
                                       headers={"Content-Type": "application/json"})
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=endpoint,
                data={"introspection": True, "response": response.to_dict()},
                request=response.request, response=response.to_dict(),
                discriminator={"endpoint": endpoint, "test": self.id},
            ))
            body = response.body or ""
            if response.status == 200 and ("__schema" in body or "queryType" in body):
                result = confirm("GraphQL introspection returned the schema",
                                 confidence=types.CONFIDENCE_HIGH,
                                 expected="introspection disabled for anonymous clients",
                                 actual="schema returned", boundary="information exposure")
                outcome.candidates.append(CandidateData(
                    category=self.category, title=self.name, severity=types.SEVERITY_LOW,
                    confidence=result.confidence, description=self.description, endpoint=endpoint,
                    method="POST", target=endpoint, source_test=self.id, source_tool="native_http",
                    security_boundary=result.security_boundary, expected=result.expected,
                    actual="introspection query succeeded",
                    impact="The full API schema aids further targeted attacks.",
                    proof_of_concept=f"POST {endpoint} [introspection]",
                    dedup_key=finding_fingerprint(self.category, endpoint, endpoint, None),
                ))
        return outcome

    @staticmethod
    def _targets(context: AssessmentContext) -> list[str]:
        configured = (context.config or {}).get("graphql_endpoints") or []
        if configured:
            return list(configured)
        return [e for e in context.endpoints if "graphql" in urlsplit(e).path.lower()]


TEST = GraphqlTest()
