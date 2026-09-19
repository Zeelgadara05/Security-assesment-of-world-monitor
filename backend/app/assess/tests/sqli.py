"""SQL injection validation (Phase 5).

Uses a boolean-based differential: the same parameter is sent with a true
condition and a false condition.  A finding requires a *reproducible* response
difference between the two conditions (probed twice) and confirms only at
Medium confidence; a lone SQL error message is recorded but never confirmed on
its own.  No destructive payloads are ever sent.
"""
from __future__ import annotations

import re

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import iter_parameters, with_query_param
from app.assess.validators import confirm, reject
from app.http.client import OutOfScopeError, RequestLimitExceeded
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

_ERROR = re.compile(r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|sqlite3\.OperationalError|Unclosed quotation mark", re.I)
_TRUE_PAYLOAD = "' AND '1'='1"
_FALSE_PAYLOAD = "' AND '1'='2"
_MIN_DELTA = 16


class SqlInjectionTest(BaseSecurityTest):
    id = "injection.sqli"
    name = "SQL injection"
    category = "sqli"
    description = "A request parameter alters SQL query semantics."
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
            client.reset_test_counter()
            base_value = item["value"] or ""
            try:
                baseline = client.get(item["endpoint"])
                error_probe = client.get(with_query_param(item["endpoint"], item["parameter"], base_value + "'"))
                true_a = client.get(with_query_param(item["endpoint"], item["parameter"], base_value + _TRUE_PAYLOAD))
                false_a = client.get(with_query_param(item["endpoint"], item["parameter"], base_value + _FALSE_PAYLOAD))
                true_b = client.get(with_query_param(item["endpoint"], item["parameter"], base_value + _TRUE_PAYLOAD))
            except (OutOfScopeError, RequestLimitExceeded):
                outcome.skipped += 1
                continue
            outcome.executed += 1
            record = {"baseline": baseline.to_dict(), "error": error_probe.to_dict(),
                      "true_a": true_a.to_dict(), "false_a": false_a.to_dict(), "true_b": true_b.to_dict(),
                      "parameter": item["parameter"]}
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_HTTP_RESPONSE, subject=item["endpoint"], data=record,
                request=true_a.request, response=true_a.to_dict(),
                discriminator={"endpoint": item["endpoint"], "parameter": item["parameter"], "test": self.id},
            ))
            verdict = self._differential(baseline, true_a, false_a, true_b)
            if verdict and verdict.confirmed:
                outcome.candidates.append(self._candidate(item, verdict, error_probe))
        return outcome

    def _differential(self, baseline, true_a, false_a, true_b):
        if true_a.error or false_a.error or true_b.error:
            return reject("probe request failed")
        if not (true_a.status == true_b.status == false_a.status == 200):
            return reject("status codes for true/false conditions differ")
        if len(true_a.body) != len(true_b.body):
            return reject("true-condition response was not reproducible")
        delta = len(true_a.body) - len(false_a.body)
        if abs(delta) < _MIN_DELTA:
            return reject("no meaningful response difference between true and false conditions")
        base_len = len(baseline.body)
        if abs(base_len - len(true_a.body)) > abs(base_len - len(false_a.body)):
            return reject("baseline matches the false condition; difference not SQL-controlled")
        return confirm(
            f"boolean SQL payload reproduced a {abs(delta)}-byte response difference",
            confidence=types.CONFIDENCE_MEDIUM,
            expected="parameter treated as an opaque value",
            actual=f"true={len(true_a.body)}B vs false={len(false_a.body)}B (reproduced)",
            boundary="database query semantics",
        )

    def _candidate(self, item, result, error_probe) -> CandidateData:
        endpoint = item["endpoint"]
        error_note = " with an accompanying SQL error message" if _ERROR.search(error_probe.body or "") else ""
        return CandidateData(
            category=self.category, title=self.name, severity=types.SEVERITY_HIGH,
            confidence=result.confidence, description=self.description, endpoint=endpoint,
            method=item["method"], target=endpoint, source_test=self.id, source_tool="native_http",
            parameter=item["parameter"], security_boundary=result.security_boundary,
            expected=result.expected, actual=result.actual + error_note,
            impact="An attacker may read or modify data outside the intended query.",
            proof_of_concept=f"GET {with_query_param(endpoint, item['parameter'], (item['value'] or '') + _TRUE_PAYLOAD)}",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, item["parameter"]),
        )


TEST = SqlInjectionTest()
