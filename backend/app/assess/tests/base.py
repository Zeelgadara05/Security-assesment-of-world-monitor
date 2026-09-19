"""Security test contract (Phase 5).

Every test declares its identity, required observations/capabilities, whether it
is active (mutates the request) and whether it needs authentication.  The base
class provides a deterministic plan -> execute -> validate loop; tests may
override :meth:`run` when their analysis is passive (consuming observations that
already exist).

A test never creates a finding directly: it produces candidates that carry an
explicit security property, and the validator's verdict decides whether the
candidate is confirmed.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.assess import confidence as conf
from app.assess.models import (
    AssessmentContext,
    CandidateData,
    ObservationData,
    TestCase,
    TestOutcome,
    ValidationResult,
)
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


@runtime_checkable
class SecurityTest(Protocol):
    id: str
    name: str
    category: str

    def is_applicable(self, context: AssessmentContext) -> tuple[bool, str]: ...
    def run(self, context: AssessmentContext) -> TestOutcome: ...


class BaseSecurityTest:
    id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    required_observations: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    active: bool = False
    destructive: bool = False
    authentication_required: bool = False

    # -- applicability -------------------------------------------------------
    def is_applicable(self, context: AssessmentContext) -> tuple[bool, str]:
        if self.active and not context.active_testing:
            return False, "active testing is disabled"
        if self.active and context.client is None:
            return False, "no HTTP client available"
        if self.required_observations and not context.has_observation(*self.required_observations):
            return False, "required observations unavailable: " + ", ".join(self.required_observations)
        if self.authentication_required and not context.auth_identities:
            return False, "no authenticated comparison identities configured"
        return True, ""

    # -- plan / execute / validate ------------------------------------------
    def plan(self, context: AssessmentContext) -> list[TestCase]:
        return [TestCase(endpoint=url, method="GET", rationale="observed HTTP endpoint")
                for url in context.endpoints]

    def execute(self, testcase: TestCase, context: AssessmentContext) -> ObservationData | None:
        raise NotImplementedError

    def validate(self, baseline, observation, context: AssessmentContext) -> ValidationResult:
        raise NotImplementedError

    # -- orchestration -------------------------------------------------------
    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        testcases = self.plan(context)
        outcome = TestOutcome(test_id=self.id, category=self.category,
                              status=types.TEST_EXECUTED, planned=len(testcases))
        for testcase in testcases:
            if context.client is not None:
                context.client.reset_test_counter()
            try:
                observation = self.execute(testcase, context)
            except Exception as exc:  # deterministic failure isolation
                outcome.status = types.TEST_FAILED
                outcome.reason = f"{type(exc).__name__}: {exc}"
                continue
            if observation is None:
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(observation)
            baseline, probe = self._baseline_probe(observation)
            try:
                result = self.validate(baseline, probe, context)
            except Exception as exc:
                outcome.status = types.TEST_FAILED
                outcome.reason = f"validation error: {type(exc).__name__}: {exc}"
                continue
            if result and result.confirmed:
                outcome.candidates.append(self.build_candidate(testcase, observation, result))
        return outcome

    def _baseline_probe(self, observation: ObservationData):
        baseline = (observation.data or {}).get("baseline")
        probe = (observation.data or {}).get("probe")
        return baseline, probe

    # -- candidate helper ----------------------------------------------------
    def build_candidate(self, testcase: TestCase, observation: ObservationData,
                        result: ValidationResult, severity: str | None = None) -> CandidateData:
        from app.assess.severity import SeverityInput, compute_severity

        endpoint = testcase.endpoint
        level = severity or compute_severity(SeverityInput(
            category=self.category,
            boundary_crossed=bool(result and result.security_boundary),
        ))
        return CandidateData(
            category=self.category,
            title=self.name,
            severity=level,
            confidence=result.confidence if result else types.CONFIDENCE_LOW,
            description=self.description,
            endpoint=endpoint,
            method=testcase.method,
            target=endpoint,
            source_test=self.id,
            source_tool=observation.tool_name,
            parameter=testcase.parameter,
            security_boundary=result.security_boundary if result else "",
            expected=result.expected if result else "",
            actual=result.actual if result else "",
            proof_of_concept=f"{testcase.method} {endpoint}",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, testcase.parameter),
        )
