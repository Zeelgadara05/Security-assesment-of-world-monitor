"""Assessment planner/executor (Phase 5).

The planner records *what will run and why*, then executes only the applicable
tests.  Passive tests consume observations; active tests issue requests through
the scope-guarded client.  Non-applicable tests still appear in the report so
coverage is honest about what was skipped and the reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.assess import applicability
from app.assess.dedup import deduplicate
from app.assess.models import AssessmentContext, CandidateData, TestCase, TestOutcome, TestRunReport
from app.assess.registry import TestRegistry, default_registry
from app.observations import types


@dataclass
class PlannedTest:
    test_id: str
    category: str
    applicable: bool
    reason: str = ""
    active: bool = False
    testcases: list[TestCase] = field(default_factory=list)


@dataclass
class AssessmentPlan:
    scan_id: int
    registry_fingerprint: str
    planned: list[PlannedTest] = field(default_factory=list)

    def applicable(self) -> list[PlannedTest]:
        return [p for p in self.planned if p.applicable]

    def not_applicable(self) -> list[PlannedTest]:
        return [p for p in self.planned if not p.applicable]

    def planned_testcases(self) -> int:
        return sum(len(p.testcases) for p in self.planned)


def plan(context: AssessmentContext, registry: TestRegistry | None = None) -> AssessmentPlan:
    registry = registry or default_registry()
    available = applicability.available_capabilities(context)
    result = AssessmentPlan(scan_id=context.scan_id, registry_fingerprint=registry.fingerprint())
    for test in registry.all():
        decision = applicability.evaluate(test, context, available)
        testcases: list[TestCase] = []
        if decision.applicable:
            try:
                testcases = test.plan(context)
            except Exception:  # a planner error must not sink the whole scan
                testcases = []
        result.planned.append(PlannedTest(
            test_id=test.id, category=test.category, applicable=decision.applicable,
            reason=decision.reason, active=bool(getattr(test, "active", False)),
            testcases=testcases,
        ))
    return result


def run(assessment_plan: AssessmentPlan, context: AssessmentContext,
        registry: TestRegistry | None = None) -> TestRunReport:
    registry = registry or default_registry()
    report = TestRunReport()
    for planned in assessment_plan.planned:
        test = registry.get(planned.test_id)
        if test is None:
            continue
        if not planned.applicable:
            report.outcomes.append(TestOutcome(
                test_id=planned.test_id, category=planned.category,
                status=types.TEST_NOT_APPLICABLE, reason=planned.reason,
                planned=len(planned.testcases)))
            continue
        try:
            outcome = test.run(context)
        except Exception as exc:  # deterministic failure isolation
            outcome = TestOutcome(test_id=planned.test_id, category=planned.category,
                                  status=types.TEST_FAILED,
                                  reason=f"{type(exc).__name__}: {exc}",
                                  planned=len(planned.testcases))
        if outcome.planned == 0 and planned.testcases:
            outcome.planned = len(planned.testcases)
        report.outcomes.append(outcome)
    return report


def plan_and_run(context: AssessmentContext, registry: TestRegistry | None = None):
    registry = registry or default_registry()
    assessment_plan = plan(context, registry)
    report = run(assessment_plan, context, registry)
    return assessment_plan, report


def confirmed_candidates(report: TestRunReport, registry: TestRegistry | None = None) -> list[CandidateData]:
    """Deduplicated confirmed-candidate list across all executed tests."""
    return deduplicate(list(report.candidates))


__all__ = [
    "PlannedTest",
    "AssessmentPlan",
    "plan",
    "run",
    "plan_and_run",
    "confirmed_candidates",
]
