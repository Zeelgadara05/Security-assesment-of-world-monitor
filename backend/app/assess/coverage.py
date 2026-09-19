"""Honest coverage accounting (Phase 5).

A scan that executed nothing must never report "0 vulnerabilities".  This module
converts the plan and report into an explicit coverage statement: how many tests
were applicable, how many actually executed, what could not run and why, and the
resulting percentage.  Findings are reported as "confirmed findings", separate
from coverage.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.assess.dedup import deduplicate
from app.assess.models import AssessmentContext, TestRunReport
from app.assess.planner import AssessmentPlan
from app.observations import types

_EXECUTED_STATUSES = (types.TEST_EXECUTED, types.TEST_VALIDATED)


@dataclass
class CoverageSummary:
    scan_id: int
    registry_fingerprint: str = ""
    tests_total: int = 0
    tests_applicable: int = 0
    tests_executed: int = 0
    tests_failed: int = 0
    tests_not_applicable: int = 0
    tests_skipped: int = 0
    testcases_planned: int = 0
    testcases_executed: int = 0
    observations: int = 0
    findings_confirmed: int = 0
    findings_by_severity: dict = field(default_factory=dict)
    findings_by_confidence: dict = field(default_factory=dict)
    coverage_percent: float | None = None
    not_executed: list = field(default_factory=list)
    tools_missing: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "registry_fingerprint": self.registry_fingerprint,
            "tests_total": self.tests_total,
            "tests_applicable": self.tests_applicable,
            "tests_executed": self.tests_executed,
            "tests_failed": self.tests_failed,
            "tests_not_applicable": self.tests_not_applicable,
            "tests_skipped": self.tests_skipped,
            "testcases_planned": self.testcases_planned,
            "testcases_executed": self.testcases_executed,
            "observations": self.observations,
            "findings_confirmed": self.findings_confirmed,
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_by_confidence": dict(self.findings_by_confidence),
            "coverage_percent": self.coverage_percent,
            "not_executed": list(self.not_executed),
            "tools_missing": list(self.tools_missing),
        }

    @property
    def findings_statement(self) -> str:
        if self.findings_confirmed == 0:
            base = "0 confirmed findings"
        else:
            base = f"{self.findings_confirmed} confirmed finding(s)"
        if self.coverage_percent is None:
            return f"{base}; coverage unknown (no applicable tests)"
        return f"{base}; assessment coverage {self.coverage_percent:.1f}%"


def summarize(assessment_plan: AssessmentPlan, report: TestRunReport,
              context: AssessmentContext | None = None) -> CoverageSummary:
    summary = CoverageSummary(scan_id=assessment_plan.scan_id,
                              registry_fingerprint=assessment_plan.registry_fingerprint)
    summary.tests_total = len(assessment_plan.planned)
    summary.tests_applicable = len(assessment_plan.applicable())
    summary.testcases_planned = assessment_plan.planned_testcases()

    for outcome, planned in zip(report.outcomes, assessment_plan.planned):
        summary.observations += len(outcome.observations)
        summary.testcases_executed += outcome.executed
        if outcome.status == types.TEST_NOT_APPLICABLE or not planned.applicable:
            summary.tests_not_applicable += 1
            summary.not_executed.append({"test_id": outcome.test_id, "reason": outcome.reason or "not applicable"})
        elif outcome.status == types.TEST_FAILED:
            summary.tests_failed += 1
            summary.not_executed.append({"test_id": outcome.test_id, "reason": outcome.reason or "failed"})
        elif outcome.status in _EXECUTED_STATUSES and outcome.executed > 0:
            summary.tests_executed += 1
        else:
            summary.tests_skipped += 1
            summary.not_executed.append({"test_id": outcome.test_id, "reason": outcome.reason or "no executable work"})

    candidates = deduplicate(list(report.candidates))
    summary.findings_confirmed = len(candidates)
    summary.findings_by_severity = dict(Counter(c.severity for c in candidates))
    summary.findings_by_confidence = dict(Counter(c.confidence for c in candidates))

    if summary.tests_applicable:
        summary.coverage_percent = round(summary.tests_executed / summary.tests_applicable * 100.0, 1)
    else:
        summary.coverage_percent = None

    if context is not None:
        summary.tools_missing = list((context.metadata or {}).get("tools_missing") or [])
    return summary


__all__ = ["CoverageSummary", "summarize"]
