"""Report summary composition (Phase 6).

Builds the report-level summary from persisted scan state, delegating pure logic
to ``app.assess.summary`` and the renderers.  The report is never an LLM product
and never asserts security posture; it asserts what was done and what was found.
"""
from __future__ import annotations

from typing import Any

from app.assess import summary as assess_summary


def scan_assessment_summary(db, scan, coverage: dict | None) -> dict[str, Any]:
    """Same fields as the /assessment endpoint, built from persisted rows."""
    return assess_summary.summary_from_scan(db, scan, coverage)


def limitations(snapshot: dict | None, coverage: dict | None, has_findings: bool) -> list[str]:
    """Honest, deterministic limitation statements derived from stored state."""
    snapshot = snapshot or {}
    cfg = snapshot.get("configuration") or {}
    gaps: list[str] = []
    if not coverage or coverage.get("coverage_percent") is None:
        gaps.append("No applicable native tests were identified; assessment coverage is unknown.")
    else:
        percent = coverage.get("coverage_percent")
        if percent < 100:
            gaps.append(
                f"Assessment coverage was {percent:.1f}%: skipped/failed or inapplicable "
                "areas are explicitly reported, never treated as 'safe'.")
    if coverage and coverage.get("tools_missing"):
        gaps.append("External tools unavailable during collection: " + ", ".join(str(t) for t in coverage["tools_missing"]) + ". Their observations are absent from this report.")
    if cfg.get("active_testing") is False:
        gaps.append("Active (mutating) testing was disabled; mutating tests were planned but their verdicts are not asserted.")
    if snapshot.get("config_fingerprint") and not cfg.get("installed_tools"):
        gaps.append("No external tool results were ingested into native confirmation.")
    if not has_findings:
        gaps.append("This report contains no confirmed findings; that reflects this assessment's coverage, not an overall security guarantee.")
    return gaps or ["No additional limitations recorded."]


def methodology() -> str:
    return (
        "Findings are confirmed only when a deterministic native validator observed "
        "an applicable test outcome with structured evidence (comparison of expected vs "
        "actual security property). External tool reports and unvalidated observations "
        "are surfaced as *candidates*, never as confirmed findings. Severity derives "
        "deterministically; no CVSS vector or score is fabricated. All requests are "
        "scope-guarded and bounded by the assessment limits."
    )


__all__ = ["limitations", "methodology", "scan_assessment_summary"]