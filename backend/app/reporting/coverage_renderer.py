"""Coverage rendering for the report (Phase 6).

Coverage describes the assessment -- not the security of the target.  The
ledger shows for every planned test: applicability, outcome, the deterministic
reason, and whether it produced findings.  The tool matrix shows which external
tools were available.  Missing coverage is always surfaced explicitly.
"""
from __future__ import annotations

from typing import Any


def coverage_payload(coverage: dict | None) -> dict[str, Any]:
    """The persisted coverage summary, with every field present and honest."""
    coverage = coverage or {}
    return {
        "registry_fingerprint": coverage.get("registry_fingerprint"),
        "tests_total": coverage.get("tests_total", 0),
        "tests_applicable": coverage.get("tests_applicable", 0),
        "tests_executed": coverage.get("tests_executed", 0),
        "tests_failed": coverage.get("tests_failed", 0),
        "tests_not_applicable": coverage.get("tests_not_applicable", 0),
        "tests_skipped": coverage.get("tests_skipped", 0),
        "testcases_planned": coverage.get("testcases_planned", 0),
        "testcases_executed": coverage.get("testcases_executed", 0),
        "observations": coverage.get("observations", 0),
        "coverage_percent": coverage.get("coverage_percent"),
        "not_executed": list(coverage.get("not_executed") or []),
        "tools_missing": list(coverage.get("tools_missing") or []),
    }


def test_ledger(tests: list[dict]) -> list[dict[str, Any]]:
    return [
        {
            "test_id": t.get("test_id"),
            "name": t.get("name"),
            "category": t.get("category"),
            "status": t.get("status"),
            "reason": t.get("reason") or "",
            "active": bool(t.get("active")),
            "observation_count": len(t.get("observation_ids") or []),
            "finding_ids": list(t.get("finding_ids") or []),
        }
        for t in tests
    ]


def tool_availability(static_tools, installed: list[str], missing: list[str]) -> dict[str, Any]:
    """Availability matrix: every tool is present/absent, defaulting to present only when known."""
    installed = set(installed or [])
    missing = set(missing or [])
    return {
        tool: {
            "installed": tool in installed,
            "missing": tool in missing,
        }
        for tool in static_tools
    }


def coverage_markdown(coverage: dict | None, tests: list[dict]) -> str:
    cov = coverage_payload(coverage)
    lines = [
        "**Coverage statement (describes the assessment, not security):**",
        "",
        f"- Registered tests: {cov['tests_total']}",
        f"- Applicable tests: {cov['tests_applicable']}",
        f"- Executed tests: {cov['tests_executed']}",
        f"- Skipped tests: {cov['tests_skipped']}",
        f"- Failed tests: {cov['tests_failed']}",
        f"- Not applicable: {cov['tests_not_applicable']}",
        f"- Test cases planned/executed: {cov['testcases_planned']}/{cov['testcases_executed']}",
        f"- Coverage: {('%.1f%%' % cov['coverage_percent']) if cov['coverage_percent'] is not None else 'unknown (no applicable tests)'}",
        "",
        "**Executed/nonexecuted ledger:**",
        "",
        "| test_id | status | active | reason | findings |",
        "|---------|--------|--------|--------|----------|",
    ]
    for t in test_ledger(tests):
        lines.append(
            f"| {t['test_id']} | {t['status']} | {'mutating' if t['active'] else 'passive'} | "
            f"{str(t['reason'] or '')[:48]} | {', '.join('F-%d' % i for i in t['finding_ids']) or '-'} |"
        )
    if not tests:
        lines.append("| *none* | *none* | *none* | *no assessment executed* | - |")
    if cov["tools_missing"]:
        lines.append("")
        lines.append("**Tools unavailable (coverage gaps):** " + ", ".join(str(t) for t in cov["tools_missing"]))
    for gap in cov["not_executed"]:
        lines.append(f"- *not executed*: `{gap.get('test_id')}` — {gap.get('reason')}")
    return "\n".join(lines)


__all__ = ["coverage_markdown", "coverage_payload", "test_ledger", "tool_availability"]