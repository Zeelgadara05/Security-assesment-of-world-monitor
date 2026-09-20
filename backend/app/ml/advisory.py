"""Deterministic coverage-gap advisory (advisory-only ML placeholder, Phase 7).

``generate`` reads persisted scan state (preflight snapshot, execution ledger,
validation results, assessment coverage) and produces an advisory that states
where security coverage is *known to be incomplete* -- because a tool was
missing, a stage was skipped, or candidates went unconfirmed.  It never invents
a probability, severity or prediction: with no model present the advisory is a
plain, auditable note.
"""
from __future__ import annotations

import datetime

from database.models import MLInference

FEATURE_SCHEMA_VERSION = "advisory-v1"

_STATUS_NONE = "none"


def _tool_gaps(scan) -> list[str]:
    pre = scan.preflight_json or {}
    missing = list(pre.get("missing") or [])
    disabled = list(pre.get("disabled") or [])
    return [t for t in missing if t not in ("real_dns", "real_tcp", "real_http")]


def _execution_status(db, scan_id: int) -> dict:
    from database.models import ToolExecution

    rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r.status or "unknown"] = by_status.get(r.status or "unknown", 0) + 1
    return by_status


def generate(db, scan, tracking_rows: dict | None = None) -> dict:
    """Build + persist the advisory record for ``scan``. Returns the payload."""
    from database.models import AssessmentTest, FindingValidation, Vulnerability

    pre = scan.preflight_json or {}
    gaps = _tool_gaps(scan)

    tests = db.query(AssessmentTest).filter(AssessmentTest.scan_id == scan.id).all()
    executed = sum(1 for t in tests if (t.status or "").startswith("executed"))
    applicable = len(tests)

    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).count()
    validations = db.query(FindingValidation).filter(FindingValidation.scan_id == scan.id).count()
    unvalidated = (
        db.query(FindingValidation)
        .filter(FindingValidation.scan_id == scan.id,
                FindingValidation.status == "rejected",
                FindingValidation.finding_id.is_(None))
        .count()
    )

    statement = (
        "No model prediction was used in this assessment. The advisory below is a "
        "deterministic coverage-gap note derived from persisted scan state."
    )
    recommendation = _recommendation(pre, gaps, executed, applicable)
    advisory_json = {
        "scope": "coverage-gap advisory",
        "disclaimer": statement,
        "execution": {
            "coverage_percent": scan.coverage,
            "tests_executed": executed,
            "tests_applicable": applicable,
            "tool_statuses": _execution_status(db, scan.id),
            "preflight_blocked": bool(pre.get("blocked_reasons")),
        },
        "tool_gaps": gaps,
        "disabled_tools": list(pre.get("disabled") or []),
        "findings": {
            "confirmed_findings": findings,
            "validation_rows": validations,
            "unvalidated_candidates": unvalidated,
            "cross_scan": tracking_rows or {},
        },
        "recommendation": recommendation,
    }

    row = MLInference(
        scan_id=scan.id,
        model_name=None,
        model_version=None,
        model_type=None,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_status=_STATUS_NONE,
        input_source="persisted_scan_state",
        status="advisory_only",
        advisory_json=advisory_json,
        generated_at=datetime.datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    return {"status": "advisory_only", "model_name": None, "advisory_json": advisory_json}


def _recommendation(pre: dict, gaps: list[str], executed: int, applicable: int) -> str:
    parts = []
    if gaps:
        parts.append(
            f"install the missing tool(s) {', '.join(sorted(gaps))} to close "
            "known coverage gaps")
    if applicable and executed < applicable:
        parts.append(
            f"{applicable - executed} applicable assessment test(s) did not run "
            "(inapplicable areas are reported as coverage, never as zero risk)")
    if not parts:
        parts.append(
            "no known coverage gaps from this run; repeat scans still cannot "
            "prove absence of vulnerabilities")
    return "; ".join(parts) + "."


__all__ = ["generate", "FEATURE_SCHEMA_VERSION"]