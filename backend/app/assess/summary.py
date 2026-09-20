"""Assessment summary, completeness and configuration snapshot (Phase 6).

This module converts the persisted engine output into the honest assessment
surface a report can consume: an aggregation of finding counts by lifecycle
status, an assessment-status/completeness classification (which describes the
assessment, never a security verdict), a persisted configuration snapshot (secrets
stored only as ``configured`` booleans), and the deterministic headline.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from app.assess import finding_lifecycle as lifecycle
from app.observations import types
from app.assess.registry import default_registry

logger = logging.getLogger("cyberagent.assessment")

# Assessment statuses (spec 21).
STATUS_NOT_STARTED = "not_started"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_COMPLETED_WITH_GAPS = "completed_with_gaps"
STATUS_FAILED = "failed"

# Completeness classification (spec 42): describes the assessment, not security.
COMPLETE = "complete"
PARTIAL = "partial"
MINIMAL = "minimal"
UNKNOWN = "unknown"

_FINDING_STATUS_COUNTS = (
    "confirmed", "candidate", "validated", "rejected", "duplicate",
    "accepted", "remediated", "reopened",
)


def aggregate(db, scan) -> dict[str, Any]:
    """Count findings grouped by lifecycle status for one scan."""
    from database.models import Vulnerability

    counts = {status: 0 for status in _FINDING_STATUS_COUNTS}
    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    for f in findings:
        key = (f.status or "confirmed").lower()
        counts[key] = counts.get(key, 0) + 1
    return {
        "total_findings": len(findings),
        "total_confirmed": counts["confirmed"],
        "total_candidates": counts["candidate"],
        "total_validated": counts["validated"],
        "total_rejected": counts["rejected"],
        "total_duplicates": counts["duplicate"],
        "total_accepted": counts["accepted"],
        "total_remediated": counts["remediated"],
        "total_reopened": counts["reopened"],
        "by_status": counts,
    }


def classify(*, coverage: dict | None, tests_failed: int = 0, tools_missing: list | None = None) -> tuple[str, str]:
    """Deterministic assessment status + completeness classification.

    ``completed`` requires no material execution failures and full applicable
    coverage; anything less is ``completed_with_gaps`` (never "secure").
    """
    tools_missing = tools_missing or []
    no_coverage = not coverage
    if no_coverage:
        return STATUS_NOT_STARTED, UNKNOWN

    coverage_percent = coverage.get("coverage_percent")
    tests_executed = int(coverage.get("tests_executed") or 0)
    tests_applicable = int(coverage.get("tests_applicable") or 0)
    tests_failed = int(coverage.get("tests_failed") or 0) or tests_failed
    tests_skipped = int(coverage.get("tests_skipped") or 0)

    material_gaps = (
        tests_failed > 0
        or tests_skipped > 0
        or bool(tools_missing)
        or coverage_percent is None
        or coverage_percent < 100.0
    )
    if tests_applicable > 0 and tests_executed > 0 and not material_gaps:
        status = STATUS_COMPLETED
        completeness = COMPLETE
    elif coverage_percent is None or tests_applicable == 0:
        status = STATUS_COMPLETED_WITH_GAPS
        completeness = UNKNOWN if coverage_percent is None else PARTIAL
    else:
        status = STATUS_COMPLETED_WITH_GAPS
        if coverage_percent >= 50.0:
            completeness = PARTIAL
        elif tests_executed > 0:
            completeness = MINIMAL
        else:
            completeness = UNKNOWN
    return status, completeness


def headline(*, aggregate_counts: dict | None = None, coverage: dict | None = None,
             status: str | None = None) -> str:
    """Deterministic headline built exclusively from stored assessment state."""
    counts = aggregate_counts or {}
    confirmed = int(counts.get("total_confirmed") or 0)
    if not coverage or coverage.get("coverage_percent") is None:
        if not coverage:
            return "No applicable tests; assessment coverage unknown."
        return f"{confirmed} confirmed finding(s); assessment coverage unknown."
    percent = coverage.get("coverage_percent")
    status = status or STATUS_COMPLETED_WITH_GAPS
    if status in (STATUS_COMPLETED_WITH_GAPS, STATUS_FAILED):
        return f"{confirmed} confirmed finding(s); assessment coverage {percent:.1f}%; assessment incomplete."
    return f"{confirmed} confirmed finding(s); assessment coverage {percent:.1f}%."


def config_fingerprint(config: dict | None) -> str:
    """SHA-256 of the canonical, secret-free configuration shape."""
    safe = json.dumps(sanitized_config(config or {}), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(safe.encode("utf-8")).hexdigest()


def sanitized_config(config: dict | None) -> dict[str, Any]:
    """Effective assessment configuration with every secret reduced to a boolean."""
    config = config or {}
    identities = config.get("auth_identities") or {}
    return {
        "active_testing": bool(config.get("active_testing", False)),
        "assessment_engine": config.get("assessment_engine") is not False,
        "auth_identities_configured": bool(identities),
        "auth_identities_labels": sorted(str(k) for k in identities.keys()),
        "jwt_tokens_configured": bool(config.get("jwt_tokens")),
        "jwt_alg_none_accepted": bool(config.get("jwt_alg_none_accepted")),
        "ssrf_validation_configured": bool(config.get("ssrf_validation_url")),
        "ssrf_token_configured": bool(config.get("ssrf_token")),
        "installed_tools": sorted(str(t) for t in (config.get("installed_tools") or [])),
        "tools_missing": sorted(str(t) for t in (config.get("tools_missing") or [])),
        "limits": {
            "max_candidate_endpoints": 25,
            "max_active_requests": 200,
            "request_timeout_seconds": 8.0,
        },
    }


def _scope_snapshot(db, scan) -> dict[str, Any]:
    """Authorized-scope summary for the report (hosts/assets, never secrets)."""
    from database.models import Asset, Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    assets = db.query(Asset).filter(Asset.project_id == scan.project_id).all()
    return {
        "target": scan.target,
        "declared_scope": list(project.scope_json or []) if project else [],
        "assets": [{"type": a.type, "value": a.value} for a in assets],
    }


def snapshot(db, scan, config: dict | None, *, coverage: dict | None = None,
             aggregate_counts: dict | None = None) -> dict[str, Any]:
    """Persist the reproducibility snapshot on the scan row."""
    safe = sanitized_config(config)
    agg = aggregate_counts or aggregate(db, scan)
    status, completeness = classify(coverage=coverage, tools_missing=safe.get("tools_missing"))
    registry = default_registry()
    snapshot_dict = {
        "assessment_version": "phase6",
        "registry_fingerprint": registry.fingerprint(),
        "config_fingerprint": config_fingerprint(config),
        "configuration": safe,
        "scope": _scope_snapshot(db, scan),
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "aggregate": agg,
    }
    scan.assessment_status = status
    scan.assessment_completeness = completeness
    scan.assessment_snapshot_json = snapshot_dict
    return snapshot_dict


def summary_from_scan(db, scan, coverage_dict: dict | None) -> dict[str, Any]:
    """Compose the full assessment summary for an API response."""
    agg = aggregate(db, scan)
    status = scan.assessment_status or (STATUS_COMPLETED_WITH_GAPS if coverage_dict else STATUS_NOT_STARTED)
    completeness = scan.assessment_completeness or UNKNOWN
    return {
        "assessment_status": status,
        "assessment_completeness": completeness,
        "coverage": coverage_dict,
        "aggregate": agg,
        "headline": headline(aggregate_counts=agg, coverage=coverage_dict, status=status),
        "snapshot": scan.assessment_snapshot_json,
    }


__all__ = [
    "COMPLETE", "MINIMAL", "PARTIAL", "STATUS_COMPLETED", "STATUS_COMPLETED_WITH_GAPS",
    "STATUS_FAILED", "STATUS_NOT_STARTED", "STATUS_RUNNING", "UNKNOWN",
    "aggregate", "classify", "config_fingerprint", "headline", "sanitized_config",
    "snapshot", "summary_from_scan",
]