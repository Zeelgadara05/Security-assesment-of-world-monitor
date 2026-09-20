"""Assessment report builder (Phase 6).

Assembles :class:`AssessmentReport` strictly from persisted scan state.  Every
section's ``markdown`` is deterministic; the JSON payload mirrors it.  The
13-section structure is fixed so exports are stable across versions.
"""
from __future__ import annotations

import datetime
import json

from app.assess import finding_lifecycle as lifecycle
from app.reporting.coverage_renderer import (
    coverage_markdown, coverage_payload, test_ledger, tool_availability,
)
from app.reporting.evidence_renderer import evidence_markdown_section, render_evidence
from app.reporting.finding_renderer import finding_to_markdown, render_finding
from app.reporting.models import AssessmentReport, ReportSection
from app.reporting.redaction import safe_text
from app.reporting.summary import limitations, methodology

_TECH_TOOLS = ("nmap", "nuclei", "httpx", "ffuf", "nikto", "sqlmap", "testssl")


def _coverage_from_tool_result(db, scan) -> dict | None:
    from database.models import ToolResult

    row = (
        db.query(ToolResult)
        .filter(ToolResult.scan_id == scan.id, ToolResult.tool_name == "native_assessment")
        .first()
    )
    if not row or not row.raw_output:
        return None
    try:
        return json.loads(row.raw_output)
    except (ValueError, TypeError):
        return None


def _assessment_tests(db, scan) -> list[dict]:
    from database.models import AssessmentTest

    rows = (
        db.query(AssessmentTest)
        .filter(AssessmentTest.scan_id == scan.id)
        .order_by(AssessmentTest.id.asc())
        .all()
    )
    return [
        {
            "test_id": t.test_id,
            "name": t.name,
            "category": t.category,
            "status": t.status,
            "reason": t.reason,
            "active": bool(t.active),
            "observation_ids": t.observation_ids or [],
            "finding_ids": t.finding_ids or [],
        }
        for t in rows
    ]


def _findings(db, scan) -> list:
    from database.models import Vulnerability

    return (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .order_by(Vulnerability.severity.desc(), Vulnerability.id.asc())
        .all()
    )


def build(db, scan) -> AssessmentReport:
    from database.models import Observation

    coverage = _coverage_from_tool_result(db, scan)
    tests = _assessment_tests(db, scan)
    findings = _findings(db, scan)
    confirmed = [f for f in findings if (f.status or lifecycle.STATUS_CONFIRMED) == lifecycle.STATUS_CONFIRMED]
    candidates = [f for f in findings if (f.status or lifecycle.STATUS_CONFIRMED) == lifecycle.STATUS_CANDIDATE]
    snapshot_data = scan.assessment_snapshot_json or {}
    cfg = snapshot_data.get("configuration") or {}

    from app.assess import summary as assess_summary

    agg = assess_summary.aggregate(db, scan)
    status = scan.assessment_status or (
        assess_summary.STATUS_COMPLETED_WITH_GAPS if coverage else assess_summary.STATUS_NOT_STARTED
    )
    completeness = scan.assessment_completeness or assess_summary.UNKNOWN
    headline = assess_summary.headline(aggregate_counts=agg, coverage=coverage, status=status)
    registry_fingerprint = coverage.get("registry_fingerprint") if coverage else snapshot_data.get("registry_fingerprint")
    config_fingerprint = snapshot_data.get("config_fingerprint") or assess_summary.config_fingerprint(scan.scan_config)
    generated_at = (scan.completed_at or datetime.datetime.utcnow()).isoformat() + "Z"

    rendered = [render_finding(db, f) for f in findings]
    confirmed_rendered = [r for r in rendered if r["status"] == lifecycle.STATUS_CONFIRMED]
    candidate_rendered = [r for r in rendered if r["status"] == lifecycle.STATUS_CANDIDATE]
    evidence_rows = [e for f in findings for e in render_evidence(db, f)]
    observation_count = db.query(Observation).filter(Observation.scan_id == scan.id).count()
    tool_matrix = tool_availability(
        _TECH_TOOLS,
        installed=cfg.get("installed_tools") or [],
        missing=cfg.get("tools_missing") or [],
    )
    limit_statement = limitations(snapshot_data, coverage, has_findings=bool(confirmed))

    # --- executive summary --------------------------------------------------
    exec_md = [
        f"# Assessment report — {scan.target}",
        "",
        f"- **Report generated:** {generated_at}",
        f"- **Assessment status:** {status}",
        f"- **Assessment completeness:** {completeness}",
        f"- **Headline:** {headline}",
        f"- **Confirmed findings:** {agg['total_confirmed']}   **Candidates:** {agg['total_candidates']}",
        f"- **Registry fingerprint:** `{registry_fingerprint or 'n/a'}`",
        f"- **Configuration fingerprint:** `{config_fingerprint}`",
        "",
        "This report is generated deterministically from persisted assessment state. "
        "Coverage describes the assessment performed, never a security guarantee.",
    ]

    # --- sections -----------------------------------------------------------
    phase7_trail = _phase7_trail(db, scan)
    phase7_md = _phase7_trail_md(phase7_trail)
    sections = [
        ReportSection(id="executive_summary", title="Executive Summary",
                      content={"headline": headline, "status": status, "completeness": completeness,
                               "confirmed": agg["total_confirmed"], "candidates": agg["total_candidates"]},
                      markdown="\n".join(exec_md)),
        ReportSection(id="assessment_completeness", title="Assessment Completeness & Configuration",
                      content={"assessment_status": status, "assessment_completeness": completeness,
                               "configuration": cfg, "snapshot": snapshot_data},
                      markdown=_completeness_md(status, completeness, cfg, snapshot_data)),
        ReportSection(id="scope", title="Scope & Authorized Targets",
                      content={"target": scan.target, "scope": (snapshot_data.get("scope") or {})},
                      markdown=_scope_md(scan, snapshot_data)),
        ReportSection(id="methodology", title="Methodology",
                      content={"statement": methodology(), "registry_fingerprint": registry_fingerprint},
                      markdown=f"**Methodology.** {methodology()}\n\nRegistry fingerprint: `{registry_fingerprint or 'n/a'}`"),
        ReportSection(id="coverage", title="Coverage & Test Ledger",
                      content=coverage_payload(coverage), markdown=coverage_markdown(coverage, tests)),
        ReportSection(id="execution_platform", title="Execution Platform & Stage Ledger",
                      content=phase7_trail["execution"], markdown=phase7_md["execution"]),
        ReportSection(id="findings", title="Confirmed Findings",
                      content=confirmed_rendered,
                      markdown=_findings_md(db, confirmed)),
        ReportSection(id="candidates", title="Candidate Findings (external, not confirmed)",
                      content=candidate_rendered,
                      markdown=_findings_md(db, candidates)),
        ReportSection(id="evidence", title="Evidence Trace",
                      content=evidence_rows,
                      markdown=_evidence_md(evidence_rows)),
        ReportSection(id="remediation", title="Remediation Guidance",
                      content=remediation_aggregate(confirmed),
                      markdown=_remediation_md(confirmed)),
        ReportSection(id="tools", title="Tool Availability",
                      content=tool_matrix, markdown=_tools_md(tool_matrix)),
        ReportSection(id="limitations", title="Limitations",
                      content=limit_statement,
                      markdown="\n".join([f"{i}. {l}" for i, l in enumerate(limit_statement, 1)])),
        ReportSection(id="reproducibility", title="Reproducibility",
                      content={"assessment_version": "phase6",
                               "registry_fingerprint": registry_fingerprint,
                               "config_fingerprint": config_fingerprint,
                               "generated_at": generated_at,
                               "observation_count": observation_count,
                               "findings": [r["id"] for r in rendered]},
                      markdown=_reproducibility_md(registry_fingerprint, config_fingerprint, generated_at, observation_count, rendered)),
        ReportSection(id="execution_ledger", title="Execution Ledger & Validations",
                      content=phase7_trail["ledger"], markdown=phase7_md["ledger"]),
    ]

    json_payload = {
        "assessment_version": "phase6",
        "execution_platform_version": "phase7",
        "scan_id": scan.id,
        "target": scan.target,
        "generated_at": generated_at,
        "assessment_status": status,
        "assessment_completeness": completeness,
        "headline": headline,
        "registry_fingerprint": registry_fingerprint,
        "config_fingerprint": config_fingerprint,
        "sections": {s.id: s.content for s in sections},
        "findings": rendered,
        "evidence": evidence_rows,
        "coverage": coverage_payload(coverage),
        "limitations": limit_statement,
        "execution_trail": phase7_trail,
    }

    parts = []
    for section in sections:
        if section.id == "executive_summary":
            parts.append(section.markdown.strip())
        else:
            parts.append(f"## {section.title}\n\n{section.markdown.strip()}")
    markdown = "\n\n---\n\n".join(parts)
    markdown += (
        "\n\n---\n\n### Notice\n"
        "This report is valid only for the authorized target described in this document. "
        "Coverage describes the assessment performed. Absence of a finding means the area "
        "was not asserted to be vulnerable under the executed tests; it does not mean the "
        "area is free of vulnerabilities outside the exercised coverage."
    )

    return AssessmentReport(
        scan_id=scan.id,
        target=scan.target,
        generated_at=generated_at,
        registry_fingerprint=registry_fingerprint or "",
        config_fingerprint=config_fingerprint,
        assessment_version="phase6",
        assessment_status=status,
        assessment_completeness=completeness,
        headline=headline,
        sections=sections,
    ), markdown, json_payload, rendered


# --------------------------------------------------------------------------- helpers
def _completeness_md(status, completeness, cfg, snapshot_data) -> str:
    lines = [
        f"- **Assessment status:** {status}",
        f"- **Assessment completeness:** {completeness}",
        f"- **Active (mutating) testing:** {'enabled' if cfg.get('active_testing') else 'disabled'}",
        f"- **Assessment engine:** {'enabled' if cfg.get('assessment_engine') is not False else 'disabled'}",
        f"- **Auth identities configured:** {cfg.get('auth_identities_configured', False)} "
        f"(labels: {', '.join(cfg.get('auth_identities_labels') or []) or 'none'})",
        f"- **JWT tokens configured:** {cfg.get('jwt_tokens_configured', False)}",
        f"- **SSRF validation configured:** {cfg.get('ssrf_validation_configured', False)}",
        f"- **Installed tools:** {', '.join(cfg.get('installed_tools') or []) or 'none'}",
        f"- **Missing tools:** {', '.join(cfg.get('tools_missing') or []) or 'none'}",
        f"- **Scope guard/limits:** max candidate endpoints 25, max active requests 200.",
    ]
    return "\n".join(lines)


def _scope_md(scan, snapshot_data) -> str:
    scope = snapshot_data.get("scope") or {}
    assets = scope.get("assets") or []
    lines = [
        f"- **Target:** `{scan.target}`",
        f"- **Declared scope:** {', '.join(scope.get('declared_scope') or []) or 'none'}",
        f"- **Discovered assets:** {', '.join('{}:{}'.format(a.get('type'), a.get('value')) for a in assets) or 'none'}",
    ]
    return "\n".join(lines)


def _findings_md(db, findings) -> str:
    if not findings:
        return "**No findings in this class.**"
    return "\n\n---\n\n".join(finding_to_markdown(db, f) for f in findings)


def _evidence_md(rows) -> str:
    return evidence_markdown_section(rows)


def remediation_aggregate(findings) -> list[dict]:
    out: list[dict] = []
    for f in findings:
        details = f.remediation_details if isinstance(f.remediation_details, dict) else {}
        summary = details.get("summary") or f.remediation or ""
        if summary and not any(existing.get("summary") == summary for existing in out):
            out.append({
                "category": f.category,
                "finding_ids": [f.id],
                "summary": summary,
                "technical_fix": details.get("technical_fix") or "",
            })
        elif summary:
            existing = next(e for e in out if e.get("summary") == summary)
            existing.setdefault("finding_ids", []).append(f.id)
    return out


def _remediation_md(findings) -> str:
    grouped = remediation_aggregate(findings)
    if not grouped:
        return "No confirmed findings; no remediation actions to prescribe."
    lines = []
    for entry in grouped:
        lines.append(f"### {entry['category'] or 'General'}")
        lines.append(f"- Applies to: {', '.join('F-%d' % i for i in entry['finding_ids'])}")
        lines.append(f"- **Summary:** {safe_text(entry['summary'])}")
        lines.append(f"- **Technical fix:** {safe_text(entry['technical_fix']) or '*see finding remediation_details*'}")
        lines.append("")
    return "\n".join(lines)


def _tools_md(matrix) -> str:
    lines = ["| tool | status |", "|------|--------|"]
    for tool, info in matrix.items():
        if info["missing"]:
            state = "unavailable"
        elif info["installed"]:
            state = "available"
        else:
            state = "unknown"
        lines.append(f"| {tool} | {state} |")
    return "\n".join(lines)


def _reproducibility_md(registry_fp, config_fp, generated_at, observation_count, rendered) -> str:
    return (
        f"- **Assessment version:** phase6\n"
        f"- **Registry fingerprint:** `{registry_fp or 'n/a'}`\n"
        f"- **Configuration fingerprint:** `{config_fp}`\n"
        f"- **Report generated:** {generated_at}\n"
        f"- **Observation rows reviewed:** {observation_count}\n"
        f"- **Finding ids:** {', '.join(str(r['id']) for r in rendered) or 'none'}"
    )


def _phase7_trail(db, scan) -> dict:
    """Deterministic execution-trail snapshot for one scan.

    Reads persisted Phase 7 rows only (ordered by id) and never invents a
    number: preflight/readiness, the stage ledger, the tool execution ledger,
    validator verdicts and the advisory record.
    """
    from database.models import (FindingValidation, MLInference, ScanStage,
                                 ToolExecution, ToolReadiness)

    preflight = scan.preflight_json or {}
    stages = [
        {
            "name": s.name, "order": s.order, "status": s.status,
            "tools": list(s.tools or []), "tests_executed": s.tests_executed or 0,
            "observations": s.observations or 0, "candidates": s.candidates or 0,
            "confirmed_findings": s.confirmed_findings or 0,
            "errors": s.errors or {}, "duration_ms": s.duration_ms,
        }
        for s in db.query(ScanStage).filter(ScanStage.scan_id == scan.id)
        .order_by(ScanStage.id.asc()).all()
    ]
    readiness = [
        {
            "tool": r.tool, "status": r.status, "executable": r.executable,
            "version": r.version, "adapter": r.adapter, "category": r.category,
            "enabled": bool(r.enabled), "reason": r.reason,
        }
        for r in db.query(ToolReadiness).filter(ToolReadiness.scan_id == scan.id)
        .order_by(ToolReadiness.id.asc()).all()
    ]
    executions = [
        {
            "tool": e.tool, "stage": e.stage, "adapter": e.adapter, "attempt": e.attempt,
            "status": e.status, "duration_ms": e.duration_ms,
            "parsed_observations": e.parsed_observations or 0,
            "cancellation_state": e.cancellation_state,
            "termination_reason": e.termination_reason, "exit_code": e.exit_code,
        }
        for e in db.query(ToolExecution).filter(ToolExecution.scan_id == scan.id)
        .order_by(ToolExecution.id.asc()).all()
    ]
    validations = [
        {
            "finding_id": v.finding_id, "validator_id": v.validator_id, "status": v.status,
            "condition": v.condition, "reason": v.reason, "observation_id": v.observation_id,
        }
        for v in db.query(FindingValidation).filter(FindingValidation.scan_id == scan.id)
        .order_by(FindingValidation.id.asc()).all()
    ]
    validation_stats: dict[str, int] = {}
    for v in validations:
        validation_stats[v["status"]] = validation_stats.get(v["status"], 0) + 1

    ml = (
        db.query(MLInference).filter(MLInference.scan_id == scan.id)
        .order_by(MLInference.id.desc()).first()
    )
    advisory = None
    if ml is not None:
        advisory = {
            "status": ml.status, "model_name": ml.model_name,
            "feature_schema_version": ml.feature_schema_version,
            "generated_at": ml.generated_at.isoformat() if ml.generated_at else None,
        }

    return {
        "execution": {
            "preflight": preflight,
            "readiness": readiness,
            "stages": stages,
            "stage_status_bucket": _bucket(stages, "status"),
        },
        "ledger": {
            "executions": executions,
            "execution_status_bucket": _bucket(executions, "status"),
            "validations": validations,
            "validation_status_bucket": validation_stats,
            "advisory": advisory,
        },
    }


def _bucket(rows: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        out[r.get(key)] = out.get(r.get(key), 0) + 1
    return out


def _phase7_trail_md(trail: dict) -> dict:
    execution = trail["execution"]
    ledger = trail["ledger"]
    pre = execution["preflight"] or {}

    ex_lines = [
        f"- **Preflight:** blocked={bool(pre.get('blocked_reasons'))} • "
        f"installed={', '.join(sorted(pre.get('installed') or [])) or 'none'} • "
        f"missing={', '.join(sorted(pre.get('missing') or [])) or 'none'} • "
        f"disabled={', '.join(sorted(pre.get('disabled') or [])) or 'none'}",
        f"- **Stages:** {', '.join('{} ({})'.format(s['name'], s['status']) for s in execution['stages']) or 'none (phase7 pipeline not used)'}",
    ]
    ex_md = "\n".join(ex_lines)

    ledger_lines = [
        "| tool | stage | status | attempts | parsed | duration_ms |",
        "|------|-------|--------|----------|--------|-------------|",
    ]
    for e in ledger["executions"]:
        ledger_lines.append(
            f"| {e['tool']} | {e['stage']} | {e['status']} | {e['attempt']} | "
            f"{e['parsed_observations']} | {e['duration_ms']} |"
        )
    if not ledger["executions"]:
        ledger_lines.append("| _no phase 7 tool executions recorded_ |")

    val_stats = " • ".join(f"{k}:{v}" for k, v in sorted(ledger["validation_status_bucket"].items()))
    ledger_lines += [
        "",
        f"- **Validator verdicts:** {val_stats or 'none'}",
    ]
    confirmed_rows = [v for v in ledger["validations"] if v["status"] == "confirmed"]
    if confirmed_rows:
        ledger_lines.append(
            "- **Confirmed finding F- ids (deterministic validation):** "
            + ", ".join("F-%d" % v["finding_id"] for v in confirmed_rows if v["finding_id"])
        )
    if ledger["advisory"]:
        adv = ledger["advisory"]
        ledger_lines.append(
            f"- **Advisory record:** {adv['status']} (schema {adv['feature_schema_version']}; "
            f"no model prediction used)"
        )
    return {"execution": ex_md, "ledger": "\n".join(ledger_lines)}


__all__ = ["build", "remediation_aggregate"]