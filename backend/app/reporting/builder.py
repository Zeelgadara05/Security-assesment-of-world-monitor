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
    evidence_rows = [
        {"finding_id": e["id"], **e}
        for f in findings
        for e in render_evidence(db, f)
    ]
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
    ]

    json_payload = {
        "assessment_version": "phase6",
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
    }

    markdown = "\n\n---\n\n".join(section.markdown for section in sections)
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


__all__ = ["build", "remediation_aggregate"]