import time
import json
import datetime
import logging
from database.connection import SessionLocal
from database.models import Scan, ToolResult, Vulnerability, Asset, Report, Observation
from app.tools.scanner_tools import (
    run_subfinder, run_assetfinder, run_dnsx, run_nmap,
    run_httpx, run_nuclei, run_gau, run_whatweb,
    STATE_NOT_INSTALLED, STATE_TIMEOUT, STATE_PARSE_FAILED, STATE_EXECUTION_FAILED,
)
from app.tools import real_probes
from app.assess import finding_rules

logger = logging.getLogger("cyberagent.workflow")


def orchestrate_scan(scan_id: int, simulation: bool = True):
    """Full multi-agent workflow.

    Planner -> Recon -> Scanning -> Real Evidence Pipeline -> Analysis (findings
    derived exclusively from persisted observations) -> Report (strictly
    downstream of the persisted findings).
    """
    db = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan ID {scan_id} not found in database.")
            return

        scan.status = "Running"
        scan.logs = "[Planner Agent] Init: Analyzing scan target security posture...\n"
        db.commit()

        if simulation:
            scan.logs += (
                "[SIMULATION] Scan running in SIMULATION_MODE: no real probes run and "
                "no findings are produced. All output is synthetic and must NOT be "
                "treated as a real security assessment.\n"
            )
            db.commit()

        target = scan.target
        time.sleep(1)

        # ----------------------------------------------------
        # 1. PLANNER AGENT
        # ----------------------------------------------------
        scan.logs += f"[Planner Agent] Target validated: {target}\n"
        scan.logs += "[Planner Agent] Scheduling Recon tools: subfinder, assetfinder, dnsx, real_dns\n"
        scan.logs += "[Planner Agent] Scheduling Port tools: nmap, real_tcp\n"
        scan.logs += "[Planner Agent] Scheduling Web / Vuln tools: httpx, WhatWeb, gau, nuclei, real_http\n"
        db.commit()
        time.sleep(1.5)

        # ----------------------------------------------------
        # 2. RECON AGENT
        # ----------------------------------------------------
        scan.logs += "[Recon Agent] Starting passive subdomain gathering via subfinder...\n"
        db.commit()
        subfinder_res = run_subfinder(target, simulation)
        save_tool_result(db, scan.id, "subfinder", subfinder_res, simulated=simulation)

        scan.logs += "[Recon Agent] Running assetfinder discovery...\n"
        db.commit()
        asset_res = run_assetfinder(target, simulation)
        save_tool_result(db, scan.id, "assetfinder", asset_res, simulated=simulation)

        # Extract unique subdomains
        subdomains = list(set((subfinder_res.get("subdomains", [])) + (asset_res.get("subdomains", []))))
        if not subdomains:
            subdomains = [target]

        scan.logs += f"[Recon Agent] Total unique subdomains identified: {len(subdomains)}\n"
        scan.logs += "[Recon Agent] Checking DNS resolution using dnsx...\n"
        db.commit()
        dnsx_res = run_dnsx(target, subdomains, simulation)
        save_tool_result(db, scan.id, "dnsx", dnsx_res, simulated=simulation)

        # Add domains and IPs as assets
        for sub in subdomains:
            add_asset(db, scan.project_id, "domain", sub, {"status": "active"})
        for item in dnsx_res.get("resolved", []):
            add_asset(db, scan.project_id, "ip", item["ip"], {"domain": item["subdomain"]})
        db.commit()

        # ----------------------------------------------------
        # 3. SCANNING AGENT
        # ----------------------------------------------------
        scan.logs += "[Scanning Agent] Initializing port and service scanning with nmap...\n"
        db.commit()
        nmap_res = run_nmap(target, simulation)
        save_tool_result(db, scan.id, "nmap", nmap_res, simulated=simulation)

        for p in nmap_res.get("ports", []):
            if p["state"] == "open":
                add_asset(db, scan.project_id, "port", f"{p['port']}/{p['protocol']}", {
                    "service": p["service"], "product": p["product"], "version": p["version"]
                })
        db.commit()

        scan.logs += "[Scanning Agent] Probing live web servers with httpx...\n"
        db.commit()
        httpx_res = run_httpx(target, simulation)
        save_tool_result(db, scan.id, "httpx", httpx_res, simulated=simulation)

        scan.logs += "[Scanning Agent] Harvesting web routes using gau...\n"
        db.commit()
        gau_res = run_gau(target, simulation)
        save_tool_result(db, scan.id, "gau", gau_res, simulated=simulation)

        scan.logs += "[Scanning Agent] Profiling server technologies via WhatWeb...\n"
        db.commit()
        whatweb_res = run_whatweb(target, simulation)
        save_tool_result(db, scan.id, "whatweb", whatweb_res, simulated=simulation)

        for tech in whatweb_res.get("techs", []):
            add_asset(db, scan.project_id, "tech", tech, {})
        db.commit()

        scan.logs += "[Scanning Agent] Starting Nuclei active vulnerability tests...\n"
        db.commit()
        nuclei_res = run_nuclei(target, simulation)
        save_tool_result(db, scan.id, "nuclei", nuclei_res, simulated=simulation)

        # ----------------------------------------------------
        # 4A. REAL EVIDENCE PIPELINE (real mode only)
        # ----------------------------------------------------
        if not simulation:
            scan.logs += "[Evidence Agent] Running real DNS/TCP/HTTP probes and persisting observations...\n"
            db.commit()
            _run_real_evidence_pipeline(db, scan, target, subdomains, nuclei_res)

        # ----------------------------------------------------
        # 4B. ANALYSIS AGENT -- findings from persisted observations only
        # ----------------------------------------------------
        scan.logs += "[AI Analysis Agent] Deriving findings exclusively from persisted observations...\n"
        db.commit()
        time.sleep(2)

        if simulation:
            # A simulated run has no observations and must never synthesize
            # findings. Score stays at the documented clean baseline.
            scan.security_score = 100
            scan.logs += (
                "[AI Analysis Agent] Simulation mode: 0 observations, 0 findings. "
                "No security findings were fabricated.\n"
            )
            db.commit()
        else:
            observations = _scan_observations(db, scan.id)
            candidates = finding_rules.evaluate_observations(observations)
            existing = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
            existing_keys = {
                v.dedup_key for v in existing
                if v.dedup_key and (v.state or "NEW").upper() not in finding_rules.RESOLVED_STATES
            }
            candidates = finding_rules.deduplicate(candidates, existing_keys)
            for candidate in candidates:
                db.add(_persisted_finding(scan, candidate, target))
            db.commit()
            scan.logs += (
                f"[AI Analysis Agent] Rule engine applied to {len(observations)} observations "
                f"produced {len(candidates)} evidence-backed finding(s).\n"
            )
            findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
            finding_dicts = [{"severity": f.severity or "Info", "state": f.state or "NEW"} for f in findings]
            scan.security_score = finding_rules.compute_score(finding_dicts)
            scan.logs += (
                f"[AI Analysis Agent] Evaluation complete. Security score calculated "
                f"from {len(findings)} persisted finding(s): {scan.security_score}/100\n"
            )
            db.commit()

        # ----------------------------------------------------
        # 5. REPORT GENERATOR -- strictly downstream of persisted data
        # ----------------------------------------------------
        scan.logs += "[Reporting Agent] Generating report from PERSISTED findings and observations...\n"
        db.commit()
        time.sleep(1.5)

        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).order_by(Vulnerability.id.asc()).all()
        observations = _scan_observations(db, scan.id)
        findings_payload = [_finding_dict(f) for f in findings]
        observations_payload = [
            {"id": o["id"], "tool": o["tool"], "kind": o["kind"], "subject": o["subject"],
             "data": o["data"], "raw": o["raw"]}
            for o in observations
        ]

        markdown_report = generate_markdown_report_content(scan, findings, observations, simulation)
        html_report = generate_html_report_content(scan, markdown_report)

        report_obj = Report(
            scan_id=scan.id,
            title=f"Security Assessment Report for {target}",
            markdown_content=markdown_report,
            json_content={
                "target": target,
                "security_score": scan.security_score,
                "simulation": simulation,
                "findings": findings_payload,
                "observations": observations_payload,
                "subdomains": subdomains,
            },
            html_content=html_report,
            pdf_content=markdown_report.encode("utf-8")  # Storing markdown source as pdf mock bytes
        )
        db.add(report_obj)

        scan.status = "Completed"
        scan.completed_at = datetime.datetime.utcnow()
        scan.logs += "[Reporting Agent] Completed. Report artifacts ready for download.\n"
        if simulation:
            scan.logs += "[SIMULATION] This scan ran in simulation mode; findings would be synthetic (none produced).\n"
        db.commit()

    except Exception as e:
        logger.error(f"Error in orchestrating scan: {e}")
        if scan is not None:
            scan.status = "Failed"
            scan.completed_at = datetime.datetime.utcnow()
            scan.logs += f"[System Error] Scan failed due to: {e}\n"
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Real evidence pipeline
# ---------------------------------------------------------------------------
def _run_real_evidence_pipeline(db, scan: Scan, target: str, subdomains: list, nuclei_res: dict):
    """Real probes -> observations + assets. External nuclei output, when real,
    is normalized into ``nuclei_finding`` observations before the rule engine sees it."""
    hosts = list(dict.fromkeys([target] + [s for s in subdomains if s != target]))

    # 1. DNS resolution (per host); resolved IPs become evidenced assets.
    for host in hosts:
        report = real_probes.dns_probe(host)
        _persist_probe(db, scan, "real_dns", report)
        for obs in report["observations"]:
            if obs["kind"] == "dns_record":
                add_asset(db, scan.project_id, "ip", obs["data"]["ip"],
                          {"domain": obs["data"]["host"], "source": "real_dns"})
    db.commit()

    # 2. TCP connect scan over each host.
    for host in hosts:
        report = real_probes.tcp_probe(host)
        _persist_probe(db, scan, "real_tcp", report)
        for obs in report["observations"]:
            if obs["kind"] == "tcp_open":
                add_asset(db, scan.project_id, "port", f"{obs['data']['port']}/tcp",
                          {"state": "open", "source": "real_tcp"})
    db.commit()

    # 3. HTTP(S) fingerprint probes (headers, title, body fingerprint).
    for host in hosts:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            report = real_probes.http_probe(url)
            _persist_probe(db, scan, "real_http", report)
    db.commit()

    # 4. Nuclei engine output (real mode) -> observations, verbatim.
    for record in (nuclei_res.get("vulnerabilities") or []):
        db.add(Observation(
            scan_id=scan.id,
            tool_name="nuclei",
            kind="nuclei_finding",
            subject=record.get("matched_at") or record.get("proof_of_concept") or scan.target,
            data_json={
                "title": record.get("title"),
                "severity": record.get("severity"),
                "cve": record.get("cve"),
                "cvss": record.get("cvss"),
                "owasp": record.get("owasp"),
                "cwe": record.get("cwe"),
                "description": record.get("description"),
                "remediation": record.get("remediation"),
                "matched_at": record.get("matched_at"),
                "template_id": record.get("template_id"),
            },
            raw_output=(record.get("proof_of_concept") or json.dumps(record, default=str)),
        ))
    db.commit()


def _persist_probe(db, scan: Scan, tool_name: str, report: dict):
    """Persist probe observations verbatim plus a ToolResult row for the tool."""
    for obs in (report.get("observations") or []):
        db.add(Observation(
            scan_id=scan.id,
            tool_name=tool_name,
            kind=obs["kind"],
            subject=obs["subject"],
            data_json=obs.get("data") or {},
            raw_output=obs.get("raw") or "",
        ))
    save_tool_result(db, scan.id, tool_name,
                     {"status": report.get("status", "success"), "log": report.get("log", "")},
                     simulated=False)


def _scan_observations(db, scan_id: int) -> list:
    rows = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.id.asc()).all()
    return [
        {"id": o.id, "tool": o.tool_name, "kind": o.kind, "subject": o.subject,
         "data": o.data_json or {}, "raw": o.raw_output or ""}
        for o in rows
    ]


def _evidence_text(candidate: dict) -> str:
    obs_ids = candidate.get("observation_ids") or []
    ids = ", ".join(f"#{i}" for i in obs_ids)
    proof = (candidate.get("proof") or "").strip()
    base = (
        f"Derived by rule {candidate['rule_id']} from persisted observation(s) {ids}; "
        "traceable via tool -> scan -> authorized target."
    )
    if proof:
        return base + " Evidence: " + proof
    return base


def _persisted_finding(scan: Scan, candidate: dict, fallback_target: str) -> Vulnerability:
    now = datetime.datetime.utcnow()
    return Vulnerability(
        scan_id=scan.id,
        title=candidate["title"],
        severity=candidate["severity"],
        description=candidate["description"],
        remediation=candidate.get("remediation"),
        cve=candidate.get("cve"),
        cvss=candidate.get("cvss"),
        owasp=candidate.get("owasp"),
        cwe=candidate.get("cwe"),
        target=candidate.get("target") or fallback_target,
        proof_of_concept=candidate.get("proof"),
        rule_id=candidate.get("rule_id"),
        dedup_key=candidate.get("dedup_key"),
        confidence=candidate.get("confidence"),
        state="NEW",
        evidence=_evidence_text(candidate),
        evidence_observation_ids=candidate.get("observation_ids") or [],
        created_at=now,
    )


def _finding_dict(f: Vulnerability) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "state": f.state or "NEW",
        "rule_id": f.rule_id,
        "confidence": f.confidence,
        "cve": f.cve,
        "cvss": f.cvss,
        "owasp": f.owasp,
        "cwe": f.cwe,
        "target": f.target,
        "evidence": f.evidence,
        "evidence_observation_ids": f.evidence_observation_ids or [],
        "remediation": f.remediation,
    }


def save_tool_result(db, scan_id: int, tool_name: str, result: dict, simulated: bool = False):
    raw_output = result.get("log", "")
    if simulated:
        raw_output = (
            "[SIMULATED] Tool output is synthetic (SIMULATION_MODE). "
            "This is NOT the result of a real security assessment.\n" + raw_output
        )

    status_map = {
        "success": "Completed",
        STATE_NOT_INSTALLED: STATE_NOT_INSTALLED,
        STATE_TIMEOUT: STATE_TIMEOUT,
        STATE_PARSE_FAILED: STATE_PARSE_FAILED,
        STATE_EXECUTION_FAILED: "Failed",
    }
    status = status_map.get(result.get("status"), "Failed")
    tool_result = ToolResult(
        scan_id=scan_id,
        tool_name=tool_name,
        status=status,
        raw_output=raw_output
    )
    db.add(tool_result)
    db.commit()


def add_asset(db, project_id: int, asset_type: str, value: str, metadata: dict):
    # Avoid inserting duplicates into project assets
    existing = db.query(Asset).filter(Asset.project_id == project_id, Asset.type == asset_type, Asset.value == value).first()
    if not existing:
        asset = Asset(project_id=project_id, type=asset_type, value=value, metadata_json=metadata)
        db.add(asset)


def generate_markdown_report_content(scan, findings, observations, simulation=False) -> str:
    timestamp = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    mode = "SIMULATION - no findings produced" if simulation else "REAL - evidence-backed findings"
    buf = list()
    buf.append("# Security Assessment Report")
    buf.append("")
    buf.append(f"**Target**: `{scan.target}`")
    buf.append(f"**Date**: {timestamp}")
    buf.append(f"**Security Score**: `{scan.security_score}/100`")
    buf.append(f"**Status**: `COMPLETED`")
    buf.append(f"**Mode**: `{mode}`")
    buf.append("")
    buf.append("---")
    buf.append("")
    buf.append("## Executive Summary")
    buf.append("")
    buf.append(
        "This report summarizes the security assessment conducted on target network "
        f"`{scan.target}`. Findings are derived exclusively from persisted observations; "
        "a finding with no evidence is never reported."
    )
    buf.append("")
    buf.append(f"We identified **{len(findings)} finding(s)**. Review the list below for direct mitigation techniques.")
    buf.append("")
    buf.append("---")
    buf.append("")
    buf.append("## Findings")
    buf.append("")

    if not findings:
        buf.append("No evidence-backed findings were produced for this scan.")
        buf.append("")
    else:
        for idx, f in enumerate(findings, 1):
            buf.append(f"### {idx}. {f.title}")
            buf.append("")
            buf.append(f"* **Severity**: `{f.severity}`")
            buf.append(f"* **State**: `{f.state or 'NEW'}`")
            buf.append(f"* **Rule**: `{f.rule_id or 'legacy'}`")
            buf.append(f"* **Confidence**: `{f.confidence or 'n/a'}`")
            buf.append(f"* **CVSS Score**: `{f.cvss or 'N/A'}`")
            buf.append(f"* **CVE Reference**: `{f.cve or 'N/A'}`")
            buf.append(f"* **OWASP Mapping**: `{f.owasp or 'N/A'}`")
            buf.append(f"* **CWE**: `{f.cwe or 'N/A'}`")
            buf.append("")
            buf.append("#### Description")
            buf.append(f.description)
            buf.append("")
            buf.append("#### Remediation")
            buf.append(f.remediation or "No remediation provided.")
            buf.append("")
            if f.proof_of_concept:
                buf.append("#### Evidence (verbatim)")
                buf.append("```text")
                buf.append(f.proof_of_concept)
                buf.append("```")
                buf.append("")
            if f.evidence:
                buf.append("#### Evidence trail")
                buf.append(f.evidence)
                buf.append("")
            buf.append("---")
            buf.append("")

    if observations:
        buf.append("## Evidence & Methodology (persisted observations)")
        buf.append("")
        for o in observations:
            buf.append(f"* `{o['kind']}` by {o['tool']} on {o['subject']}")
        buf.append("")
    return "\n".join(buf)


def generate_html_report_content(scan, markdown_content) -> str:
    # A simple, premium styled HTML fallback for rendering
    html_body = markdown_content.replace('\n', '<br>')
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CyberAgent Security Report - {scan.target}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; padding: 40px; line-height: 1.6; }}
            h1, h2, h3 {{ color: #22c55e; }}
            pre {{ background: #020617; border: 1px solid #1e293b; padding: 15px; border-radius: 8px; overflow-x: auto; color: #a7f3d0; }}
            code {{ font-family: Consolas, monospace; background: #1e293b; padding: 2px 6px; border-radius: 4px; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #ef4444; }}
        </style>
    </head>
    <body>
        <h1>CyberAgent Security Assessment Report</h1>
        <p><strong>Target:</strong> {scan.target}</p>
        <p><strong>Score:</strong> {scan.security_score}/100</p>
        <hr>
        <div>
            {html_body}
        </div>
    </body>
    </html>
    """