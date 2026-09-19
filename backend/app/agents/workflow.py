import time
import random
import datetime
import logging
from database.connection import SessionLocal
from database.models import Scan, ToolResult, Vulnerability, Asset, Report
from app.tools.scanner_tools import (
    run_subfinder, run_assetfinder, run_dnsx, run_nmap,
    run_httpx, run_nuclei, run_gau, run_whatweb,
    STATE_NOT_INSTALLED, STATE_TIMEOUT, STATE_PARSE_FAILED, STATE_EXECUTION_FAILED,
)

logger = logging.getLogger("cyberagent.workflow")

def orchestrate_scan(scan_id: int, simulation: bool = True):
    """
    Simulates or executes the complete multi-agent workflow:
    Planner -> Recon -> Scanning -> AI Analysis -> Report Generator
    """
    db = SessionLocal()
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
                "[SIMULATION] Scan running in SIMULATION_MODE: all generated output is "
                "synthetic and must NOT be treated as a real security assessment.\n"
            )
            db.commit()

        target = scan.target
        time.sleep(1)

        # ----------------------------------------------------
        # 1. PLANNER AGENT
        # ----------------------------------------------------
        scan.logs += f"[Planner Agent] Target validated: {target}\n"
        scan.logs += f"[Planner Agent] Scheduling Recon tools: subfinder, assetfinder, dnsx\n"
        scan.logs += f"[Planner Agent] Scheduling Port tools: nmap\n"
        scan.logs += f"[Planner Agent] Scheduling Web / Vuln tools: httpx, WhatWeb, gau, nuclei\n"
        db.commit()
        time.sleep(1.5)

        # ----------------------------------------------------
        # 2. RECON AGENT
        # ----------------------------------------------------
        scan.logs += f"[Recon Agent] Starting passive subdomain gathering via subfinder...\n"
        db.commit()
        subfinder_res = run_subfinder(target, simulation)
        save_tool_result(db, scan.id, "subfinder", subfinder_res, simulated=simulation)

        scan.logs += f"[Recon Agent] Running assetfinder discovery...\n"
        db.commit()
        asset_res = run_assetfinder(target, simulation)
        save_tool_result(db, scan.id, "assetfinder", asset_res, simulated=simulation)

        # Extract unique subdomains
        subdomains = list(set((subfinder_res.get("subdomains", [])) + (asset_res.get("subdomains", []))))
        if not subdomains:
            subdomains = [target]

        scan.logs += f"[Recon Agent] Total unique subdomains identified: {len(subdomains)}\n"
        scan.logs += f"[Recon Agent] Checking DNS resolution using dnsx...\n"
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
        scan.logs += f"[Scanning Agent] Initializing port and service scanning with nmap...\n"
        db.commit()
        nmap_res = run_nmap(target, simulation)
        save_tool_result(db, scan.id, "nmap", nmap_res, simulated=simulation)

        # Add open ports as assets
        for p in nmap_res.get("ports", []):
            if p["state"] == "open":
                add_asset(db, scan.project_id, "port", f"{p['port']}/{p['protocol']}", {
                    "service": p["service"], "product": p["product"], "version": p["version"]
                })
        db.commit()

        scan.logs += f"[Scanning Agent] Probing live web servers with httpx...\n"
        db.commit()
        httpx_res = run_httpx(target, simulation)
        save_tool_result(db, scan.id, "httpx", httpx_res, simulated=simulation)

        scan.logs += f"[Scanning Agent] Harvesting web routes using gau...\n"
        db.commit()
        gau_res = run_gau(target, simulation)
        save_tool_result(db, scan.id, "gau", gau_res, simulated=simulation)

        scan.logs += f"[Scanning Agent] Profiling server technologies via WhatWeb...\n"
        db.commit()
        whatweb_res = run_whatweb(target, simulation)
        save_tool_result(db, scan.id, "whatweb", whatweb_res, simulated=simulation)

        for tech in whatweb_res.get("techs", []):
            add_asset(db, scan.project_id, "tech", tech, {})
        db.commit()

        scan.logs += f"[Scanning Agent] Starting Nuclei active vulnerability tests...\n"
        db.commit()
        nuclei_res = run_nuclei(target, simulation)
        save_tool_result(db, scan.id, "nuclei", nuclei_res, simulated=simulation)

        # ----------------------------------------------------
        # 4. AI ANALYSIS AGENT
        # ----------------------------------------------------
        scan.logs += f"[AI Analysis Agent] Parsing scan logs and mapping identified issues to frameworks...\n"
        db.commit()
        time.sleep(2)

        vulns_to_save = nuclei_res.get("vulnerabilities", [])
        score = 100
        for v in vulns_to_save:
            # Add vulnerability record
            vuln_obj = Vulnerability(
                scan_id=scan.id,
                title=v["title"],
                severity=v["severity"],
                description=v["description"],
                remediation=v["remediation"],
                cve=v.get("cve"),
                cvss=v.get("cvss"),
                owasp=v.get("owasp"),
                mitre=v.get("mitre"),
                target=v.get("target") or target,
                proof_of_concept=v.get("proof_of_concept")
            )
            db.add(vuln_obj)

            # Recalculate security score dynamically based on severity
            if v["severity"] == "Critical":
                score -= 25
            elif v["severity"] == "High":
                score -= 15
            elif v["severity"] == "Medium":
                score -= 8
            elif v["severity"] == "Low":
                score -= 3

        scan.security_score = max(score, 10)
        scan.logs += f"[AI Analysis Agent] Evaluation complete. Security score calculated: {scan.security_score}/100\n"
        db.commit()

        # ----------------------------------------------------
        # 5. REPORT GENERATOR
        # ----------------------------------------------------
        scan.logs += f"[Reporting Agent] Generating Executive Report (Markdown, JSON, HTML, PDF)...\n"
        db.commit()
        time.sleep(1.5)

        markdown_report = generate_markdown_report_content(scan, vulns_to_save)
        html_report = generate_html_report_content(scan, markdown_report)
        
        report_obj = Report(
            scan_id=scan.id,
            title=f"Security Assessment Report for {target}",
            markdown_content=markdown_report,
            json_content={
                "target": target,
                "security_score": scan.security_score,
                "vulnerabilities": vulns_to_save,
                "subdomains": subdomains,
                "open_ports": nmap_res.get("ports", [])
            },
            html_content=html_report,
            pdf_content=markdown_report.encode("utf-8") # Storing markdown source as pdf mock bytes
        )
        db.add(report_obj)

        scan.status = "Completed"
        scan.completed_at = datetime.datetime.utcnow()
        scan.logs += f"[Reporting Agent] Completed. Report artifacts ready for download.\n"
        if simulation:
            scan.logs += "[SIMULATION] This scan ran in simulation mode; findings are synthetic.\n"
        db.commit()

    except Exception as e:
        logger.error(f"Error in orchestrating scan: {e}")
        if scan:
            scan.status = "Failed"
            scan.completed_at = datetime.datetime.utcnow()
            scan.logs += f"[System Error] Scan failed due to: {e}\n"
            db.commit()
    finally:
        db.close()

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

def generate_markdown_report_content(scan, vulnerabilities) -> str:
    timestamp = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    report = f"""# Security Assessment Report

**Target**: `{scan.target}`  
**Date**: {timestamp}  
**Security Score**: `{scan.security_score}/100`  
**Status**: `COMPLETED`

---

## Executive Summary
This report summarizes the security assessment conducted on target network `{scan.target}`. Using an autonomous AI planning agent workflow, information gathering (subdomain discovery, port mapping) and active vulnerability analysis were executed. 

We identified **{len(vulnerabilities)} vulnerabilities** of varying severities. Review the list below for direct mitigation techniques.

---

## Vulnerabilities Found

"""
    for idx, v in enumerate(vulnerabilities, 1):
        report += f"""### {idx}. {v['title']}
* **Severity**: `{v['severity']}`  
* **CVSS Score**: `{v['cvss'] or 'N/A'}`  
* **CVE Reference**: `{v['cve'] or 'N/A'}`  
* **OWASP Mapping**: `{v['owasp'] or 'N/A'}`  
* **MITRE ATT&CK Mapping**: `{v['mitre'] or 'N/A'}`  

#### Description
{v['description']}

#### Remediation
{v['remediation']}

#### Proof of Concept
```http
{v['proof_of_concept']}
```

---
"""
    return report

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
