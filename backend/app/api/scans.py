from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import asyncio
import json
from database.connection import get_db
from database.models import Scan, Project, Vulnerability, ToolResult, Asset
from database.schemas import ScanRequest, normalize_target
from app.core.auth import (
    get_current_user,
    get_or_create_user_project,
    get_owned_scan,
    is_target_in_scope,
)
from app.workers.tasks import trigger_background_scan
from app.config import settings
from database.models import User

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/trigger")
def trigger_scan(payload: ScanRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Triggers an authenticated scan for a target inside the user's scope."""
    project = get_or_create_user_project(db, user)
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()

    if not is_target_in_scope(payload.target, project, assets):
        raise HTTPException(
            status_code=403,
            detail=(
                "Target is outside the authorized scope for this project. "
                "Add it to the project scope first (see /scans/scope)."
            ),
        )

    new_scan = Scan(
        project_id=project.id,
        target=payload.target,
        status="Pending",
        logs="[System] Initializing Scan Request...\n"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Launch scanning asynchronously. The simulation flag is driven by the
    # SIMULATION_MODE configuration boundary, never hardcoded here.
    simulation = settings.simulation_mode
    trigger_background_scan(new_scan.id, simulation=simulation)

    return {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "status": new_scan.status,
        "simulation": simulation,
        "created_at": new_scan.created_at
    }


@router.get("/list")
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves scan records belonging to the authenticated user only."""
    projects = db.query(Project).filter(Project.user_id == user.id).all()
    project_ids = [p.id for p in projects]
    if not project_ids:
        return []
    scans = (
        db.query(Scan)
        .filter(Scan.project_id.in_(project_ids))
        .order_by(Scan.created_at.desc())
        .all()
    )
    return [
        {
            "id": s.id,
            "target": s.target,
            "status": s.status,
            "security_score": s.security_score,
            "created_at": s.created_at,
            "completed_at": s.completed_at
        }
        for s in scans
    ]


@router.get("/scope")
def get_scope(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The authenticated user's authorized scan scope for their project."""
    project = get_or_create_user_project(db, user)
    return {
        "project_id": project.id,
        "project_name": project.name,
        "scope": project.scope_json or [],
    }


@router.post("/scope")
def add_scope_entry(payload: ScanRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Add one authorized target (domain / IPv4 / CIDR) to the user's scope."""
    project = get_or_create_user_project(db, user)
    scope = list(project.scope_json or [])
    target = payload.target  # already normalized by ScanRequest
    if target not in scope:
        scope.append(target)
        project.scope_json = scope
        db.commit()
    return {"project_id": project.id, "scope": scope, "added": target}


@router.get("/{scan_id}/details")
def get_scan_details(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves metadata and findings for a scan owned by the user."""
    scan = get_owned_scan(db, user, scan_id)

    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    tool_results = db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()

    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "security_score": scan.security_score,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
        "logs": scan.logs,
        "vulnerabilities": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "description": v.description,
                "remediation": v.remediation,
                "cve": v.cve,
                "cvss": v.cvss,
                "owasp": v.owasp,
                "mitre": v.mitre,
                "cwe": v.cwe,
                "rule_id": v.rule_id,
                "state": v.state or "NEW",
                "confidence": v.confidence,
                "target": v.target,
                "proof_of_concept": v.proof_of_concept,
                "evidence": v.evidence,
                "evidence_observation_ids": v.evidence_observation_ids or [],
                "resolved_at": v.resolved_at,
            }
            for v in vulnerabilities
        ],
        "tools": [{"name": tr.tool_name, "status": tr.status} for tr in tool_results]
    }


@router.get("/summary")
def scan_summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Aggregated, real metrics for the dashboard, across the user's own scans.

    Every number is derived from persisted rows owned by the authenticated
    user; there are no hardcoded or sample figures here.
    """
    project_ids = [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
    scans = []
    open_findings = []
    open_ports = []

    if project_ids:
        scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.asc()).all()
        scan_ids = [s.id for s in scans]

        open_states = {"NEW", "CONFIRMED"}
        open_findings = [
            f for f in db.query(Vulnerability).filter(Vulnerability.scan_id.in_(scan_ids)).all()
            if (f.state or "NEW").upper() in open_states
        ]

        ports = db.query(Asset).filter(
            Asset.project_id.in_(project_ids), Asset.type == "port"
        ).all()
        open_ports = [
            a for a in ports
            if (a.metadata_json or {}).get("state") == "open" or a.value.endswith("/tcp")
        ]

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in open_findings:
        sev = (f.severity or "").capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1

    status = {"Pending": 0, "Running": 0, "Completed": 0, "Failed": 0}
    for s in scans:
        status[s.status] = status.get(s.status, 0) + 1

    return {
        "total_findings": len(open_findings),
        "open_findings": len(open_findings),
        "severity_distribution": severity_counts,
        "open_ports_total": len({p.value for p in open_ports}),
        "open_ports": sorted({p.value for p in open_ports}),
        "scans_total": len(scans),
        "scans_by_status": status,
        "score_history": [
            {"target": s.target, "score": s.security_score, "created_at": s.created_at, "id": s.id}
            for s in scans
        ],
    }


@router.get("/{scan_id}/stream")
async def stream_scan_logs(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Server Sent Events (SSE) logs streaming endpoint for realtime UI tracking.

    Communicated via a native EventSource, which cannot attach Authorization
    headers, so the session token is also accepted through the ``token``
    query parameter when present.
    """
    get_owned_scan(db, user, scan_id)

    async def log_generator():
        last_length = 0
        while True:
            # Re-fetch scan status inside generator loop
            local_db = next(get_db())
            try:
                scan = local_db.query(Scan).filter(Scan.id == scan_id).first()
                if not scan:
                    yield f"data: {json.dumps({'error': 'Scan ID not found'})}\n\n"
                    break

                current_logs = scan.logs or ""
                # Stream only new log content
                if len(current_logs) > last_length:
                    new_chunk = current_logs[last_length:]
                    last_length = len(current_logs)
                    yield f"data: {json.dumps({'logs': new_chunk, 'status': scan.status, 'score': scan.security_score})}\n\n"

                if scan.status in ["Completed", "Failed"]:
                    # Send a final resolution event and end stream
                    yield f"data: {json.dumps({'status': scan.status, 'done': True, 'score': scan.security_score})}\n\n"
                    break

                await asyncio.sleep(0.5)
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
            finally:
                local_db.close()

    return StreamingResponse(log_generator(), media_type="text/event-stream")