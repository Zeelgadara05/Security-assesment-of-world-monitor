from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import asyncio
import json
import time
from database.connection import get_db
from database.models import Scan, Project, Vulnerability, ToolResult
from database.schemas import ScanRequest
from app.workers.tasks import trigger_background_scan
from app.config import settings

router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("/trigger")
def trigger_scan(payload: ScanRequest, db: Session = Depends(get_db)):
    """Triggers an autonomous security scan for a target domain or IP."""
    # Fetch default sandbox project
    project = db.query(Project).filter(Project.name == "Default Sandbox").first()
    if not project:
        raise HTTPException(status_code=404, detail="Default Project Sandbox not initialized.")

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
def list_scans(db: Session = Depends(get_db)):
    """Retrieves all security scan records from the database."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
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

@router.get("/{scan_id}/details")
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """Retrieves metadata and findings for a specific scan ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

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
                "target": v.target,
                "proof_of_concept": v.proof_of_concept
            }
            for v in vulnerabilities
        ],
        "tools": [{"name": tr.tool_name, "status": tr.status} for tr in tool_results]
    }

@router.get("/{scan_id}/stream")
async def stream_scan_logs(scan_id: int, db: Session = Depends(get_db)):
    """Server Sent Events (SSE) logs streaming endpoint for realtime UI tracking."""
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
