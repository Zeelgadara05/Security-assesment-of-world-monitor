from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import asyncio
import json
import datetime
from database.connection import get_db
from database.models import (
    Scan, Project, Vulnerability, ToolResult, Asset, Observation, AssessmentTest,
    FindingEvidence, ToolReadiness, ToolExecution, ScanStage, MLInference,
)
from app.orchestration import events as phase7_events
from app.orchestration import state as phase7_state
from database.schemas import ScanRequest
from app.core.auth import (
    get_current_user,
    get_or_create_user_project,
    get_owned_scan,
    is_target_in_scope,
)
from app.workers.tasks import trigger_background_scan, cancel_scan
from app.agents import lifecycle
from app.config import settings
from database.models import User

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanCreate(ScanRequest):
    """POST /scans payload: authorized target + optional job configuration.

    ``tools`` toggles which scanners take part (default: all available),
    ``severity`` applies an analysis threshold (default: report everything),
    ``profile`` is an operator hint persisted for the record.
    Phase 5/6 config keys are passed through to the assessment engine:
    ``active_testing`` (opt-in mutating tests, default False),
    ``assessment_engine`` (default True), plus optional evidence-carrying
    inputs (auth identities, SSRF validation callback, JWT case data).
    """
    tools: dict[str, bool] | None = None
    severity: str | None = None
    profile: str | None = None
    # Phase 5 assessment engine options.
    active_testing: bool | None = None
    assessment_engine: bool | None = None
    auth_identities: dict | list | None = None
    ssrf_validation_url: str | None = None
    ssrf_token: str | None = None
    jwt_tokens: list[str] | None = None
    jwt_alg_none_accepted: bool | None = None
    installed_tools: list[str] | None = None
    tools_missing: list[str] | None = None


def _create_and_enqueue(db: Session, user: User, target: str, config: dict | None = None) -> Scan:
    """Shared creation path: scope check -> Scan(row) -> background enqueue."""
    project = get_or_create_user_project(db, user)
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()

    if not is_target_in_scope(target, project, assets):
        raise HTTPException(
            status_code=403,
            detail=(
                "Target is outside the authorized scope for this project. "
                "Add it to the project scope first (see /scans/scope)."
            ),
        )

    new_scan = Scan(
        project_id=project.id,
        target=target,
        status="Pending",
        stage=lifecycle.QUEUED,
        scan_config=dict(config or {}),
        logs="[System] Initializing Scan Request...\n"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    new_scan.state = "created"  # Phase 7 state machine entry state
    db.commit()

    # Launch scanning asynchronously. The simulation flag is driven by the
    # SIMULATION_MODE configuration boundary, never hardcoded here.
    simulation = settings.simulation_mode
    new_scan.scan_config = dict(new_scan.scan_config or {})
    new_scan.scan_config["simulation"] = simulation
    db.commit()
    db.refresh(new_scan)

    # Seed the plan (total_tasks/planned list) at enqueue time so the plan is
    # visible immediately, before the background worker thread has scheduled.
    from app.agents.workflow import _seed_progress
    _seed_progress(db, new_scan, new_scan.scan_config, simulation)

    trigger_background_scan(new_scan.id, simulation=simulation, config=new_scan.scan_config)

    # Phase 7: record when the scan entered the worker queue so the pipeline
    # can measure how long it sat in queue before a worker picked it up.
    new_scan.queue_started_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(new_scan)

    return new_scan


@router.post("")
def create_scan(payload: ScanCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """POST /scans: create and enqueue a scan with optional configuration."""
    config = {}
    if payload.tools is not None:
        config["tools"] = {t: bool(payload.tools.get(t, True)) for t in
                           ("subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei")}
    if payload.severity:
        config["severity"] = payload.severity
    if payload.profile:
        config["profile"] = payload.profile
    # Phase 5/6 config passthrough (only explicitly provided keys are set).
    if payload.active_testing is not None:
        config["active_testing"] = bool(payload.active_testing)
    if payload.assessment_engine is not None:
        config["assessment_engine"] = bool(payload.assessment_engine)
    if payload.auth_identities is not None:
        config["auth_identities"] = payload.auth_identities
    if payload.ssrf_validation_url:
        config["ssrf_validation_url"] = payload.ssrf_validation_url
    if payload.ssrf_token:
        config["ssrf_token"] = payload.ssrf_token
    if payload.jwt_tokens is not None:
        config["jwt_tokens"] = list(payload.jwt_tokens)
    if payload.jwt_alg_none_accepted is not None:
        config["jwt_alg_none_accepted"] = bool(payload.jwt_alg_none_accepted)
    if payload.installed_tools is not None:
        config["installed_tools"] = list(payload.installed_tools)
    if payload.tools_missing is not None:
        config["tools_missing"] = list(payload.tools_missing)
    if not config:
        config = None

    new_scan = _create_and_enqueue(db, user, payload.target, config)
    return {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "status": new_scan.status,
        "stage": new_scan.stage,
        "simulation": settings.simulation_mode,
        "coverage": new_scan.coverage,
        "created_at": new_scan.created_at,
    }


@router.post("/trigger")
def trigger_scan(payload: ScanRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Backward-compatible trigger: enqueues a scan with default configuration."""
    new_scan = _create_and_enqueue(db, user, payload.target, None)
    return {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "status": new_scan.status,
        "simulation": settings.simulation_mode,
        "created_at": new_scan.created_at,
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


@router.get("/coverage")
def coverage_overview(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Cross-scan coverage snapshot for the authenticated user (real metrics)."""
    project_ids = [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
    scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).all() if project_ids else []
    return {
        "scans": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "stage": s.stage,
                "coverage": s.coverage,
                "progress": s.progress or {},
                "security_score": s.security_score,
            }
            for s in scans
        ],
        "average_coverage": None if not scans else _avg([s.coverage for s in scans if s.coverage is not None], None),
    }


def _avg(values: list, default=None):
    return default if not values else round(sum(values) / len(values), 2)


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


def _assessment_coverage(db: Session, scan_id: int) -> dict | None:
    """Phase 5 coverage summary persisted as the ``native_assessment`` tool result."""
    row = (
        db.query(ToolResult)
        .filter(ToolResult.scan_id == scan_id, ToolResult.tool_name == "native_assessment")
        .first()
    )
    if not row or not row.raw_output:
        return None
    try:
        return json.loads(row.raw_output)
    except (ValueError, TypeError):
        return None


def _assessment_tests(db: Session, scan_id: int) -> list[dict]:
    rows = (
        db.query(AssessmentTest)
        .filter(AssessmentTest.scan_id == scan_id)
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


def _finding_evidence(db: Session, finding_id: int) -> list[dict]:
    rows = (
        db.query(FindingEvidence)
        .filter(FindingEvidence.finding_id == finding_id)
        .order_by(FindingEvidence.id.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "observation_id": e.observation_id,
            "evidence_type": e.evidence_type,
            "expected": e.expected,
            "actual": e.actual,
            "security_boundary": e.security_boundary,
            "redaction_status": e.redaction_status,
            # Phase 6 evidence integrity metadata.
            "request_hash": e.request_hash,
            "response_hash": e.response_hash,
            "original_size": e.original_size,
            "captured_size": e.captured_size,
            "truncated": e.truncated,
        }
        for e in rows
    ]


def _vulnerability_dict(db: Session, v: Vulnerability) -> dict:
    """Serialize a finding including Phase 5 assessment fields and evidence."""
    from app.assess import finding_lifecycle as lifecycle

    return {
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
        # Phase 5 assessment metadata (null for Phase 3 findings).
        "category": v.category,
        "endpoint": v.endpoint,
        "http_method": v.http_method,
        "source_test": v.source_test,
        "source_tool": v.source_tool,
        "validation_reason": v.validation_reason,
        "impact": v.impact,
        "evidence_records": _finding_evidence(db, v.id),
        # Phase 6 lifecycle + reporting fields.
        "status": v.status or lifecycle.STATUS_CONFIRMED,
        "affected_component": v.affected_component,
        "parameter": v.parameter,
        "cvss_version": v.cvss_version,
        "cvss_vector": v.cvss_vector,
        "cvss_score": v.cvss_score,
        "business_impact": v.business_impact,
        "technical_impact": v.technical_impact,
        "impact_details": v.impact_details,
        "remediation_details": v.remediation_details,
        "fingerprint": v.fingerprint or v.dedup_key,
        "first_seen": v.first_seen,
        "last_seen": v.last_seen,
    }


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Full scan detail: lifecycle stage, progress, coverage, findings, tools."""
    scan = get_owned_scan(db, user, scan_id)
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    tool_results = db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()
    observations = db.query(Observation).filter(Observation.scan_id == scan_id).count()

    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "stage": scan.stage or lifecycle.QUEUED,
        "security_score": scan.security_score,
        "coverage": scan.coverage,
        "progress": scan.progress or {},
        "scan_config": scan.scan_config or {},
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "cancelled_at": scan.cancelled_at,
        "error": scan.error,
        "logs": scan.logs,
        "simulation": bool((scan.scan_config or {}).get("simulation", settings.simulation_mode)),
        "vulnerabilities": [_vulnerability_dict(db, v) for v in vulnerabilities],
        "observations_count": observations,
        "assessment": {
            "coverage": _assessment_coverage(db, scan_id),
            "tests": _assessment_tests(db, scan_id),
        },
        "tools": [
            {"name": tr.tool_name, "status": tr.status, "raw_output": tr.raw_output}
            for tr in tool_results
        ],
    }


@router.get("/{scan_id}/observations")
def get_scan_observations(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Persisted evidence observations for a scan owned by the user."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.id.asc()).all()
    return [
        {"id": o.id, "tool": o.tool_name, "kind": o.kind, "subject": o.subject,
         "data": o.data_json or {}, "raw": o.raw_output or "", "created_at": o.created_at,
         "observation_type": o.observation_type or o.kind, "source": o.source,
         "status": o.status, "fingerprint": o.fingerprint,
         "request": o.request_json, "response": o.response_json}
        for o in rows
    ]


@router.get("/{scan_id}/findings")
def get_scan_findings(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Persisted findings (evidence-backed) for a scan owned by the user."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).order_by(Vulnerability.id.asc()).all()
    return [_vulnerability_dict(db, v) for v in rows]


@router.get("/{scan_id}/coverage")
def get_scan_coverage(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Coverage for one scan: planned vs completed tasks, honest percentages."""
    scan = get_owned_scan(db, user, scan_id)
    progress = scan.progress or {}
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "coverage": scan.coverage,
        "completed_tasks": progress.get("completed_tasks", 0),
        "failed_tasks": progress.get("failed_tasks", 0),
        "total_tasks": progress.get("total_tasks", 0),
        "completed_tools": progress.get("completed_tools", 0),
        "total_tools": progress.get("total_tools", 0),
        "percent": progress.get("percent", 0),
        "planned_tasks": progress.get("planned_tasks", []),
        "security_score": scan.security_score,
        "assessment": _assessment_coverage(db, scan.id),
    }


@router.post("/{scan_id}/cancel")
def cancel_scan_job(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Request cancellation of a queued/running scan owned by the user."""
    scan = get_owned_scan(db, user, scan_id)
    if scan.stage and lifecycle.is_terminal(scan.stage):
        return {"scan_id": scan.id, "status": scan.status, "message": "Scan already in a terminal state.", "stage": scan.stage}

    requested = cancel_scan(scan_id)
    if not requested:
        # Never enqueued (e.g. backfilled row): mark cancelled immediately.
        scan.stage = lifecycle.CANCELLED
        scan.status = "Cancelled"
        scan.cancelled_at = datetime.datetime.utcnow()
        scan.updated_at = datetime.datetime.utcnow()
        scan.logs += "[Worker] Scan cancelled by user; remaining stages abandoned.\n"
        db.commit()
    else:
        scan.cancel_requested = True
        scan.updated_at = datetime.datetime.utcnow()
        db.commit()
    return {"scan_id": scan.id, "status": "Cancelled", "stage": lifecycle.CANCELLED, "message": "Cancellation requested."}


@router.get("/{scan_id}/events")
async def stream_scan_events(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """SSE endpoint streaming real, persisted scan lifecycle events.

    Events are derived from the persisted ``Scan`` row + child rows and only
    emitted when they actually change: stage transitions, tool completions,
    progress/coverage updates, findings, terminal resolution.  Never invented.
    """
    get_owned_scan(db, user, scan_id)

    async def event_generator():
        last = {"stage": None, "tools": set(), "findings": set(), "progress": None,
                "completed_at": None}
        while True:
            local_db = next(get_db())
            try:
                scan = local_db.query(Scan).filter(Scan.id == scan_id).first()
                if not scan:
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Scan ID not found'})}\n\n"
                    break

                tools = local_db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()
                findings = local_db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

                if (scan.stage or lifecycle.QUEUED) != last["stage"]:
                    last["stage"] = scan.stage or lifecycle.QUEUED
                    yield f"data: {json.dumps({'type': 'stage', 'stage': last['stage'], 'status': scan.status, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

                tool_ids = {tr.id for tr in tools}
                for tr in tools:
                    if tr.id not in last["tools"]:
                        last["tools"].add(tr.id)
                        yield f"data: {json.dumps({'type': 'tool', 'tool': tr.tool_name, 'status': tr.status, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

                finding_ids = {f.id for f in findings}
                for f in findings:
                    if f.id not in last["findings"]:
                        last["findings"].add(f.id)
                        yield f"data: {json.dumps({'type': 'finding', 'id': f.id, 'title': f.title, 'severity': f.severity, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

                progress = (scan.progress or {}).get("percent")
                if progress != last["progress"]:
                    last["progress"] = progress
                    yield f"data: {json.dumps({'type': 'progress', 'percent': progress, 'coverage': scan.coverage, 'security_score': scan.security_score, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

                if scan.completed_at and scan.completed_at != last["completed_at"]:
                    last["completed_at"] = scan.completed_at
                    yield f"data: {json.dumps({'type': 'done', 'status': scan.status, 'stage': scan.stage or lifecycle.QUEUED, 'coverage': scan.coverage, 'security_score': scan.security_score})}\n\n"
                    break

                if lifecycle.is_terminal(scan.stage or ""):
                    yield f"data: {json.dumps({'type': 'done', 'status': scan.status, 'stage': scan.stage, 'coverage': scan.coverage, 'security_score': scan.security_score})}\n\n"
                    break

                await asyncio.sleep(0.5)
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
                break
            finally:
                local_db.close()

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{scan_id}/assessment")
def get_scan_assessment(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Phase 6 assessment summary: coverage, aggregates, completeness, snapshot.

    Describes the assessment performed (coverage %, executed/failed/skipped
    tests, lifecycle aggregates), never a security verdict on the target.
    """
    scan = get_owned_scan(db, user, scan_id)
    from app.assess import summary as assess_summary

    coverage = _assessment_coverage(db, scan_id)
    return assess_summary.summary_from_scan(db, scan, coverage)


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: int,
    format: str = "json",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Phase 6 report export (json|markdown).

    The report is deterministic, built only from persisted state, and preserves
    finding ids, evidence ids, coverage, limitations, the registry fingerprint
    and timestamps.  Each export is recorded with a content hash for reproducibility.
    """
    scan = get_owned_scan(db, user, scan_id)
    fmt = (format or "json").lower()
    if fmt not in ("json", "markdown"):
        raise HTTPException(status_code=400, detail="format must be 'json' or 'markdown'.")

    from app.reporting import builder as report_builder
    from app.reporting import export as report_export

    report, markdown, json_payload, _rendered = report_builder.build(db, scan)

    if fmt == "json":
        payload = report_export.render_json(json_payload)
        response = {
            "format": "json",
            "scan_id": scan.id,
            "target": scan.target,
            "generated_at": report.generated_at,
            "registry_fingerprint": report.registry_fingerprint,
            "config_fingerprint": report.config_fingerprint,
            "content_hash": report_export.content_hash(payload),
            "report": json_payload,
        }
        record_payload = payload
        content_json = json_payload
        content_markdown = None
    else:
        payload = report_export.render_markdown(markdown)
        response = {
            "format": "markdown",
            "scan_id": scan.id,
            "target": scan.target,
            "generated_at": report.generated_at,
            "registry_fingerprint": report.registry_fingerprint,
            "config_fingerprint": report.config_fingerprint,
            "content_hash": report_export.content_hash(payload),
            "report": payload,
        }
        record_payload = payload
        content_json = None
        content_markdown = payload

    report_export.persist_export(
        db,
        scan_id=scan.id,
        fmt=fmt,
        payload=record_payload,
        content_json=content_json,
        content_markdown=content_markdown,
        registry_fingerprint=report.registry_fingerprint,
        config_fingerprint=report.config_fingerprint,
        user_id=str(getattr(user, "id", "")),
    )
    return response


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


# ---------------------------------------------------------------------------
# Phase 7 execution-platform endpoints
# ---------------------------------------------------------------------------
@router.get("/{scan_id}/state")
def get_scan_state(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Phase 7 state machine summary for a scan (+ legal next transitions)."""
    scan = get_owned_scan(db, user, scan_id)
    current = scan.state or phase7_state.CREATED
    return {
        "scan_id": scan.id,
        "state": current,
        "coarse_status": scan.status,
        "stage": scan.stage or lifecycle.QUEUED,
        "coarse_completion": phase7_state.coarse_completion(current),
        "terminal": phase7_state.is_terminal(current),
        "transitions": sorted(phase7_state.ALL)
        if phase7_state.is_terminal(current)
        else phase7_state.ALL,
        "queue_waited_ms": scan.queue_waited_ms,
        "updated_at": scan.updated_at,
    }


@router.get("/{scan_id}/stages")
def get_scan_stages(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Real per-stage progress ledger for one scan."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(ScanStage).filter(ScanStage.scan_id == scan_id).order_by(ScanStage.id.asc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "order": r.order,
            "status": r.status,
            "reason": r.reason,
            "tools": r.tools or [],
            "tests_executed": r.tests_executed or 0,
            "observations": r.observations or 0,
            "candidates": r.candidates or 0,
            "confirmed_findings": r.confirmed_findings or 0,
            "errors": r.errors or {},
            "duration_ms": r.duration_ms,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
        }
        for r in rows
    ]


@router.get("/{scan_id}/executions")
def get_scan_executions(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Real execution ledger: every tool attempt/skip with process telemetry."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).order_by(ToolExecution.id.asc()).all()
    return [
        {
            "id": r.id,
            "stage": r.stage,
            "tool": r.tool,
            "adapter": r.adapter,
            "attempt": r.attempt,
            "status": r.status,
            "executable": r.executable,
            "tool_version": r.tool_version,
            "target": r.target,
            "command_redacted": r.command_redacted,
            "exit_code": r.exit_code,
            "duration_ms": r.duration_ms,
            "stdout_size": r.stdout_size,
            "stderr_size": r.stderr_size,
            "truncated": bool(r.stdout_truncated or r.stderr_truncated),
            "parsed_observations": r.parsed_observations or 0,
            "cancellation_state": r.cancellation_state,
            "termination_reason": r.termination_reason,
            "error_code": r.error_code,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
        }
        for r in rows
    ]


@router.get("/{scan_id}/readiness")
def get_scan_readiness(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Preflight snapshot: what was installed/disabled/missing when the scan ran."""
    scan = get_owned_scan(db, user, scan_id)
    rows = db.query(ToolReadiness).filter(ToolReadiness.scan_id == scan_id).order_by(ToolReadiness.id.asc()).all()
    return {
        "scan_id": scan.id,
        "preflight": scan.preflight_json or {},
        "tools": [
            {
                "tool": r.tool,
                "status": r.status,
                "executable": r.executable,
                "version": r.version,
                "adapter": r.adapter,
                "category": r.category,
                "enabled": bool(r.enabled),
                "reason": r.reason,
                "checked_at": r.checked_at,
            }
            for r in rows
        ],
    }


@router.get("/{scan_id}/typed-events")
def get_scan_typed_events(
    scan_id: int,
    cursor: int = 0,
    limit: int = 500,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Replay the ordered Phase 7 typed event stream from a cursor."""
    get_owned_scan(db, user, scan_id)
    if limit < 1 or limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 2000.")
    return phase7_events.replay(db, scan_id, cursor=cursor, limit=limit)


@router.get("/{scan_id}/ml-advisory")
def get_scan_ml_advisory(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The deterministic advisory-only record for a scan (no model predictions)."""
    scan = get_owned_scan(db, user, scan_id)
    row = (
        db.query(MLInference)
        .filter(MLInference.scan_id == scan_id)
        .order_by(MLInference.id.desc())
        .first()
    )
    if row is None:
        return {"scan_id": scan.id, "advisory": None}
    return {
        "scan_id": scan.id,
        "id": row.id,
        "status": row.status,
        "model_name": row.model_name,
        "model_version": row.model_version,
        "feature_schema_version": row.feature_schema_version,
        "training_status": row.training_status,
        "generated_at": row.generated_at,
        "advisory": row.advisory_json,
    }


@router.get("/{scan_id}/compare")
def compare_scans(
    scan_id: int,
    with_scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cross-scan finding diff: added/removed/retained/reintroduced fingerprints."""
    scan_a = get_owned_scan(db, user, scan_id)
    scan_b = get_owned_scan(db, user, with_scan_id)
    from app.assess import tracking

    diff = tracking.compare(db, scan_a.id, scan_b.id)
    diff["same_target"] = (scan_a.target or "").strip() == (scan_b.target or "").strip()
    if not diff["same_target"]:
        diff["note"] = "Scans have different targets; the diff compares raw fingerprints only."
    return diff


@router.post("/{scan_id}/retry")
def retry_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Re-enqueue a terminal scan for another run (evidence is preserved;
    rule dedup prevents duplicate findings on re-assessment)."""
    scan = get_owned_scan(db, user, scan_id)
    current = scan.state or phase7_state.CREATED
    if not phase7_state.is_terminal(current):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot retry a scan in non-terminal state {current!r}.",
        )
    if current != phase7_state.CANCELLED:
        scan.state = phase7_state.CREATED
    scan.stage = lifecycle.QUEUED
    scan.status = "Pending"
    scan.error = None
    scan.completed_at = None
    scan.cancelled_at = None
    scan.queue_waited_ms = None
    scan.queue_started_at = datetime.datetime.utcnow()
    scan.preflight_json = None
    scan.progress = lifecycle.empty_progress()
    scan.logs = (scan.logs or "") + "[System] Retry requested; re-enqueuing for a new run...\n"
    scan.updated_at = datetime.datetime.utcnow()
    db.commit()

    config = dict(scan.scan_config or {})
    simulation = config.get("simulation", settings.simulation_mode)
    trigger_background_scan(scan.id, simulation=simulation, config=config)
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "state": scan.state,
        "stage": scan.stage,
        "simulation": simulation,
    }