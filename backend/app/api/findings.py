"""Finding triage + lifecycle API (Phase 3/6).

Triage moves a finding deterministically:

  * Phase 3 record state (``NEW``/``CONFIRMED``/``FALSE_POSITIVE``/...) is kept in
    sync with the Phase 6 lifecycle status (``candidate``/``confirmed``/``rejected``/...).
  * Every transition is validated against the lifecycle state graph and appended
    immutably to the ``finding_status_history`` audit trail.

READ endpoints also serve the finding detail (with proof-of-concept, CVSS
consistency result, status history) and the integrity-verified evidence records
(redacted request/response payloads + hashes).  Ownership is enforced through
the scan -> project -> user chain; other users' findings are indistinguishable
from missing ones.
"""
import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database.connection import get_db
from database.models import User, Vulnerability
from app.core.auth import get_current_user, get_owned_scan
from app.assess import finding_lifecycle as lifecycle

router = APIRouter(prefix="/findings", tags=["findings"])

# Legacy triage action -> lifecycle status (Phase 6).
ACTIONS = {
    "confirm": lifecycle.STATUS_CONFIRMED,
    "false_positive": lifecycle.STATUS_REJECTED,
    "duplicate": lifecycle.STATUS_DUPLICATE,
    "accepted_risk": lifecycle.STATUS_ACCEPTED,
    "resolve": lifecycle.STATUS_REMEDIATED,
}

# Lifecycle status -> Phase 3 record state (kept in sync for score/charts).
_STATE_BY_STATUS = {
    lifecycle.STATUS_CONFIRMED: "CONFIRMED",
    lifecycle.STATUS_VALIDATED: "CONFIRMED",
    lifecycle.STATUS_CANDIDATE: "NEW",
    lifecycle.STATUS_REJECTED: "FALSE_POSITIVE",
    lifecycle.STATUS_DUPLICATE: "DUPLICATE",
    lifecycle.STATUS_ACCEPTED: "ACCEPTED_RISK",
    lifecycle.STATUS_REMEDIATED: "RESOLVED",
    lifecycle.STATUS_REOPENED: "NEW",
}


def _get_owned_finding(db: Session, user: User, finding_id: int) -> Vulnerability:
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    get_owned_scan(db, user, finding.scan_id)  # 404 when not owned
    return finding


def _actor(user: User) -> str:
    return str(getattr(user, "email", None) or getattr(user, "username", None) or user.id)


class TriagePayload(BaseModel):
    action: str
    reason: str | None = None


@router.post("/{finding_id}/triage")
def triage_finding(
    finding_id: int,
    payload: TriagePayload,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Transition a finding through the lifecycle state graph (ownership enforced)."""
    action = (payload.action or "").strip().lower()
    if action not in ACTIONS:
        raise HTTPException(status_code=400, detail=f"Invalid action. Use one of: {', '.join(ACTIONS)}.")

    finding = _get_owned_finding(db, user, finding_id)
    to_status = ACTIONS[action]
    try:
        lifecycle.transition(
            db, finding, to_status,
            actor=_actor(user),
            reason=payload.reason or f"operator triage to {to_status}",
        )
    except lifecycle.InvalidTransition as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finding.state = _STATE_BY_STATUS.get(to_status, "NEW")
    finding.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "status": finding.status,
        "state": finding.state,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
    }


def _history(db: Session, finding_id: int) -> list[dict]:
    from database.models import FindingStatusHistory

    rows = (
        db.query(FindingStatusHistory)
        .filter(FindingStatusHistory.finding_id == finding_id)
        .order_by(FindingStatusHistory.id.asc())
        .all()
    )
    return [
        {
            "id": h.id,
            "from_status": h.from_status,
            "to_status": h.to_status,
            "actor": h.actor,
            "reason": h.reason,
            "created_at": h.created_at.isoformat() if h.created_at else None,
        }
        for h in rows
    ]


@router.get("/{finding_id}")
def get_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Full finding detail: lifecycle, CVSS consistency, PoC, evidence, history."""
    from app.assess.poc import build_poc
    from app.reporting.finding_renderer import cvss_block, history_entries
    from app.reporting.evidence_renderer import render_evidence
    from database.models import FindingEvidence

    finding = _get_owned_finding(db, user, finding_id)

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status or lifecycle.STATUS_CONFIRMED,
        "state": finding.state or "NEW",
        "description": finding.description,
        "category": finding.category,
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter": finding.parameter,
        "affected_component": finding.affected_component,
        "source_test": finding.source_test,
        "source_tool": finding.source_tool,
        "validation_reason": finding.validation_reason,
        "remediation": finding.remediation,
        "remediation_details": finding.remediation_details,
        "impact_details": finding.impact_details,
        "cvss": cvss_block(db, finding),
        "proof_of_concept": build_poc(db, finding),
        "evidence": render_evidence(db, finding),
        "history": history_entries(db, finding),
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "resolved_at": finding.resolved_at,
    }


@router.get("/{finding_id}/evidence")
def get_finding_evidence(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Integrity-verified evidence with the redacted request/response proof."""
    from app.assess.evidence import verify_evidence_integrity
    from database.models import FindingEvidence

    finding = _get_owned_finding(db, user, finding_id)
    rows = db.query(FindingEvidence).filter(FindingEvidence.finding_id == finding.id).order_by(FindingEvidence.id.asc()).all()
    return {
        "finding_id": finding.id,
        "evidence": [
            {
                "id": e.id,
                "observation_id": e.observation_id,
                "evidence_type": e.evidence_type,
                "request": e.request_json,
                "response": e.response_json,
                "expected": e.expected,
                "actual": e.actual,
                "security_boundary": e.security_boundary,
                "redaction_status": e.redaction_status,
                "request_hash": e.request_hash,
                "response_hash": e.response_hash,
                "original_size": e.original_size,
                "captured_size": e.captured_size,
                "truncated": e.truncated,
                "integrity": verify_evidence_integrity(e),
            }
            for e in rows
        ],
    }


__all__ = ["ACTIONS", "get_finding", "get_finding_evidence", "router"]