"""Finding triage API (Phase 3).

Findings are persisted with state ``NEW``.  This API moves a finding through a
deterministic triage state machine:

    NEW / CONFIRMED  -> CONFIRMED | FALSE_POSITIVE | DUPLICATE
                        | ACCEPTED_RISK | RESOLVED

Findings in FALSE_POSITIVE / DUPLICATE / RESOLVED states no longer count against
the security score.  Transition history is preserved implicitly through
``updated_at`` / ``resolved_at`` timestamps.
"""
import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database.connection import get_db
from database.models import User, Vulnerability
from app.core.auth import get_current_user, get_owned_scan

router = APIRouter(prefix="/findings", tags=["findings"])

ACTIONS = {
    "confirm": "CONFIRMED",
    "false_positive": "FALSE_POSITIVE",
    "duplicate": "DUPLICATE",
    "accepted_risk": "ACCEPTED_RISK",
    "resolve": "RESOLVED",
}


class TriagePayload(BaseModel):
    action: str


@router.post("/{finding_id}/triage")
def triage_finding(
    finding_id: int,
    payload: TriagePayload,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Transition a finding to the requested state (ownership enforced)."""
    action = (payload.action or "").strip().lower()
    if action not in ACTIONS:
        raise HTTPException(status_code=400, detail=f"Invalid action. Use one of: {', '.join(ACTIONS)}.")

    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")

    # Ownership: the referenced scan must belong to the current user.
    get_owned_scan(db, user, finding.scan_id)

    now = datetime.datetime.utcnow()
    next_state = ACTIONS[action]
    finding.state = next_state
    finding.updated_at = now
    if next_state in ("FALSE_POSITIVE", "DUPLICATE", "ACCEPTED_RISK", "RESOLVED"):
        finding.resolved_at = now
    else:
        finding.resolved_at = None
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "state": finding.state,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
    }