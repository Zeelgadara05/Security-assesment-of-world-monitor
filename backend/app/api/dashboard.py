"""Dashboard aggregation endpoint (Phase 9).

``GET /dashboard/summary`` answers the dashboard with cross-scan analytics
built exclusively from persisted rows *owned by the authenticated user*:

  * finding lifecycle buckets (candidate / confirmed / accepted) by severity,
  * coverage trend across recent scans,
  * observation / evidence volume (the honest evidence chain),
  * asset graph surface (assets discovered vs. observations linked to assets),
  * cadence (recent scan activity by day).

Every number is derived from real rows; nothing is simulated or interpolated.
The legacy ``/scans/summary`` endpoint is untouched.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database.connection import get_db
from database.models import (
    Asset, Observation, Project, Scan, Vulnerability, User,
)
from app.assess import finding_lifecycle as lifecycle
from app.core.auth import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _owned_scan_ids(db: Session, user: User) -> list[int]:
    project_ids = [
        p.id for p in db.query(Project).filter(Project.user_id == user.id).all()
    ]
    if not project_ids:
        return []
    return [
        s.id for s in db.query(Scan)
        .filter(Scan.project_id.in_(project_ids))
        .order_by(Scan.created_at.asc()).all()
    ]


@router.get("/summary")
def dashboard_summary(user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """Cross-scan analytics across the caller's own scans (real rows only)."""
    scan_ids = _owned_scan_ids(db, user)

    if not scan_ids:
        return _empty_payload()

    findings = (
        db.query(Vulnerability).filter(Vulnerability.scan_id.in_(scan_ids))
        .order_by(Vulnerability.scan_id.asc(), Vulnerability.id.asc()).all()
    )

    # lifecycle buckets (status is the Phase 9 lifecycle, not the legacy state)
    buckets = {
        lifecycle.STATUS_CANDIDATE: 0,
        lifecycle.STATUS_CONFIRMED: 0,
        lifecycle.STATUS_REJECTED: 0,
        lifecycle.STATUS_DUPLICATE: 0,
        lifecycle.STATUS_ACCEPTED: 0,
        lifecycle.STATUS_REMEDIATED: 0,
    }
    for f in findings:
        key = (f.status or lifecycle.STATUS_CONFIRMED)
        if key in buckets:
            buckets[key] += 1
        else:
            buckets.setdefault(key, 0)
            buckets[key] += 1

    severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    by_rule: dict[str, int] = {}
    for f in findings:
        sev = (f.severity or "").capitalize()
        if sev in severity:
            severity[sev] += 1
        rule = f.rule_id or "legacy"
        by_rule[rule] = by_rule.get(rule, 0) + 1

    # coverage trend from the latest phase-7 scan_stages rows / preflight trail
    coverage_trend, by_status, cadence = _scan_trends(db, scan_ids)

    # evidence chain volume: observations persisted per scan
    observations = (
        db.query(Observation).filter(Observation.scan_id.in_(scan_ids)).all()
        if scan_ids else []
    )
    obs_by_scan: dict[int, int] = {}
    for o in observations:
        obs_by_scan[o.scan_id] = obs_by_scan.get(o.scan_id, 0) + 1

    assets = (
        db.query(Asset).filter(Asset.project_id.in_(
            [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
        )).all()
    )
    asset_types: dict[str, int] = {}
    for a in assets:
        asset_types[a.type] = asset_types.get(a.type, 0) + 1

    # recent findings with asset context when an observation is linked
    recent = _recent_findings(db, findings)

    return {
        "findings_lifecycle": buckets,
        "findings_by_severity": severity,
        "findings_by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "confirmed_findings": buckets.get(lifecycle.STATUS_CONFIRMED, 0),
        "candidate_findings": buckets.get(lifecycle.STATUS_CANDIDATE, 0),
        "scans_total": len(scan_ids),
        "scans_by_status": by_status,
        "coverage_trend": coverage_trend,
        "cadence": cadence,
        "observation_count": len(observations),
        "observations_by_scan": obs_by_scan,
        "assets_total": len(assets),
        "assets_by_type": asset_types,
        "recent_findings": recent,
    }


def _scan_trends(db: Session, scan_ids: list[int]):
    scans = (
        db.query(Scan).filter(Scan.id.in_(scan_ids)).order_by(Scan.created_at.asc()).all()
    )
    by_status: dict[str, int] = {}
    coverage_trend: list[dict] = []
    cadence: dict[str, int] = {}

    from datetime import timedelta

    for s in scans:
        by_status[s.status] = by_status.get(s.status, 0) + 1
        if s.coverage is not None:
            coverage_trend.append({
                "scan_id": s.id, "target": s.target,
                "coverage": s.coverage, "created_at": s.created_at,
            })
        day = (s.created_at or s.updated_at)
        if day is not None:
            key = day.strftime("%Y-%m-%d")
            cadence[key] = cadence.get(key, 0) + 1
    return coverage_trend, by_status, cadence


def _recent_findings(db: Session, findings) -> list[dict]:
    from database.models import FindingObservationLink

    recent = list(findings)[-20:]
    rows = []
    for f in recent:
        linked_obs = [
            link.observation_id
            for link in db.query(FindingObservationLink)
            .filter(FindingObservationLink.finding_id == f.id).all()
        ]
        evidence_note = ""
        if linked_obs:
            obs = db.query(Observation).filter(
                Observation.id.in_(linked_obs)).first()
            if obs is not None:
                evidence_note = f"{obs.kind} by {obs.tool_name} on {obs.subject}"
        rows.append({
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "severity": f.severity,
            "status": (f.status or lifecycle.STATUS_CONFIRMED),
            "category": f.category,
            "endpoint": f.endpoint,
            "evidence_note": evidence_note,
        })
    return list(reversed(rows))


def _empty_payload() -> dict:
    return {
        "findings_lifecycle": {},
        "findings_by_severity": {},
        "findings_by_rule": {},
        "confirmed_findings": 0,
        "candidate_findings": 0,
        "scans_total": 0,
        "scans_by_status": {},
        "coverage_trend": [],
        "cadence": {},
        "observation_count": 0,
        "observations_by_scan": {},
        "assets_total": 0,
        "assets_by_type": {},
        "recent_findings": [],
    }


__all__ = ["router"]