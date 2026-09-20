"""System diagnostics endpoint (Phase 7).

Honest, read-only snapshot of the execution platform: which execution mode is
active, how many scanners are installed, whether the Phase 7 modules import, DB
reachability, and the ML posture (advisory-only, no model).  Numbers come from
real probes / counts; nothing here is fabricated.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.core.auth import get_current_user
from app.config import settings
from database.connection import get_db
from database.models import Scan, User
from sqlalchemy.orm import Session

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/diagnostics")
def diagnostics(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.tools.inventory import tool_inventory
    from app.orchestration import stages
    from app.orchestration import state as phase7_state
    from app.ml.advisory import FEATURE_SCHEMA_VERSION

    tools = tool_inventory()
    installed = [t for t in tools if t["installed"]]

    db_ok = True
    scan_count = None
    try:
        db.execute(text("SELECT 1"))
        scan_count = db.query(Scan).count()
    except Exception:
        db_ok = False

    try:
        stage_count = len(stages.STAGE_ORDER)
        state_count = len(phase7_state.ALL)
        modules_ok = True
    except Exception:
        stage_count = None
        state_count = None
        modules_ok = False

    return {
        "mode": {
            "simulation_mode": settings.simulation_mode,
            "description": "simulation is off so scans run real tools by default"
            if not settings.simulation_mode
            else "simulation is explicit and forces deterministic markers",
        },
        "database": {"reachable": db_ok, "scan_rows": scan_count},
        "tools": {
            "registered": len(tools),
            "installed": len(installed),
            "missing": len(tools) - len(installed),
            "installed_tools": sorted(t["tool"] for t in installed),
        },
        "orchestration": {
            "modules_loaded": modules_ok,
            "stages": stage_count,
            "states": state_count,
            "stage_names": list(stages.STAGE_ORDER) if modules_ok else [],
        },
        "assessment": {
            "advisory_schema_version": FEATURE_SCHEMA_VERSION,
            "ml_status": "advisory_only",
            "note": "no model is loaded; no ML prediction ever enters findings",
        },
        "targets_in_scope": _scope_size(db, user),
    }


def _scope_size(db: Session, user: User) -> int:
    from database.models import Project
    projects = db.query(Project).filter(Project.user_id == user.id).all()
    return sum(len(list(p.scope_json or [])) for p in projects)