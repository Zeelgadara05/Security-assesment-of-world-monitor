from fastapi import APIRouter, Depends
from app.core.auth import get_current_user
from app.tools.inventory import tool_inventory
from app.config import settings
from database.models import User

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("/inventory")
def get_tool_inventory(user: User = Depends(get_current_user)):
    """Real tool inventory: installed binaries + version + category.

    Reporting is honest: every entry reflects an actual ``shutil.which``
    probe on the host, never an assumption about what should be available.
    """
    return {
        "tools": tool_inventory(),
        "simulation_mode": settings.simulation_mode,
        "simulated": settings.simulation_mode,
    }


@router.get("/status")
def get_tool_status(user: User = Depends(get_current_user)):
    """Readiness status of every scanner the Phase 7 pipeline can schedule.

    Buckets tools into installed / missing / probes so the UI can render a
    health panel and a preflight preview before a scan is created.
    """
    tools = tool_inventory()
    installed = [t for t in tools if t["installed"]]
    missing = [t for t in tools if not t["installed"]]
    return {
        "total": len(tools),
        "installed_count": len(installed),
        "missing_count": len(missing),
        "installed": installed,
        "missing": missing,
        "simulation_mode": settings.simulation_mode,
    }


@router.post("/refresh")
def refresh_tool_status(user: User = Depends(get_current_user)):
    """Re-merge fresh PATH entries and re-probe every scanner.

    Call this after installing a scanner at runtime; it makes the new binary
    visible to the pipeline without a backend restart.
    """
    from app.tools.scanner_tools import refresh_tool_path
    refresh_tool_path()
    tools = tool_inventory()
    return {
        "refreshed": True,
        "tools": tools,
        "installed_count": sum(1 for t in tools if t["installed"]),
        "simulation_mode": settings.simulation_mode,
    }