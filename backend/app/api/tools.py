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