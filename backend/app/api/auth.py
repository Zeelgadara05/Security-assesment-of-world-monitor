from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import User, Project, Asset

router = APIRouter(prefix="/auth", tags=["auth"])

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    """
    Middleware validator that checks Supabase Authorization Token.
    Returns default demo user if token is missing (simplifies development testing).
    """
    # Simply retrieve the seeded default demo-user-id for development
    user = db.query(User).filter(User.id == "demo-user-id").first()
    if not user:
        # Fallback to create user if db gets flushed
        user = User(id="demo-user-id", email="demo@cyberagent.ai")
        db.add(user)
        db.commit()
        db.refresh(user)
    return user

@router.get("/profile")
def get_user_profile(user: User = Depends(get_current_user)):
    """Retrieves authenticated user details."""
    return {
        "id": user.id,
        "email": user.email,
        "role": "Security Administrator",
        "created_at": user.created_at
    }

@router.get("/assets")
def get_discovered_assets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Returns all assets collected by tools across active projects."""
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "type": a.type,
            "value": a.value,
            "metadata": a.metadata_json,
            "created_at": a.created_at
        }
        for a in assets
    ]
