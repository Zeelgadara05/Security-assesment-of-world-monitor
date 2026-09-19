import datetime
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.config import settings
from app.core import security
from app.core.auth import (
    get_current_user,
    get_user_projects,
    require_admin,
)
from database.connection import get_db
from database.models import Asset, Project, User
from database.models import Session as AuthSession

router = APIRouter(prefix="/auth", tags=["auth"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterPayload(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _email_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
        return v

    @field_validator("password")
    @classmethod
    def _password_valid(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class LoginPayload(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _email_valid(cls, v: str) -> str:
        return v.strip().lower()


def _public_user(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at,
    }


def _create_session_response(user: User, token: str, expires_at: datetime.datetime) -> dict:
    return {
        "user": _public_user(user),
        "token": token,
        "expires_at": expires_at.isoformat(),
    }


@router.post("/register", status_code=201)
def register(payload: RegisterPayload, db: Session = Depends(get_db)):
    """Create a new user account (role: user). Registration is self-service."""
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = User(
        id=__import__("uuid").uuid4().hex,
        email=payload.email,
        password_hash=security.hash_password(payload.password),
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _public_user(user)


@router.post("/login")
def login(payload: LoginPayload, db: Session = Depends(get_db)):
    """Verify credentials and start a session. Same error for any mismatch.

    The returned token is opaque; the server only stores its SHA-256 digest.
    """
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or not security.verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    raw_token, digest = security.generate_session_token()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(
        hours=settings.session_ttl_hours
    )
    session = AuthSession(
        token_hash=digest,
        user_id=user.id,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()
    return _create_session_response(user, raw_token, expires_at)


@router.post("/logout")
def logout(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke the session identified by the presented token.

    The user model carries no token itself; the raw token is read from the
    request (header, cookie or query) and its session row is revoked so the
    token is immediately invalid even if it was exfiltrated before logout.
    """
    from app.core.auth import _extract_token
    raw = _extract_token(request)
    # The dependency has already verified the session is valid, so revoking it
    # here makes the token immediately useless even if it was exfiltrated.
    digest = security.hash_session_token(raw) if raw else None
    if digest:
        row = db.query(AuthSession).filter(AuthSession.token_hash == digest).first()
        if row is not None and row.revoked_at is None:
            row.revoked_at = datetime.datetime.utcnow()
            db.commit()
    return {"status": "logged_out", "email": user.email}


@router.get("/me")
def get_me(user: User = Depends(get_current_user)):
    """Details of the authenticated user."""
    return _public_user(user)


@router.get("/profile")
def get_profile(user: User = Depends(get_current_user)):
    """Alias of /auth/me for backward compatibility."""
    return _public_user(user)


@router.get("/assets")
def get_discovered_assets(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Assets collected across the authenticated user's own projects."""
    projects = get_user_projects(db, user)
    project_ids = [p.id for p in projects]
    if not project_ids:
        return []
    assets = (
        db.query(Asset)
        .filter(Asset.project_id.in_(project_ids))
        .order_by(Asset.created_at.desc())
        .all()
    )
    return [
        {
            "id": a.id,
            "type": a.type,
            "value": a.value,
            "metadata": a.metadata_json,
            "created_at": a.created_at,
        }
        for a in assets
    ]


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin-only listing of registered users."""
    users = db.query(User).order_by(User.created_at.asc()).all()
    return [_public_user(u) for u in users]


@router.get("/admin/overview")
def admin_overview(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin-only aggregate overview used to demonstrate RBAC enforcement."""
    from database.models import ChatHistory, Report, Scan, ToolResult, Vulnerability

    counts = {
        "users": db.query(User).count(),
        "projects": db.query(Project).count(),
        "scans": db.query(Scan).count(),
        "assets": db.query(Asset).count(),
        "reports": db.query(Report).count(),
        "tool_results": db.query(ToolResult).count(),
        "vulnerabilities": db.query(Vulnerability).count(),
        "chat_messages": db.query(ChatHistory).count(),
    }
    return {"overview": counts, "admin": _public_user(admin)}