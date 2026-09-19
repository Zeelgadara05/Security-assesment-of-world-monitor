"""Authentication and authorization dependencies.

``get_current_user`` is the single enforcement point for "who is calling".
It accepts a session token presented as:
  * ``Authorization: Bearer <token>`` (preferred for programmatic clients), or
  * the ``cyberagent_session`` cookie, or
  * a ``token`` query parameter (required by the SSE stream, which - as a
    native ``EventSource`` - cannot attach headers).

Sessions are opaque tokens stored as SHA-256 digests with an expiry.  No
request is ever treated as authenticated implicitly.

``require_admin`` layers context-based authorization (RBAC) on top of
authentication; every resource endpoint additionally verifies ownership of
the requested scan/project through the user -> project -> scan chain.
"""
import datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.core import security
from database.connection import get_db
from database.models import Asset, Project, Scan, Session, User
from database.schemas import normalize_target

_TOKEN_COOKIE = "cyberagent_session"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization")
    if auth:
        scheme, _, value = auth.partition(" ")
        if scheme.strip().lower() == "bearer" and value.strip():
            return value.strip()
        return None
    cookie = request.cookies.get(_TOKEN_COOKIE)
    if cookie:
        return cookie
    return request.query_params.get("token")


def authenticate_session(db: Session, token: str) -> User:
    """Validate a raw session token against the sessions table."""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")
    digest = security.hash_session_token(token)
    row = (
        db.query(Session)
        .filter(Session.token_hash == digest)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    now = datetime.datetime.utcnow()
    if row.revoked_at is not None or row.expires_at <= now:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    user = db.query(User).filter(User.id == row.user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Resolve the authenticated user for the request."""
    token = _extract_token(request)
    return authenticate_session(db, token)


def require_admin(user: User = Depends(get_current_user)) -> User:
    """RBAC guard: only users with role ``admin`` may pass."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator privileges required.")
    return user


# ---------------------------------------------------------------------------
# Ownership helpers (user -> project -> scan/asset)
# ---------------------------------------------------------------------------
def get_user_projects(db: Session, user: User) -> list[Project]:
    return db.query(Project).filter(Project.user_id == user.id).all()


def get_or_create_user_project(db: Session, user: User) -> Project:
    """Return the user's project, creating a personal one on first use.

    Every project is owned by exactly one user; scans and assets are attached
    to the project, which is how per-user isolation is enforced.
    """
    project = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.created_at.asc(), Project.id.asc())
        .first()
    )
    if project is not None:
        return project
    project = Project(
        name="My Project",
        description="Personal project for authorized security assessments.",
        user_id=user.id,
        scope_json=[],
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def get_owned_scan(db: Session, user: User, scan_id: int) -> Scan:
    """Fetch a scan only if it belongs to one of the user's projects.

    Returns 404 for both "no such scan" and "not yours" so the existence of
    other users' data is never disclosed.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    owned = (
        db.query(Project)
        .filter(Project.id == scan.project_id, Project.user_id == user.id)
        .first()
    )
    if owned is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def get_project_for_asset(db: Session, user: User, asset: Asset) -> Project | None:
    """Return the project an asset belongs to only when owned by the user."""
    return (
        db.query(Project)
        .filter(Project.id == asset.project_id, Project.user_id == user.id)
        .first()
    )


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------
def is_target_in_scope(target: str, project: Project, assets: list[Asset]) -> bool:
    """Decide whether a normalized target may be scanned for this project.

    Authorized scope is the union of:
      * project.scope_json entries (declared ownership), and
      * assets already discovered in the project (self-discovered targets).

    Matching rules:
      * domain   -> exact match, or the requested target being a subdomain
                    of the authorized domain,
      * IPv4     -> exact match,
      * CIDR     -> the requested IPv4 falling inside the block.

    A project with neither a declared scope nor any discovered asset grants
    no targets.
    """
    try:
        normalized = normalize_target(target)
    except ValueError:
        return False

    entries = list(project.scope_json or [])
    for asset in assets:
        if asset.type in ("domain", "ip"):
            entries.append(asset.value)

    for entry in entries:
        try:
            candidate = normalize_target(str(entry))
        except ValueError:
            continue
        if _entry_matches(candidate, normalized):
            return True
    return False


def _entry_matches(entry: str, target: str) -> bool:
    import ipaddress

    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            ip = ipaddress.ip_address(target)
            if ip.version == network.version:
                return ip in network
        except ValueError:
            return False
        return False
    if entry == target:
        return True
    dots = entry.count(".")
    if dots >= 1 and all(c.isalnum() or c in ".-" for c in entry):
        if target.endswith("." + entry):
            return True
    return False