from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database.connection import get_db
from database.models import ChatHistory, Scan, Vulnerability, User
from app.core.auth import get_current_user, get_owned_scan

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatPayload(BaseModel):
    scan_id: int
    message: str


def _finding_haystack(v: Vulnerability) -> str:
    return " ".join(str(x) for x in [
        v.title, v.description, v.remediation, v.cve, v.rule_id, v.owasp, v.cwe,
    ]).lower()


def _compile_response(scan: Scan, vulns: list, message: str) -> str:
    """Deterministic, data-driven assistant. Compiled exclusively from the
    PERSISTED findings of the scan; it never cites invented vulnerabilities."""
    msg_lower = message.lower()
    has_findings = bool(vulns)

    if "remediation" in msg_lower or "fix" in msg_lower or "action" in msg_lower:
        if not has_findings:
            return (
                f"Target **{scan.target}** has no evidence-backed findings on "
                "record. There is nothing to remediate from persisted findings."
            )
        lines = [
            f"Based on the persisted findings for target **{scan.target}** "
            f"({len(vulns)} issue(s)):\n"
        ]
        for i, v in enumerate(vulns, 1):
            lines.append(
                f"{i}. **{v.title}** ({v.severity}, state={v.state or 'NEW'}): "
                f"{v.remediation or 'No remediation provided.'}"
            )
        return "\n".join(lines)

    # Security-header / component keywords -> findings that actually mention them.
    keywords = [
        "csp", "content-security-policy", "hsts", "strict-transport-security",
        "x-content-type-options", "x-frame-options", "server version", "banner",
        "jquery", "outdated", "nuclei", "cve", "header", "injection",
    ]
    hits = [v for v in vulns if any(k in msg_lower and k in _finding_haystack(v) for k in keywords)]
    if hits:
        answers = []
        for v in hits[:5]:
            answers.append(
                f"**{v.title}** ({v.severity}, state={v.state or 'NEW'}, rule={v.rule_id or 'legacy'})\n"
                f"{v.description}\nRemediation: {v.remediation or 'None provided.'}"
            )
        return "\n\n".join(answers)
    if msg_lower and any(k in msg_lower for k in keywords) and not hits:
        return (
            f"No persisted finding for target **{scan.target}** matches the "
            "keyword in your request. Only evidence-backed findings are reported."
        )

    context = "\n".join(
        f"- {v.title} ({v.severity}) [state={v.state or 'NEW'}]: {v.remediation or 'No remediation provided.'}"
        for v in vulns
    ) or "No evidence-backed findings are persisted for this target."
    return (
        f"Greetings. I am the CyberAgent assistant, reviewing **persisted** "
        f"findings for target **{scan.target}**.\n\nVulnerability Context Summary:\n{context}\n\n"
        "Ask about remediation, a specific finding, or a security header."
    )


@router.post("/query")
def submit_chat_query(
    payload: ChatPayload,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Submits a user chat query to the AI Security Copilot.

    The referenced scan must belong to the authenticated user.  The assistant is
    a deterministic, keyword-assisted simulator (no LLM): replies are compiled
    exclusively from the scan's PERSISTED findings and are never fabricated.
    """
    scan = get_owned_scan(db, user, payload.scan_id)

    user_chat = ChatHistory(scan_id=payload.scan_id, role="user", message=payload.message)
    db.add(user_chat)
    db.commit()

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == payload.scan_id).all()
    response = _compile_response(scan, vulns, payload.message)

    assistant_chat = ChatHistory(scan_id=payload.scan_id, role="assistant", message=response)
    db.add(assistant_chat)
    db.commit()

    return {
        "scan_id": payload.scan_id,
        "role": "assistant",
        "message": response,
        "created_at": assistant_chat.created_at,
        "simulated": True,
    }


@router.get("/history/{scan_id}")
def get_chat_history(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves conversation thread logs for a chat owned by the user."""
    get_owned_scan(db, user, scan_id)
    history = db.query(ChatHistory).filter(ChatHistory.scan_id == scan_id).order_by(ChatHistory.created_at.asc()).all()
    return [
        {
            "role": h.role,
            "message": h.message,
            "created_at": h.created_at
        }
        for h in history
    ]