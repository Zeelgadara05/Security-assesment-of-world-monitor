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


@router.post("/query")
def submit_chat_query(
    payload: ChatPayload,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Submits a user chat query to the AI Security Copilot.
    Uses target vulnerabilities and context memory to provide specialized remediation instructions.
    The referenced scan must belong to the authenticated user.
    """
    scan = get_owned_scan(db, user, payload.scan_id)

    # Save user message to history
    user_chat = ChatHistory(scan_id=payload.scan_id, role="user", message=payload.message)
    db.add(user_chat)
    db.commit()

    # Get scan details and vulnerabilities as core prompt context
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == payload.scan_id).all()
    vuln_context = "\n".join([
        f"- {v.title} ({v.severity}): CVE={v.cve or 'None'}, CVSS={v.cvss or 'N/A'}, OWASP={v.owasp or 'N/A'}"
        for v in vulns
    ])

    # Simple smart logic fallback rules acting as AI Security Specialist.
    # This is a deterministic, keyword-driven SIMULATED assistant, not an LLM.
    msg_lower = payload.message.lower()

    if "sql injection" in msg_lower or "cve-2024-3849" in msg_lower:
        response = (
            "The **SQL Injection (CVE-2024-3849)** finding represents a **Critical** security risk (CVSS 9.8). "
            "It was detected in the search queries of the target application. "
            "### Remediation Steps:\n"
            "1. **Use Parameterized Queries**: Ensure your database adapter uses prepared statements.\n"
            "   ```python\n"
            "   # SECURE IMPLEMENTATION\n"
            "   cursor.execute(\"SELECT * FROM users WHERE name = %s\", (user_input,))\n"
            "   ```\n"
            "2. **Implement Input Validation**: Define strict schemas using frameworks like Pydantic.\n"
            "3. **Minimize SQL Database Privileges**: Restrict the web server user's db access."
        )
    elif "csp" in msg_lower or "content-security-policy" in msg_lower:
        response = (
            "The **Missing Content-Security-Policy (CSP)** finding is a **Low** severity risk. "
            "It makes your web application vulnerable to Cross-Site Scripting (XSS) and Clickjacking attacks. "
            "### Recommended CSP Header configuration:\n"
            "```http\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.com; style-src 'self' 'unsafe-inline';\n"
            "```\n"
            "Add this header dynamically inside your Nginx configurations or backend application middleware."
        )
    elif "cve-2015-9251" in msg_lower or "jquery" in msg_lower:
        response = (
            "The **Outdated jQuery Version (1.12.4)** finding maps to **CVE-2015-9251** (Medium Severity, CVSS 6.1). "
            "This package contains cross-site scripting flaws when parsed against remote elements.\n"
            "### Remediation Plan:\n"
            "Upgrade your front-end configuration bundle dependencies:\n"
            "```bash\n"
            "npm install jquery@3.7.1\n"
            "```"
        )
    elif "remediation" in msg_lower or "fix" in msg_lower or "action" in msg_lower:
        response = (
            f"Based on the scanning findings for target **{scan.target}**, you have {len(vulns)} issues:\n\n"
            "**Priority 1: SQL Injection (Critical)**\n"
            "Action: Refactor the query builder into parameterized calls immediately. This accounts for a CVSS of 9.8.\n\n"
            "**Priority 2: Outdated jQuery Component (Medium)**\n"
            "Action: Upgrade standard build dependencies to version 3.7.1.\n\n"
            "**Priority 3: Missing CSP (Low)**\n"
            "Action: Inject modern Content-Security-Policy HTTP headers inside reverse proxy config."
        )
    else:
        # Default response compiled based on scanner findings context
        response = (
            f"Greetings. I am CyberAgent AI copilot. I am reviewing scan findings for target **{scan.target}**.\n\n"
            f"Vulnerability Context Summary:\n{vuln_context or 'No vulnerabilities detected for this sandbox scan target.'}\n\n"
            "Please ask me details about any vulnerability, remediation steps, or ask for general code patches!"
        )

    # Save assistant response to history (SIMULATED assistant output)
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