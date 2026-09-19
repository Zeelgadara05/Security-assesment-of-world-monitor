"""End-to-end scan lifecycle against the throwaway database.

SIMULATION_MODE=true is forced via conftest, so the full multi-agent workflow
runs in simulation. It sleeps through its tool stages (~25-30s), so we poll
with a generous deadline.
"""

import time

from database.connection import SessionLocal, seed_defaults
from database.models import Scan, ToolResult

POLL_TIMEOUT = 90.0
POLL_INTERVAL = 2.0
EXPECTED_TOOLS = {
    "subfinder",
    "assetfinder",
    "dnsx",
    "nmap",
    "httpx",
    "gau",
    "whatweb",
    "nuclei",
}


def _wait_for_terminal(client, scan_id):
    deadline = time.time() + POLL_TIMEOUT
    last = None
    while time.time() < deadline:
        entries = client.get("/scans/list").json()
        last = next((e for e in entries if e["id"] == scan_id), None)
        if last and last["status"] in ("Completed", "Failed"):
            return last
        time.sleep(POLL_INTERVAL)
    return last


def test_scan_reaches_completed_with_simulation_markers(client):
    seed_defaults()

    resp = client.post("/scans/trigger", json={"target": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("Pending", "Running")
    assert data["simulation"] is True, "SIMULATION_MODE=true must be reflected in the trigger response"
    scan_id = data["scan_id"]

    terminal = _wait_for_terminal(client, scan_id)
    assert terminal is not None, "scan never reached a terminal state"
    assert terminal["status"] == "Completed", f"scan finished with status {terminal['status']}"
    assert terminal["completed_at"] is not None

    details = client.get(f"/scans/{scan_id}/details").json()
    assert details["completed_at"] is not None
    assert 10 <= (details["security_score"] or 0) <= 100
    assert isinstance(details["vulnerabilities"], list)
    tool_names = {t["name"] for t in details["tools"]}
    assert tool_names == EXPECTED_TOOLS

    logs = details["logs"] or ""
    assert "[SIMULATION]" in logs
    assert "SIMULATION_MODE" in logs
    assert not logs.startswith("[SIMULATED]")  # banner is a log entry, not a tool result

    db = SessionLocal()
    try:
        rows = db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()
        assert len(rows) == len(EXPECTED_TOOLS)
        assert all(r.raw_output.startswith("[SIMULATED]") for r in rows)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        assert scan.completed_at is not None
        assert scan.security_score is not None
    finally:
        db.close()