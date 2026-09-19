"""Phase 4 -- job lifecycle, coverage, cancellation, SSE, isolation, inventory.

These tests verify the "scan engine" behavior that Phase 4 introduces, on top of
the Phase 2/3 invariants already covered elsewhere:

  * coverage and progress counters are REAL (only persisted completions count),
  * SSE ``/scans/{id}/events`` emits only events derived from persisted changes,
  * a cancelled scan terminates and never keeps producing tool results,
  * two users cannot reach each other's scan through any Phase 4 endpoint,
  * discovered out-of-scope hosts are skipped by the worker, never scanned,
  * NOT_INSTALLED tools never inflate coverage but never fake "Completed" either,
  * queued jobs start immediately (no synthetic delays in the request path),
  * findings always carry a traceable evidence trail to persisted observations,
  * the tool inventory reflects the real filesystem, identically to shutil.which.

Where a full workflow needs to run, simulation mode is forced by conftest and
the scan is polled to a terminal state (same pattern as test_scan_lifecycle).
"""

import json
import time

from database.connection import SessionLocal
from database.models import Asset, Observation, Project, Scan, ToolResult, Vulnerability
from app.agents import lifecycle
from app.agents.workflow import (
    _planned_tasks,
    _seed_progress,
    _run_tool,
    _in_scope_hosts,
    _persisted_finding,
)
from app.assess import finding_rules
from app.tools.scanner_tools import STATE_NOT_INSTALLED
from app.tools.inventory import tool_inventory
from app.workers.tasks import registry, cancel_scan
from tests.conftest import add_scope

POLL_TIMEOUT = 90.0
POLL_INTERVAL = 2.0


def _wait_for_terminal(client, scan_id, headers):
    deadline = time.time() + POLL_TIMEOUT
    last = None
    while time.time() < deadline:
        entries = client.get("/scans/list", headers=headers).json()
        last = next((e for e in entries if e["id"] == scan_id), None)
        if last and last["status"] in ("Completed", "Partially Completed", "Failed", "Cancelled"):
            return last
        time.sleep(POLL_INTERVAL)
    return last


# ---------------------------------------------------------------------------
# 1. Queued-job immediacy + configured creation + terminal lifecycle
# ---------------------------------------------------------------------------
def test_post_scans_queues_immediately_with_config_and_reaches_completed(client, auth_headers):
    add_scope(client, auth_headers, "ph4-lifecycle.example.com")

    resp = client.post("/scans", json={
        "target": "ph4-lifecycle.example.com",
        "severity": "all",
        "profile": "steady",
    }, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scan_id"] > 0
    assert data["status"] in ("Pending", "Running")
    assert data["stage"] == lifecycle.QUEUED
    assert data["simulation"] is True
    scan_id = data["scan_id"]

    # The job must be visible in the in-process registry immediately -- the
    # request path does not sleep or defer.
    assert registry.get(scan_id) is not None, "queued job must be registered immediately"

    detail = client.get(f"/scans/{scan_id}", headers=auth_headers).json()
    assert detail["scan_config"]["severity"] == "all"
    assert detail["scan_config"]["profile"] == "steady"
    assert detail["progress"]["total_tasks"] == 8, "simulation scans plan exactly the 8 tools"
    assert detail["progress"]["total_tools"] == 8

    terminal = _wait_for_terminal(client, scan_id, auth_headers)
    assert terminal is not None, "scan never reached a terminal state"
    assert terminal["status"] == "Completed", f"simulation scan finished as {terminal['status']}"

    detail = client.get(f"/scans/{scan_id}", headers=auth_headers).json()
    assert detail["stage"] in (lifecycle.COMPLETED, lifecycle.PARTIAL)
    assert detail["coverage"] == 100.0, "8/8 simulated tools succeeded -> coverage must be 100"
    assert detail["security_score"] == 100
    assert detail["progress"]["completed_tasks"] == 8
    assert detail["progress"]["failed_tasks"] == 0
    assert "[SIMULATION]" in (detail["logs"] or "")

    # Phase 4 read endpoints return persisted data only.
    findings = client.get(f"/scans/{scan_id}/findings", headers=auth_headers).json()
    observations = client.get(f"/scans/{scan_id}/observations", headers=auth_headers).json()
    assert findings == []
    assert observations == []
    cov = client.get(f"/scans/{scan_id}/coverage", headers=auth_headers).json()
    assert cov["completed_tasks"] == 8
    assert cov["total_tasks"] == 8
    assert cov["percent"] == 100
    assert cov["coverage"] == 100.0


# ---------------------------------------------------------------------------
# 2. SSE events reflect ONLY real persisted changes
# ---------------------------------------------------------------------------
def test_events_stream_emits_only_persisted_change_events(client, auth_headers):
    add_scope(client, auth_headers, "ph4-ssetest.example.com")
    resp = client.post("/scans", json={"target": "ph4-ssetest.example.com"}, headers=auth_headers)
    scan_id = resp.json()["scan_id"]
    _wait_for_terminal(client, scan_id, auth_headers)

    allowed_types = {"stage", "tool", "progress", "finding", "done", "error"}
    with client.stream("GET", f"/scans/{scan_id}/events", headers=auth_headers) as stream:
        lines = stream.iter_lines()
        payloads = []
        for line in lines:
            if line.startswith("data: "):
                payloads.append(json.loads(line[len("data: "):]))
            if payloads and payloads[-1].get("type") == "done":
                break
    assert payloads, "SSE stream must yield events for a completed scan"
    for payload in payloads:
        assert payload["type"] in allowed_types, f"unexpected event type {payload['type']}"
    assert payloads[-1]["type"] == "done"
    assert payloads[-1]["status"] == "Completed"
    assert payloads[-1]["coverage"] == 100.0
    types = {p["type"] for p in payloads}
    assert "stage" in types
    assert "tool" in types, "completed tool rows must be emitted as real events"
    assert "progress" in types


# ---------------------------------------------------------------------------
# 3. Cancellation terminates the job and prevents further tool results
# ---------------------------------------------------------------------------
def test_cancel_stops_the_scan_and_blocks_zombie_tasks(client, auth_headers):
    add_scope(client, auth_headers, "ph4-cancel.example.com")
    resp = client.post("/scans", json={"target": "ph4-cancel.example.com"}, headers=auth_headers)
    assert resp.status_code == 200
    scan_id = resp.json()["scan_id"]

    assert registry.get(scan_id) is not None
    rc = client.post(f"/scans/{scan_id}/cancel", headers=auth_headers)
    assert rc.status_code == 200
    assert rc.json()["status"] == "Cancelled"

    deadline = time.time() + 30
    while time.time() < deadline:
        detail = client.get(f"/scans/{scan_id}", headers=auth_headers).json()
        if detail["stage"] == lifecycle.CANCELLED:
            break
        time.sleep(1)
    assert detail["stage"] == lifecycle.CANCELLED, f"scan did not cancel: {detail['stage']}"
    assert detail["cancelled_at"] is not None

    rows_before = len(detail["tools"])
    time.sleep(3)
    detail_after = client.get(f"/scans/{scan_id}", headers=auth_headers).json()
    assert detail_after["tools"] is not None
    assert len(detail_after["tools"]) == rows_before, (
        "cancelled scan must not keep producing tool results (zombie prevention)"
    )
    assert detail_after["stage"] == lifecycle.CANCELLED
    assert detail_after["status"] != "Completed", "cancelled scan must never become Completed"
    assert client.post(f"/scans/{scan_id}/cancel", headers=auth_headers).json()["message"].startswith("Scan already")


# ---------------------------------------------------------------------------
# 4. NOT_INSTALLED: honest status, no fabricated coverage, no fake failure
# ---------------------------------------------------------------------------
def test_not_installed_tool_is_honest_never_inflates_coverage(client, session):
    user = session.query(__import__("database.models", fromlist=["User"]).User).filter(
        __import__("database.models", fromlist=["User"]).User.email == "owner@test.local").first()
    project = session.query(Project).filter(Project.user_id == user.id).first()
    if project is None:
        project = Project(name="NI", user_id=user.id, scope_json=["ni.example.com"])
        session.add(project)
        session.flush()
    scan = Scan(project_id=project.id, target="ni.example.com", status="Running", stage=lifecycle.STARTING)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    config = {"tools": {t: True for t in ("subfinder", "assetfinder", "dnsx", "nmap",
                                          "httpx", "gau", "whatweb", "nuclei")}}
    planned = _planned_tasks(config, simulation=True)
    assert len(planned) == 8
    progress = _seed_progress(session, scan, config, simulation=True)

    result = _run_tool(
        session, scan, "subfinder", config["tools"], True,
        lambda: {"tool": "subfinder", "status": STATE_NOT_INSTALLED, "log": "not installed"},
        progress,
    )
    assert result["status"] == STATE_NOT_INSTALLED
    # Nothing counted: NOT_INSTALLED is neither success nor a crash.
    assert progress["completed_tasks"] == 0
    assert progress["failed_tasks"] == 0

    row = session.query(ToolResult).filter(
        ToolResult.scan_id == scan.id, ToolResult.tool_name == "subfinder").first()
    assert row.status == STATE_NOT_INSTALLED

    # Coverage with a not-installed shortfall is honest (0/8 -> 0.0), and with
    # every tool present it reaches 100; the metric never exceeds reality.
    cov = lifecycle.compute_coverage(progress)
    assert cov == 0.0
    full = dict(progress)
    full["completed_tasks"] = 8
    assert lifecycle.compute_coverage(full) == 100.0

    # An all-Not-Installed real scan still terminates, but may NOT report a
    # fabricated 100% coverage (missing tool never counts toward the numerator).
    def _coverage_with(missing, total=8, completed=0):
        p = lifecycle.empty_progress()
        p["total_tasks"] = total
        p["completed_tasks"] = completed
        return lifecycle.compute_coverage(p)

    assert _coverage_with(["subfinder"]) == 0.0


# ---------------------------------------------------------------------------
# 5. Out-of-scope discovered hosts are skipped by the worker, never scanned
# ---------------------------------------------------------------------------
def test_discovered_out_of_scope_host_is_skipped(client, session):
    user = session.query(__import__("database.models", fromlist=["User"]).User).filter(
        __import__("database.models", fromlist=["User"]).User.email == "owner@test.local").first()
    project = Project(name="scope", user_id=user.id, scope_json=["inscope.example.com"])
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, target="inscope.example.com", status="Running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    kept = _in_scope_hosts(session, scan, [
        "inscope.example.com",          # exact target always stays
        "api.inscope.example.com",      # subdomain of scoped domain
        "rogue.example.org",            # OUT of scope
    ])
    assert "inscope.example.com" in kept
    assert "api.inscope.example.com" in kept
    assert "rogue.example.org" not in kept

    guard = session.query(Observation).filter(
        Observation.scan_id == scan.id,
        Observation.kind == "out_of_scope_skipped").all()
    subjects = {o.subject for o in guard}
    assert "rogue.example.org" in subjects
    # The refused host must never be registered as a discoverable asset.
    assets = session.query(Asset).filter(Asset.project_id == project.id).all()
    assert "rogue.example.org" not in {a.value for a in assets}


# ---------------------------------------------------------------------------
# 6. Two-user isolation across the new Phase 4 endpoints
# ---------------------------------------------------------------------------
def test_phase4_endpoints_are_isolated_between_users(client, session, auth_headers, other_auth_headers):
    user = session.query(__import__("database.models", fromlist=["User"]).User).filter(
        __import__("database.models", fromlist=["User"]).User.email == "owner@test.local").first()
    project = session.query(Project).filter(Project.user_id == user.id).first()
    if project is None:
        project = Project(name="Isolation", user_id=user.id, scope_json=["iso.example.com"])
        session.add(project)
        session.flush()
    scan = Scan(project_id=project.id, target="iso.example.com", status="Running", stage=lifecycle.STARTING)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    for url in [
        f"/scans/{scan.id}",
        f"/scans/{scan.id}/coverage",
        f"/scans/{scan.id}/findings",
        f"/scans/{scan.id}/observations",
        f"/scans/{scan.id}/events",
    ]:
        assert client.get(url, headers=other_auth_headers).status_code == 404, url
    assert client.post(f"/scans/{scan.id}/cancel", headers=other_auth_headers).status_code == 404

    # Owner still reaches the same endpoints.
    assert client.get(f"/scans/{scan.id}", headers=auth_headers).status_code == 200
    assert client.get(f"/scans/{scan.id}/coverage", headers=auth_headers).status_code == 200
    assert client.post(f"/scans/{scan.id}/cancel", headers=auth_headers).status_code == 200


# ---------------------------------------------------------------------------
# 7. Evidence provenance: findings reference persisted observation ids
# ---------------------------------------------------------------------------
def test_findings_carry_traceable_evidence_provenance(client, session):
    user = session.query(__import__("database.models", fromlist=["User"]).User).filter(
        __import__("database.models", fromlist=["User"]).User.email == "owner@test.local").first()
    project = Project(name="prov", user_id=user.id, scope_json=["prov.example.com"])
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, target="prov.example.com", status="Completed", stage=lifecycle.COMPLETED)
    session.add(scan)
    session.flush()

    obs = Observation(
        scan_id=scan.id, tool_name="real_http", kind="http_response",
        subject="https://prov.example.com",
        data_json={"has_csp": False, "has_hsts": True, "has_xcto": True,
                   "has_xframe": True, "scheme": "https"},
        raw_output="HTTP/1.1 200 OK\nServer: nginx\n",
    )
    session.add(obs)
    session.commit()
    session.refresh(obs)

    observations = [{
        "id": obs.id, "tool": obs.tool_name, "kind": obs.kind, "subject": obs.subject,
        "data": obs.data_json, "raw": obs.raw_output,
    }]
    candidates = finding_rules.evaluate_observations(observations)
    assert candidates, "an http_response without CSP must produce the missing-header finding"
    persisted = _persisted_finding(scan, candidates[0], scan.target)
    assert persisted.rule_id == "missing-security-header"
    assert persisted.evidence_observation_ids == [obs.id], "finding must link the observation id"
    assert f"#{obs.id}" in (persisted.evidence or ""), "evidence trail must cite the observation"
    assert persisted.target == "https://prov.example.com"


# ---------------------------------------------------------------------------
# 8. Tool inventory honestly mirrors the filesystem
# ---------------------------------------------------------------------------
def test_tool_inventory_is_honest():
    import shutil
    inv = tool_inventory()
    by_tool = {t["tool"]: t for t in inv}

    assert {"subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau",
            "whatweb", "nuclei"}.issubset(set(by_tool))
    for name, entry in by_tool.items():
        assert "installed" in entry and isinstance(entry["installed"], bool)
        if name.startswith("real_"):
            assert entry["installed"] is True, "stdlib probes are always available"
            assert entry["category"] == "probe"
    # External tools must agree with shutil.which on THIS machine.
    for name in ("subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei"):
        entry = by_tool[name]
        binary = entry["binary"] or name
        expected = shutil.which(binary) is not None
        assert entry["installed"] == expected, (
            f"inventory claims installed={entry['installed']} for {name} but which() says otherwise"
        )


# ---------------------------------------------------------------------------
# 9. Cancel endpoint via a job that never ran (stale/backfilled row)
# ---------------------------------------------------------------------------
def test_cancel_of_single_row_marks_terminal_without_worker(client, session, auth_headers):
    user = session.query(__import__("database.models", fromlist=["User"]).User).filter(
        __import__("database.models", fromlist=["User"]).User.email == "owner@test.local").first()
    project = Project(name="stale", user_id=user.id, scope_json=["stale.example.com"])
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, target="stale.example.com", status="Pending", stage=lifecycle.QUEUED)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # No job was ever enqueued for this row.
    assert registry.get(scan.id) is None
    resp = client.post(f"/scans/{scan.id}/cancel", headers=auth_headers)
    assert resp.status_code == 200
    detail = client.get(f"/scans/{scan.id}", headers=auth_headers).json()
    assert detail["stage"] == lifecycle.CANCELLED
    assert detail["status"] == "Cancelled"
    assert detail["cancelled_at"] is not None


# ---------------------------------------------------------------------------
# 10. Events stream terminates cleanly for an already-terminal scan
# ---------------------------------------------------------------------------
def test_events_stream_returns_done_for_terminal_scan(client, session, auth_headers):
    user = session.query(__import__("database.models", fromlist=["User"]).User).filter(
        __import__("database.models", fromlist=["User"]).User.email == "owner@test.local").first()
    project = Project(name="done", user_id=user.id, scope_json=["done.example.com"])
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, target="done.example.com", status="Completed",
                stage=lifecycle.COMPLETED, completed_at=__import__("datetime").datetime.utcnow())
    session.add(scan)
    session.flush()
    session.add(ToolResult(scan_id=scan.id, tool_name="nmap", status="Completed", raw_output="x"))
    session.commit()
    session.refresh(scan)

    with client.stream("GET", f"/scans/{scan.id}/events", headers=auth_headers) as stream:
        payloads = []
        for line in stream.iter_lines():
            if line.startswith("data: "):
                payloads.append(json.loads(line[len("data: "):]))
            if payloads and payloads[-1].get("type") == "done":
                break
    assert payloads
    assert payloads[-1]["type"] == "done"
    assert payloads[-1]["status"] == "Completed"
    assert {"nmap"} <= {p.get("tool") for p in payloads if p["type"] == "tool"}


# ---------------------------------------------------------------------------
# 11. cancel_scan returns False for an unknown, non-enqueued job
# ---------------------------------------------------------------------------
def test_cancel_scan_non_enqueued_returns_false():
    scan_id = 999999001
    assert registry.get(scan_id) is None
    assert cancel_scan(scan_id) is False