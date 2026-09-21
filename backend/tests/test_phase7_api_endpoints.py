"""Phase 7 API endpoints.

Exercises the new scan endpoints (state, stages, executions, readiness,
typed-events, ml-advisory, compare, retry) against the throwaway database.
Rows are seeded directly so the tests stay hermetic: no background worker is
needed and no network/tool is touched.  Ownership isolation is asserted through
the second (non-owner) authenticated user.
"""

import datetime

from database.connection import SessionLocal
from database.models import (
    MLInference,
    Scan,
    ScanEvent,
    ScanStage,
    ToolExecution,
    ToolReadiness,
    User,
    Vulnerability,
)
from app.core.auth import get_or_create_user_project
from app.orchestration import state as phase7_state


def _owner_user(db):
    return db.query(User).filter(User.email == "owner@test.local").first()


def _seed_scan(db, user, target="example.com", state=phase7_state.CREATED,
               status="Pending"):
    project = get_or_create_user_project(db, user)
    scan = Scan(
        project_id=project.id,
        target=target,
        status=status,
        stage="queued",
        state=state,
        scan_config={},
        logs="[System] Seeded phase7 endpoint test.\n",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _terminal_scan(db, user, target="example.com"):
    scan = _seed_scan(db, user, target=target, state=phase7_state.COMPLETED,
                      status="Completed")
    scan.stage = "completed"
    scan.completed_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(scan)
    return scan


def _seed_finding(db, scan, fingerprint):
    db.add(Vulnerability(
        scan_id=scan.id,
        target=scan.target,
        title=f"finding {fingerprint}",
        severity="High",
        state="NEW",
        status="confirmed",
        rule_id="xss.reflected",
        description="seeded finding for compare",
        fingerprint=fingerprint,
        dedup_key=fingerprint,
        evidence_observation_ids=[999],
    ))
    db.commit()


def test_state_stages_executions_and_ownership_isolation(client, auth_headers,
                                                         other_auth_headers, session):
    user = _owner_user(session)
    scan = _terminal_scan(session, user)

    session.add(ScanStage(
        scan_id=scan.id, name="PRECHECK", order=1, status="completed",
        tools=["real_dns", "real_tcp"], tests_executed=0, observations=2,
        duration_ms=12,
    ))
    session.add(ScanStage(
        scan_id=scan.id, name="REPORTING", order=13, status="completed",
        tools=[], duration_ms=3,
    ))
    session.add(ToolExecution(
        scan_id=scan.id, stage="PASSIVE_RECON", tool="subfinder", adapter="legacy",
        attempt=1, status="completed", target=scan.target,
        parsed_observations=0, duration_ms=50, stdout_truncated=False,
        started_at=datetime.datetime.utcnow(), finished_at=datetime.datetime.utcnow(),
    ))
    session.add(ToolExecution(
        scan_id=scan.id, stage="PASSIVE_RECON", tool="subfinder", adapter="legacy",
        attempt=2, status="timeout", target=scan.target,
        parsed_observations=0, duration_ms=30000, stdout_truncated=True,
        termination_reason="stub timeout",
    ))
    session.commit()

    # state
    resp = client.get(f"/scans/{scan.id}/state", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan.id
    assert body["state"] == phase7_state.COMPLETED
    assert body["terminal"] is True
    assert body["queue_waited_ms"] is None

    # stages
    resp = client.get(f"/scans/{scan.id}/stages", headers=auth_headers)
    assert resp.status_code == 200
    stages = resp.json()
    assert len(stages) == 2
    assert stages[0]["name"] == "PRECHECK"
    assert stages[0]["status"] == "completed"
    assert stages[1]["name"] == "REPORTING"

    # executions
    resp = client.get(f"/scans/{scan.id}/executions", headers=auth_headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 2
    first = rows[0]
    assert first["tool"] == "subfinder"
    assert first["adapter"] == "legacy"
    assert first["attempt"] == 1
    assert first["status"] == "completed"
    assert rows[1]["status"] == "timeout"
    assert rows[1]["termination_reason"] == "stub timeout"

    # ownership isolation: the other user cannot see this scan
    for path in (
        f"/scans/{scan.id}/state",
        f"/scans/{scan.id}/stages",
        f"/scans/{scan.id}/executions",
        f"/scans/{scan.id}/readiness",
        f"/scans/{scan.id}/typed-events",
        f"/scans/{scan.id}/ml-advisory",
        f"/scans/{scan.id}/compare?with_scan_id=1",
    ):
        resp = client.get(path, headers=other_auth_headers)
        assert resp.status_code == 404, (path, resp.status_code)

    resp = client.post(f"/scans/{scan.id}/retry", headers=other_auth_headers)
    assert resp.status_code == 404


def test_readiness_preflight_and_typed_events(client, auth_headers, session):
    user = _owner_user(session)
    scan = _seed_scan(session, user)
    scan.preflight_json = {"runnable": True, "installed": ["subfinder"],
                           "missing": ["nmap"], "disabled": []}
    session.add(ToolReadiness(
        scan_id=scan.id, tool="subfinder", status="installed",
        executable="/usr/bin/subfinder", version="v2.6.5", adapter="legacy",
        category="recon", enabled=True,
        checked_at=datetime.datetime.utcnow(),
    ))
    session.add(ToolReadiness(
        scan_id=scan.id, tool="nmap", status="missing", executable=None,
        version=None, adapter="external", category="service", enabled=True,
        reason="binary not found",
        checked_at=datetime.datetime.utcnow(),
    ))
    session.add(ScanEvent(scan_id=scan.id, event_type="state",
                          data={"state": phase7_state.QUEUED}, seq=1))
    session.add(ScanEvent(scan_id=scan.id, event_type="tool",
                          data={"tool": "subfinder", "status": "completed",
                                "attempt": 1}, seq=2))
    session.add(ScanEvent(scan_id=scan.id, event_type="done",
                          data={"state": phase7_state.COMPLETED}, seq=3))
    session.commit()

    resp = client.get(f"/scans/{scan.id}/readiness", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["preflight"]["runnable"] is True
    by_tool = {t["tool"]: t for t in body["tools"]}
    assert by_tool["subfinder"]["status"] == "installed"
    assert by_tool["subfinder"]["adapter"] == "legacy"
    assert by_tool["nmap"]["status"] == "missing"
    assert by_tool["nmap"]["reason"] == "binary not found"

    # typed events: paging and cursor semantics
    resp = client.get(f"/scans/{scan.id}/typed-events?limit=2",
                      headers=auth_headers)
    assert resp.status_code == 200
    page1 = resp.json()
    assert page1["has_more"] is True
    assert [e["seq"] for e in page1["events"]] == [1, 2]

    resp = client.get(
        f"/scans/{scan.id}/typed-events?cursor={page1['cursor']}&limit=10",
        headers=auth_headers)
    page2 = resp.json()
    assert page2["has_more"] is False
    assert [e["seq"] for e in page2["events"]] == [3]
    assert page2["events"][0]["data"]["state"] == phase7_state.COMPLETED

    # limit bounds
    resp = client.get(f"/scans/{scan.id}/typed-events?limit=2001",
                      headers=auth_headers)
    assert resp.status_code == 400


def test_ml_advisory_and_compare(client, auth_headers, session):
    user = _owner_user(session)
    scan = _seed_scan(session, user)
    session.add(MLInference(
        scan_id=scan.id,
        status="advisory_only",
        model_name=None,
        model_version=None,
        training_status="none",
        feature_schema_version="phase7-v1",
        advisory_json={
            "tool_gaps": [],
            "executed_tests": 0,
            "applicable_tests": 0,
            "recommendation": "deterministic advisory only; no model in play",
        },
        generated_at=datetime.datetime.utcnow(),
    ))
    session.commit()

    resp = client.get(f"/scans/{scan.id}/ml-advisory", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "advisory_only"
    assert body["model_name"] is None
    assert body["advisory"]["recommendation"].startswith("deterministic advisory")

    bare = _seed_scan(session, user, target="bare.example.com")
    resp = client.get(f"/scans/{bare.id}/ml-advisory", headers=auth_headers)
    assert resp.json()["advisory"] is None

    # compare: same target diff buckets
    a = _terminal_scan(session, user, target="ex.com")
    b = _terminal_scan(session, user, target="ex.com")
    _seed_finding(session, a, "fp-gone")
    _seed_finding(session, b, "fp-new")
    resp = client.get(f"/scans/{a.id}/compare?with_scan_id={b.id}",
                      headers=auth_headers)
    assert resp.status_code == 200
    diff = resp.json()
    assert diff["same_target"] is True
    assert diff["removed"] == ["fp-gone"]
    assert diff["added"] == ["fp-new"]
    assert "note" not in diff

    # compare: different targets carry an explicit warning note
    other = _terminal_scan(session, user, target="other.com")
    resp = client.get(f"/scans/{a.id}/compare?with_scan_id={other.id}",
                      headers=auth_headers)
    diff = resp.json()
    assert diff["same_target"] is False
    assert diff["note"]


def test_retry_only_terminal_scans_and_resets_state(client, auth_headers, session,
                                                    monkeypatch):
    user = _owner_user(session)
    calls = []
    from app.api import scans as scans_api
    monkeypatch.setattr(scans_api, "trigger_background_scan",
                        lambda scan_id, simulation, config: calls.append(
                            (scan_id, simulation, config)))

    scan = _terminal_scan(session, user)
    scan.preflight_json = {"runnable": True, "installed": [], "missing": []}
    scan.queue_waited_ms = 123
    scan.progress = {"completed_tasks": 24, "total_tasks": 24, "percent": 100.0}
    session.commit()

    resp = client.post(f"/scans/{scan.id}/retry", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan.id
    assert body["state"] == phase7_state.CREATED
    assert body["stage"] == "queued"
    assert body["status"] == "Pending"

    db = SessionLocal()
    try:
        reloaded = db.query(Scan).filter(Scan.id == scan.id).first()
        assert reloaded.state == phase7_state.CREATED
        assert reloaded.completed_at is None
        assert reloaded.queue_waited_ms is None
        assert reloaded.preflight_json is None
        assert reloaded.progress["total_tasks"] == 0
        assert "Retry requested" in (reloaded.logs or "")
    finally:
        db.close()

    assert len(calls) == 1 and calls[0][0] == scan.id

    # non-terminal scans cannot be retried
    running = _seed_scan(session, user, state=phase7_state.RUNNING,
                         status="Running")
    resp = client.post(f"/scans/{running.id}/retry", headers=auth_headers)
    assert resp.status_code == 409
    assert "non-terminal" in resp.json()["detail"]