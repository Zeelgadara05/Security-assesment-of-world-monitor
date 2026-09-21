"""World Monitor discovery tool in the real execution pipeline (Phase 8).

``world_monitor_discovery`` is a native probe: when the scan configuration
carries a World Monitor deployment reference it probes that deployment over
real sockets and normalizes every fact into the shared observation pipeline;
when nothing is configured it is recorded as an honest ``skipped`` (never a
fabricated success).
"""
from __future__ import annotations

import uuid

import pytest

from app.orchestration import executions
from app.observations import types as obs_types
from database.connection import SessionLocal
from database.models import Observation, Project, Scan, ToolExecution, ToolResult, User, WorldMonitorTarget
from tests.test_phase8_world_monitor_provider import OPENAPI_DOC, _make_server

ROUTES = {
    "/": (200, {"Server": "WM-Server/3.1"}, "<html>World Monitor</html>"),
    "/api": (200, {"Content-Type": "application/json"}, {"ok": True}),
    "/openapi.json": (200, {"Content-Type": "application/json"}, OPENAPI_DOC),
    "/escape": (302, {"Location": "http://evil.example/internal"}, ""),
}


@pytest.fixture()
def wm_base():
    base, server = _make_server(ROUTES)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _make_scan(session, target="wm-tool.example", scan_config=None):
    owner = User(id=f"wmtool-{uuid.uuid4().hex[:8]}", email=f"wmtool-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="wm-tool", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending",
                scan_config=dict(scan_config or {}))
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def _fetch(scan_id):
    db = SessionLocal()
    try:
        return db.query(Scan).filter(Scan.id == scan_id).first()
    finally:
        db.close()


def _wm_obs(db, scan_id):
    return db.query(Observation).filter(
        Observation.tool_name == "world_monitor_discovery",
        Observation.scan_id == scan_id).all()


def test_not_configured_is_honest_skip(session):
    scan_id = _make_scan(session, scan_config={})
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "world_monitor_discovery", {}, None, {})
        assert result["status"] == "skipped"
        row = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).first()
        assert row.status == "skipped"
        assert row.adapter == "native_probe"
        tr = db.query(ToolResult).filter(ToolResult.scan_id == scan_id)[0]
        assert tr.status == "Skipped"
        obs = db.query(Observation).filter(Observation.scan_id == scan_id).all()
        assert any(o.kind == "wm_not_configured" for o in obs)
    finally:
        db.close()


def test_explicit_config_probes_and_persists(session, wm_base):
    wm = {"base_url": wm_base, "api_base_url": f"{wm_base}/api",
          "openapi_url": f"{wm_base}/openapi.json"}
    scan_id = _make_scan(session, scan_config={"world_monitor": wm})
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "world_monitor_discovery",
                                         {"world_monitor": wm}, None, {})
        assert result["status"] == "success"
        ex = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).first()
        assert ex.status == "completed"
        assert ex.parsed_observations >= 4
        rows = _wm_obs(db, scan_id)
        assert len(rows) >= 4
        by_kind = {}
        for r in rows:
            by_kind.setdefault(r.kind, []).append(r.data_json or {})
        assert len(by_kind.get("http_response", [])) == 1
        assert len(by_kind.get("api_route", [])) == 3
        sample = by_kind["api_route"][0]
        assert sample.get("source") == "world_monitor"
        assert sample.get("source_type") == "api_discovery"
        assert sample.get("method") in ("GET", "POST")
        assert sample.get("path")
        health = by_kind["http_response"][0]
        assert health.get("reachable") is True
        assert health.get("source") == "world_monitor"
    finally:
        db.close()


def test_registered_target_reference(session, wm_base):
    scan_id = _make_scan(session, scan_config={})
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        target = WorldMonitorTarget(
            project_id=scan.project_id, base_url=wm_base,
            api_base_url=f"{wm_base}/api", openapi_url=f"{wm_base}/openapi.json",
        )
        db.add(target)
        db.commit()
        db.refresh(target)
        scan.scan_config = {"world_monitor": {"target_id": target.id}}
        db.commit()
        db.refresh(scan)
        result = executions.execute_tool(db, scan, "world_monitor_discovery",
                                         {"world_monitor": {"target_id": target.id}}, None, {})
        assert result["status"] == "success"
        rows = _wm_obs(db, scan_id)
        assert any(d.get("target_id") == target.id for d in
                   [(r.data_json or {}) for r in rows])
    finally:
        db.close()


def test_cross_host_explicit_config_is_refused(session, wm_base):
    wm = {"base_url": wm_base, "api_base_url": "http://evil.example/api"}
    scan_id = _make_scan(session, scan_config={"world_monitor": wm})
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "world_monitor_discovery",
                                         {"world_monitor": wm}, None, {})
        assert result["status"] == "skipped"
        rows = db.query(Observation).filter(Observation.scan_id == scan_id).all()
        assert any(o.kind == "wm_not_configured" for o in rows)
    finally:
        db.close()


def test_redirect_out_of_scope_recorded_not_followed(session, wm_base):
    wm = {"base_url": f"{wm_base}/escape"}
    scan_id = _make_scan(session, scan_config={"world_monitor": wm})
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "world_monitor_discovery",
                                         {"world_monitor": wm}, None, {})
        assert result["status"] == "success"
        rows = _wm_obs(db, scan_id)
        errors = [r for r in rows if r.observation_type == obs_types.OBS_ERROR]
        assert errors, "blocked probe must be recorded as an error observation"
        combined = " ".join(str((r.data_json or {}).get("error", "")) for r in errors)
        assert "blocked" in combined.lower()
    finally:
        db.close()


def test_preflight_flags_tool_as_native_probe():
    from app.orchestration.preflight import _PROBE_TOOLS
    from app.tools.inventory import tool_inventory
    assert "world_monitor_discovery" in _PROBE_TOOLS
    entries = {e["tool"]: e for e in tool_inventory()}
    assert entries["world_monitor_discovery"]["installed"] is True
