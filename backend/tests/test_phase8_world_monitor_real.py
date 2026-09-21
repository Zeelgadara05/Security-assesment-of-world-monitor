"""Phase 8 World Monitor real end-to-end tests.

These run the *real* Phase 7 pipeline (``orchestrate_scan_phase7``,
``simulation=False``) with a World Monitor deployment served by a genuine
localhost HTTP fixture.  Nothing about the World Monitor path is stubbed: the
configured deployment is reached over real sockets and every fact it yields is
normalized through ``build_observation`` into the shared observation store.

The only thing the scan's *other* tools see is the loopback target itself, so
missing binaries and refused connections are recorded honestly as gaps.
"""
from __future__ import annotations

import uuid

import pytest

from app.orchestration import pipeline
from app.orchestration import state as SM
from database.connection import SessionLocal
from database.models import (Observation, Project, Scan, ToolExecution, User,
                             WorldMonitorTarget)
from tests.test_phase8_world_monitor_provider import OPENAPI_DOC, _make_server

WM_HOST = "127.0.0.1"

ROUTES = {
    "/": (200, {"Server": "WM-Prod/4.0"}, "<html>World Monitor console</html>"),
    "/api": (200, {"Content-Type": "application/json"}, {"status": "ok"}),
    "/openapi.json": (200, {"Content-Type": "application/json"}, OPENAPI_DOC),
}


@pytest.fixture(scope="module")
def wm_base():
    base, server = _make_server(ROUTES)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _make_scan(session, scan_config):
    owner = User(id=f"p8real-{uuid.uuid4().hex[:8]}", email=f"p8real-{uuid.uuid4().hex[:8]}@t.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p8real", user_id=owner.id, scope_json=[WM_HOST])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=WM_HOST, status="Pending",
                stage="queued", state="created", scan_config=dict(scan_config or {}), logs="")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def _wm_execution(db, scan_id):
    return (db.query(ToolExecution)
            .filter(ToolExecution.scan_id == scan_id,
                    ToolExecution.tool == "world_monitor_discovery").first())


def _wm_observations(db, scan_id):
    return (db.query(Observation)
            .filter(Observation.scan_id == scan_id,
                    Observation.tool_name == "world_monitor_discovery").all())


def test_explicit_config_flows_through_real_pipeline(session, wm_base):
    wm = {"base_url": wm_base, "api_base_url": f"{wm_base}/api",
          "openapi_url": f"{wm_base}/openapi.json"}
    scan_id = _make_scan(session, {"world_monitor": wm})
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        assert SM.is_terminal(scan.state or ""), scan.state

        ex = _wm_execution(db, scan_id)
        assert ex is not None, "the configured World Monitor tool must be planned and executed"
        assert ex.status == "completed"
        assert ex.adapter == "native_probe"
        assert (ex.parsed_observations or 0) >= 4

        obs = _wm_observations(db, scan_id)
        kinds = {o.kind for o in obs}
        assert "http_response" in kinds
        assert "api_route" in kinds
        routes = [o for o in obs if o.kind == "api_route"]
        assert len(routes) == 3
        assert all((o.data_json or {}).get("source") == "world_monitor" for o in obs)
    finally:
        db.close()


def test_registered_target_flows_through_real_pipeline(session, wm_base):
    scan_id = _make_scan(session, {})
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        target = WorldMonitorTarget(
            project_id=scan.project_id, base_url=wm_base,
            api_base_url=f"{wm_base}/api", openapi_url=f"{wm_base}/openapi.json")
        db.add(target)
        db.commit()
        db.refresh(target)
        scan.scan_config = {"world_monitor": {"target_id": target.id}}
        db.commit()
        db.refresh(scan)
        target_id = target.id
    finally:
        db.close()

    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        assert SM.is_terminal(scan.state or "")
        ex = _wm_execution(db, scan_id)
        assert ex is not None and ex.status == "completed"
        obs = _wm_observations(db, scan_id)
        assert obs
        assert any((o.data_json or {}).get("target_id") == target_id for o in obs)
    finally:
        db.close()


def test_unconfigured_scan_never_plans_world_monitor(session):
    scan_id = _make_scan(session, {})
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)
    db = SessionLocal()
    try:
        assert _wm_execution(db, scan_id) is None, \
            "a scan with no World Monitor reference must not plan the WM tool"
        assert _wm_observations(db, scan_id) == []
    finally:
        db.close()