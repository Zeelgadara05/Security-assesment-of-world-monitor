"""Unit tests for the simulation marker on persisted tool results and the
per-state mapping of adapter output to ToolResult.status.
"""

import uuid

from app.agents.workflow import save_tool_result
from app.tools.scanner_tools import (
    STATE_EXECUTION_FAILED,
    STATE_NOT_INSTALLED,
    STATE_PARSE_FAILED,
    STATE_TIMEOUT,
)
from database.connection import SessionLocal
from database.models import Project, Scan, ToolResult, User


def _make_user_project(session) -> tuple[User, Project]:
    suffix = uuid.uuid4().hex[:8]
    user = User(id=f"marker-{suffix}", email=f"marker-{suffix}@test.local", role="user")
    session.add(user)
    session.commit()
    project = Project(name="Marker Project", user_id=user.id, scope_json=[])
    session.add(project)
    session.commit()
    session.refresh(project)
    return user, project


def _new_scan(session):
    _, project = _make_user_project(session)
    scan = Scan(
        project_id=project.id,
        target="marker.example.com",
        status="Pending",
        logs="",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def test_simulated_output_gets_prefix(session):
    scan = _new_scan(session)
    save_tool_result(
        session, scan.id, "probe", {"status": "success", "log": "raw line 1"}, simulated=True
    )
    row = session.query(ToolResult).filter(ToolResult.scan_id == scan.id).first()
    assert row.raw_output.startswith("[SIMULATED]")
    assert "raw line 1" in row.raw_output


def test_real_output_stored_verbatim(session):
    scan = _new_scan(session)
    save_tool_result(
        session, scan.id, "probe-real", {"status": "success", "log": "raw line 1"}, simulated=False
    )
    row = session.query(ToolResult).filter(ToolResult.scan_id == scan.id).first()
    assert row.raw_output == "raw line 1"
    assert not row.raw_output.startswith("[SIMULATED]")


def test_marker_respected_per_call(session):
    scan = _new_scan(session)
    save_tool_result(
        session, scan.id, "a", {"status": "success", "log": "same"}, simulated=True
    )
    save_tool_result(
        session, scan.id, "b", {"status": "success", "log": "same"}, simulated=False
    )
    a = session.query(ToolResult).filter(ToolResult.tool_name == "a").first()
    b = session.query(ToolResult).filter(ToolResult.tool_name == "b").first()
    assert a.raw_output.startswith("[SIMULATED]")
    assert b.raw_output == "same"


def test_adapter_states_map_to_tool_result_status(session):
    """Non-success adapter results must map to explicit persisted states,
    never to a fabricated success."""
    scan = _new_scan(session)
    cases = {
        "notinst": (STATE_NOT_INSTALLED, STATE_NOT_INSTALLED),
        "timeout": (STATE_TIMEOUT, STATE_TIMEOUT),
        "parse": (STATE_PARSE_FAILED, STATE_PARSE_FAILED),
        "execfail": (STATE_EXECUTION_FAILED, "Failed"),
        "success": ("success", "Completed"),
    }
    for i, (tool, (in_state, out_state)) in enumerate(cases.items()):
        save_tool_result(
            session, scan.id, f"t{i}-{tool}",
            {"status": in_state, "log": f"state {in_state}"}, simulated=False,
        )
        row = session.query(ToolResult).filter(ToolResult.tool_name == f"t{i}-{tool}").first()
        assert row.status == out_state, f"{tool}: got {row.status!r}, want {out_state!r}"