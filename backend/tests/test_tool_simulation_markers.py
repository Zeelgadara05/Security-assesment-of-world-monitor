"""Unit tests for the simulation marker on persisted tool results.

The full workflow test covers the simulated path; these tests lock down the
marker helper itself and assert that real (non-simulated) output is stored
verbatim.
"""

from app.agents.workflow import save_tool_result
from database.connection import seed_defaults
from database.models import Project, Scan, ToolResult
from database.connection import SessionLocal


def _new_scan(db):
    seed_defaults()
    project = db.query(Project).filter(Project.name == "Default Sandbox").first()
    scan = Scan(
        project_id=project.id,
        target="marker.example.com",
        status="Pending",
        logs="",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
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