"""Phase 7 tool execution ledger tests.

``execute_tool`` records one ToolExecution row per attempt and only reports a
terminal outcome that really happened: skipped/disabled, not_installed, timeout
+ retry then completed, cancellation.  It never fabricates a success.
"""

import types
import uuid

import pytest

from app.orchestration import executions
from app.tools import scanner_tools
from database.connection import SessionLocal
from database.models import Project, Scan, ToolExecution, ToolResult, User

_STATES = ("completed", "not_installed", "timeout", "parse_failed", "skipped", "failed")


def _make_scan(session, target="p7ex.example"):
    owner = User(id=f"p7ex-{uuid.uuid4().hex[:8]}", email=f"p7ex-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7ex", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def _fetch(scan_id):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        return scan
    finally:
        db.close()


def _executions_of(scan_id):
    db = SessionLocal()
    try:
        return db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
    finally:
        db.close()


def test_disabled_tool_is_skipped_with_an_execution_row(session):
    scan_id = _make_scan(session)
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(
            db, scan, "ffuf", {"tools": {"ffuf": False}}, None, {})
        assert result["status"] == "skipped"
        rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        assert len(rows) == 1 and rows[0].status == "skipped"
        assert rows[0].adapter  # honest about which runner kind was involved
        tr = db.query(ToolResult).filter(ToolResult.scan_id == scan_id)[0]
        assert tr.status == "Skipped"
    finally:
        db.close()


def test_legacy_missing_binary_is_not_installed_not_fabricated(monkeypatch, session):
    monkeypatch.setitem(
        executions._LEGACY_RUNNERS, "subfinder",
        lambda target: {"status": scanner_tools.STATE_NOT_INSTALLED, "log": ""},
    )
    scan_id = _make_scan(session)
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "subfinder", {}, None, {})
        assert result["status"] == scanner_tools.STATE_NOT_INSTALLED
        rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        assert len(rows) == 1 and rows[0].status == "not_installed"
        assert rows[0].error_code == "not_installed"
    finally:
        db.close()


def test_legacy_success_records_completed_execution(monkeypatch, session):
    monkeypatch.setitem(
        executions._LEGACY_RUNNERS, "subfinder",
        lambda target: {"status": "success", "subdomains": [], "log": "[subfinder] none"},
    )
    scan_id = _make_scan(session)
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "subfinder", {}, None, {})
        assert result["status"] == "success"
        rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        assert len(rows) == 1
        assert rows[0].status == "completed"
        assert rows[0].stage  # mapped to a pipeline stage
    finally:
        db.close()


class _Result:
    def __init__(self, status, observations=None, **kw):
        self.status = status
        self.observations = observations or []
        self.command = kw.get("command") or ["nmap", "-T4"]
        self.exit_code = kw.get("exit_code")
        self.error = kw.get("error")
        self.duration_ms = kw.get("duration_ms", 12)
        self.raw_output = kw.get("raw_output") or "[fake]"


class _SequenceAdapter:
    statuses: list[str]

    def run(self, target, simulation=False, options=None, cancel_check=None):
        status = self.statuses.pop(0)
        if status == scanner_tools.STATE_COMPLETED:
            return _Result(scanner_tools.STATE_COMPLETED)
        return _Result(status, error=f"simulated {status}")


def test_adapter_timeout_then_success_retries_once(monkeypatch, session):
    adapter = _SequenceAdapter()
    adapter.statuses = [scanner_tools.STATE_TIMEOUT, scanner_tools.STATE_COMPLETED]
    monkeypatch.setattr(executions, "get_adapter", lambda tool: adapter)
    scan_id = _make_scan(session)
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "nmap", {}, None, {})
        assert result["status"] == "success"
        rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        assert [r.attempt for r in rows] == [1, 2]
        assert [r.status for r in rows] == ["timeout", "completed"]
        assert rows[1].duration_ms is not None
    finally:
        db.close()


def test_adapter_failure_is_only_retried_on_transients(monkeypatch, session):
    adapter = _SequenceAdapter()
    adapter.statuses = [scanner_tools.STATE_PARSE_FAILED]
    monkeypatch.setattr(executions, "get_adapter", lambda tool: adapter)
    scan_id = _make_scan(session)
    scan = _fetch(scan_id)
    db = SessionLocal()
    try:
        result = executions.execute_tool(db, scan, "nmap", {}, None, {})
        assert result["status"] == scanner_tools.STATE_PARSE_FAILED
        rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        assert [r.status for r in rows] == ["parse_failed"]
        assert rows[0].error_code == "parse_failed"
    finally:
        db.close()


def test_cancelled_job_aborts_before_execution(session):
    scan_id = _make_scan(session)
    scan = _fetch(scan_id)
    db = SessionLocal()
    job = types.SimpleNamespace(is_cancelled=lambda: True)
    from app.workers.tasks import ScanCancelled
    try:
        with pytest.raises(ScanCancelled):
            executions.execute_tool(db, scan, "real_dns", {}, job, {})
        assert db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).count() == 0
    finally:
        db.close()


def test_clip_bounds_output():
    big = "x" * 20000
    clipped = executions.clip(big)
    assert len(clipped) == 12000 + len("\n...[truncated]")
    assert clipped.endswith("...[truncated]")
    assert executions.clip("tiny") == "tiny"