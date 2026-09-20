"""Phase 7 preflight tests.

``build_preflight`` probes the real environment and persists ToolReadiness rows.
A missing binary must be recorded as missing (never as available), disabled
tools separated, an empty sanitized target blocks, and an empty toolset blocks.
"""

import uuid

import pytest

from app.orchestration import preflight
from database.connection import SessionLocal
from database.models import Project, Scan, ToolReadiness, User


def _make_scan(session, target="p7pre.example"):
    owner = User(id=f"p7pre-{uuid.uuid4().hex[:8]}", email=f"p7pre-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7pre", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def _inventory(installed: set[str]) -> list[dict]:
    out = []
    for tool in ("real_dns", "real_tcp", "real_http"):
        out.append({"tool": tool, "binary": None, "installed": True, "path": None,
                    "version": None, "category": "probe", "note": "stdlib probe"})
    for tool in ("subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau",
                 "whatweb", "nuclei", "ffuf", "nikto", "sqlmap", "testssl"):
        present = tool in installed
        out.append({"tool": tool, "binary": tool, "installed": present,
                    "path": f"/bin/{tool}" if present else None, "version": "1.0" if present else None,
                    "category": "recon", "note": None if present else f"{tool} not found on PATH"})
    return out


def test_preflight_records_installed_and_missing_honestly(monkeypatch, session):
    monkeypatch.setattr(preflight, "tool_inventory",
                        lambda: _inventory({"subfinder", "nmap", "real_dns"}))
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        snap = preflight.build_preflight(db, scan, {})
        db.commit()
        assert scan.preflight_json is not None
        assert "subfinder" in snap["installed"]
        assert "assetfinder" in snap["missing"]
        assert snap["disabled"] == ["ffuf", "nikto", "sqlmap", "testssl"]  # opt-in extras
        assert snap["runnable"] is True
        assert not snap["blocked_reasons"]

        rows = db.query(ToolReadiness).filter(ToolReadiness.scan_id == scan_id).all()
        by_tool = {r.tool: r for r in rows}
        assert by_tool["subfinder"].status == "installed"
        assert by_tool["nmap"].status == "installed"
        assert by_tool["assetfinder"].status == "missing"
        assert by_tool["assetfinder"].reason
        assert by_tool["real_http"].status == "installed"
        assert all(not r.enabled for r in rows if r.tool in ("ffuf", "nikto", "sqlmap", "testssl"))
    finally:
        db.close()


def test_preflight_separates_disabled_tools(monkeypatch, session):
    monkeypatch.setattr(preflight, "tool_inventory", lambda: _inventory(set()))
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        snap = preflight.build_preflight(db, scan, {"tools": {"subfinder": False}})
        db.commit()
        assert "subfinder" in snap["disabled"]
        assert "subfinder" not in snap["installed"]
        assert "subfinder" not in snap["missing"]
        assert snap["runnable"] is True  # stdlib probes always present
        rows = db.query(ToolReadiness).filter(ToolReadiness.scan_id == scan_id).all()
        sub = next(r for r in rows if r.tool == "subfinder")
        assert sub.status == "disabled"
    finally:
        db.close()


def test_preflight_blocks_on_unsafe_empty_target(monkeypatch, session):
    monkeypatch.setattr(preflight, "tool_inventory", lambda: _inventory({"subfinder"}))
    scan_id = _make_scan(session, target="")
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        snap = preflight.build_preflight(db, scan, {})
        db.commit()
        reasons = preflight.blocked(snap)
        assert any("empty" in r for r in reasons)
        assert scan.preflight_json["blocked_reasons"] == reasons
    finally:
        db.close()


def test_preflight_blocks_when_nothing_runnable(monkeypatch, session):
    def no_probes_inventory():
        return [{"tool": t, "binary": t, "installed": False, "path": None,
                 "version": None, "category": "recon", "note": "missing"} for t in
                ("subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei")]

    monkeypatch.setattr(preflight, "tool_inventory", no_probes_inventory)
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        snap = preflight.build_preflight(db, scan, {})
        db.commit()
        assert snap["runnable"] is False
        assert preflight.blocked(snap)
    finally:
        db.close()


def test_never_presents_missing_as_installed(monkeypatch, session):
    monkeypatch.setattr(preflight, "tool_inventory", lambda: _inventory(set()))
    scan_id = _make_scan(session)
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        snap = preflight.build_preflight(db, scan, {})
        db.commit()
        assert "nuclei" in snap["missing"]
        assert "nuclei" not in snap["installed"]
        assert snap["runnable"] is True  # probes keep it honest, but never claim nuclei
    finally:
        db.close()