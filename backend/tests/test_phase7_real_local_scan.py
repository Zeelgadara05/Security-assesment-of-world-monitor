"""Phase 7 mandatory real-local-scan tests (appendix, Phase 7).

Unlike the hermetic suite, these tests exercise the REAL execution chain with
no stub on probes, adapters, legacy scanners or the Phase 5 engine:

  * a genuine local HTTP fixture is served over a real socket on port 80
    (the pipeline's stdlib probes connect to the configured HTTP port);
  * ``orchestrate_scan_phase7(..., simulation=False)`` runs the full 13-stage
    pipeline against it, performing real DNS/TCP/HTTP requests on loopback;
  * findings are asserted to be derived ONLY from persisted observations, and
    every tool that the machine cannot satisfy (missing binary) is recorded as
    ``not_installed`` with zero observations -- the scan may never claim full
    completion ("completed") while a planned tool could not run.

The fixture is skipped (not faked) when the loopback HTTP port cannot be
bound, so the test never fabricates a socket.
"""

import datetime
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import socket

from app.orchestration import pipeline
from app.orchestration import state as SM
from app.orchestration.stages import plan_tasks
from app.tools.inventory import tool_inventory
from app.tools import scanner_tools
from database.connection import SessionLocal
from database.models import (FindingObservationLink, FindingValidation,
                             MLInference, Observation, Project, Scan, ScanEvent,
                             ScanStage, ToolExecution, ToolResult, User,
                             Vulnerability)

HTTP_PORT = 80

_HTML = b"""<!doctype html>
<html>
<head><title>Local fixture</title></head>
<body>
  <h1>phase7 local fixture</h1>
  <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    def _respond(self):
        self.send_response(200)
        self.send_header("Server", "FixtureServer/1.2")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_HTML)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(_HTML)

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def local_http_fixture():
    try:
        server = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _Handler)
    except OSError as exc:
        pytest.skip(
            f"loopback HTTP port {HTTP_PORT} is not bindable here "
            f"({exc}); real-local-scan tests cannot run honestly.")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()


def _installed_names() -> set[str]:
    return {t["tool"] for t in tool_inventory() if t["installed"]}


@pytest.fixture(scope="module")
def real_scan(session, local_http_fixture):
    """Run one real phase7 scan against the local fixture; return scan id."""
    owner = User(id=f"p7real-{uuid.uuid4().hex[:8]}",
                 email=f"p7real-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7real", user_id=owner.id, scope_json=["127.0.0.1"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="127.0.0.1", status="Pending",
                stage="queued", state="created")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    scan_id = scan.id

    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        assert scan is not None
        assert SM.is_terminal(scan.state or ""), f"expected terminal, got {scan.state}"
        assert scan.completed_at is not None
    finally:
        db.close()
    return scan_id


def _read(scan_id):
    db = SessionLocal()
    try:
        return db.query(Scan).filter(Scan.id == scan_id).first()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 1. the full honest chain against a real local fixture
# ---------------------------------------------------------------------------
def test_real_local_scan_full_honest_chain(real_scan):
    scan_id = real_scan
    scan = _read(scan_id)
    db = SessionLocal()
    try:
        obs = db.query(Observation).filter(Observation.scan_id == scan_id).all()
        kinds = {o.kind for o in obs}
        # real stdlib probes performed real loopback requests
        assert "http_response" in kinds, kinds
        assert "dns_record" in kinds, kinds
        assert "tcp_open" in kinds, kinds
        http_resp = next(o for o in obs if o.kind == "http_response")
        data = http_resp.data_json or {}
        assert data.get("url") == "http://127.0.0.1"
        assert data.get("status_code") == 200
        assert bool(data.get("has_csp")) is False  # fixture sends no CSP
        assert "body_match" in kinds, "jquery body fact must be observed"

        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        assert findings, "real observations must produce real findings"
        ids = {o.id for o in obs}
        for f in findings:
            assert f.evidence_observation_ids, \
                f"every finding cites evidence: {f.rule_id} {f.title} src={f.source_test} status={f.status}"
            assert all(i in ids for i in (f.evidence_observation_ids or [])), \
                "finding evidence must reference persisted observations of this scan"
        rules = {f.rule_id for f in findings}
        assert {"missing-security-header", "outdated-jquery"} <= rules, rules
        outdated = next(f for f in findings if (
            (f.rule_id or "").startswith("outdated-jquery")))
        assert "1.12.4" in (outdated.title or "")

        # deterministic validator verdicts for confirmed findings
        validations = db.query(FindingValidation).filter(
            FindingValidation.scan_id == scan_id).all()
        confirmed = [v for v in validations if v.status == "confirmed" and v.finding_id]
        assert confirmed, "confirmed findings must carry confirmed validator verdicts"
        assert db.query(FindingObservationLink).filter(
            FindingObservationLink.finding_id.in_([f.id for f in findings])).count() > 0

        # finding lifecycle: every finding has history + status
        from app.assess import finding_lifecycle as lifecycle
        for f in findings:
            assert (f.status or lifecycle.STATUS_CONFIRMED) in (
                lifecycle.STATUS_CONFIRMED, lifecycle.STATUS_CANDIDATE)
            assert (f.state or "NEW") == "NEW"

        # typed event stream is complete and ordered
        events = db.query(ScanEvent).filter(
            ScanEvent.scan_id == scan_id).order_by(ScanEvent.id).all()
        types_seen = {e.event_type for e in events}
        assert {"state", "stage", "tool", "preflight", "coverage", "done"} <= types_seen
        done = [e.data for e in events if e.event_type == "done"]
        assert done and done[-1].get("state") == scan.state
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)

        # 13-stage ledger
        stages = db.query(ScanStage).filter(
            ScanStage.scan_id == scan_id).order_by(ScanStage.id).all()
        assert len(stages) == 13
        assert [s.name for s in stages][0] == "PRECHECK"
        assert [s.name for s in stages][-1] == "REPORTING"

        # advisory is advisory-only; no model ever enters the record
        ml = db.query(MLInference).filter(MLInference.scan_id == scan_id).all()
        assert ml and ml[0].status == "advisory_only" and ml[0].model_name is None
        advisory = (ml[0].advisory_json or {})
        assert (advisory.get("tool_gaps") or []), "missing tools must appear as gaps"

        # report is generated with the execution platform trail
        from database.models import Report
        reports = db.query(Report).filter(Report.scan_id == scan_id).all()
        assert reports
        payload = reports[0].json_content
        assert payload["execution_platform_version"] == "phase7"
        trail = payload["execution_trail"]
        assert len(payload["stages"]) == 13
        assert payload["findings"]
        assert payload["preflight"]["runnable"] is True
        assert (payload["preflight"].get("missing") or []), \
            "preflight must record the unconsumable tools honestly"
        assert len(trail.get("tools") or []) == len(plan_tasks({})) - (
            len([t for t in plan_tasks({}) if t.startswith("stage:")]))
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 2. missing-tools environment: gaps, never a fabricated completion
# ---------------------------------------------------------------------------
def test_missing_tools_are_gaps_never_successes(real_scan):
    scan_id = real_scan
    scan = _read(scan_id)
    db = SessionLocal()
    try:
        planned = {t.split(":", 1)[1] for t in plan_tasks({}) if t.startswith("tool:")}
        installed = _installed_names()
        missing_planned = sorted(planned - installed)

        executions = {
            ex.tool: ex
            for ex in db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        }
        assert set(planned) == set(executions), "every planned tool gets an execution row"

        for tool in missing_planned:
            ex = executions[tool]
            assert ex.status == "not_installed", \
                f"{tool} is missing but recorded as {ex.status}"
            assert (ex.parsed_observations or 0) == 0, \
                f"{tool} produced observations despite a missing binary"
            tr = db.query(ToolResult).filter(
                ToolResult.scan_id == scan_id, ToolResult.tool_name == tool).one()
            assert tr.status == scanner_tools.STATE_NOT_INSTALLED

        for tool in installed & planned:
            assert executions[tool].status == "completed"

        progress = scan.progress or {}
        failed = progress.get("failed_tasks") or 0
        assert failed == len(missing_planned), \
            f"failed_tasks {failed} must equal missing tools {len(missing_planned)}"
        assert progress["percent"] < 100.0
        assert (scan.coverage or 100) < 100.0

        if missing_planned:
            assert scan.state == SM.COMPLETED_WITH_GAPS, \
                "missing tools must never end in a clean 'completed'"
            assert scan.status == "Partially Completed"
        else:
            assert scan.state == SM.COMPLETED

        # preflight snapshot mirrors the executions
        pre = scan.preflight_json or {}
        assert set(pre.get("missing") or []) .issuperset(set(missing_planned))
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 3. Phase 8.5: the real report exposes SIH-area coverage + provenance
# ---------------------------------------------------------------------------
def test_real_scan_report_exposes_sih_coverage_and_provenance(real_scan):
    scan_id = real_scan
    from app.reporting import builder

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        report = builder.build(db, scan)
        payload = report.json_content

        sih = payload["sih_coverage"]
        assert sih["framework"] == "SIH26163"
        assert len(sih["areas"]) == 7
        exercised = {a["key"] for a in sih["areas"] if a["executed"] > 0}
        assert exercised, "real assessment ledger must exercise at least one SIH area"
        assert exercised & {"client_side", "secure_communication", "data_protection"}, exercised

        provenances = {f["provenance"] for f in payload["findings"]}
        assert "validated" in provenances, "real validators must yield validated findings"

        assert "SIH26163 Security-Area Coverage" in report.markdown
        assert "**Provenance:** validated" in report.markdown
    finally:
        db.close()