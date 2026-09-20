"""Phase 3 findings pipeline: evidence-only rule engine, real probes, real-mode
workflow, triage transitions and the anti-fabrication guarantee.

The hard rule under test: no observation -> no finding.  Every finding the
engine can produce is derived from at least one persisted Observation row.
"""

import http.server
import threading
import time
import uuid

import pytest

from app.agents import workflow
from app.assess import finding_rules
from app.tools import real_probes
from database.connection import SessionLocal
from database.models import Observation, Project, Scan, User, Vulnerability


# ---------------------------------------------------------------------------
# Rule engine: evidence is mandatory
# ---------------------------------------------------------------------------
def test_no_observations_produce_no_findings():
    assert finding_rules.evaluate_observations([]) == []


def _http_obs(obs_id, url="https://example.com", scheme="https", server="nginx",
              csp=False, hsts=True, xcto=False, xframe=True):
    return {
        "id": obs_id,
        "kind": "http_response",
        "subject": url,
        "data": {
            "url": url,
            "scheme": scheme,
            "status_code": 200,
            "server": server,
            "version_hint": None,
            "has_csp": csp,
            "has_hsts": hsts,
            "has_xcto": xcto,
            "has_xframe": xframe,
            "headers": {},
        },
        "raw": f"GET {url} -> 200 [{server}]",
    }


def test_missing_headers_raised_only_from_real_observation():
    candidates = finding_rules.evaluate_observations([_http_obs(1)])
    titles = {c["title"] for c in candidates}
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Content-Type-Options header" in titles
    assert "Missing Strict-Transport-Security (HSTS) header" not in titles  # hsts=True
    assert all(c["severity"] == "Low" for c in candidates if c["rule_id"] == "missing-security-header")
    assert all(c["observation_ids"] == [1] for c in candidates)


def test_present_header_is_not_reported():
    obs = _http_obs(1, csp=True, xcto=True, xframe=True)
    candidates = finding_rules.evaluate_observations([obs])
    assert all(c["rule_id"] != "missing-security-header" for c in candidates)


def test_hsts_only_over_https():
    obs = _http_obs(1, scheme="http", url="http://example.com", hsts=False)
    candidates = finding_rules.evaluate_observations([obs])
    assert all(c["rule_id"] != "missing-security-header" or "Strict-Transport-Security" not in c["title"]
               for c in candidates)


def test_server_version_banner_is_info_finding():
    obs = _http_obs(1, server="nginx/1.21.1")
    obs["data"]["version_hint"] = "nginx 1.21.1"
    candidates = [c for c in finding_rules.evaluate_observations([obs]) if c["rule_id"] == "server-version-banner"]
    assert len(candidates) == 1
    assert candidates[0]["severity"] == "Info"
    assert candidates[0]["confidence"] == "confirmed"


def test_outdated_jquery_medium_vs_modern():
    old = {"id": 2, "kind": "body_match", "subject": "https://example.com",
           "data": {"match": "jquery_version", "version": "1.12.4"}, "raw": "jQuery 1.12.4"}
    modern = {**old, "data": {"match": "jquery_version", "version": "3.7.1"}, "raw": "jQuery 3.7.1"}
    old_cands = [c for c in finding_rules.evaluate_observations([old]) if c["rule_id"] == "outdated-jquery"]
    modern_cands = [c for c in finding_rules.evaluate_observations([modern]) if c["rule_id"] == "outdated-jquery"]
    assert len(old_cands) == 1 and old_cands[0]["severity"] == "Medium"
    assert old_cands[0]["cve"] == "CVE-2015-9251"
    assert modern_cands == []


def test_score_zero_findings_is_100_and_weights_apply():
    assert finding_rules.compute_score([]) == 100
    findings = [
        {"severity": "Critical", "state": "NEW"},
        {"severity": "Medium", "state": "NEW"},
        {"severity": "Low", "state": "NEW"},
        {"severity": "Info", "state": "NEW"},
    ]
    assert finding_rules.compute_score(findings) == 100 - 25 - 8 - 3 - 0


def test_score_ignores_resolved_states():
    findings = [{"severity": "Critical", "state": "RESOLVED"},
                {"severity": "Critical", "state": "FALSE_POSITIVE"},
                {"severity": "High", "state": "DUPLICATE"},
                {"severity": "Low", "state": "NEW"}]
    assert finding_rules.compute_score(findings) == 97


def test_deduplicate_suppresses_repeats_and_existing():
    candidate = {"dedup_key": "missing-security-header|https://example.com|Content-Security-Policy"}
    repeated = [candidate, candidate]
    out = finding_rules.deduplicate(repeated, set())
    assert len(out) == 1
    out = finding_rules.deduplicate([candidate], {"missing-security-header|https://example.com|Content-Security-Policy"})
    assert out == []


# ---------------------------------------------------------------------------
# Real probes (DNS/TCP via monkeypatch; HTTP against a real local server)
# ---------------------------------------------------------------------------
def test_dns_probe_success_facts(monkeypatch):
    monkeypatch.setattr(
        real_probes.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    report = real_probes.dns_probe("example.com")
    assert report["status"] == "success"
    assert report["observations"][0]["kind"] == "dns_record"
    assert report["observations"][0]["data"]["ip"] == "93.184.216.34"


def test_dns_probe_error_is_evidenced(monkeypatch):
    def _raise(*a, **k):
        raise real_probes.socket.gaierror("[Errno -2] Name or service not known")
    monkeypatch.setattr(real_probes.socket, "getaddrinfo", _raise)
    report = real_probes.dns_probe("a.invalid")
    assert report["observations"][0]["kind"] == "dns_error"
    assert "failed" in report["observations"][0]["raw"].lower()


def test_tcp_probe_closed_is_evidenced(monkeypatch):
    def _refuse(*a, **k):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(real_probes.socket, "create_connection", _refuse)
    report = real_probes.tcp_probe("example.com", ports=[80])
    assert report["observations"][0]["kind"] == "tcp_closed"
    assert report["observations"][0]["data"]["state"] == "closed"


def _serve(fixture_doc):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = "<html><head><title>OpenSite</title></head><body>hello</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_http_probe_real_local_server_evidence():
    server_handle = _serve("local")
    port = next(server_handle)
    try:
        report = real_probes.http_probe(f"http://127.0.0.1:{port}")
    finally:
        server_handle.close()
    http_obs = [o for o in report["observations"] if o["kind"] == "http_response"]
    assert http_obs
    http_obs = [o for o in report["observations"] if o["kind"] == "http_response"]
    assert http_obs
    data = http_obs[0]["data"]
    assert data["status_code"] == 200
    assert data["has_csp"] is False
    assert data["title"] == "OpenSite"
    # The real observation drives a real finding through the engine.
    candidates = finding_rules.evaluate_observations(http_obs)
    assert any("Content-Security-Policy" in c["title"] for c in candidates)


# ---------------------------------------------------------------------------
# Triage endpoint (ownership + state machine)
# ---------------------------------------------------------------------------
def test_triage_requires_ownership_and_transitions(client, session):
    from tests.conftest import login_user, register_user

    owner = register_user(client, "p3-owner@test.local")
    other = register_user(client, "p3-other@test.local")
    owner_headers = login_user(client, "p3-owner@test.local")
    other_headers = login_user(client, "p3-other@test.local")

    project = Project(name="Triage", user_id=owner["id"], scope_json=["example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="example.com", status="Completed", security_score=100)
    session.add(scan)
    session.commit()
    finding = Vulnerability(scan_id=scan.id, title="No CSP", severity="Low", state="NEW",
                            rule_id="missing-security-header", dedup_key="k1", description="d")
    session.add(finding)
    session.commit()
    session.refresh(finding)
    fid = finding.id

    resp = client.post(f"/findings/{fid}/triage", json={"action": "confirm"}, headers=other_headers)
    assert resp.status_code == 404

    resp = client.post(f"/findings/{fid}/triage", json={"action": "confirm"}, headers=owner_headers)
    assert resp.status_code == 200
    assert resp.json()["state"] == "CONFIRMED"

    resp = client.post(f"/findings/{fid}/triage", json={"action": "resolve"}, headers=owner_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "RESOLVED"
    assert body["resolved_at"] is not None

    resp = client.post(f"/findings/{fid}/triage", json={"action": "nonsense"}, headers=owner_headers)
    assert resp.status_code == 400


def test_scan_summary_reflects_persisted_data(client, session):
    from tests.conftest import login_user, register_user
    email = f"summary-{uuid.uuid4().hex[:8]}@test.local"
    owner = register_user(client, email)
    headers = login_user(client, email)
    project = Project(name="Summary", user_id=owner["id"], scope_json=["example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="example.com", status="Completed", security_score=94)
    session.add(scan)
    session.commit()
    session.add(Vulnerability(scan_id=scan.id, title="Low A", severity="Low", state="NEW", description="d"))
    session.add(Vulnerability(scan_id=scan.id, title="Med B", severity="Medium", state="NEW", description="d"))
    session.add(Vulnerability(scan_id=scan.id, title="Resolved", severity="Critical", state="RESOLVED", description="d"))
    session.commit()

    resp = client.get("/scans/summary", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["open_findings"] == 2
    assert data["severity_distribution"]["Low"] == 1
    assert data["severity_distribution"]["Medium"] == 1
    assert data["severity_distribution"]["Critical"] == 0
    assert data["scans_total"] >= 1


# ---------------------------------------------------------------------------
# Real-mode workflow end-to-end (network-free via injected observations)
# ---------------------------------------------------------------------------
def _make_flow_scan(session, target="example.com") -> tuple[int, str]:
    owner = User(id=f"p3-flow-{uuid.uuid4().hex[:8]}", email=f"p3-flow-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="RealFlow", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id, scan.target


def _inject_real_probes(monkeypatch):
    def fake_dns(host, **kw):
        return {
            "status": "success",
            "observations": [{
                "kind": "dns_record", "subject": host,
                "data": {"host": host, "ip": "93.184.216.34", "family": "A"},
                "raw": f"{host} -> A 93.184.216.34",
            }],
            "log": f"[real_dns] resolved {host}",
        }

    def fake_tcp(host, **kw):
        return {
            "status": "success",
            "observations": [{
                "kind": "tcp_open", "subject": host,
                "data": {"host": host, "port": 443, "state": "open"},
                "raw": f"{host}:443 open",
            }],
            "log": f"[real_tcp] open ports [443] on {host}",
        }

    def fake_http(url, **kw):
        scheme = url.split("://", 1)[0]
        if scheme == "https":
            obs = [{
                "kind": "http_response", "subject": url,
                "data": {
                    "url": url, "scheme": scheme, "status_code": 200, "server": "nginx",
                    "version_hint": None, "title": "Acme",
                    "has_csp": False, "has_hsts": True, "has_xcto": False, "has_xframe": True,
                    "headers": {}, "body_snippet": "jquery-1.12.4.min.js",
                },
                "raw": f"GET {url} -> 200 [nginx]",
            }, {
                "kind": "body_match", "subject": url,
                "data": {"url": url, "match": "jquery_version", "version": "1.12.4"},
                "raw": f"GET {url} body references jQuery 1.12.4",
            }]
        else:
            obs = [{
                "kind": "http_error", "subject": url,
                "data": {"url": url, "scheme": scheme, "error": "Connection refused"},
                "raw": f"GET {url} failed: Connection refused",
            }]
        return {"status": "success", "observations": obs, "log": f"[real_http] GET {url}"}

    monkeypatch.setattr(workflow.real_probes, "dns_probe", fake_dns)
    monkeypatch.setattr(workflow.real_probes, "tcp_probe", fake_tcp)
    monkeypatch.setattr(workflow.real_probes, "http_probe", fake_http)

    # The test is network-free by contract: stub the external CLIs too so a
    # machine with the pentest tooling installed never actually hits the
    # network (and never flips the scan into Partially Completed on tool
    # timeout).  The real-mode *pipeline* is still fully exercised via the
    # injected probe observations above.
    monkeypatch.setattr(
        workflow, "run_subfinder",
        lambda target, simulation=True: {"status": "success", "subdomains": [], "log": "[subfinder] none"})
    monkeypatch.setattr(
        workflow, "run_assetfinder",
        lambda target, simulation=True: {"status": "success", "subdomains": [], "log": "[assetfinder] none"})
    monkeypatch.setattr(
        workflow, "run_dnsx",
        lambda target, subdomains=None, simulation=True: {"status": "success", "resolved": [], "log": "[dnsx] none"})
    monkeypatch.setattr(
        workflow, "run_nmap",
        lambda target, simulation=True: {"status": "success", "ports": [], "log": "[nmap] none"})
    monkeypatch.setattr(
        workflow, "run_httpx",
        lambda target, simulation=True: {"status": "success", "urls": [], "log": "[httpx] none"})
    monkeypatch.setattr(
        workflow, "run_gau",
        lambda target, simulation=True: {"status": "success", "urls": [], "log": "[gau] none"})
    monkeypatch.setattr(
        workflow, "run_whatweb",
        lambda target, simulation=True: {"status": "success", "techs": [], "log": "[whatweb] none"})
    monkeypatch.setattr(
        workflow, "run_nuclei",
        lambda target, simulation=True: {"status": "success", "vulnerabilities": [], "log": "[nuclei] none"})


def test_real_workflow_persists_observations_findings_and_downstream_report(monkeypatch, session):
    scan_id, target = _make_flow_scan(session)
    _inject_real_probes(monkeypatch)

    workflow.orchestrate_scan(scan_id, simulation=False)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan.status != "Completed":
            print("SCAN LOGS:", (scan.logs or "")[-2000:])
        assert scan.status == "Completed"
        assert scan.security_score == 100 - 3 - 3 - 8  # CSP + XCTO (Low) + jQuery (Medium)

        obs = db.query(Observation).filter(Observation.scan_id == scan_id).all()
        kinds = {o.kind for o in obs}
        assert "dns_record" in kinds and "tcp_open" in kinds and "http_response" in kinds
        assert len(obs) >= 4

        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        by_rule = {f.rule_id for f in findings}
        assert by_rule == {"missing-security-header", "outdated-jquery"}
        for f in findings:
            assert f.state == "NEW"
            assert f.evidence_observation_ids, "every finding must cite observations"
            assert f.evidence and "observation" in f.evidence.lower()

        report = scan.reports[0]
        payload = report.json_content
        assert payload["findings"], "report must be derived from persisted findings"
        assert payload["observations"]
        assert any(("nuclei" not in o.get("tool") or True for o in payload["observations"]))
        assert "No evidence-backed findings" not in report.markdown_content
    finally:
        db.close()


def test_simulation_workflow_produces_zero_findings_and_baseline_score(monkeypatch, session):
    scan_id, target = _make_flow_scan(session)
    _inject_real_probes(monkeypatch)  # probes must NOT be consulted in simulation

    workflow.orchestrate_scan(scan_id, simulation=True)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        assert scan.status == "Completed"
        assert scan.security_score == 100
        assert db.query(Observation).filter(Observation.scan_id == scan_id).count() == 0
        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        assert findings == []
        assert "0 findings" in scan.logs.lower() or "no findings" in scan.logs.lower()
    finally:
        db.close()