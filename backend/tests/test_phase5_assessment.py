"""Phase 5 assessment foundation tests.

Covers the observation layer (persistence, redaction, fingerprinting, user
isolation), the tool capability matrix, the assessment-test ledger and
structured finding evidence.  These are the deterministic building blocks the
assessment engine depends on -- no network and no external tools required.
"""

import datetime
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import inspect

from app.assess import coverage, dedup, planner, registry as registry_mod
from app.assess.models import AssessmentContext, CandidateData, TestCase as AssessTestCase
from app.assess.tests import AUTHORIZATION, HEADERS, IDOR, SQLI, XSS
from app.http.client import HttpLimits
from app.http.responses import HTTPResponse
from app.observations import types as obs_types
from app.observations.fingerprint import finding_fingerprint, observation_fingerprint
from app.observations.normalize import (
    REDACTED,
    build_observation,
    normalize_endpoint,
    redact_headers,
    redact_mapping,
)
from app.tools import capabilities as capmod
from database.models import (
    AssessmentTest,
    FindingEvidence,
    Observation,
    Project,
    Scan,
    ToolResult,
    User,
    Vulnerability,
)


def _owner_scan(session, email: str, target: str = "p5.example.com"):
    """Create (or fetch) a user + project + scan owned by that user."""
    user = session.query(User).filter(User.email == email).first()
    if user is None:
        user = User(id=f"p5-{email}", email=email, password_hash="x", role="user")
        session.add(user)
        session.flush()
    project = session.query(Project).filter(Project.user_id == user.id).first()
    if project is None:
        project = Project(name="p5", user_id=user.id, scope_json=[])
        session.add(project)
        session.flush()
    scan = Scan(project_id=project.id, target=target, status="Completed", stage="completed")
    session.add(scan)
    session.commit()
    return user, project, scan


# ---------------------------------------------------------------------------
# Observation layer
# ---------------------------------------------------------------------------
def test_observation_persisted_with_redacted_credentials(session):
    user, _project, scan = _owner_scan(session, "p5-obs@test.local")

    kwargs = build_observation(
        scan_id=scan.id,
        observation_type=obs_types.OBS_HTTP_RESPONSE,
        subject="https://p5.example.com/login",
        tool_name="native_http",
        source=obs_types.SOURCE_HTTP_CLIENT,
        user_id=user.id,
        target=scan.target,
        asset="p5.example.com",
        request={
            "method": "POST",
            "url": "https://p5.example.com/login",
            "headers": {"Authorization": "Bearer super-secret-token", "Cookie": "sid=abc123"},
            "body": {"username": "alice", "password": "hunter2"},
        },
        response={
            "status": 200,
            "headers": {"Set-Cookie": "session=deadbeef", "Content-Type": "text/html"},
            "body": {"ok": True},
        },
        discriminator={"endpoint": "https://p5.example.com/login", "method": "POST"},
    )
    obs = Observation(**kwargs)
    session.add(obs)
    session.commit()
    session.refresh(obs)

    assert obs.observation_type == obs_types.OBS_HTTP_RESPONSE
    assert obs.user_id == user.id
    assert obs.fingerprint and len(obs.fingerprint) == 64
    assert obs.status == obs_types.STATUS_OBSERVED
    # Credentials are redacted before persistence.
    assert obs.request_json["headers"]["Authorization"] == REDACTED
    assert obs.request_json["headers"]["Cookie"] == REDACTED
    assert obs.request_json["body"]["password"] == REDACTED
    assert obs.response_json["headers"]["Set-Cookie"] == REDACTED
    # Non-sensitive data survives.
    assert obs.request_json["body"]["username"] == "alice"
    assert obs.response_json["body"] == {"ok": True}


def test_redaction_helpers_cover_headers_keys_and_inline_tokens():
    headers = redact_headers({
        "Authorization": "Bearer abc.def.ghi",
        "X-Api-Key": "k-123",
        "Accept": "application/json",
    })
    assert headers["Authorization"] == REDACTED
    assert headers["X-Api-Key"] == REDACTED
    assert headers["Accept"] == "application/json"

    body = redact_mapping({
        "username": "bob",
        "access_token": "tok-1",
        "nested": {"client_secret": "shh", "ok": 1},
        "note": "call /x?api_key=zzz now",
    })
    assert body["username"] == "bob"
    assert body["access_token"] == REDACTED
    assert body["nested"]["client_secret"] == REDACTED
    assert body["nested"]["ok"] == 1
    assert "zzz" not in body["note"]


def test_normalize_endpoint_strips_query_and_normalizes():
    assert normalize_endpoint("https://Example.com/a/b?x=1&y=2") == "https://example.com/a/b"
    assert normalize_endpoint("https://example.com/a//b/") == "https://example.com/a/b"
    assert normalize_endpoint("") == ""


def test_observation_fingerprint_is_stable_and_identity_sensitive():
    base = dict(observation_type=obs_types.OBS_HTTP_RESPONSE, subject="https://a.example.com/x")
    disc = {"endpoint": "https://a.example.com/x", "method": "GET"}
    fp1 = observation_fingerprint(**base, asset="a.example.com", discriminator=disc)
    fp2 = observation_fingerprint(**base, asset="a.example.com", discriminator=disc)
    assert fp1 == fp2

    # A different method is a different identity.
    fp3 = observation_fingerprint(**base, asset="a.example.com",
                                 discriminator={"endpoint": "https://a.example.com/x", "method": "POST"})
    assert fp1 != fp3
    # A different type is a different identity.
    fp4 = observation_fingerprint(observation_type=obs_types.OBS_HEADER,
                                  subject="https://a.example.com/x",
                                  asset="a.example.com", discriminator=disc)
    assert fp1 != fp4


def test_finding_fingerprint_ignores_query_values_but_not_category():
    a = finding_fingerprint("xss", "app.example.com", "https://app.example.com/search?q=1", "q")
    b = finding_fingerprint("xss", "app.example.com", "https://app.example.com/search?q=2", "q")
    c = finding_fingerprint("sqli", "app.example.com", "https://app.example.com/search?q=1", "q")
    assert a == b
    assert a != c


def test_observations_are_isolated_by_user(session):
    user_a, _pa, scan_a = _owner_scan(session, "p5-iso-a@test.local", "a-isolated.example.com")
    user_b, _pb, scan_b = _owner_scan(session, "p5-iso-b@test.local", "b-isolated.example.com")

    for scan, uid, subject in (
        (scan_a, user_a.id, "a-isolated.example.com"),
        (scan_b, user_b.id, "b-isolated.example.com"),
    ):
        session.add(Observation(**build_observation(
            scan_id=scan.id,
            observation_type=obs_types.OBS_HOST,
            subject=subject,
            tool_name="native_dns",
            user_id=uid,
        )))
    session.commit()

    a_ids = {o.id for o in session.query(Observation).filter(Observation.user_id == user_a.id)}
    b_ids = {o.id for o in session.query(Observation).filter(Observation.user_id == user_b.id)}
    assert a_ids and b_ids and a_ids.isdisjoint(b_ids)

    a_hosts = {o.subject for o in session.query(Observation).filter(Observation.user_id == user_a.id)}
    assert "b-isolated.example.com" not in a_hosts


# ---------------------------------------------------------------------------
# Tool capability matrix
# ---------------------------------------------------------------------------
def test_capability_matrix_native_always_available():
    matrix = {c["tool"]: c for c in capmod.tool_capability_matrix()}
    native = matrix["native_http"]
    assert native["installed"] is True
    assert native["native"] is True
    assert capmod.CAP_AUTHORIZATION_TESTING in native["capabilities"]
    assert "Not Installed" not in native["adapter_status"]


def test_external_capabilities_gated_by_installation():
    matrix = {c["tool"]: c for c in capmod.tool_capability_matrix()}
    nmap = matrix["nmap"]
    assert nmap["declared_capabilities"], "declared capabilities are always documented"
    if nmap["installed"]:
        assert nmap["capabilities"] == nmap["declared_capabilities"]
        assert nmap["adapter_status"] == "available"
    else:
        # A declared capability is never reported available when the binary is absent.
        assert nmap["capabilities"] == []
        assert nmap["adapter_status"] == "not_installed"


# ---------------------------------------------------------------------------
# Assessment ledger + evidence
# ---------------------------------------------------------------------------
def test_assessment_test_ledger_persists_and_relates_to_scan(session):
    _user, _project, scan = _owner_scan(session, "p5-ledger@test.local", "ledger.example.com")
    session.add(AssessmentTest(
        scan_id=scan.id, test_id="http.security_headers", name="Security headers",
        category="http", status=obs_types.TEST_PLANNED, reason="http endpoint observed",
    ))
    session.add(AssessmentTest(
        scan_id=scan.id, test_id="authorization.basic", name="Authorization boundary",
        category="authorization", status=obs_types.TEST_NOT_APPLICABLE,
        reason="no authenticated comparison identity configured",
    ))
    session.commit()

    rows = {t.test_id: t for t in session.query(AssessmentTest).filter(AssessmentTest.scan_id == scan.id)}
    assert rows["http.security_headers"].status == obs_types.TEST_PLANNED
    assert rows["authorization.basic"].status == obs_types.TEST_NOT_APPLICABLE
    assert "identity" in rows["authorization.basic"].reason


def test_finding_evidence_links_finding_and_observation_and_cascades(session):
    _user, _project, scan = _owner_scan(session, "p5-evidence@test.local", "evidence.example.com")
    obs = Observation(**build_observation(
        scan_id=scan.id,
        observation_type=obs_types.OBS_HTTP_RESPONSE,
        subject="https://evidence.example.com/admin",
        tool_name="native_http",
        response={"status": 200, "headers": {"Server": "nginx"}, "body": "ok"},
    ))
    finding = Vulnerability(
        scan_id=scan.id, title="Missing security header", severity="Low",
        description="CSP absent", state="CONFIRMED", category="http",
        confidence=obs_types.CONFIDENCE_HIGH,
    )
    session.add_all([obs, finding])
    session.flush()
    evidence = FindingEvidence(
        finding_id=finding.id, observation_id=obs.id, evidence_type="comparison",
        expected="Content-Security-Policy present", actual="header absent",
        security_boundary="browser content execution", redaction_status="redacted",
    )
    session.add(evidence)
    session.commit()

    session.refresh(finding)
    assert len(finding.evidence_records) == 1
    record = finding.evidence_records[0]
    assert record.observation_id == obs.id
    assert record.expected.startswith("Content-Security-Policy")

    finding_id = finding.id
    session.delete(finding)
    session.commit()
    assert session.query(FindingEvidence).filter(FindingEvidence.finding_id == finding_id).count() == 0


# ---------------------------------------------------------------------------
# Planner / registry / coverage
# ---------------------------------------------------------------------------
class FakeClient:
    """Scripted HTTP client so engine tests need no network."""

    def __init__(self, handler):
        self.handler = handler
        self.requests = 0

    def reset_test_counter(self):
        pass

    def _do(self, method, url, headers=None, body=None, **kw):
        self.requests += 1
        return self.handler(method, url, headers, body)

    def get(self, url, **kw):
        return self._do("GET", url, kw.get("headers"), None)

    def post(self, url, body=None, **kw):
        return self._do("POST", url, kw.get("headers"), body)

    def options(self, url, **kw):
        return self._do("OPTIONS", url, kw.get("headers"), None)

    def trace(self, url, **kw):
        return self._do("TRACE", url, kw.get("headers"), None)


def _response(url, status=200, headers=None, body="", error=None):
    resp = HTTPResponse(status=status, url=url, headers=headers or {}, body=body, error=error)
    resp.request = {"method": "GET", "url": url, "headers": {}}
    return resp


def _context(endpoints=None, observations=None, client=None, **kw):
    return AssessmentContext(
        scan_id=1, target="t.example", simulation=True, active_testing=True,
        limits=HttpLimits(), client=client, endpoints=endpoints or [],
        observations=observations or [], **kw,
    )


def test_registry_fingerprint_is_stable_and_describes_tests():
    reg_a = registry_mod.default_registry()
    reg_b = registry_mod.default_registry()
    assert reg_a.fingerprint() == reg_b.fingerprint()
    assert len(reg_a.all()) == len(reg_b.all())
    described = reg_a.describe()
    assert all("id" in d and "category" in d for d in described)
    assert reg_a.get("injection.sqli") is not None


def test_planner_marks_active_tests_not_applicable_when_active_disabled():
    context = _context(endpoints=["http://t.example/"])
    context.active_testing = False
    plan = planner.plan(context)
    decisions = {p.test_id: p for p in plan.planned}
    assert decisions["injection.xss.reflected"].applicable is False
    assert "active testing is disabled" in decisions["injection.xss.reflected"].reason
    # Active tests did not build testcases.
    assert decisions["injection.xss.reflected"].testcases == []


def test_planner_requires_observations_for_passive_tests():
    context = _context()
    plan = planner.plan(context)
    decisions = {p.test_id: p for p in plan.planned}
    assert decisions["http.security_headers"].applicable is False
    assert "observations" in decisions["http.security_headers"].reason


def test_headers_test_reports_at_most_low_for_missing_headers():
    obs = {
        "id": 7,
        "observation_type": obs_types.OBS_HTTP_RESPONSE,
        "subject": "https://t.example/",
        "response_json": {"status": 200, "url": "https://t.example/", "headers": {"server": "nginx"}},
    }
    context = _context(observations=[obs])
    outcome = HEADERS.run(context)
    assert outcome.candidates, "missing headers should produce candidates"
    for candidate in outcome.candidates:
        assert candidate.severity in (obs_types.SEVERITY_INFO, obs_types.SEVERITY_LOW)
    assert any("Strict-Transport-Security" in c.title for c in outcome.candidates)


def test_xss_rejects_escaped_reflection_and_confirms_unescaped():
    import html

    context = _context(endpoints=["http://t.example/search?q=hello"])

    def _echo(url):
        return dict(parse_qsl(urlsplit(url).query)).get("q", "")

    def escaped(method, url, headers, body):
        return _response(url, body=f"<html>{html.escape(_echo(url))}</html>")

    context.client = FakeClient(escaped)
    assert XSS.run(context).candidates == []

    def unescaped(method, url, headers, body):
        return _response(url, body=f"<html>{_echo(url)}</html>")

    context.client = FakeClient(unescaped)
    outcome = XSS.run(context)
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0].severity == obs_types.SEVERITY_MEDIUM


def test_sqli_boolean_differential_confirms_and_rejects():
    endpoint = "http://t.example/item?id=5"
    context = _context(endpoints=[endpoint])

    def differential(method, url, headers, body):
        query = dict(parse_qsl(urlsplit(url).query))
        value = query.get("id", "")
        if "AND '1'='1" in value:
            return _response(url, body="x" * 120)
        if "AND '1'='2" in value:
            return _response(url, body="x" * 60)
        if value.endswith("'"):
            return _response(url, body="x" * 100)
        return _response(url, body="x" * 100)

    context.client = FakeClient(differential)
    outcome = SQLI.run(context)
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0].severity == obs_types.SEVERITY_HIGH

    def flat(method, url, headers, body):
        return _response(url, body="x" * 100)

    context.client = FakeClient(flat)
    assert SQLI.run(context).candidates == []


def test_authorization_confirms_only_when_denied_content_is_returned():
    check = {"endpoint": "http://t.example/admin", "identity": "guest",
             "marker": '"role":"admin"'}
    context = _context(config={"authorization_checks": [check]},
                       auth_identities={"guest": {"headers": {"X-Identity": "guest"}}})

    context.client = FakeClient(lambda m, u, h, b: _response(u, body='{"role":"admin"}'))
    outcome = AUTHORIZATION.run(context)
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0].severity == obs_types.SEVERITY_HIGH

    context.client = FakeClient(lambda m, u, h, b: _response(u, status=403, body="forbidden"))
    assert AUTHORIZATION.run(context).candidates == []


def test_idor_confirms_only_for_non_owner_read():
    check = {"endpoint": "http://t.example/orders/1001", "owner_identity": "alice",
             "owner_marker": '"owner":"alice"'}
    context = _context(
        config={"idor_checks": [check]},
        auth_identities={"alice": {"headers": {"X-Identity": "alice"}},
                         "bob": {"headers": {"X-Identity": "bob"}}},
    )

    context.client = FakeClient(lambda m, u, h, b: _response(u, body='{"owner":"alice"}'))
    outcome = IDOR.run(context)
    assert len(outcome.candidates) == 1

    context.client = FakeClient(lambda m, u, h, b: _response(u, status=404, body="not found"))
    assert IDOR.run(context).candidates == []


def test_dedup_merges_same_category_endpoint_and_parameter():
    def candidate(actual):
        return CandidateData(
            category="xss", title="Reflected XSS", severity="Medium", confidence="HIGH",
            description="d", endpoint="http://t.example/s?q=1", method="GET",
            target="http://t.example/s?q=1", source_test="injection.xss.reflected",
            parameter="q", actual=actual,
            dedup_key="fixed-key",
        )

    merged = dedup.deduplicate([candidate("a"), candidate("b")])
    assert len(merged) == 1


def test_coverage_is_honest_when_nothing_is_applicable():
    context = _context()
    context.active_testing = False
    plan, report = planner.plan_and_run(context)
    summary = coverage.summarize(plan, report, context)
    assert summary.tests_applicable == 0
    assert summary.findings_confirmed == 0
    assert summary.coverage_percent is None
    statement = summary.findings_statement
    assert "0 confirmed findings" in statement
    assert "0 vulnerabilities" not in statement


def test_assessment_test_ledger_is_importable():
    assert AssessTestCase and CandidateData and obs_types.STATUS_OBSERVED


# ---------------------------------------------------------------------------
# End-to-end against a real local server (scope-guarded native client)
# ---------------------------------------------------------------------------
def _serve_assessment():
    import http.server
    import threading
    from urllib.parse import parse_qsl, urlsplit

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            value = dict(parse_qsl(urlsplit(self.path).query)).get("q", "")
            body = f"<html><body>result: {value}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "LocalFixture")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_engine_end_to_end_confirms_reflected_xss_and_reports_coverage():
    from app.assess import registry as registry_mod
    from app.http.client import OutOfScopeError, SafeHttpClient

    server = _serve_assessment()
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    target = f"{base}/search?q=hello"
    try:
        client = SafeHttpClient(scope_guard=lambda url: "127.0.0.1" in url, limits=HttpLimits())
        assert client.scope_guard(target)

        seeded = client.get(target)
        observation = {
            "observation_type": obs_types.OBS_HTTP_RESPONSE,
            "subject": target,
            "response_json": seeded.to_dict(redact=False),
        }

        context = _context(endpoints=[target], observations=[observation], client=client)
        plan, report = planner.plan_and_run(context, registry_mod.default_registry())
        summary = coverage.summarize(plan, report, context)

        candidates = planner.confirmed_candidates(report)
        assert any(c.category == "xss" for c in candidates), [c.category for c in candidates]
        assert summary.findings_confirmed >= 1
        assert summary.tests_applicable > 0
        assert summary.coverage_percent is not None and summary.coverage_percent > 0

        try:
            client.get("http://example.com/")
            raise AssertionError("scope guard should have blocked an out-of-scope request")
        except OutOfScopeError:
            pass
    finally:
        server.shutdown()
        server.server_close()


def test_scan_detail_exposes_assessment_coverage_tests_and_evidence(client, session):
    import json as _json
    import uuid

    from tests.conftest import login_user, register_user

    email = f"p5-api-{uuid.uuid4().hex[:8]}@test.local"
    owner = register_user(client, email)
    headers = login_user(client, email)

    project = Project(name="p5-api", user_id=owner["id"], scope_json=["t.example"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="t.example", status="Completed", stage="completed", coverage=50.0)
    session.add(scan)
    session.commit()

    finding = Vulnerability(
        scan_id=scan.id, title="Reflected XSS", severity="Medium", description="d", state="NEW",
        category="xss", endpoint="http://t.example/s", http_method="GET",
        source_test="injection.xss.reflected", source_tool="native_http", confidence="HIGH",
    )
    session.add(finding)
    session.flush()
    session.add(FindingEvidence(
        finding_id=finding.id, evidence_type="comparison", expected="encoded", actual="raw",
        security_boundary="script execution", redaction_status="redacted",
    ))
    session.add(AssessmentTest(
        scan_id=scan.id, test_id="injection.xss.reflected", name="XSS", category="xss",
        status="executed", reason="", active=True,
    ))
    session.add(ToolResult(
        scan_id=scan.id, tool_name="native_assessment", status="Completed",
        raw_output=_json.dumps({"coverage_percent": 50.0, "findings_confirmed": 1,
                                "tests_executed": 4, "tests_applicable": 8}),
    ))
    session.commit()

    resp = client.get(f"/scans/{scan.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["assessment"]["coverage"]["coverage_percent"] == 50.0
    assert data["assessment"]["tests"][0]["test_id"] == "injection.xss.reflected"
    xss = next(v for v in data["vulnerabilities"] if v["category"] == "xss")
    assert xss["source_test"] == "injection.xss.reflected"
    assert xss["evidence_records"][0]["evidence_type"] == "comparison"

    resp2 = client.get(f"/scans/{scan.id}/coverage", headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["assessment"]["tests_executed"] == 4


def test_run_assessment_persists_engine_outputs(session):
    import uuid

    from app.assess import engine
    from app.observations.normalize import build_observation

    server = _serve_assessment()
    port = server.server_address[1]
    endpoint = f"http://127.0.0.1:{port}/search?q=hello"
    try:
        user = User(id=f"p5-eng-{uuid.uuid4().hex[:8]}", email=f"p5-eng-{uuid.uuid4().hex[:8]}@test.local",
                    role="user")
        session.add(user)
        session.commit()
        project = Project(name="p5-engine", user_id=user.id, scope_json=["127.0.0.1"])
        session.add(project)
        session.commit()
        scan = Scan(project_id=project.id, target=f"127.0.0.1:{port}", status="Running", stage="analysis")
        session.add(scan)
        session.commit()

        session.add(Observation(**build_observation(
            scan_id=scan.id, observation_type=obs_types.OBS_HTTP_RESPONSE, subject=endpoint,
            tool_name="native_http", source="http_client", user_id=user.id, target=scan.target,
            response={"status": 200, "url": endpoint, "headers": {"Content-Type": "text/html"}, "body": "hello"},
            discriminator={"endpoint": endpoint, "method": "GET"},
        )))
        session.commit()

        result = engine.run_assessment(session, scan, simulation=False,
                                       config={"active_testing": True, "assessment_engine": True})
        assert result["executed"] is True, result
        assert result["findings_confirmed"] >= 1
        assert result["coverage"]["tests_executed"] >= 1

        findings = session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        xss = [f for f in findings if f.category == "xss"]
        assert xss, [f.category for f in findings]
        assert xss[0].source_test == "injection.xss.reflected"

        evidence = session.query(FindingEvidence).filter(FindingEvidence.finding_id == xss[0].id).all()
        assert evidence

        ledger = session.query(AssessmentTest).filter(AssessmentTest.scan_id == scan.id).all()
        assert len(ledger) >= 1
        assert any(t.test_id == "injection.xss.reflected" and t.status == "executed" for t in ledger)

        tool_rows = session.query(ToolResult).filter(
            ToolResult.scan_id == scan.id, ToolResult.tool_name == "native_assessment").all()
        assert tool_rows
    finally:
        server.shutdown()
        server.server_close()
