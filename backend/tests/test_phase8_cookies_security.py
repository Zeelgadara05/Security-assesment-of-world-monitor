"""Cookie security-attribute capture + redaction guarantees (Phase 8, 17.2).

Three guarantees are locked in:

  1. cookie *values* never leave the capture boundary -- attributes are
     extracted (name/flags only) and values are discarded at capture time;
  2. ``Set-Cookie`` headers are redacted to ``<REDACTED>`` in every persisted
     response structure (normalization path);
  3. the native ``cookies.security_attributes`` test evaluates only captured
     attributes and issues honest hardening candidates.

All HTTP here is real (stdlib client against a localhost fixture); nothing is
mocked.
"""
from __future__ import annotations

import json
import threading

import pytest
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from app.assess.models import AssessmentContext
from app.assess.tests.cookies import TEST as COOKIES_TEST
from app.http.client import HttpLimits, SafeHttpClient
from app.http.cookies import extract_cookie_attributes
from app.observations.normalize import REDACTED, build_observation, redact_headers
from app.observations import types
from app.tools.real_probes import http_probe

WEAK_COOKIE = "session_id=SUPERSECRETVALUE123; Path=/"
HARDENED_COOKIE = "session_id=SUPERSECRETVALUE123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600"


class _CookieHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if self.path == "/weak":
            self.send_header("Set-Cookie", "session_id=SUPERSECRETVALUE123; Path=/")
        elif self.path == "/two":
            self.send_header("Set-Cookie", "a=1; HttpOnly")
            self.send_header("Set-Cookie", "b=2; Secure; SameSite=Strict")
        elif self.path == "/hardened":
            self.send_header("Set-Cookie", HARDENED_COOKIE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # pragma: no cover
        pass


@pytest.fixture()
def cookie_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CookieHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _guard(base: str, **_):
    allowed = base.split("://", 1)[-1]
    return lambda url: (url or "").split("://", 1)[-1].split("/", 1)[0].lower() == allowed.lower()


# ---------------------------------------------------------------------------
# attribute parser: name + flags only, values never captured
# ---------------------------------------------------------------------------
def test_extract_attributes_never_contains_values():
    out = extract_cookie_attributes(HARDENED_COOKIE)
    assert len(out) == 1
    entry = out[0]
    assert entry["name"] == "session_id"
    assert entry["httponly"] is True
    assert entry["secure"] is True
    assert entry["samesite"] == "Lax"
    assert entry["max_age"] == 3600
    assert entry["session"] is False
    assert "SUPERSECRETVALUE123" not in json.dumps(out)


def test_extract_attributes_flags_absent():
    out = extract_cookie_attributes([WEAK_COOKIE])
    entry = out[0]
    assert entry["httponly"] is False
    assert entry["secure"] is False
    assert entry["samesite"] is None
    assert entry["session"] is True


def test_extract_attributes_multiple_headers():
    out = extract_cookie_attributes(["a=1; HttpOnly", "b=2; Secure; SameSite=Strict"])
    names = [c["name"] for c in out]
    assert names == ["a", "b"]
    assert out[1]["samesite"] == "Strict"


# ---------------------------------------------------------------------------
# redaction guarantee at every persistence layer
# ---------------------------------------------------------------------------
def test_redact_headers_covers_set_cookie():
    redacted = redact_headers({"Set-Cookie": [HARDENED_COOKIE], "Content-Type": "text/html"})
    assert redacted["Set-Cookie"] == REDACTED
    assert redacted["Content-Type"] == "text/html"


def test_build_observation_redacts_set_cookie_and_keeps_attributes():
    response = {
        "status": 200,
        "url": "http://x",
        "headers": {"Set-Cookie": HARDENED_COOKIE},
        "body": "",
        "cookies": extract_cookie_attributes(HARDENED_COOKIE),
    }
    obs = build_observation(
        scan_id=1,
        observation_type=types.OBS_HTTP_RESPONSE,
        subject="http://x",
        tool_name="native_http",
        source=types.SOURCE_HTTP_CLIENT,
        response=response,
    )
    header_value = obs["response_json"]["headers"].get("Set-Cookie") or obs["response_json"]["headers"].get("set-cookie")
    if isinstance(header_value, list):
        assert REDACTED in header_value
    else:
        assert header_value == REDACTED
    assert obs["response_json"]["cookies"][0]["name"] == "session_id"
    assert "SUPERSECRETVALUE123" not in json.dumps(obs, default=str)


# ---------------------------------------------------------------------------
# client + real probe capture
# ---------------------------------------------------------------------------
def test_client_captures_attribute_only_cookies(cookie_server):
    guard = _guard(cookie_server)
    client = SafeHttpClient(guard, HttpLimits(active_testing=False, request_timeout=5))
    resp = client.get(f"{cookie_server}/weak")
    cookie = resp.cookies[0]
    assert cookie["name"] == "session_id"
    assert cookie["httponly"] is False
    assert "SUPERSECRETVALUE123" not in json.dumps(resp.cookies)
    headers_out = resp.to_dict()["headers"]
    assert (headers_out.get("set-cookie") or headers_out.get("Set-Cookie")) == REDACTED


def test_client_captures_multiple_cookies(cookie_server):
    client = SafeHttpClient(_guard(cookie_server), HttpLimits(active_testing=False, request_timeout=5))
    resp = client.get(f"{cookie_server}/two")
    assert {c["name"] for c in resp.cookies} == {"a", "b"}
    assert "SUPERSECRETVALUE123" not in json.dumps(resp.cookies)


def test_real_probe_capture_leaks_no_values(cookie_server):
    report = http_probe(f"{cookie_server}/weak")
    obs = report["observations"][0]
    assert obs["kind"] == "http_response"
    cookies = obs["data"]["cookies"]
    assert cookies[0]["name"] == "session_id"
    persisted = json.dumps(obs)
    assert "SUPERSECRETVALUE123" not in persisted
    assert "set-cookie" not in json.dumps(obs["data"]["headers"]).lower()


# ---------------------------------------------------------------------------
# native assessment test behaviour
# ---------------------------------------------------------------------------
def _obs(url, cookies, response_cookies=None):
    data = {"cookies": cookies}
    response = {"url": url, "status": 200, "headers": {"Content-Type": "text/html"}}
    if response_cookies is not None:
        response["cookies"] = response_cookies
    return {"observation_type": types.OBS_HTTP_RESPONSE, "kind": types.OBS_HTTP_RESPONSE,
            "subject": url, "data_json": data, "response_json": response}


def _run_cookies(outcomes):
    context = AssessmentContext(
        scan_id=1, target="http://x", simulation=False, active_testing=False,
        observations=outcomes,
    )
    return COOKIES_TEST.run(context)


def test_native_test_flags_missing_attributes_http():
    outcome = _run_cookies([_obs("http://target.example/page", extract_cookie_attributes(WEAK_COOKIE))])
    titles = {c.title for c in outcome.candidates}
    assert "Cookie without HttpOnly" in titles
    assert "Cookie without SameSite" in titles
    assert "Cookie without Secure over HTTP" not in titles  # only flagged over HTTPS
    assert outcome.status == types.TEST_EXECUTED


def test_native_test_flags_missing_secure_over_https():
    outcome = _run_cookies([_obs("https://target.example/page", extract_cookie_attributes(WEAK_COOKIE))])
    titles = {c.title for c in outcome.candidates}
    assert "Cookie without Secure over HTTPS" in titles


def test_native_test_passes_hardened_cookies():
    outcome = _run_cookies([_obs("https://target.example/page", extract_cookie_attributes(HARDENED_COOKIE))])
    assert outcome.candidates == []


def test_native_test_not_applicable_without_https_observations():
    outcome = _run_cookies([])
    assert outcome.status == types.TEST_NOT_APPLICABLE


def test_native_test_reads_client_response_cookies():
    weak = extract_cookie_attributes(WEAK_COOKIE)
    obs = _obs("http://target.example/x", [], response_cookies=weak)
    outcome = _run_cookies([obs])
    assert any("HttpOnly" in c.title for c in outcome.candidates)