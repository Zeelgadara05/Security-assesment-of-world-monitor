"""World Monitor provider tests: real HTTP against a controlled local fixture.

These tests deliberately use a real localhost HTTP server (stdlib
http.server), not a mocked HTTP client -- the integration path must prove
itself against real sockets, redirects, status codes and bodies.

The fixture is test-only data and is never production state.
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
from urllib.parse import urlparse

import pytest

from app.integrations.world_monitor.discovery import TargetConfig, discover
from app.integrations.world_monitor.health import check_health
from app.integrations.world_monitor.provider import WorldMonitorProvider

OPENAPI_DOC = {
    "openapi": "3.0.3",
    "info": {"title": "World Monitor Fixture", "version": "1.2.3"},
    "paths": {
        "/health": {
            "get": {
                "operationId": "getHealth",
                "tags": ["health"],
                "security": [{"ApiKeyAuth": []}],
            },
        },
        "/services/{service_id}": {
            "get": {
                "operationId": "getService",
                "tags": ["services"],
                "parameters": [{"name": "service_id", "in": "path", "required": True}],
            },
            "post": {
                "operationId": "createService",
                "tags": ["services"],
                "security": [{"ApiKeyAuth": []}],
            },
        },
    },
}


class _RoutingHandler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def _respond(self):
        r = urlparse(self.path)
        route = self.routes.get(r.path)
        if route is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"not found")
            return
        status, headers, body = route
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        else:
            body = (body or "").encode("utf-8")
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._respond()

    def do_POST(self):  # noqa: N802
        self._respond()

    def log_message(self, *args):  # pragma: no cover - quiet the test server
        pass


def _make_server(routes: dict):
    handler = type("FixtureHandler", (_RoutingHandler,), {"routes": routes})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return f"http://{host}:{port}", server


@pytest.fixture()
def wm_server():
    routes = {
        "/": (200, {"Server": "WM-Server/1.2", "Content-Security-Policy": "default-src 'self'"}, "<html>World Monitor</html>"),
        "/api": (200, {"Content-Type": "application/json"}, {"status": "ok"}),
        "/openapi.json": (200, {"Content-Type": "application/json"}, OPENAPI_DOC),
        "/not-json": (200, {"Content-Type": "text/html"}, "<html>not a document</html>"),
        "/r": (302, {"Location": "/landing", "Content-Type": "text/html"}, ""),
        "/landing": (200, {"Content-Type": "text/html"}, "<html>landed</html>"),
    }
    base, server = _make_server(routes)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _guard(base: str):
    def guard(url: str) -> bool:
        host = (urlparse(url).netloc or "").lower()
        allowed = (urlparse(base).netloc or "").lower()
        return host == allowed
    return guard


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------
def test_health_reachable_reports_real_facts(wm_server):
    guard = _guard(wm_server)
    result = check_health(wm_server, guard)
    assert result.reachable is True
    assert result.http_status == 200
    assert "WM-Server/1.2" in (result.server or "")
    assert result.elapsed_ms >= 0
    assert result.error is None


def test_health_unavailable_when_server_offline():
    # Get a port number from a socket that we then close: connecting fails.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    result = check_health(url, _guard(url))
    assert result.reachable is False
    assert result.http_status == 0
    assert result.error


def test_health_out_of_scope_is_blocked(wm_server):
    guard = lambda url: False  # noqa: E731
    result = check_health(wm_server, guard)
    assert result.reachable is False
    assert "outside authorized scope" in (result.error or "")


def test_health_every_http_status_is_reachable(wm_server):
    # A 5xx is still a reachable deployment: reachability != security verdict.
    guard = lambda url: True  # noqa: E731
    result = check_health(f"{wm_server}/api", guard)
    assert result.reachable is True
    assert result.http_status == 200


def test_redirect_into_scope_followed_once(wm_server):
    result = check_health(f"{wm_server}/r", _guard(wm_server))
    assert result.reachable is True
    assert result.http_status == 200


def test_redirect_out_of_scope_is_blocked(wm_server):
    routes = {"/escape": (302, {"Location": "http://evil.example/internal"}, "")}
    base, server = _make_server(routes)
    try:
        result = check_health(f"{base}/escape", _guard(base))
        assert result.reachable is False
        assert "blocked" in (result.error or "")
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
def test_discover_full_pipeline(wm_server):
    target = TargetConfig(base_url=wm_server, api_base_url=f"{wm_server}/api",
                          openapi_url=f"{wm_server}/openapi.json")
    result = discover(target, _guard(wm_server))
    assert result.health is not None and result.health.reachable is True
    assert result.target_status == "discovered"
    assert result.openapi_status == "available"
    assert result.discovered_version == "1.2.3"
    assert len(result.endpoints) == 3
    methods = {e.method for e in result.endpoints}
    assert methods == {"GET", "POST"}
    assert any(e.operation_id == "getService" for e in result.endpoints)
    auth_ep = next(e for e in result.endpoints if e.operation_id == "getHealth")
    assert auth_ep.authentication_hint
    by_source = {s.source for s in result.steps}
    assert {"base_url", "api_base", "openapi"}.issubset(by_source)
    # No guessed paths: unsupported metadata/frontend/rpc steps are recorded.
    unsupported = [s for s in result.steps if s.status == "unsupported"]
    assert len(unsupported) >= 1
    assert result.error is None


def test_discover_without_openapi_never_guesses(wm_server):
    target = TargetConfig(base_url=wm_server, api_base_url=f"{wm_server}/api")
    result = discover(target, _guard(wm_server))
    assert result.target_status == "partially_discovered"
    assert result.openapi_status == "unconfigured"
    assert result.endpoints == []
    assert result.discovered_version is None
    assert any(s.status == "unsupported" for s in result.steps)


def test_discover_rejects_non_json_openapi(wm_server):
    target = TargetConfig(base_url=wm_server, api_base_url=f"{wm_server}/api",
                          openapi_url=f"{wm_server}/not-json")
    result = discover(target, _guard(wm_server))
    assert result.openapi_status == "unavailable"
    assert result.endpoints == []
    assert result.target_status == "partially_discovered"


def test_discover_base_unreachable_short_circuits():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    result = discover(TargetConfig(base_url=url), lambda _u: True)
    assert result.target_status == "unavailable"
    assert result.endpoints == []
    assert result.openapi_status == "unconfigured"


def test_discover_empty_base_is_not_configured():
    result = discover(TargetConfig(base_url=""), lambda _u: True)
    assert result.target_status == "unavailable"
    assert result.error and "no World Monitor base URL" in result.error


def test_discover_blocked_openapi_url(wm_server):
    guard = _guard(wm_server)

    def limited(url: str) -> bool:
        if url.rstrip("/") == f"{wm_server}/openapi.json":
            return False
        return guard(url)

    target = TargetConfig(base_url=wm_server, api_base_url=f"{wm_server}/api",
                          openapi_url=f"{wm_server}/openapi.json")
    result = discover(target, limited)
    assert result.openapi_status == "unavailable"
    assert result.endpoints == []
    step = next(s for s in result.steps if s.source == "openapi")
    assert step.status == "blocked"


# ---------------------------------------------------------------------------
# provider facade + pure inventory parsing
# ---------------------------------------------------------------------------
def test_provider_exposes_required_operations(wm_server):
    provider = WorldMonitorProvider(_guard(wm_server))
    health = provider.check_health(wm_server)
    assert health.reachable is True

    result = provider.discover(TargetConfig(
        base_url=wm_server, api_base_url=f"{wm_server}/api",
        openapi_url=f"{wm_server}/openapi.json"))
    assert result.target_status == "discovered"
    assert len(result.endpoints) == 3

    inventory = provider.get_api_inventory(OPENAPI_DOC)
    assert len(inventory) == 3
    assert inventory[0].source == "openapi"


def test_get_api_inventory_pure():
    provider = WorldMonitorProvider(scope_guard=lambda _u: True)
    endpoints = provider.get_api_inventory({})
    assert endpoints == []
    bare = provider.get_api_inventory({"info": {}, "paths": {}})
    assert bare == []