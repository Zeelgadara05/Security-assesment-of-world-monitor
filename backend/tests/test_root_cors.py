"""Root endpoint behavior and CORS handling.

Phase 2 enables credentialed CORS (sessions may be passed via cookie), still
restricted to an explicit origin allow-list - never a wildcard.
"""

CORS_ORIGIN = "http://localhost:5173"
DISALLOWED_ORIGIN = "http://evil.example.com"


def test_root_health(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "online"
    assert body["simulation_mode"] is True


def test_cors_preflight_allowed_origin_with_credentials(client):
    resp = client.options(
        "/scans/list",
        headers={
            "Origin": CORS_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == CORS_ORIGIN
    # Credentials are allowed because session cookies are part of the auth flow.
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_ignores_disallowed_origin(client):
    resp = client.options(
        "/scans/list",
        headers={
            "Origin": DISALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    # Starlette's CORSMiddleware rejects preflights from origins that are not
    # configured, and never echoes the origin back.
    assert resp.status_code == 400
    assert "access-control-allow-origin" not in resp.headers


def test_cors_on_actual_public_get(client):
    resp = client.get("/", headers={"Origin": CORS_ORIGIN})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == CORS_ORIGIN
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_on_authenticated_endpoint(client, auth_headers):
    resp = client.get("/scans/list", headers={**auth_headers, "Origin": CORS_ORIGIN})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == CORS_ORIGIN