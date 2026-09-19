"""Root endpoint behavior and CORS handling (config-driven, no wildcard+credentials)."""

CORS_ORIGIN = "http://localhost:5173"
DISALLOWED_ORIGIN = "http://evil.example.com"


def test_root_health(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "online"
    assert body["simulation_mode"] is True


def test_cors_preflight_allowed_origin(client):
    resp = client.options(
        "/scans/list",
        headers={
            "Origin": CORS_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == CORS_ORIGIN
    assert resp.headers.get("access-control-allow-credentials") in (None, "false")


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


def test_cors_on_actual_get(client):
    resp = client.get("/scans/list", headers={"Origin": CORS_ORIGIN})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == CORS_ORIGIN