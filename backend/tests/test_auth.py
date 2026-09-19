"""Real authentication: registration, login, logout/revocation, expiry,
password protection and session invalidation."""

import datetime

from database.connection import SessionLocal
from database.models import Session as AuthSession
from database.models import User

WEAK_PASSWORD = "short"
GOOD_PASSWORD = "CorrectHorseBatteryStaple!"


def test_register_creates_user_with_hashed_password(client, session):
    resp = client.post("/auth/register", json={"email": "new@test.local", "password": GOOD_PASSWORD})
    assert resp.status_code == 201
    body = resp.json()
    assert body["role"] == "user"
    assert "password" not in body

    row = session.query(User).filter(User.email == "new@test.local").first()
    assert row is not None
    assert row.password_hash.startswith("pbkdf2_sha256$")
    assert GOOD_PASSWORD not in row.password_hash


def test_register_rejects_duplicate_email(client):
    client.post("/auth/register", json={"email": "dup@test.local", "password": GOOD_PASSWORD})
    resp = client.post("/auth/register", json={"email": "dup@test.local", "password": GOOD_PASSWORD})
    assert resp.status_code == 409


def test_register_rejects_weak_password(client):
    resp = client.post("/auth/register", json={"email": "weak@test.local", "password": WEAK_PASSWORD})
    assert resp.status_code == 422


def test_register_rejects_invalid_email(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": GOOD_PASSWORD})
    assert resp.status_code == 422


def test_login_success_and_me(client):
    client.post("/auth/register", json={"email": "loginme@test.local", "password": GOOD_PASSWORD})
    resp = client.post("/auth/login", json={"email": "LOGINME@test.local", "password": GOOD_PASSWORD})
    assert resp.status_code == 200
    data = resp.json()
    assert data["token"]
    assert data["user"]["email"] == "loginme@test.local"

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {data['token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "loginme@test.local"


def test_login_unknown_email_and_wrong_password_same_response(client):
    client.post("/auth/register", json={"email": "enum@test.local", "password": GOOD_PASSWORD})
    unknown = client.post("/auth/login", json={"email": "ghost@test.local", "password": "Whatever123!"})
    wrong = client.post("/auth/login", json={"email": "enum@test.local", "password": "WrongPass123!"})
    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]


def test_profile_alias(client):
    resp = client.post("/auth/register", json={"email": "prof@test.local", "password": GOOD_PASSWORD})
    headers = {"Authorization": f"Bearer {client.post('/auth/login', json={'email': 'prof@test.local', 'password': GOOD_PASSWORD}).json()['token']}"}
    assertions_login = client.get("/auth/me", headers=headers)
    assert resp.status_code == 201
    assert assertions_login.status_code == 200
    profile = client.get("/auth/profile", headers=headers)
    assert profile.status_code == 200
    assert profile.json()["role"] in ("admin", "user")


def test_protected_routes_need_auth(client):
    assert client.get("/scans/list").status_code == 401
    assert client.post("/scans/trigger", json={"target": "example.com"}).status_code == 401
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/profile").status_code == 401
    assert client.post("/auth/logout").status_code == 401


def test_logout_revokes_session(client):
    client.post("/auth/register", json={"email": "logout@test.local", "password": GOOD_PASSWORD})
    token = client.post("/auth/login", json={"email": "logout@test.local", "password": GOOD_PASSWORD}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/auth/me", headers=headers).status_code == 200
    resp = client.post("/auth/logout", headers=headers)
    assert resp.status_code == 200

    # Token is revoked server-side: transport-level reuse is rejected.
    assert client.get("/auth/me", headers=headers).status_code == 401
    # And a stale session row for another login is not resurrected.
    assert client.post("/auth/login", json={"email": "logout@test.local", "password": GOOD_PASSWORD}).status_code == 200


def test_expired_session_is_rejected(client, session):
    client.post("/auth/register", json={"email": "expire@test.local", "password": GOOD_PASSWORD})
    token = client.post("/auth/login", json={"email": "expire@test.local", "password": GOOD_PASSWORD}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/me", headers=headers).status_code == 200

    now_past = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    user = session.query(User).filter(User.email == "expire@test.local").first()
    for s in session.query(AuthSession).filter(AuthSession.user_id == user.id).all():
        s.expires_at = now_past
    session.commit()

    assert client.get("/auth/me", headers=headers).status_code == 401


def test_token_digest_stored_not_plaintext(client, session):
    client.post("/auth/register", json={"email": "digest@test.local", "password": GOOD_PASSWORD})
    token = client.post("/auth/login", json={"email": "digest@test.local", "password": GOOD_PASSWORD}).json()["token"]
    user = session.query(User).filter(User.email == "digest@test.local").first()
    rows = session.query(AuthSession).filter(AuthSession.user_id == user.id).all()
    assert rows
    stored_hashes = [r.token_hash for r in rows]
    assert token not in stored_hashes
    assert all(len(h) == 64 for h in stored_hashes)

    # Querying by the presented token directly must not match; the server
    # hashes before lookup.
    match = session.query(AuthSession).filter(AuthSession.token_hash == token).first()
    assert match is None


def test_session_accepts_query_param_for_sse_style_requests(client):
    client.post("/auth/register", json={"email": "sse@test.local", "password": GOOD_PASSWORD})
    token = client.post("/auth/login", json={"email": "sse@test.local", "password": GOOD_PASSWORD}).json()["token"]
    resp = client.get(f"/auth/me?token={token}")
    assert resp.status_code == 200
    assert resp.json()["email"] == "sse@test.local"