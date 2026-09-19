"""Cryptographic primitives for authentication.

Passwords are stored as PBKDF2-HMAC-SHA256 hashes using the stdlib only
(no third-party dependency; verified available on Python 3.14 in this
project's virtualenv).  Iteration count follows OWASP guidance (600k) and is
embedded in the stored value so it can be raised independently of existing
rows.

Session tokens are opaque 32-byte values generated with ``secrets`` and
persisted only as their SHA-256 digest.  A token leak therefore cannot be
used to authenticate unless the digest itself is stolen from the database.
"""
import base64
import hmac
import hashlib
import secrets

# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 600_000
_ALG = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    """Return a self-describing ``pbkdf2_sha256$<iterations>$<salt>$<hash>`` string."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return _format(_ALG, PBKDF2_ITERATIONS, salt, digest)


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time password verification against a stored hash string."""
    if not stored:
        return False
    try:
        alg, iterations, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if alg != _ALG:
        return False
    try:
        iterations = int(iterations)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(actual, expected)


def _format(alg: str, iterations: int, salt: bytes, digest: bytes) -> str:
    return "{0}${1}${2}${3}".format(
        alg,
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


# ---------------------------------------------------------------------------
# Session tokens (opaque bearer)
# ---------------------------------------------------------------------------
TOKEN_BYTES = 32


def generate_session_token() -> tuple[str, str]:
    """Return ``(raw_token, sha256_hex_digest)``. Only the digest is stored."""
    raw = secrets.token_hex(TOKEN_BYTES)
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_session_token(raw_token: str) -> str:
    """Digest used to look up a session from a presented token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()