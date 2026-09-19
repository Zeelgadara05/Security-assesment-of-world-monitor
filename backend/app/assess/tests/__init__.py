"""Security test catalogue for the Phase 5 assessment engine.

Tests are pure, deterministic objects.  They are registered explicitly (no
import-time magic) so the executable catalogue is auditable in code review.
"""
from __future__ import annotations

from app.assess.tests.auth import TEST as AUTHENTICATION
from app.assess.tests.authorization import TEST as AUTHORIZATION
from app.assess.tests.cors import TEST as CORS
from app.assess.tests.disclosure import TEST as DISCLOSURE
from app.assess.tests.graphql import TEST as GRAPHQL
from app.assess.tests.headers import TEST as HEADERS
from app.assess.tests.idor import TEST as IDOR
from app.assess.tests.jwt import TEST as JWT
from app.assess.tests.methods import TEST as METHODS
from app.assess.tests.oauth import TEST as OAUTH
from app.assess.tests.redirects import TEST as REDIRECTS
from app.assess.tests.sqli import TEST as SQLI
from app.assess.tests.ssrf import TEST as SSRF
from app.assess.tests.ssti import TEST as SSTI
from app.assess.tests.tls import TEST as TLS
from app.assess.tests.xss import TEST as XSS

ALL_TESTS = [
    HEADERS,
    DISCLOSURE,
    AUTHENTICATION,
    METHODS,
    REDIRECTS,
    CORS,
    TLS,
    JWT,
    AUTHORIZATION,
    IDOR,
    XSS,
    SSTI,
    SQLI,
    SSRF,
    GRAPHQL,
    OAUTH,
]


def get_all_tests() -> list:
    """Return a fresh copy of the registered security tests."""
    return list(ALL_TESTS)


__all__ = ["ALL_TESTS", "get_all_tests"]
