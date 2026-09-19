"""Phase 5 native HTTP engine: scope-safe client + differential primitives."""
from app.http.client import (
    HttpLimits,
    OutOfScopeError,
    RequestLimitExceeded,
    SafeHttpClient,
)
from app.http.fingerprints import fetch_tls_info, host_of, port_of, technology_hints
from app.http.requests import HTTPRequest
from app.http.responses import (
    HTTPResponse,
    compare_body,
    compare_content_type,
    compare_headers,
    compare_length,
    compare_redirect,
    compare_status,
    compare_structure,
    compare_timing,
)

__all__ = [
    "HttpLimits",
    "SafeHttpClient",
    "OutOfScopeError",
    "RequestLimitExceeded",
    "HTTPRequest",
    "HTTPResponse",
    "compare_status",
    "compare_headers",
    "compare_body",
    "compare_length",
    "compare_structure",
    "compare_timing",
    "compare_redirect",
    "compare_content_type",
    "fetch_tls_info",
    "host_of",
    "port_of",
    "technology_hints",
]
