"""Canonical observation-type vocabulary (Phase 5).

An observation is a factual, tool-produced measurement.  The ``observation_type``
is the normalized classifier that security tests and the planner switch on; the
legacy ``kind`` column remains for Phase 3 compatibility.  Keep this list closed
and deterministic -- tests must never invent ad-hoc type strings.
"""
from __future__ import annotations

# --- Observation types -----------------------------------------------------
OBS_HOST = "host"
OBS_PORT = "port"
OBS_SERVICE = "service"
OBS_HTTP_ENDPOINT = "http_endpoint"
OBS_HTTP_REQUEST = "http_request"
OBS_HTTP_RESPONSE = "http_response"
OBS_TECHNOLOGY = "technology"
OBS_HEADER = "header"
OBS_CERTIFICATE = "certificate"
OBS_REDIRECT = "redirect"
OBS_AUTHENTICATION = "authentication"
OBS_AUTHORIZATION = "authorization"
OBS_PARAMETER = "parameter"
OBS_API_ROUTE = "api_route"
OBS_GRAPHQL_ENDPOINT = "graphql_endpoint"
OBS_JWT = "jwt"
OBS_OAUTH = "oauth"
OBS_ERROR = "error"
OBS_DISCLOSURE = "disclosure"
OBS_TOOL_OUTPUT = "tool_output"
OBS_VULNERABILITY = "vulnerability"

OBSERVATION_TYPES = (
    OBS_HOST, OBS_PORT, OBS_SERVICE, OBS_HTTP_ENDPOINT, OBS_HTTP_REQUEST,
    OBS_HTTP_RESPONSE, OBS_TECHNOLOGY, OBS_HEADER, OBS_CERTIFICATE,
    OBS_REDIRECT, OBS_AUTHENTICATION, OBS_AUTHORIZATION, OBS_PARAMETER,
    OBS_API_ROUTE, OBS_GRAPHQL_ENDPOINT, OBS_JWT, OBS_OAUTH, OBS_ERROR,
    OBS_DISCLOSURE, OBS_TOOL_OUTPUT, OBS_VULNERABILITY,
)

# --- Observation status ----------------------------------------------------
STATUS_OBSERVED = "observed"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUS_UNREACHABLE = "unreachable"
STATUS_NOT_TESTED = "not_tested"

OBSERVATION_STATUSES = (
    STATUS_OBSERVED, STATUS_ERROR, STATUS_SKIPPED, STATUS_UNREACHABLE, STATUS_NOT_TESTED,
)

# --- Sources ---------------------------------------------------------------
SOURCE_HTTP_CLIENT = "http_client"
SOURCE_EXTERNAL_TOOL = "external_tool"
SOURCE_STDLIB_PROBE = "stdlib_probe"
SOURCE_SCOPE_GUARD = "scope_guard"
SOURCE_ASSESSOR = "assessor"

# --- Assessment test statuses ---------------------------------------------
TEST_PLANNED = "planned"
TEST_NOT_APPLICABLE = "not_applicable"
TEST_SKIPPED = "skipped"
TEST_EXECUTED = "executed"
TEST_VALIDATED = "validated"
TEST_FAILED = "failed"
TEST_REJECTED = "rejected"

TEST_STATUSES = (
    TEST_PLANNED, TEST_NOT_APPLICABLE, TEST_SKIPPED, TEST_EXECUTED,
    TEST_VALIDATED, TEST_FAILED, TEST_REJECTED,
)

# --- Finding lifecycle ------------------------------------------------------
FINDING_CANDIDATE = "candidate"
FINDING_VALIDATING = "validating"
FINDING_CONFIRMED = "confirmed"
FINDING_REJECTED = "rejected"
FINDING_DUPLICATE = "duplicate"

# --- Confidence levels ------------------------------------------------------
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_CONFIRMED = "CONFIRMED"

CONFIDENCE_LEVELS = (CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH, CONFIDENCE_CONFIRMED)

# --- Severity ---------------------------------------------------------------
SEVERITY_INFO = "Info"
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"

SEVERITY_ORDER = (SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)
