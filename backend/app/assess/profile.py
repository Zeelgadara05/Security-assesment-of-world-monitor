"""Deterministic finding profiling (Phase 6).

``profile_finding`` produces the auditable surface of a confirmed/candidate
finding: affected component (evidence-based), structured remediation, and
non-exaggerated technical + business impact statements.  Everything here is a
deterministic mapping -- never LLM prose and never claims beyond the evidence
(no automatic "account takeover", "RCE" or "database compromise").
"""
from __future__ import annotations

from typing import Any

_COMPONENT_BY_CATEGORY = {
    "tls": "tls",
    "graphql": "graphql",
    "oauth": "oauth",
    "jwt": "authentication",
    "authentication": "authentication",
    "session": "authentication",
    "authorization": "authorization",
    "idor": "authorization",
    "bola": "authorization",
}
_API_CATEGORIES = {"sqli", "ssti", "ssrf", "xss", "api_security", "input_validation", "injection"}
_HTTP_CATEGORIES = {"headers", "cors", "methods", "redirects", "disclosure",
                    "information_disclosure", "configuration", "privacy"}

TECHNICAL_IMPACT = {
    "xss": "Executable client-side script injection in a server response.",
    "sqli": "Untrusted input is concatenated into SQL, enabling query manipulation.",
    "ssti": "Untrusted input is evaluated as a server-side template expression.",
    "ssrf": "A URL parameter allows server-side requests to unintended hosts.",
    "authorization": "Server-side ownership/permission checks may be bypassed.",
    "idor": "Object references are accessible without ownership/permission checks.",
    "bola": "Object references are accessible without ownership/permission checks.",
    "jwt": "JWT tokens may be accepted without strict algorithm/expiry validation.",
    "oauth": "OAuth redirect targets may not be strictly validated.",
    "graphql": "The GraphQL schema and its fields are exposed via introspection.",
    "headers": "Required security headers are missing or misconfigured.",
    "cors": "Cross-origin policy permits origins outside the trusted set.",
    "redirects": "Unvalidated redirect parameters allow off-scope navigation.",
    "methods": "Unsafe HTTP methods are enabled on server-side resources.",
    "disclosure": "Verbose responses expose implementation or infrastructure details.",
    "information_disclosure": "Verbose responses expose implementation or infrastructure details.",
    "tls": "Transport encryption is weakened by protocol/cipher configuration.",
    "session": "Session cookies lack hardening flags or expose session state.",
    "authentication": "Authentication controls are missing or weak.",
}

BUSINESS_IMPACT = {
    "xss": "User-session exposure and potential confidentiality loss in the browser.",
    "sqli": "Integrity risk from query manipulation and possible data disclosure.",
    "ssti": "Integrity risk from server-side template evaluation.",
    "ssrf": "Unauthorized actions against internal resources (confidentiality/integrity).",
    "authorization": "Unauthorized user actions and resource access across identities.",
    "idor": "Unauthorized user actions and privacy exposure across identities.",
    "bola": "Unauthorized user actions and privacy exposure across identities.",
    "jwt": "Privacy exposure if forged tokens grant unintended access.",
    "oauth": "Credential/interception risk if redirects are lax (privacy exposure).",
    "graphql": "Information disclosure of the API surface.",
    "headers": "Reduced defense-in-depth against client-side attacks.",
    "cors": "Confidentiality loss via unauthorized cross-origin reads.",
    "redirects": "Operational disruption via phishing using the trusted domain.",
    "methods": "Integrity risk if state-changing methods are misused.",
    "disclosure": "Regulatory/compliance exposure when internal details leak.",
    "information_disclosure": "Regulatory/compliance exposure when internal details leak.",
    "tls": "Confidentiality/integrity exposure over the transport layer.",
    "session": "Session hijacking risk contributing to account-level confidentiality loss.",
    "authentication": "Account-level confidentiality and integrity risk.",
}

_SEVERITY_ADVERB = {
    "Critical": "material",
    "High": "significant",
    "Medium": "moderate",
    "Low": "limited",
    "Info": "informational",
}

REMEDIATION: dict[str, dict[str, Any]] = {
    "authorization": {
        "summary": "Enforce server-side ownership/permission checks on every object request.",
        "technical_fix": "Add an authorization guard to each handler that loads a resource, verifying "
                         "the requester owns it or holds the required role before the object is returned.",
        "configuration_fix": "Apply deny-by-default access rules at the API gateway/proxy layer.",
        "validation_steps": "For each endpoint, request a resource belonging to a second identity and "
                            "verify a 403/404 is returned.",
        "regression_test": "Add an automated access-control test that replays the second-identity request.",
    },
    "idor": {
        "summary": "Enforce object-level ownership checks before returning resources.",
        "technical_fix": "Map requested object references to the requester's owned set server-side; "
                         "never trust client-supplied ids without an ownership query.",
        "configuration_fix": "Restrict object routes to authenticated owners at the routing layer.",
        "validation_steps": "Call the endpoint with the victim's object id as each identity and confirm denial.",
        "regression_test": "Assert that cross-identity object access returns 403/404.",
    },
    "bola": {
        "summary": "Enforce object-level ownership checks before returning resources.",
        "technical_fix": "Apply the same ownership guard as the authorization fix.",
        "configuration_fix": "Same as authorization.",
        "validation_steps": "Same as IDOR validation.",
        "regression_test": "Assert that cross-identity object access returns 403/404.",
    },
    "xss": {
        "summary": "Escape output contexts and validate/sanitize untrusted input.",
        "technical_fix": "Context-aware output encoding in templates and Content-Security-Policy headers.",
        "configuration_fix": "Set CSP and X-Content-Type-Options at the reverse proxy.",
        "validation_steps": "Replay the harmless marker payload and verify it renders escaped.",
        "regression_test": "Automated reflected-XSS regression against the affected endpoint.",
    },
    "sqli": {
        "summary": "Use parameterized queries and never concatenate untrusted input into SQL.",
        "technical_fix": "Replace string-built queries with parameterized statements/ORM bindings.",
        "configuration_fix": "Ensure DB credentials follow least-privilege per application role.",
        "validation_steps": "Replay the differential payload and confirm no behavioral difference resolves to a value.",
        "regression_test": "Parameterized-query regression test over the affected parameter.",
    },
    "ssti": {
        "summary": "Treat templates as code; never evaluate untrusted template input.",
        "technical_fix": "Use sandboxed template engines or static templates with no user-controlled expressions.",
        "configuration_fix": "Disable template auto-reload and arbitrary expression access.",
        "validation_steps": "Replay a harmless expression and confirm it is never evaluated.",
        "regression_test": "Automated SSTI regression against the affected parameter.",
    },
    "ssrf": {
        "summary": "Validate server-side request targets before forwarding.",
        "technical_fix": "Allow only a scheme+host allowlist and block loopback/link-local ranges.",
        "configuration_fix": "Route outbound requests through a deny-by-default egress filter.",
        "validation_steps": "Send a controlled callback request and confirm it is never made to off-scope hosts.",
        "regression_test": "Automated SSRF check using the configured validation callback.",
    },
    "jwt": {
        "summary": "Enforce strict JWT validation (algorithm, expiry, signature).",
        "technical_fix": "Reject 'none', pin an algorithm allowlist, verify signatures and expiry.",
        "configuration_fix": "Rotate signing keys and store them outside the application bundle.",
        "validation_steps": "Submit an alg-none and an expired token and confirm rejection.",
        "regression_test": "JWT rejection regression test over alg/exp behavior.",
    },
    "oauth": {
        "summary": "Validate redirect URIs against an explicit allowlist.",
        "technical_fix": "Exact-match redirect_uri against registered clients; reject open wildcards.",
        "configuration_fix": "Maintain a per-client registered redirect allowlist.",
        "validation_steps": "Attempt a redirect to an unlisted host and confirm it is refused.",
        "regression_test": "Automated redirect_uri validation regression test.",
    },
    "graphql": {
        "summary": "Disable or restrict introspection outside development.",
        "technical_fix": "Gate introspection queries behind an authenticated, authorized role.",
        "configuration_fix": "Disable introspection in production configuration.",
        "validation_steps": "Send an introspection query unauthenticated and confirm denial.",
        "regression_test": "Automated introspection denial regression test.",
    },
    "headers": {
        "summary": "Configure the missing security headers at the application or proxy layer.",
        "technical_fix": "Add the required headers to the application middleware response set.",
        "configuration_fix": "Set headers at the reverse proxy (nginx/caddy/waf) for all routes.",
        "validation_steps": "Re-request the endpoint and verify header presence and values.",
        "regression_test": "Automated header presence regression test.",
    },
    "cors": {
        "summary": "Use an explicit allowlist of trusted origins; avoid credentialed wildcard policies.",
        "technical_fix": "Return Access-Control-Allow-Origin from the allowlist only and echo credentials "
                         "only for allowlisted origins.",
        "configuration_fix": "Configure CORS at the gateway with explicit origins, not '*'-with-credentials.",
        "validation_steps": "Send an Origin header for an untrusted host and confirm it is not reflected.",
        "regression_test": "Automated CORS origin regression test.",
    },
    "redirects": {
        "summary": "Validate redirect targets; never forward arbitrary 'next' parameters.",
        "technical_fix": "Allow only relative or allowlisted URLs; reject off-scope schemes/hosts.",
        "configuration_fix": "Centralize the redirect validator at the shared auth middleware.",
        "validation_steps": "Request the endpoint with an off-scope redirect target and confirm denial.",
        "regression_test": "Automated open-redirect regression test.",
    },
    "methods": {
        "summary": "Disable unsafe HTTP methods on production resources.",
        "technical_fix": "Reject OPTIONS/PUT/DELETE/TRACE for resources that do not support them.",
        "configuration_fix": "Enforce method allowlists at the server layer.",
        "validation_steps": "Send the disallowed method and confirm 405.",
        "regression_test": "Automated HTTP-method regression test.",
    },
    "disclosure": {
        "summary": "Do not expose implementation and infrastructure details to clients.",
        "technical_fix": "Strip version banners, schema/source listing and stack traces from responses.",
        "configuration_fix": "Configure server software and framework headers to omit versions.",
        "validation_steps": "Re-request the endpoint and confirm no banner/stack data is returned.",
        "regression_test": "Automated disclosure regression test.",
    },
    "information_disclosure": {
        "summary": "Do not expose implementation and infrastructure details to clients.",
        "technical_fix": "Strip version banners, schema/source listing and stack traces from responses.",
        "configuration_fix": "Configure server software and framework headers to omit versions.",
        "validation_steps": "Re-request the endpoint and confirm no banner/stack data is returned.",
        "regression_test": "Automated disclosure regression test.",
    },
    "tls": {
        "summary": "Restrict protocols/ciphers to current, secure standards.",
        "technical_fix": "Disable legacy protocols and weak cipher suites; prefer TLS 1.2+.",
        "configuration_fix": "Apply a strict cipher/protocol policy at the load balancer/TLS terminator.",
        "validation_steps": "Re-run the TLS handshake with legacy protocols and confirm refusal.",
        "regression_test": "Automated TLS policy regression test.",
    },
    "session": {
        "summary": "Harden session cookies and rotation.",
        "technical_fix": "Set Secure, HttpOnly and SameSite on session cookies; rotate on privilege change.",
        "configuration_fix": "Apply cookie flags centrally in the identity middleware.",
        "validation_steps": "Confirm the cookie flags are present over HTTPS responses.",
        "regression_test": "Automated session-cookie flag regression test.",
    },
    "authentication": {
        "summary": "Enforce strong authentication controls.",
        "technical_fix": "Add or harden authentication: rate limiting, MFA, account lockout, secure storage.",
        "configuration_fix": "Configure the identity provider to require strong flows.",
        "validation_steps": "Exercise the authentication path and confirm required controls are enforced.",
        "regression_test": "Automated authentication-control regression test.",
    },
}

_GENERIC_REMEDIATION = {
    "summary": "Harden the affected control according to security best practice.",
    "technical_fix": "Apply the project's security guidance for the affected category.",
    "configuration_fix": "Review the associated configuration for safe defaults.",
    "validation_steps": "Re-run the affected test and confirm the condition is resolved.",
    "regression_test": "Add a regression test that replays the validated condition.",
}


def resolve_component(*, category: str | None, source_test: str | None, endpoint: str | None,
                      source_tool: str | None) -> str:
    """Evidence-based affected-component resolution (never claims 'database')."""
    category = (category or "").lower()
    endpoint = (endpoint or "").lower()
    source_tool = (source_tool or "").lower()
    if category in _COMPONENT_BY_CATEGORY and category not in _API_CATEGORIES:
        return _COMPONENT_BY_CATEGORY[category]
    if "/graphql" in endpoint or category == "graphql":
        return "graphql"
    if endpoint.startswith("/api/") or category in _API_CATEGORIES:
        return "backend/api"
    if category in _HTTP_CATEGORIES:
        if "redirects" == category:
            return "frontend"
        return "configuration"
    if source_tool in ("nmap", "testssl", "native_tls"):
        return "network"
    return "configuration"


def remediation_for(category: str) -> dict[str, Any]:
    return dict(REMEDIATION.get((category or "").lower(), _GENERIC_REMEDIATION))


def technical_impact_for(category: str, severity: str | None) -> str:
    text = TECHNICAL_IMPACT.get((category or "").lower())
    if not text:
        text = "A security-relevant weakness affecting the indicated component."
    adverb = _SEVERITY_ADVERB.get(severity or "", "limited")
    return f"{adverb.capitalize()} impact: {text}"


def business_impact_for(category: str, severity: str | None, endpoint: str | None = None) -> str:
    text = BUSINESS_IMPACT.get((category or "").lower())
    if not text:
        text = "Potential confidentiality, integrity, or availability impact."
    scope = f" on {endpoint or 'the affected resource'}"
    return f"Assessed ({severity or 'Info'}): {text} Observed{scope}."


def profile_finding(*, category: str | None, severity: str | None, source_test: str | None,
                    endpoint: str | None, source_tool: str | None) -> dict[str, Any]:
    """Assemble the deterministic profile for a finding."""
    component = resolve_component(category=category, source_test=source_test,
                                  endpoint=endpoint, source_tool=source_tool)
    return {
        "affected_component": component,
        "impact_details": {
            "technical": technical_impact_for(category, severity),
            "business": business_impact_for(category, severity, endpoint),
        },
        "remediation_details": remediation_for(category),
    }


__all__ = [
    "BUSINESS_IMPACT",
    "REMEDIATION",
    "TECHNICAL_IMPACT",
    "business_impact_for",
    "profile_finding",
    "remediation_for",
    "resolve_component",
    "technical_impact_for",
]