"""Tool capability matrix (Phase 5).

Phase 4 answered only "installed / not installed".  Phase 5 must answer what a
tool can actually *do*: its capabilities, categories, input requirements, output
format and whether it observes passively or actively mutates the target.  A
capability is reported as available only when the underlying binary is
installed; the capability list itself is a static, auditable declaration (never
inferred from a tool merely existing).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Capability identifiers shared with the planner and coverage engine.
CAP_PORT_SCAN = "port_scan"
CAP_SERVICE_DETECTION = "service_detection"
CAP_VERSION_DETECTION = "version_detection"
CAP_SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
CAP_DNS_RESOLUTION = "dns_resolution"
CAP_URL_DISCOVERY = "url_discovery"
CAP_HTTP_PROBE = "http_probe"
CAP_HTTP_FINGERPRINT = "http_fingerprint"
CAP_TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
CAP_VULNERABILITY_SCAN = "vulnerability_scan"
CAP_DIRECTORY_FUZZING = "directory_fuzzing"
CAP_PARAMETER_FUZZING = "parameter_fuzzing"
CAP_WEB_SERVER_SCAN = "web_server_scan"
CAP_SQL_INJECTION = "sql_injection"
CAP_TLS_ANALYSIS = "tls_analysis"
# Native (stdlib) capabilities: always available, no external binary required.
CAP_HTTP_REQUEST = "http_request"
CAP_HEADER_ANALYSIS = "header_analysis"
CAP_CORS_ANALYSIS = "cors_analysis"
CAP_METHOD_ANALYSIS = "method_analysis"
CAP_REDIRECT_ANALYSIS = "redirect_analysis"
CAP_DISCLOSURE_ANALYSIS = "disclosure_analysis"
CAP_XSS_VALIDATION = "xss_validation"
CAP_SQLI_VALIDATION = "sqli_validation"
CAP_SSTI_VALIDATION = "ssti_validation"
CAP_AUTHORIZATION_TESTING = "authorization_testing"
CAP_JWT_ANALYSIS = "jwt_analysis"


@dataclass(frozen=True)
class ToolCapability:
    tool: str
    binary: str | None
    capabilities: tuple[str, ...]
    categories: tuple[str, ...]
    input_requirements: tuple[str, ...] = ()
    output_format: str = "text"
    active: bool = False
    native: bool = False
    description: str = ""


_CATALOG: dict[str, ToolCapability] = {
    "nmap": ToolCapability(
        tool="nmap", binary="nmap",
        capabilities=(CAP_PORT_SCAN, CAP_SERVICE_DETECTION, CAP_VERSION_DETECTION),
        categories=("service", "network"), input_requirements=("host",),
        output_format="text", active=True,
        description="Port and service/version detection.",
    ),
    "nuclei": ToolCapability(
        tool="nuclei", binary="nuclei",
        capabilities=(CAP_VULNERABILITY_SCAN,),
        categories=("vulnerability",), input_requirements=("url", "host"),
        output_format="jsonl", active=True,
        description="Template-based vulnerability scanning.",
    ),
    "httpx": ToolCapability(
        tool="httpx", binary="httpx",
        capabilities=(CAP_HTTP_PROBE, CAP_HTTP_FINGERPRINT),
        categories=("http",), input_requirements=("url", "host"),
        output_format="text", active=True,
        description="HTTP probing and server/title fingerprinting.",
    ),
    "subfinder": ToolCapability(
        tool="subfinder", binary="subfinder",
        capabilities=(CAP_SUBDOMAIN_ENUMERATION,),
        categories=("recon",), input_requirements=("domain",),
        output_format="text", active=False,
        description="Passive subdomain enumeration.",
    ),
    "assetfinder": ToolCapability(
        tool="assetfinder", binary="assetfinder",
        capabilities=(CAP_SUBDOMAIN_ENUMERATION,),
        categories=("recon",), input_requirements=("domain",),
        output_format="text", active=False,
        description="Passive subdomain/asset discovery.",
    ),
    "dnsx": ToolCapability(
        tool="dnsx", binary="dnsx",
        capabilities=(CAP_DNS_RESOLUTION,),
        categories=("dns",), input_requirements=("host",),
        output_format="text", active=False,
        description="DNS resolution and record probing.",
    ),
    "gau": ToolCapability(
        tool="gau", binary="gau",
        capabilities=(CAP_URL_DISCOVERY,),
        categories=("http",), input_requirements=("domain",),
        output_format="text", active=False,
        description="Passive URL discovery from public archives.",
    ),
    "whatweb": ToolCapability(
        tool="whatweb", binary="whatweb",
        capabilities=(CAP_TECHNOLOGY_FINGERPRINT,),
        categories=("http",), input_requirements=("url",),
        output_format="text", active=True,
        description="Web technology fingerprinting.",
    ),
    "ffuf": ToolCapability(
        tool="ffuf", binary="ffuf",
        capabilities=(CAP_DIRECTORY_FUZZING, CAP_PARAMETER_FUZZING),
        categories=("http", "fuzzing"), input_requirements=("url", "wordlist"),
        output_format="json", active=True,
        description="Content and parameter fuzzing (active).",
    ),
    "nikto": ToolCapability(
        tool="nikto", binary="nikto",
        capabilities=(CAP_WEB_SERVER_SCAN,),
        categories=("http", "vulnerability"), input_requirements=("url",),
        output_format="text", active=True,
        description="Web server misconfiguration scanning (active).",
    ),
    "sqlmap": ToolCapability(
        tool="sqlmap", binary="sqlmap",
        capabilities=(CAP_SQL_INJECTION,),
        categories=("injection",), input_requirements=("url", "parameter"),
        output_format="text", active=True,
        description="SQL injection testing (active; gated, never destructive here).",
    ),
    "testssl": ToolCapability(
        tool="testssl", binary="testssl",
        capabilities=(CAP_TLS_ANALYSIS,),
        categories=("tls",), input_requirements=("host", "port"),
        output_format="json", active=False,
        description="TLS/SSL configuration analysis.",
    ),
    # --- Native stdlib capabilities (always available) ---------------------
    "native_http": ToolCapability(
        tool="native_http", binary=None,
        capabilities=(
            CAP_HTTP_REQUEST, CAP_HEADER_ANALYSIS, CAP_CORS_ANALYSIS,
            CAP_METHOD_ANALYSIS, CAP_REDIRECT_ANALYSIS, CAP_DISCLOSURE_ANALYSIS,
            CAP_XSS_VALIDATION, CAP_SQLI_VALIDATION, CAP_SSTI_VALIDATION,
            CAP_AUTHORIZATION_TESTING, CAP_JWT_ANALYSIS,
        ),
        categories=("http", "assessment"), output_format="structured",
        active=True, native=True,
        description="Native HTTP observation and differential testing engine.",
    ),
    "native_tls": ToolCapability(
        tool="native_tls", binary=None,
        capabilities=(CAP_TLS_ANALYSIS,),
        categories=("tls",), output_format="structured", native=True,
        description="Native TLS certificate and protocol inspection.",
    ),
}

# External (installable) tool names, in catalog order.
EXTERNAL_TOOLS = tuple(
    name for name, cap in _CATALOG.items() if not cap.native
)


def capability(name: str) -> ToolCapability | None:
    return _CATALOG.get(name)


def has_capability(tool: str, capability_id: str) -> bool:
    cap = _CATALOG.get(tool)
    return bool(cap and capability_id in cap.capabilities)


def capabilities_for(name: str, *, installed: bool | None = None, version: str | None = None) -> dict:
    """Serialize a tool's capabilities, optionally with live install state."""
    cap = _CATALOG.get(name)
    if cap is None:
        return {
            "tool": name, "installed": False, "version": None,
            "capabilities": [], "categories": [], "native": False,
            "active": False, "output_format": None, "input_requirements": [],
            "description": "", "adapter_status": "unknown",
        }
    if installed is None:
        installed = cap.native
        if not cap.native:
            try:
                from app.tools.inventory import tool_inventory

                entry = next((t for t in tool_inventory() if t["tool"] == name), None)
                installed = bool(entry and entry["installed"])
                version = version or (entry or {}).get("version")
            except Exception:
                installed = False
    return {
        "tool": cap.tool,
        "installed": bool(installed),
        "version": version,
        "capabilities": list(cap.capabilities) if installed else [],
        "declared_capabilities": list(cap.capabilities),
        "categories": list(cap.categories),
        "native": cap.native,
        "active": cap.active,
        "output_format": cap.output_format,
        "input_requirements": list(cap.input_requirements),
        "description": cap.description,
        "adapter_status": "native" if cap.native else ("available" if installed else "not_installed"),
    }


def tool_capability_matrix(*, inventory: list[dict] | None = None) -> list[dict]:
    """Full capability matrix, merging optional live inventory install state."""
    install_state: dict[str, dict] = {}
    if inventory:
        install_state = {t.get("tool"): t for t in inventory}
    matrix = []
    for name, cap in _CATALOG.items():
        if cap.native:
            matrix.append(capabilities_for(name, installed=True))
            continue
        entry = install_state.get(name)
        if entry is not None:
            matrix.append(capabilities_for(name, installed=bool(entry.get("installed")), version=entry.get("version")))
        else:
            matrix.append(capabilities_for(name))
    return matrix
