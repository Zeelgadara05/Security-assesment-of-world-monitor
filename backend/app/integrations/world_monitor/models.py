"""World Monitor integration boundary (Phase 8).

Structured, deterministic result types for the World Monitor provider.  These
are the *only* shapes the rest of the application consumes from the World
Monitor integration.  Nothing here fabricates data: every field is filled from
a real probe result or left at its neutral value (``None`` / ``unavailable`` /
``unsupported`` / ``blocked``), which is itself an honest state.

Connectivity states come from ``database.models`` so the ORM and the provider
share one vocabulary.  They never include ``secure``/``insecure`` -- security
posture is determined by assessment findings, never by connectivity.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from database.models import (
    WORLD_MONITOR_STATUS_CHECKING,
    WORLD_MONITOR_STATUS_DISCOVERED,
    WORLD_MONITOR_STATUS_NOT_CONFIGURED,
    WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED,
    WORLD_MONITOR_STATUS_REACHABLE,
    WORLD_MONITOR_STATUS_UNAVAILABLE,
)

# Discovery step outcomes: checked but unusable is "unavailable"; a step the
# integration is not equipped for (or would require guessing) is "unsupported";
# rejected by scope policy is "blocked".
STEP_CHECKED = "checked"
STEP_REACHABLE = "reachable"
STEP_UNAVAILABLE = "unavailable"
STEP_UNSUPPORTED = "unsupported"
STEP_BLOCKED = "blocked"

# Where an endpoint/inventory row came from (never an invented source).
SOURCE_BASE_URL = "base_url"
SOURCE_API_BASE = "api_base"
SOURCE_OPENAPI = "openapi"
SOURCE_FRONTEND = "frontend"
SOURCE_RPC = "rpc"

# OpenAPI / RPC metadata availability, recorded honestly.
OPENAPI_UNCONFIGURED = "unconfigured"
OPENAPI_AVAILABLE = "available"
OPENAPI_UNAVAILABLE = "unavailable"
OPENAPI_UNSUPPORTED = "unsupported"
RPC_UNSUPPORTED = "unsupported"


@dataclass
class HealthResult:
    """Result of one real health/connectivity probe against a WM base URL."""

    url: str
    reachable: bool = False
    http_status: int = 0
    elapsed_ms: float = 0.0
    server: str | None = None
    version_hint: str | None = None
    detected_metadata: dict = field(default_factory=dict)
    tls: dict | None = None
    error: str | None = None
    checked_at: str = field(default_factory=datetime.datetime.utcnow().isoformat)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "http_status": self.http_status,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "server": self.server,
            "version_hint": self.version_hint,
            "detected_metadata": self.detected_metadata,
            "tls": self.tls,
            "error": self.error,
            "checked_at": self.checked_at,
        }


@dataclass
class DiscoveryStep:
    """One real step in the ordered World Monitor discovery sequence."""

    order: int
    source: str
    location: str
    status: str  # checked|reachable|unavailable|unsupported|blocked
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "order": self.order,
            "source": self.source,
            "location": self.location,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class APIEndpoint:
    """One normalized, actually-discovered World Monitor API endpoint."""

    method: str
    path: str
    operation_id: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str = SOURCE_OPENAPI
    authentication_hint: str | None = None

    def to_dict(self) -> dict:
        return {
            "method": self.method.upper(),
            "path": self.path,
            "operation_id": self.operation_id,
            "tags": list(self.tags or []),
            "source": self.source,
            "authentication_hint": self.authentication_hint,
        }


@dataclass
class DiscoveryResult:
    """Result of a World Monitor discovery run (target status + steps)."""

    base_url: str
    target_status: str = WORLD_MONITOR_STATUS_NOT_CONFIGURED
    steps: list[DiscoveryStep] = field(default_factory=list)
    endpoints: list[APIEndpoint] = field(default_factory=list)
    openapi_status: str = OPENAPI_UNCONFIGURED
    rpc_status: str = RPC_UNSUPPORTED
    discovered_version: str | None = None
    started_at: str = field(default_factory=datetime.datetime.utcnow().isoformat)
    finished_at: str | None = None
    error: str | None = None
    health: HealthResult | None = None

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "target_status": self.target_status,
            "steps": [s.to_dict() for s in self.steps],
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "openapi_status": self.openapi_status,
            "rpc_status": self.rpc_status,
            "discovered_version": self.discovered_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "health": self.health.to_dict() if self.health else None,
        }


__all__ = [
    "HealthResult", "DiscoveryStep", "APIEndpoint", "DiscoveryResult",
    "STEP_CHECKED", "STEP_REACHABLE", "STEP_UNAVAILABLE", "STEP_UNSUPPORTED",
    "STEP_BLOCKED",
    "SOURCE_BASE_URL", "SOURCE_API_BASE", "SOURCE_OPENAPI", "SOURCE_FRONTEND",
    "SOURCE_RPC",
    "OPENAPI_UNCONFIGURED", "OPENAPI_AVAILABLE", "OPENAPI_UNAVAILABLE",
    "OPENAPI_UNSUPPORTED", "RPC_UNSUPPORTED",
    "WORLD_MONITOR_STATUS_CHECKING", "WORLD_MONITOR_STATUS_DISCOVERED",
    "WORLD_MONITOR_STATUS_NOT_CONFIGURED", "WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED",
    "WORLD_MONITOR_STATUS_REACHABLE", "WORLD_MONITOR_STATUS_UNAVAILABLE",
]