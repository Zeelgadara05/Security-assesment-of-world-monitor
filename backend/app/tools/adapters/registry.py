"""External tool adapter registry (Phase 5).

Maps a tool name to its normalizing adapter and exposes capability-based lookup
so the planner can ask "which installed tool can satisfy this capability?".
The registry is static and deterministic; install state is resolved per call.
"""
from __future__ import annotations

from app.tools.adapters.base import (
    ExternalToolAdapter,
    SENSITIVE_ARG_FLAGS,
    ToolObservation,
    ToolParseError,
    ToolRunResult,
    redact_command,
    safe_target,
)
from app.tools.adapters.ffuf import FfufAdapter
from app.tools.adapters.httpx import HttpxAdapter
from app.tools.adapters.nikto import NiktoAdapter
from app.tools.adapters.nmap import NmapAdapter
from app.tools.adapters.nuclei import NucleiAdapter
from app.tools.adapters.sqlmap import SqlmapAdapter
from app.tools.adapters.testssl import TestsslAdapter

_ADAPTER_CLASSES = (
    NmapAdapter, NucleiAdapter, HttpxAdapter, FfufAdapter,
    NiktoAdapter, SqlmapAdapter, TestsslAdapter,
)

ADAPTERS: dict[str, ExternalToolAdapter] = {
    adapter.tool_name: adapter for adapter in (cls() for cls in _ADAPTER_CLASSES)
}


def get_adapter(tool: str) -> ExternalToolAdapter | None:
    return ADAPTERS.get(tool)


def adapters_for_capability(capability_id: str, *, installed_only: bool = False) -> list[ExternalToolAdapter]:
    found = [a for a in ADAPTERS.values() if capability_id in a.declared_capabilities]
    if installed_only:
        found = [a for a in found if a.available()]
    return found


def available_adapters() -> list[ExternalToolAdapter]:
    return [a for a in ADAPTERS.values() if a.available()]


def run_adapter(tool: str, target: str, *, simulation: bool = False,
                options: dict | None = None) -> ToolRunResult:
    adapter = get_adapter(tool)
    if adapter is None:
        raise KeyError(f"no adapter registered for tool {tool!r}")
    return adapter.run(target, simulation=simulation, options=options)


__all__ = [
    "ADAPTERS",
    "ExternalToolAdapter",
    "SENSITIVE_ARG_FLAGS",
    "ToolObservation",
    "ToolParseError",
    "ToolRunResult",
    "adapters_for_capability",
    "available_adapters",
    "get_adapter",
    "redact_command",
    "run_adapter",
    "safe_target",
]
