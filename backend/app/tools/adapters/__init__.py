"""External tool adapters (Phase 5).

Each adapter turns a CLI binary's structured output into normalized
``ToolObservation`` values that flow through the same redaction and persistence
pipeline as native observations.  A missing binary yields ``Not Installed`` and
zero observations -- never a fabricated result.
"""
from __future__ import annotations

from app.tools.adapters.base import (
    ExternalToolAdapter,
    ToolObservation,
    ToolParseError,
    ToolRunResult,
    redact_command,
    safe_target,
)
from app.tools.adapters.registry import (
    ADAPTERS,
    adapters_for_capability,
    available_adapters,
    get_adapter,
    run_adapter,
)

__all__ = [
    "ADAPTERS",
    "ExternalToolAdapter",
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
