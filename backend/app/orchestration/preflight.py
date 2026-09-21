"""Real per-scan preflight (Phase 7).

Before any tool runs the pipeline snapshots what is actually available: PATH
resolution + version probes for every planned tool (via the shared inventory),
which tools the operator disabled, and which Phase 5 adapters can normalize a
tool's output.  The result is persisted twice:

  * ``scan.preflight_json`` -- the full machine-readable snapshot,
  * one ``ToolReadiness`` row per planned tool (installed / missing /
    disabled / adapter_unavailable).

A missing binary is recorded as missing -- never presented as available.  The
pipeline gates on this snapshot when deciding ``blocked`` vs. proceding with
honest coverage.
"""
from __future__ import annotations

import datetime
import shutil
import time

from app.orchestration.stages import TOOL_TO_STAGE, enabled as stage_enabled
from app.tools.adapters.registry import get_adapter
from app.tools.inventory import tool_inventory
from app.tools.scanner_tools import sanitize_input

_PROBE_TOOLS = ("real_dns", "real_tcp", "real_http", "world_monitor_discovery")

# Stage -> coarse category, kept in sync with app/orchestration/stages.
_STAGE_CATEGORY = {
    "TARGET_NORMALIZATION": "probe",
    "PASSIVE_RECON": "recon",
    "DNS_DISCOVERY": "dns",
    "PORT_SERVICE_DISCOVERY": "service",
    "HTTP_DISCOVERY": "http",
    "TECHNOLOGY_IDENTIFICATION": "http",
    "VULNERABILITY_DISCOVERY": "vulnerability",
}


def _adapter_kind(tool: str) -> str:
    if tool in _PROBE_TOOLS:
        return "probe"
    if get_adapter(tool) is not None:
        return "external"
    return "legacy"


def _tool_entry(tool: str, inv_index: dict) -> dict:
    """Return the inventory-style entry for one tool (real PATH probe)."""
    entry = inv_index.get(tool)
    if entry is not None:
        return entry
    adapter = get_adapter(tool)
    binary = adapter.binary if adapter is not None else tool
    path = shutil.which(binary)
    return {
        "tool": tool,
        "binary": binary,
        "installed": path is not None,
        "path": path or None,
        "version": None,  # inventory has no probe for this tool
        "category": "vulnerability",
        "note": None if path is not None else f"{binary} not found on PATH",
    }


def build_preflight(db, scan, config: dict | None) -> dict:
    """Probe the real environment and persist the readiness snapshot.

    Returns the snapshot dict (also stored on ``scan.preflight_json``).  The
    pipeline decides ``blocked`` from ``snapshot["blocked_reasons"]``.
    """
    from database.models import ToolReadiness

    config = dict(config or {})
    started = time.monotonic()
    inv = {e["tool"]: e for e in tool_inventory()}
    requested = (config.get("tools") or {})

    tools: list[dict] = []
    blocked_reasons: list[str] = []
    notes: list[str] = []

    sanitized_target = sanitize_input(scan.target or "")
    if not sanitized_target:
        blocked_reasons.append(
            f"target {scan.target!r} is empty after input sanitization; "

            "no tools can be pointed at a safe subject")

    for tool in sorted(TOOL_TO_STAGE):
        # Conditional tool: only relevant when the scan actually references a
        # World Monitor deployment; otherwise it is not planned at all and must
        # not appear as a (misleading) disabled/missing entry.
        if tool == "world_monitor_discovery" and not config.get("world_monitor"):
            continue
        entry = _tool_entry(tool, inv)
        adapter = get_adapter(tool)
        requested_on = stage_enabled(config, tool)
        stage = TOOL_TO_STAGE[tool]
        if not requested_on:
            status = "disabled"
            reason = "disabled by scan configuration"
        elif entry.get("installed"):
            status = "installed"
            reason = None
        elif adapter is not None and adapter.available():
            status = "installed"
            reason = f"{entry.get('binary') or tool} available via adapter"
        else:
            status = "missing"
            reason = entry.get("note") or f"{entry.get('binary') or tool} not found on PATH"
            notes.append(reason)

        tools.append({
            "name": tool,
            "binary": entry.get("binary"),
            "stage": stage,
            "category": _STAGE_CATEGORY.get(stage, "probe"),
            "status": status,
            "enabled": requested_on,
            "executable": entry.get("path"),
            "version": entry.get("version"),
            "adapter": _adapter_kind(tool),
            "reason": reason,
        })

    installed = [t["name"] for t in tools if t["status"] == "installed"]
    missing = [t["name"] for t in tools if t["status"] == "missing"]
    disabled = [t["name"] for t in tools if t["status"] == "disabled"]

    # A probe or adapter tool being present is enough to run a real assessment
    # (with honest coverage).  Only zero installed + zero stdlib probes blocks.
    runnable = any(t["status"] == "installed" and t["name"] in _PROBE_TOOLS
                   for t in tools) or len(installed) > 0

    duration_ms = int((time.monotonic() - started) * 1000)
    snapshot = {
        "checked_at": datetime.datetime.utcnow().isoformat(),
        "duration_ms": duration_ms,
        "target": scan.target,
        "target_sanitized": sanitized_target,
        "config": {
            "tools": {t: stage_enabled(config, t) for t in sorted(TOOL_TO_STAGE)},
            "severity": config.get("severity", "all"),
            "profile": config.get("profile", "steady"),
            "active_testing": bool(config.get("active_testing", False)),
        },
        "tools": tools,
        "installed": installed,
        "missing": missing,
        "disabled": disabled,
        "runnable": runnable,
        "blocked_reasons": blocked_reasons,
        "notes": notes,
    }
    if not runnable:
        snapshot["blocked_reasons"].append(
            "no enabled tool is operational on this host (all missing/disabled)")

    scan.preflight_json = snapshot

    now = datetime.datetime.utcnow()
    for t in tools:
        db.add(ToolReadiness(
            scan_id=scan.id,
            tool=t["name"],
            status=t["status"],
            executable=t.get("executable"),
            version=t.get("version"),
            adapter=t.get("adapter"),
            category=t.get("category"),
            enabled=bool(t.get("enabled")),
            reason=t.get("reason"),
            duration_ms=duration_ms,
            checked_at=now,
        ))
    db.flush()
    return snapshot


def planned_tool_settings(snapshot: dict) -> dict:
    """tool -> enabled flag from a persisted preflight snapshot."""
    return {
        t["name"]: bool(t.get("enabled")) and t.get("status") == "installed"
        for t in (snapshot or {}).get("tools", [])
    }


def blocked(snapshot: dict) -> list[str]:
    return list((snapshot or {}).get("blocked_reasons") or [])


__all__ = ["build_preflight", "blocked", "planned_tool_settings"]