"""Tool inventory: honest availability / version detection for every scanner.

Phase 4: the UI (and operators) must see which scanners are actually installed
and callable, never be told a scanner "ran" when its binary is absent.  This
module answers that against the real filesystem via ``shutil.which`` and a
version probe, and enriches each tool with its last persisted result.

Detection is real: ``which`` plus running ``<binary> --version`` (or a binary-
specific probe) with a hard timeout.  A tool is listed with ``installed: false``
when the binary cannot be found; it is never presented as available.
"""
from __future__ import annotations

import shutil
import subprocess
import time
import logging

from app.tools.scanner_tools import ADAPTERS, STATE_NOT_INSTALLED, BINARY_TIMEOUT_SECONDS

logger = logging.getLogger("cyberagent.inventory")

_VERSION_PROBE_TIMEOUT = 5

# Optional, per-tool version arguments (checked in order until one succeeds).
_VERSION_ARGS: dict[str, list[list[str]]] = {
    "subfinder": [["subfinder", "-version"], ["subfinder", "--version"]],
    "assetfinder": [["assetfinder", "-version"], ["assetfinder", "--version"]],
    "dnsx": [["dnsx", "-version"], ["dnsx", "--version"]],
    "nmap": [["nmap", "--version"], ["nmap", "-V"]],
    "httpx": [["httpx", "-version"], ["httpx", "--version"]],
    "gau": [["gau", "--version"], ["gau", "-version"]],
    "whatweb": [["whatweb", "--version"], ["whatweb", "-v"]],
    "nuclei": [["nuclei", "-version"], ["nuclei", "--version"]],
}

# Cap version output noise.
_VERSION_OUTPUT_LIMIT = 40
_VERSION_PROBE_CACHE: dict[str, dict] = {}
_VERSION_PROBE_CACHE_TTL = 60.0
_VERSION_PROBE_CACHE_AT: dict[str, float] = {}


def _run_version_probe(binary: str) -> str | None:
    """Return a short, real version string for an installed binary, or None."""
    candidates = _VERSION_ARGS.get(binary, [[binary, "-V"], [binary, "--version"]])
    for args in candidates:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=_VERSION_PROBE_TIMEOUT,
                shell=False,
            )
            if proc.returncode != 0:
                continue
            text = (proc.stdout or proc.stderr or "").strip()
            if not text:
                continue
            # First line, trimmed; keeps the surface small and honest.
            return text.splitlines()[0][:_VERSION_OUTPUT_LIMIT].strip()
        except Exception:  # pragma: no cover - environment specific
            continue
    return None


def _cached_probe(binary: str) -> str | None:
    now = time.monotonic()
    hit_at = _VERSION_PROBE_CACHE_AT.get(binary)
    if hit_at is not None and now - hit_at < _VERSION_PROBE_CACHE_TTL:
        return _VERSION_PROBE_CACHE.get(binary)
    version = _run_version_probe(binary)
    _VERSION_PROBE_CACHE[binary] = version
    _VERSION_PROBE_CACHE_AT[binary] = now
    return version


def tool_inventory() -> list[dict]:
    """Real snapshot of every registered scanner + the stdlib probes."""
    tools = []
    for name, adapter in ADAPTERS.items():
        binary = adapter.binary if getattr(adapter, "binary", "") else name
        path = shutil.which(binary)
        installed = path is not None
        entry = {
            "tool": name,
            "binary": binary,
            "installed": installed,
            "path": path or None,
            "version": _cached_probe(binary) if installed else None,
            "category": _category(name),
            "note": None if installed else f"{binary} not found on PATH",
        }
        tools.append(entry)
    # Stdlib probes are always available (no external binary required).
    for probe, label in [("real_dns", "DNS resolution"), ("real_tcp", "TCP connect scan"),
                         ("real_http", "HTTP fingerprinting"),
                         ("world_monitor_discovery", "World Monitor deployment discovery")]:
        tools.append({
            "tool": probe,
            "binary": None,
            "installed": True,
            "path": None,
            "version": None,
            "category": "probe",
            "note": f"stdlib probe - {label} (no external binary required)",
        })
    return tools


def _category(name: str) -> str:
    if name in ("subfinder", "assetfinder"):
        return "recon"
    if name == "dnsx":
        return "dns"
    if name == "nmap":
        return "service"
    if name in ("httpx", "gau", "whatweb"):
        return "http"
    if name == "nuclei":
        return "vulnerability"
    return "probe"