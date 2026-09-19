"""External-tool adapter base (Phase 5).

Phase 4 adapters returned loosely-shaped dicts keyed by ``tool``.  Phase 5
needs every external binary to feed the *same* normalized observation pipeline
as the native engine, so an adapter here has one job:

    target + options  ->  run binary  ->  parse stdout  ->  [ToolObservation]

Three guarantees are enforced in this module and must not be bypassed:

  * availability -- a missing binary yields ``Not Installed`` and ZERO
    observations.  Nothing is ever fabricated for a tool that did not run.
  * execution    -- binaries are invoked with a list of arguments and
    ``shell=False``; the target is stripped of control characters.  Parsers
    only ever read stdout, never the network.
  * parsing      -- malformed output raises ``ToolParseError`` and is reported
    as ``Parse Failed`` rather than being silently coerced into observations.

``ToolObservation`` is a tool-neutral value object; ``to_observation_data``
turns it into the exact kwargs accepted by ``build_observation`` so the
persistence layer stays the single redaction/normalization choke point.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from app.observations import types
from app.observations.normalize import build_observation
from app.tools.capabilities import ToolCapability, capability
from app.tools.scanner_tools import (
    BINARY_TIMEOUT_SECONDS,
    STATE_COMPLETED,
    STATE_EXECUTION_FAILED,
    STATE_NOT_INSTALLED,
    STATE_PARSE_FAILED,
    STATE_TIMEOUT,
    is_tool_installed,
)

# Arguments that must never be persisted in cleartext (values after these flags
# are masked in ``redact_command``).  Only unambiguous credential flags live
# here -- short flags like ``-p`` are tool-specific and intentionally excluded.
SENSITIVE_ARG_FLAGS = frozenset({
    "--cookie", "--header", "--token", "--data", "--data-raw",
    "--password", "--auth", "--authorization", "--api-key",
})

_UNSAFE_TARGET = re.compile(r"[\s\x00-\x1f\"'`$|;&<>(){}]")

# Arguments that would make a run destructive/out-of-scope; adapters reject
# them outright rather than trusting the caller.
FORBIDDEN_OPTIONS = frozenset({
    "dump", "dump_all", "os_shell", "os_cmd", "file_read", "file_write",
    "sql_shell", "batch_dump", "risk_high",
})


class ToolParseError(ValueError):
    """Raised when a tool's stdout cannot be trusted as structured output."""


def safe_target(target: str) -> str:
    """Strip shell/control characters from a target without lossy URL mangling.

    ``shell=False`` already makes injection impossible; this is defence in
    depth so a stray newline can never split a target into two arguments.
    """
    return _UNSAFE_TARGET.sub("", target or "")


def redact_command(command: Sequence[str]) -> list[str]:
    """Mask the value following any sensitive flag."""
    out: list[str] = []
    mask_next = False
    for token in command:
        if mask_next:
            out.append("<REDACTED>")
            mask_next = False
            continue
        out.append(token)
        if token in SENSITIVE_ARG_FLAGS:
            mask_next = True
    return out


@dataclass
class ToolObservation:
    """A single normalized, tool-produced measurement."""

    observation_type: str
    subject: str
    data: dict = field(default_factory=dict)
    raw_output: str = ""
    status: str = types.STATUS_OBSERVED
    discriminator: Any = None

    def __post_init__(self) -> None:
        if self.observation_type not in types.OBSERVATION_TYPES:
            raise ValueError(f"unknown observation_type: {self.observation_type!r}")

    def to_observation_data(
        self,
        *,
        scan_id: int,
        tool_name: str,
        source: str = types.SOURCE_EXTERNAL_TOOL,
        user_id: str | None = None,
        target: str | None = None,
        asset: str | None = None,
        tool_version: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        return build_observation(
            scan_id=scan_id,
            observation_type=self.observation_type,
            subject=self.subject,
            tool_name=tool_name,
            source=source,
            user_id=user_id,
            target=target,
            asset=asset,
            tool_version=tool_version,
            data=self.data or None,
            raw_output=self.raw_output,
            metadata=metadata,
            status=self.status,
            discriminator=self.discriminator,
        )


@dataclass
class ToolRunResult:
    """Outcome of one adapter invocation; observations are the only payload."""

    tool: str
    status: str
    observations: list[ToolObservation] = field(default_factory=list)
    raw_output: str = ""
    error: str | None = None
    command: list[str] = field(default_factory=list)
    duration_ms: int = 0
    exit_code: int | None = None
    installed: bool = True

    @property
    def ok(self) -> bool:
        return self.status == STATE_COMPLETED

    @property
    def executed(self) -> bool:
        return self.status in (STATE_COMPLETED, STATE_PARSE_FAILED)


class ExternalToolAdapter:
    """Base class shared by every external scanner adapter."""

    tool_name: str = ""
    binary: str = ""
    output_format: str = "text"
    # Environment variable holding an optional explicit binary path.
    path_env: str | None = None

    # --- capability declaration -------------------------------------------
    def capability(self) -> ToolCapability | None:
        return capability(self.tool_name)

    @property
    def declared_capabilities(self) -> tuple[str, ...]:
        cap = self.capability()
        return tuple(cap.capabilities) if cap else ()

    @property
    def active(self) -> bool:
        cap = self.capability()
        return bool(cap and cap.active)

    # --- availability ------------------------------------------------------
    def installed_binary(self) -> str | None:
        env = None
        if self.path_env:
            import os

            env = env or os.getenv(self.path_env)
        if env:
            return env
        return self.binary if is_tool_installed(self.binary) else None

    def available(self) -> bool:
        return self.installed_binary() is not None

    # --- hooks -------------------------------------------------------------
    def build_command(self, target: str, options: dict) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        raise NotImplementedError

    def extract_output(self, completed: subprocess.CompletedProcess, options: dict) -> str:
        """Return the text to parse.  File-emitting tools override this."""
        return completed.stdout or ""

    # --- execution ---------------------------------------------------------
    def run(self, target: str, *, simulation: bool = False,
            options: dict | None = None) -> ToolRunResult:
        opts = dict(options or {})
        forbidden = FORBIDDEN_OPTIONS.intersection(opts)
        if forbidden:
            return ToolRunResult(
                tool=self.tool_name, status=STATE_EXECUTION_FAILED,
                error=f"forbidden options: {', '.join(sorted(forbidden))}",
                installed=self.available(),
            )
        sanitized = safe_target(target)
        if simulation:
            return ToolRunResult(
                tool=self.tool_name, status=STATE_COMPLETED, observations=[],
                raw_output=f"[{self.tool_name}] [SIMULATION] no observations synthesized; "
                           f"real output required",
                installed=self.available(),
            )
        binary = self.installed_binary()
        if binary is None:
            return ToolRunResult(
                tool=self.tool_name, status=STATE_NOT_INSTALLED, observations=[],
                error=f"{self.binary} not found on PATH",
                raw_output=f"[{self.tool_name}] NOT INSTALLED: {self.binary} is not on PATH. "
                           f"No scan was executed.",
                installed=False,
            )
        command = self.build_command(sanitized, opts)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True,
                timeout=BINARY_TIMEOUT_SECONDS, shell=False,
            )
        except subprocess.TimeoutExpired:
            return ToolRunResult(
                tool=self.tool_name, status=STATE_TIMEOUT, command=redact_command(command),
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"execution exceeded {BINARY_TIMEOUT_SECONDS}s", installed=True,
            )
        except FileNotFoundError:
            return ToolRunResult(
                tool=self.tool_name, status=STATE_NOT_INSTALLED, command=redact_command(command),
                error=f"{self.binary} not found on PATH", installed=False,
            )
        except OSError as exc:  # pragma: no cover - environment specific
            return ToolRunResult(
                tool=self.tool_name, status=STATE_EXECUTION_FAILED,
                command=redact_command(command), error=str(exc), installed=True,
            )

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = self.extract_output(completed, opts)
        try:
            observations = self.parse(stdout, sanitized)
        except ToolParseError as exc:
            return ToolRunResult(
                tool=self.tool_name, status=STATE_PARSE_FAILED, observations=[],
                raw_output=stdout, error=str(exc), command=redact_command(command),
                duration_ms=duration_ms, exit_code=completed.returncode, installed=True,
            )
        return ToolRunResult(
            tool=self.tool_name, status=STATE_COMPLETED, observations=observations,
            raw_output=stdout, command=redact_command(command), duration_ms=duration_ms,
            exit_code=completed.returncode, installed=True,
        )

    # --- helpers for parsers ----------------------------------------------
    @staticmethod
    def parse_json(stdout: str) -> Any:
        import json

        text = (stdout or "").strip()
        if not text:
            raise ToolParseError("empty output where JSON was expected")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolParseError(f"invalid JSON output: {exc}") from exc

    @staticmethod
    def parse_jsonl(stdout: str) -> list[Any]:
        import json

        records: list[Any] = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ToolParseError(f"invalid JSON line: {exc}") from exc
        return records
