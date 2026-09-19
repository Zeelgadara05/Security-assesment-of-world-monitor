"""sqlmap adapter -- conservative, non-destructive SQL injection observations.

Only boolean-based detection at level 1 / risk 1 is permitted.  Any option that
would read, write or dump data is rejected by ``FORBIDDEN_OPTIONS`` in the base
class.  The text parser emits an observation ONLY when sqlmap explicitly reports
an injectable parameter; the common "do not appear to be injectable" outcome
produces no observations (never a fabricated negative finding).
"""
from __future__ import annotations

import re

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation, ToolParseError

_PARAMETER_RE = re.compile(r"^\s*Parameter:\s*(?P<name>[^()]+?)(?:\s*\((?P<place>[^)]*)\))?\s*$")
_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+?)\s*$")
_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(?P<payload>.+?)\s*$")


class SqlmapAdapter(ExternalToolAdapter):
    tool_name = "sqlmap"
    binary = "sqlmap"
    output_format = "text"

    def build_command(self, target: str, options: dict) -> list[str]:
        parameter = options.get("parameter")
        if not parameter:
            raise ToolParseError("sqlmap adapter requires 'parameter'")
        return [
            "sqlmap", "-u", target, "-p", str(parameter),
            "--batch", "--flush-session",
            "--level", str(options.get("level", 1)),
            "--risk", str(options.get("risk", 1)),
            "--technique", "B",
        ]

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        observations: list[ToolObservation] = []
        current: dict | None = None
        types_found: list[str] = []
        payloads: list[str] = []

        def flush() -> None:
            if current is None or not types_found:
                return
            observations.append(ToolObservation(
                types.OBS_VULNERABILITY,
                target,
                data={
                    "parameter": current["name"],
                    "place": current.get("place"),
                    "types": list(types_found),
                    "payloads": list(payloads),
                    "source_tool": "sqlmap",
                },
                discriminator={"parameter": current["name"], "place": current.get("place")},
            ))

        for line in (stdout or "").splitlines():
            param_match = _PARAMETER_RE.match(line)
            if param_match:
                flush()
                current = {
                    "name": param_match.group("name").strip(),
                    "place": (param_match.group("place") or "").strip() or None,
                }
                types_found = []
                payloads = []
                continue
            if current is None:
                continue
            type_match = _TYPE_RE.match(line)
            if type_match:
                types_found.append(type_match.group("type"))
                continue
            payload_match = _PAYLOAD_RE.match(line)
            if payload_match:
                payloads.append(payload_match.group("payload"))

        flush()
        return observations
