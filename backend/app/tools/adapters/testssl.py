"""testssl adapter -- JSON TLS analysis normalized into certificate/finding observations."""
from __future__ import annotations

import os

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation, ToolParseError

# Severities testssl uses for findings that warrant an observation.
_REPORTABLE_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"}
_OK_SEVERITIES = {"OK", "INFO"}
_CERT_PREFIX = "cert_"


class TestsslAdapter(ExternalToolAdapter):
    tool_name = "testssl"
    binary = "testssl"
    output_format = "json"

    def build_command(self, target: str, options: dict) -> list[str]:
        output = options.get("output", "testssl-report.json")
        command = ["testssl", "--quiet", "--jsonfile", str(output)]
        command.append(target)
        return command

    def extract_output(self, completed, options: dict) -> str:
        path = options.get("output", "testssl-report.json")
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        return completed.stdout or ""

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        payload = self.parse_json(stdout)
        if isinstance(payload, dict):
            entries = payload.get("scanResult") or payload.get("results") or []
        elif isinstance(payload, list):
            entries = payload
        else:
            raise ToolParseError("unexpected testssl JSON shape")
        if not isinstance(entries, list):
            raise ToolParseError("testssl entries is not a list")

        observations: list[ToolObservation] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_id = str(entry.get("id") or "")
            finding = entry.get("finding") or entry.get("value") or ""
            severity = str(entry.get("severity") or "").upper()

            if entry_id.startswith(_CERT_PREFIX):
                observations.append(ToolObservation(
                    types.OBS_CERTIFICATE,
                    target,
                    data={
                        "id": entry_id,
                        "finding": finding,
                        "severity": severity or None,
                        "source_tool": "testssl",
                    },
                    discriminator={"id": entry_id},
                ))
                continue

            if severity in _REPORTABLE_SEVERITIES and severity not in _OK_SEVERITIES:
                observations.append(ToolObservation(
                    types.OBS_VULNERABILITY,
                    target,
                    data={
                        "id": entry_id or None,
                        "finding": finding,
                        "severity": severity.capitalize(),
                        "cve": entry.get("cve"),
                        "cwe": entry.get("cwe"),
                        "source_tool": "testssl",
                    },
                    discriminator={"id": entry_id, "finding": finding},
                ))
        return observations
