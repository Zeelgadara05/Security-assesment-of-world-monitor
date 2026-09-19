"""nikto adapter -- JSON web-server scan results normalized into observations."""
from __future__ import annotations

import os

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation, ToolParseError


class NiktoAdapter(ExternalToolAdapter):
    tool_name = "nikto"
    binary = "nikto"
    output_format = "json"

    def build_command(self, target: str, options: dict) -> list[str]:
        output = options.get("output", "nikto-report.json")
        command = ["nikto", "-h", target, "-Format", "json", "-output", str(output), "-nointeractive"]
        if options.get("tuning"):
            command += ["-Tuning", str(options["tuning"])]
        return command

    def extract_output(self, completed, options: dict) -> str:
        path = options.get("output", "nikto-report.json")
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        return completed.stdout or ""

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        try:
            payload = self.parse_json(stdout)
        except ToolParseError:
            # nikto can prefix the JSON document with banner text; recover the
            # first object/array without ever inventing records.
            text = (stdout or "").lstrip()
            start = min([i for i in (text.find("{"), text.find("[")) if i != -1] or [-1])
            if start == -1:
                raise
            try:
                import json

                payload = json.loads(text[start:])
            except Exception as exc:  # noqa: BLE001 - converted to typed error
                raise ToolParseError(f"invalid nikto JSON: {exc}") from exc

        if isinstance(payload, dict):
            findings = payload.get("vulnerabilities") or payload.get("items") or []
        elif isinstance(payload, list):
            findings = payload
        else:
            raise ToolParseError("unexpected nikto JSON shape")
        if not isinstance(findings, list):
            raise ToolParseError("nikto findings is not a list")

        observations: list[ToolObservation] = []
        for record in findings:
            if not isinstance(record, dict):
                continue
            url = record.get("url") or record.get("uri") or target
            message = record.get("msg") or record.get("message") or record.get("description") or ""
            observations.append(ToolObservation(
                types.OBS_VULNERABILITY,
                url,
                data={
                    "id": record.get("id") or record.get("osvdb"),
                    "osvdb": record.get("osvdb"),
                    "message": message,
                    "method": record.get("method") or "GET",
                    "url": url,
                    "references": record.get("references"),
                    "source_tool": "nikto",
                },
                discriminator={"id": record.get("id") or record.get("osvdb"), "url": url},
            ))
        return observations
