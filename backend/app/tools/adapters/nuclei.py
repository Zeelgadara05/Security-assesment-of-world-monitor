"""nuclei adapter -- JSONL template findings normalized into observations."""
from __future__ import annotations

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation


class NucleiAdapter(ExternalToolAdapter):
    tool_name = "nuclei"
    binary = "nuclei"
    output_format = "jsonl"

    def build_command(self, target: str, options: dict) -> list[str]:
        command = ["nuclei", "-target", target, "-jsonl", "-silent"]
        if options.get("templates"):
            command += ["-t", str(options["templates"])]
        if options.get("severity"):
            command += ["-severity", str(options["severity"])]
        return command

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        observations: list[ToolObservation] = []
        for record in self.parse_jsonl(stdout):
            if not isinstance(record, dict):
                continue
            info = record.get("info") or {}
            classification = info.get("classification") or {}
            matched_at = record.get("matched-at") or record.get("host") or target
            template_id = record.get("template-id")
            observations.append(ToolObservation(
                types.OBS_VULNERABILITY,
                matched_at,
                data={
                    "title": info.get("name") or template_id or "Nuclei finding",
                    "severity": (info.get("severity") or "info").capitalize(),
                    "template_id": template_id,
                    "matcher_name": record.get("matcher-name"),
                    "cve": ", ".join(classification.get("cve-id") or []) or None,
                    "cwe": ", ".join(classification.get("cwe-id") or []) or None,
                    "tags": info.get("tags") or [],
                    "description": info.get("description"),
                    "remediation": info.get("remediation"),
                    "matched_at": matched_at,
                    "source_tool": "nuclei",
                },
                discriminator={"template_id": template_id, "matched_at": matched_at},
            ))
        return observations
