"""httpx adapter -- JSONL probes normalized into HTTP response/technology observations."""
from __future__ import annotations

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation


class HttpxAdapter(ExternalToolAdapter):
    tool_name = "httpx"
    binary = "httpx"
    output_format = "jsonl"

    def build_command(self, target: str, options: dict) -> list[str]:
        return [
            "httpx", "-u", target, "-json", "-silent",
            "-status-code", "-title", "-web-server", "-tech-detect",
        ]

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        observations: list[ToolObservation] = []
        for record in self.parse_jsonl(stdout):
            if not isinstance(record, dict):
                continue
            url = record.get("url") or record.get("input") or target
            observations.append(ToolObservation(
                types.OBS_HTTP_RESPONSE,
                url,
                data={
                    "url": url,
                    "status_code": record.get("status_code") or record.get("status-code"),
                    "title": record.get("title"),
                    "webserver": record.get("webserver") or record.get("web-server"),
                    "content_type": (record.get("header") or {}).get("content_type")
                    if isinstance(record.get("header"), dict) else None,
                    "content_length": record.get("content_length") or record.get("content-length"),
                    "final_url": record.get("final_url") or record.get("final-url"),
                    "source_tool": "httpx",
                },
                discriminator={"endpoint": url, "method": "GET"},
            ))
            tech = record.get("tech") or record.get("technologies")
            if isinstance(tech, str):
                tech = [tech]
            for name in tech or []:
                observations.append(ToolObservation(
                    types.OBS_TECHNOLOGY, url,
                    data={"url": url, "technology": name},
                    discriminator={"endpoint": url, "technology": name},
                ))
        return observations
