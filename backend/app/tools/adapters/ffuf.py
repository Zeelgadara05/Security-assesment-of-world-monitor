"""ffuf adapter -- JSON fuzzing results normalized into endpoint observations.

ffuf writes its JSON report to a file (``-of json -o <path>``), so the adapter
overrides ``extract_output`` to read that file.  Parsing itself is pure and
unit-testable against a JSON string.
"""
from __future__ import annotations

import os

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation, ToolParseError


class FfufAdapter(ExternalToolAdapter):
    tool_name = "ffuf"
    binary = "ffuf"
    output_format = "json"

    def build_command(self, target: str, options: dict) -> list[str]:
        wordlist = options.get("wordlist")
        if not wordlist:
            raise ToolParseError("ffuf requires a wordlist")
        mode = options.get("mode", "dir")
        if mode == "parameter":
            url = target if "FUZZ" in target else f"{target}{options.get('path', '/?FUZZ=test')}"
        else:
            url = target if "FUZZ" in target else f"{target}{options.get('path', '/FUZZ')}"
        command = [
            "ffuf", "-u", url, "-w", str(wordlist),
            "-of", "json", "-o", str(options.get("output", "ffuf-report.json")),
            "-mc", str(options.get("match_codes", "200,204,301,302,307,401,403,405,500")),
        ]
        if options.get("method"):
            command += ["-X", str(options["method"])]
        return command

    def extract_output(self, completed, options: dict) -> str:
        path = options.get("output", "ffuf-report.json")
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        return completed.stdout or ""

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        payload = self.parse_json(stdout)
        results = payload.get("results") if isinstance(payload, dict) else payload
        if results is None:
            raise ToolParseError("ffuf JSON has no 'results' array")
        if not isinstance(results, list):
            raise ToolParseError("ffuf 'results' is not a list")

        observations: list[ToolObservation] = []
        for record in results:
            if not isinstance(record, dict):
                continue
            url = record.get("url") or target
            inputs = record.get("input") or {}
            observations.append(ToolObservation(
                types.OBS_HTTP_ENDPOINT,
                url,
                data={
                    "url": url,
                    "status": record.get("status"),
                    "length": record.get("length"),
                    "words": record.get("words"),
                    "lines": record.get("lines"),
                    "content_type": record.get("content-type") or record.get("content_type"),
                    "redirect_location": record.get("redirectlocation"),
                    "input": inputs,
                    "source_tool": "ffuf",
                },
                discriminator={"endpoint": url, "input": inputs},
            ))
        return observations
