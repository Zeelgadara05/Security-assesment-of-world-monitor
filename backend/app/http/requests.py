"""Structured HTTP request value object (Phase 5).

Requests captured as evidence are always redacted before serialization: the
``to_dict`` helper routes headers/bodies through the observation redactor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from app.observations.normalize import redact_headers, redact_mapping


@dataclass
class HTTPRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        headers: Mapping[str, Any] = redact_headers(self.headers) if redact else dict(self.headers)
        body: Any = self.body
        if redact and body is not None:
            body = redact_mapping({"body": body})["body"]
        return {
            "method": self.method.upper(),
            "url": self.url,
            "headers": dict(headers),
            "body": body,
        }
