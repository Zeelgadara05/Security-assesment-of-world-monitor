"""Report export + persistence (Phase 6).

Export materializes the deterministic JSON payload and the Markdown document,
records a :class:`ReportExport` row with a content hash and the registry /
configuration fingerprints it was generated against, so any export is
reproducible.  JSON is emitted with sorted keys for stable diffs.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_json(json_payload: dict) -> str:
    return json.dumps(json_payload, sort_keys=True, separators=(",", ":"), default=str)


def render_markdown(markdown: str) -> str:
    return markdown.strip() + "\n"


def persist_export(db, *, scan_id: int, fmt: str, payload: str, content_json: dict | None = None,
                   content_markdown: str | None = None, registry_fingerprint: str = "",
                   config_fingerprint: str = "", user_id: str | None = None) -> dict[str, Any]:
    """Persist one export and return its metadata row (id, hash, fingerprints)."""
    from database.models import ReportExport

    digest = content_hash(payload)
    row = ReportExport(
        scan_id=scan_id,
        user_id=user_id,
        format=fmt,
        content_hash=digest,
        registry_fingerprint=registry_fingerprint or None,
        config_fingerprint=config_fingerprint or None,
        content_length=len(payload),
        generated_at=datetime.datetime.utcnow(),
        content_json=content_json,
        content_markdown=content_markdown,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "export_id": row.id,
        "format": row.format,
        "content_hash": row.content_hash,
        "content_length": row.content_length,
        "generated_at": row.generated_at,
    }


__all__ = ["content_hash", "persist_export", "render_json", "render_markdown"]