"""Deterministic finding deduplication and merging (Phase 5).

Two candidates that describe the same underlying issue (same category, host,
endpoint, parameter and evidence signature) collapse into one candidate whose
evidence and observation provenance is the union of both.
"""
from __future__ import annotations

from app.assess.models import CandidateData
from app.observations.fingerprint import finding_fingerprint


def candidate_dedup_key(candidate: CandidateData, host: str | None = None) -> str:
    if candidate.dedup_key:
        return candidate.dedup_key
    return finding_fingerprint(
        candidate.category,
        host or candidate.target,
        candidate.endpoint,
        candidate.parameter,
    )


def deduplicate(candidates: list[CandidateData], host: str | None = None, existing_keys: set[str] | None = None) -> list[CandidateData]:
    """Merge duplicate candidates and drop ones already persisted."""
    existing = existing_keys or set()
    merged: dict[str, CandidateData] = {}
    for candidate in candidates:
        key = candidate_dedup_key(candidate, host)
        candidate.dedup_key = key
        if key in existing:
            continue
        if key not in merged:
            merged[key] = candidate
            continue
        _merge(merged[key], candidate)
    return list(merged.values())


def _merge(target: CandidateData, incoming: CandidateData) -> None:
    for obs_id in incoming.observation_ids:
        if obs_id not in target.observation_ids:
            target.observation_ids.append(obs_id)
    seen = {(e.evidence_type, e.expected, e.actual) for e in target.evidence}
    for evidence in incoming.evidence:
        marker = (evidence.evidence_type, evidence.expected, evidence.actual)
        if marker not in seen:
            target.evidence.append(evidence)
            seen.add(marker)
    # Keep the strongest severity and confidence; never weaken evidence.
    from app.assess.severity import _LEVELS
    if _LEVELS.index(incoming.severity) > _LEVELS.index(target.severity):
        target.severity = incoming.severity
    from app.assess.confidence import rank
    if rank(incoming.confidence) > rank(target.confidence):
        target.confidence = incoming.confidence
    if incoming.source_tool and incoming.source_tool not in target.source_tool:
        target.source_tool = f"{target.source_tool}, {incoming.source_tool}" if target.source_tool else incoming.source_tool
