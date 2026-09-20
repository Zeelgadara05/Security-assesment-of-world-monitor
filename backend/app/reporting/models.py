"""Deterministic assessment-report data model (Phase 6).

The report is a list of explicit sections; every section renders to Markdown.
Export only materializes this model -- nothing in the report is invented, it is
all rebuilt from persisted scan state (findings, evidence, tests, coverage,
configuration snapshot).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportSection:
    id: str
    title: str
    content: Any  # structured (JSON-friendly) content
    markdown: str  # rendered markdown body for this section


@dataclass
class AssessmentReport:
    scan_id: int
    target: str
    generated_at: str
    registry_fingerprint: str
    config_fingerprint: str
    assessment_version: str
    assessment_status: str
    assessment_completeness: str
    headline: str
    sections: list[ReportSection] = field(default_factory=list)

    def section(self, section_id: str) -> ReportSection | None:
        for section in self.sections:
            if section.id == section_id:
                return section
        return None


__all__ = ["AssessmentReport", "ReportSection"]