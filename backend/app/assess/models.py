"""Core value objects for the Phase 5 assessment engine.

These are deliberately plain dataclasses: the engine is deterministic and
database-agnostic at this layer so it can be unit tested without a scan, a
network or a database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.http.client import HttpLimits, SafeHttpClient
from app.observations import types as obs_types


@dataclass
class AssessmentContext:
    """Everything a security test is allowed to know about a scan."""

    scan_id: int
    target: str
    simulation: bool = True
    active_testing: bool = True
    user_id: str | None = None
    limits: HttpLimits = field(default_factory=HttpLimits)
    scope_guard: Callable[[str], bool] = field(default=lambda url: False)
    client: SafeHttpClient | None = None
    observations: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    auth_identities: dict[str, dict] = field(default_factory=dict)
    ssrf_validation_url: str | None = None
    config: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def observations_of(self, *types: str) -> list[dict]:
        wanted = set(types)
        return [o for o in self.observations if (o.get("observation_type") or o.get("kind")) in wanted]

    def has_observation(self, *types: str) -> bool:
        return bool(self.observations_of(*types))


@dataclass
class TestCase:
    """One concrete unit of work planned by a security test."""

    endpoint: str
    method: str = "GET"
    parameter: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    marker: str | None = None
    rationale: str = ""
    resume: dict[str, Any] = field(default_factory=dict)


@dataclass
class ObservationData:
    """An observation produced by a test, ready to be persisted."""

    observation_type: str
    subject: str
    data: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    status: str = obs_types.STATUS_OBSERVED
    discriminator: Any = None
    tool_name: str = "native_http"
    source: str = obs_types.SOURCE_HTTP_CLIENT


@dataclass
class ValidationResult:
    """Deterministic verdict for a candidate."""

    confirmed: bool
    confidence: str = obs_types.CONFIDENCE_LOW
    reason: str = ""
    expected: str = ""
    actual: str = ""
    security_boundary: str = ""


@dataclass
class EvidenceData:
    evidence_type: str
    expected: str = ""
    actual: str = ""
    security_boundary: str = ""
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    observation_index: int | None = None


@dataclass
class CandidateData:
    """A finding candidate.  Only ``confirmed`` candidates become findings."""

    category: str
    title: str
    severity: str
    confidence: str
    description: str
    endpoint: str
    method: str
    target: str
    source_test: str
    source_tool: str = "native_http"
    parameter: str | None = None
    security_boundary: str = ""
    expected: str = ""
    actual: str = ""
    impact: str = ""
    remediation: str = ""
    proof_of_concept: str = ""
    observation_ids: list[int] = field(default_factory=list)
    evidence: list[EvidenceData] = field(default_factory=list)
    dedup_key: str = ""
    status: str = obs_types.FINDING_CANDIDATE
    cwe: str | None = None
    owasp: str | None = None


@dataclass
class TestOutcome:
    """Result of running one security test for one context."""

    test_id: str
    category: str
    status: str = obs_types.TEST_EXECUTED
    reason: str = ""
    observations: list[ObservationData] = field(default_factory=list)
    candidates: list[CandidateData] = field(default_factory=list)
    planned: int = 0
    executed: int = 0
    skipped: int = 0


@dataclass
class TestRunReport:
    """Aggregate outcome across all tests for a scan."""

    outcomes: list[TestOutcome] = field(default_factory=list)

    @property
    def observations(self) -> list[ObservationData]:
        return [o for outcome in self.outcomes for o in outcome.observations]

    @property
    def candidates(self) -> list[CandidateData]:
        return [c for outcome in self.outcomes for c in outcome.candidates]

    def planned(self) -> int:
        return sum(o.planned for o in self.outcomes)

    def executed(self) -> int:
        return sum(o.executed for o in self.outcomes)

    def skipped(self) -> int:
        return sum(o.skipped for o in self.outcomes)

    def failed(self) -> int:
        return sum(1 for o in self.outcomes if o.status == obs_types.TEST_FAILED)

    def not_applicable(self) -> int:
        return sum(1 for o in self.outcomes if o.status == obs_types.TEST_NOT_APPLICABLE)
