"""Applicability engine (Phase 5).

Turns "can this test run?" into an explicit, recordable decision.  A test is not
applicable when active testing is disabled, when a required observation was never
produced, when a required capability is unavailable (the tool is not installed),
or when authenticated comparison identities are missing.  The reason is retained
so coverage can honestly explain what did *not* run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.assess.models import AssessmentContext
from app.tools import capabilities as caps


@dataclass
class ApplicabilityDecision:
    test_id: str
    category: str
    applicable: bool
    reason: str = ""
    active: bool = False
    requires_active_testing: bool = False
    missing_observations: list[str] = field(default_factory=list)
    missing_capabilities: list[str] = field(default_factory=list)


def native_capabilities() -> set[str]:
    available: set[str] = set()
    for name in ("native_http", "native_tls"):
        cap = caps.capability(name)
        if cap:
            available.update(cap.capabilities)
    return available


def available_capabilities(context: AssessmentContext | None = None) -> set[str]:
    """Capabilities observable from native tooling plus declared installed tools.

    External tools count only when the scan context declares them installed
    (``metadata['installed_tools']``), so applicability never guesses based on a
    binary that merely happens to be on PATH.
    """
    available = native_capabilities()
    installed = []
    if context is not None:
        installed = (context.metadata or {}).get("installed_tools") or []
    for tool in installed:
        cap = caps.capability(tool)
        if cap:
            available.update(cap.capabilities)
    return available


def evaluate(test, context: AssessmentContext, available: set[str] | None = None) -> ApplicabilityDecision:
    available = available if available is not None else available_capabilities(context)
    decision = ApplicabilityDecision(test_id=test.id, category=test.category, applicable=True,
                                     active=bool(getattr(test, "active", False)))

    # Delegate the generic gates (active/client/observations/auth) to the test so
    # a test can refine applicability for its own preconditions.
    applicable, reason = test.is_applicable(context)
    if not applicable:
        required_obs = list(getattr(test, "required_observations", ()) or ())
        decision.missing_observations = [obs for obs in required_obs if not context.has_observation(obs)]
        return _no(decision, reason)

    required_caps = list(getattr(test, "required_capabilities", ()) or ())
    missing_caps = [cap for cap in required_caps if cap not in available]
    if missing_caps:
        decision.missing_capabilities = missing_caps
        return _no(decision, "required capabilities unavailable: " + ", ".join(missing_caps))

    return decision


def evaluate_all(registry, context: AssessmentContext) -> list[ApplicabilityDecision]:
    available = available_capabilities(context)
    return [evaluate(test, context, available) for test in registry.all()]


def _no(decision: ApplicabilityDecision, reason: str) -> ApplicabilityDecision:
    decision.applicable = False
    decision.reason = reason
    return decision


__all__ = [
    "ApplicabilityDecision",
    "native_capabilities",
    "available_capabilities",
    "evaluate",
    "evaluate_all",
]
