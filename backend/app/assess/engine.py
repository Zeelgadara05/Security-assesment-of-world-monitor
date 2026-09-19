"""Scan-time bridge between the database and the Phase 5 assessment engine.

This module is the only place that knows about both the ORM and the pure engine.
It builds an :class:`AssessmentContext` from persisted scan state, runs the
planner, and persists observations, the assessment-test ledger, confirmed
findings and structured evidence.  It is deliberately conservative:

  * it never runs in simulation mode;
  * active (mutating) testing is opt-in via ``config['active_testing']``;
  * every request is scope-guarded against the project's authorized scope;
  * it never fabricates a finding -- only validated candidates are persisted;
  * a failure here degrades the scan to "assessment skipped", never a crash.
"""
from __future__ import annotations

import datetime
import json
import logging

from app.observations.normalize import build_observation, normalize_endpoint

logger = logging.getLogger("cyberagent.assessment")

_MAX_ENDPOINTS = 25
_MAX_REQUESTS = 200


def _scan_user_id(db, scan) -> str | None:
    from database.models import Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    return getattr(project, "user_id", None)


def _scope_guard(db, scan):
    from app.core.auth import is_target_in_scope
    from app.http.fingerprints import host_of
    from database.models import Asset, Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    assets = db.query(Asset).filter(Asset.project_id == scan.project_id).all()

    def guard(url: str) -> bool:
        host = host_of(url)
        if not host:
            return False
        if host == scan.target:
            return True
        return bool(project and is_target_in_scope(host, project, assets))

    return guard


def _candidate_endpoints(db, scan) -> list[str]:
    """In-scope HTTP endpoints derived from persisted observations and assets.

    Full observed URLs (scheme://host:port/path?query) are preserved so active
    parameter tests have real parameters to work with; asset/target hosts are
    expanded into both schemes.
    """
    from database.models import Asset, Observation

    guard = _scope_guard(db, scan)
    endpoints: list[str] = []

    def add(url: str) -> None:
        candidate = url.split("#", 1)[0]
        if guard(candidate) and candidate not in endpoints:
            endpoints.append(candidate)

    for obs in db.query(Observation).filter(Observation.scan_id == scan.id).all():
        subject = obs.subject or ""
        if subject.startswith("http"):
            add(subject)

    hosts: list[str] = []
    for value in (scan.target,):
        if value and value not in hosts:
            hosts.append(value)
    for asset in db.query(Asset).filter(Asset.project_id == scan.project_id).all():
        if asset.type in ("domain", "ip") and asset.value and asset.value not in hosts:
            hosts.append(asset.value)

    for host in hosts:
        for scheme in ("https", "http"):
            add(f"{scheme}://{host}")
            if len(endpoints) >= _MAX_ENDPOINTS:
                return endpoints
    return endpoints


def _load_observation_dicts(db, scan_id: int) -> list[dict]:
    from database.models import Observation

    rows = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.id.asc()).all()
    return [
        {
            "id": o.id,
            "observation_type": o.observation_type or o.kind,
            "kind": o.kind,
            "subject": o.subject,
            "data_json": o.data_json or {},
            "response_json": o.response_json,
            "raw_output": o.raw_output or "",
        }
        for o in rows
    ]


def _build_context(db, scan, config: dict, active_testing: bool):
    from app.assess.models import AssessmentContext
    from app.http.client import HttpLimits, SafeHttpClient

    limits = HttpLimits(max_requests_per_scan=_MAX_REQUESTS, active_testing=active_testing)
    guard = _scope_guard(db, scan)
    client = SafeHttpClient(guard, limits, capture_tls=True)
    return AssessmentContext(
        scan_id=scan.id,
        target=scan.target,
        simulation=False,
        active_testing=active_testing,
        user_id=_scan_user_id(db, scan),
        limits=limits,
        scope_guard=guard,
        client=client,
        observations=_load_observation_dicts(db, scan.id),
        endpoints=_candidate_endpoints(db, scan),
        assets=[scan.target],
        auth_identities=dict(config.get("auth_identities") or {}),
        ssrf_validation_url=config.get("ssrf_validation_url"),
        config=config,
        metadata={
            "installed_tools": list(config.get("installed_tools") or []),
            "jwt_tokens": list(config.get("jwt_tokens") or []),
            "jwt_alg_none_accepted": bool(config.get("jwt_alg_none_accepted")),
            "ssrf_token": config.get("ssrf_token"),
            "tools_missing": list(config.get("tools_missing") or []),
        },
    )


def run_assessment(db, scan, simulation: bool = True, config: dict | None = None,
                   user_id: str | None = None) -> dict:
    """Run the Phase 5 engine for ``scan`` and persist its outputs.

    Returns a deterministic summary dict; ``{"executed": False, ...}`` when the
    engine intentionally did not run (simulation or disabled).
    """
    config = dict(config or {})
    if simulation:
        return {"executed": False, "reason": "simulation mode", "findings_confirmed": 0}
    if config.get("assessment_engine") is False:
        return {"executed": False, "reason": "assessment engine disabled", "findings_confirmed": 0}

    from app.assess import coverage as coverage_mod
    from app.assess import planner
    from app.assess.registry import default_registry

    active_testing = bool(config.get("active_testing", False))
    registry = default_registry()
    context = _build_context(db, scan, config, active_testing)
    if user_id is None:
        user_id = context.user_id

    assessment_plan, report = planner.plan_and_run(context, registry)

    observation_rows = _persist_observations(db, scan, report, user_id, context.target)
    candidates = planner.confirmed_candidates(report, registry)
    candidates = _drop_existing(db, scan, candidates)
    finding_rows, finding_by_key = _persist_findings(db, scan, candidates, observation_rows, context.target)
    _persist_assessment_tests(db, scan, assessment_plan, report, registry, observation_rows, finding_by_key)
    coverage_summary = coverage_mod.summarize(assessment_plan, report, context)
    _persist_tool_result(db, scan, coverage_summary, len(observation_rows))
    db.commit()

    return {
        "executed": True,
        "active_testing": active_testing,
        "coverage": coverage_summary.to_dict(),
        "findings_confirmed": coverage_summary.findings_confirmed,
        "statement": coverage_summary.findings_statement,
    }


def _persist_observations(db, scan, report, user_id, target) -> list[dict]:
    from database.models import Observation

    rows: list[dict] = []
    for outcome in report.outcomes:
        for produced in outcome.observations:
            kwargs = build_observation(
                scan_id=scan.id,
                observation_type=produced.observation_type,
                subject=(produced.subject or target)[:255],
                tool_name=produced.tool_name,
                source=produced.source,
                user_id=user_id,
                target=target,
                asset=_host(produced.subject),
                data=produced.data,
                raw_output=produced.raw_output,
                request=produced.request,
                response=produced.response,
                status=produced.status,
                discriminator=produced.discriminator,
            )
            row = Observation(**kwargs)
            db.add(row)
            db.flush()
            rows.append({"id": row.id, "test_id": outcome.test_id, "endpoint": produced.subject,
                         "parameter": (produced.data or {}).get("parameter"), "request": produced.request,
                         "response": produced.response})
    return rows


def _drop_existing(db, scan, candidates):
    from database.models import Vulnerability

    existing = {
        v.dedup_key for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        if v.dedup_key
    }
    return [c for c in candidates if c.dedup_key not in existing]


def _persist_findings(db, scan, candidates, observation_rows, target) -> tuple[list, dict]:
    from app.assess.evidence import summary as evidence_summary
    from database.models import Vulnerability

    index = _observation_index(observation_rows)
    finding_by_key: dict[str, int] = {}
    rows = []
    for candidate in candidates:
        row = Vulnerability(
            scan_id=scan.id,
            title=candidate.title,
            severity=candidate.severity,
            description=candidate.description,
            remediation=candidate.remediation or None,
            cwe=candidate.cwe,
            owasp=candidate.owasp,
            target=candidate.target or target,
            proof_of_concept=candidate.proof_of_concept,
            rule_id=candidate.category,
            dedup_key=candidate.dedup_key,
            confidence=candidate.confidence,
            state="NEW",
            category=candidate.category,
            endpoint=candidate.endpoint,
            http_method=candidate.method,
            source_test=candidate.source_test,
            source_tool=candidate.source_tool,
            validation_reason=candidate.actual or "",
            impact=candidate.impact or None,
            evidence=evidence_summary(candidate),
            evidence_observation_ids=[o["id"] for o in _matching_observations(index, candidate)],
            created_at=datetime.datetime.utcnow(),
        )
        db.add(row)
        db.flush()
        rows.append(row)
        finding_by_key[candidate.dedup_key] = row.id
        _persist_evidence(db, row, candidate, index)
    return rows, finding_by_key


def _persist_evidence(db, finding, candidate, index) -> None:
    from app.assess.evidence import evidence_to_kwargs
    from app.assess.models import EvidenceData
    from database.models import FindingEvidence

    matches = _matching_observations(index, candidate)
    if matches:
        for match in matches[:3]:
            evidence = EvidenceData(
                evidence_type="comparison", expected=candidate.expected, actual=candidate.actual,
                security_boundary=candidate.security_boundary, request=match.get("request"),
                response=match.get("response"),
            )
            db.add(FindingEvidence(**evidence_to_kwargs(finding.id, evidence, match["id"])))
    else:
        evidence = EvidenceData(
            evidence_type="comparison", expected=candidate.expected, actual=candidate.actual,
            security_boundary=candidate.security_boundary,
        )
        db.add(FindingEvidence(**evidence_to_kwargs(finding.id, evidence, None)))


def _observation_index(rows):
    index: dict[tuple[str, str | None, str | None], dict] = {}
    for row in rows:
        key = (normalize_endpoint(row.get("endpoint") or ""), row.get("parameter"), row.get("test_id"))
        index.setdefault(key, row)
    return index


def _matching_observations(index, candidate):
    endpoint = normalize_endpoint(candidate.endpoint)
    matches = []
    for key, row in index.items():
        if key[0] != endpoint:
            continue
        if candidate.parameter and key[1] and key[1] != candidate.parameter:
            continue
        matches.append(row)
    return matches


def _persist_assessment_tests(db, scan, assessment_plan, report, registry, observation_rows, finding_by_key):
    from database.models import AssessmentTest

    produced_by_test: dict[str, list[int]] = {}
    for row in observation_rows:
        produced_by_test.setdefault(row["test_id"], []).append(row["id"])

    now = datetime.datetime.utcnow()
    for planned, outcome in zip(assessment_plan.planned, report.outcomes):
        test = registry.get(planned.test_id)
        finding_ids = [
            finding_by_key[c.dedup_key]
            for c in outcome.candidates
            if c.dedup_key in finding_by_key
        ]
        db.add(AssessmentTest(
            scan_id=scan.id,
            test_id=planned.test_id,
            name=(test.name if test else planned.test_id),
            category=planned.category,
            status=outcome.status,
            reason=outcome.reason or planned.reason or "",
            target=scan.target,
            active=planned.active,
            required_observations=list(getattr(test, "required_observations", ()) or []),
            required_capabilities=list(getattr(test, "required_capabilities", ()) or []),
            observation_ids=produced_by_test.get(planned.test_id, []),
            finding_ids=finding_ids,
            started_at=now,
            completed_at=now,
        ))


def _persist_tool_result(db, scan, coverage_summary, observation_count: int):
    from database.models import ToolResult

    db.add(ToolResult(
        scan_id=scan.id,
        tool_name="native_assessment",
        status="Completed",
        raw_output=json.dumps(coverage_summary.to_dict(), default=str),
        parsed_observations=observation_count,
        completed_at=datetime.datetime.utcnow(),
    ))


def _host(url: str | None) -> str | None:
    if not url:
        return None
    from app.http.fingerprints import host_of

    return host_of(url) or None


__all__ = ["run_assessment"]
