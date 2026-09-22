"""Phase 9: granular evidence-chain events and the asset graph.

The pipeline must emit granular typed events only *after* a real row was
persisted: ``asset.discovered``, ``observation.created``, ``finding.candidate``,
``finding.verified`` / ``finding.rejected``.  ``_populate_asset_graph`` links
every observation onto a deduplicated asset row (host / endpoint hierarchy),
never inventing assets that no observation references.
"""

import uuid

from app.orchestration import events
from app.orchestration.pipeline import _populate_asset_graph
from database.models import (
    Asset, Observation, Project, Scan, ScanEvent, User, Vulnerability,
)


def _seed(db, email):
    user = User(id=f"p9ev-{uuid.uuid4().hex[:8]}", email=email, role="user")
    db.add(user)
    db.commit()
    project = Project(name="p9ev", user_id=user.id, scope_json=["r.example"])
    db.add(project)
    db.commit()
    scan = Scan(project_id=project.id, target="r.example", status="Running", stage="service_scan")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _event_types(db, scan_id):
    return [
        e.event_type for e in db.query(ScanEvent)
        .filter(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id.asc()).all()
    ]


def test_granular_events_and_asset_graph(session):
    email = f"p9ev-{uuid.uuid4().hex[:8]}@test.local"
    scan = _seed(session, email)

    # observation.created after real persistence (bare host subject)
    obs = Observation(scan_id=scan.id, kind="dns_record", subject="api.r.example",
                      tool_name="real_dns", data_json={"ip": "10.0.0.1"}, raw_output="10.0.0.1")
    session.add(obs)
    session.flush()
    events.emit_observation(session, scan.id, obs.id, obs.kind, obs.subject, obs.tool_name)
    # URL subject exercises the endpoint → host link
    obs_url = Observation(scan_id=scan.id, kind="http_response", subject="https://api.r.example/",
                          tool_name="native_http", data_json={"status": 200}, raw_output="{}")
    session.add(obs_url)
    session.flush()
    events.emit_observation(session, scan.id, obs_url.id, obs_url.kind, obs_url.subject, obs_url.tool_name)
    session.commit()

    # finding.candidate then finding.verified
    f0 = Vulnerability(scan_id=scan.id, title="Header check", severity="Medium", description="d",
                       state="NEW", category="headers", endpoint="https://api.r.example/",
                       http_method="GET", source_test="http.security_headers",
                       source_tool="native_http", status="candidate",
                       rule_id="missing-security-header")
    session.add(f0)
    session.flush()
    events.emit_finding_candidate(session, scan.id, f0.id or 0, f0.title or "",
                                  f0.severity or "", f0.rule_id or "")
    session.commit()
    f0.status = "confirmed"
    events.emit_finding_verified(session, scan.id, f0.id or 0, f0.title or "",
                                 f0.severity or "", f0.rule_id or "")
    session.commit()

    # asset graph: observation subject resolves to an endpoint owned by a host
    _populate_asset_graph(session, scan)

    rows = session.query(Asset).filter(Asset.project_id == scan.project_id).all()
    by_key = {(a.type, a.value): a for a in rows}
    assert ("host", "r.example") in by_key
    assert ("host", "api.r.example") in by_key, "observation subject host must be a real asset"
    assert ("endpoint", "https://api.r.example/") in by_key

    endpoint = by_key[("endpoint", "https://api.r.example/")]
    host = by_key[("host", "api.r.example")]
    assert endpoint.parent_asset_id == host.id, "endpoint → host edge must be real"
    assert endpoint.scan_id == scan.id

    obs_row = session.query(Observation).filter(Observation.id == obs.id).first()
    assert obs_row.asset_id == host.id, "bare-host observation links to its host asset"
    obs_url_row = session.query(Observation).filter(Observation.id == obs_url.id).first()
    assert obs_url_row.asset_id == endpoint.id, "URL observation links onto its endpoint asset"

    # granular events appended in real order
    typed = _event_types(session, scan.id)
    assert "observation.created" in typed
    assert "asset.discovered" in typed
    assert "finding.candidate" in typed
    assert "finding.verified" in typed
    # observations predate findings in the chain
    assert typed.index("observation.created") < typed.index("finding.candidate")

    # idempotent: a second pass creates no duplicate or new assets
    _populate_asset_graph(session, scan)
    again = session.query(Asset).filter(Asset.project_id == scan.project_id).all()
    assert len(again) == len(rows)


def test_unknown_event_type_is_rejected(session):
    scan = _seed(session, f"p9ev-bad-{uuid.uuid4().hex[:8]}@test.local")
    before = session.query(ScanEvent).filter(ScanEvent.scan_id == scan.id).count()
    try:
        events.emit(session, scan.id, "not.a.real.event", {"x": 1})
    except ValueError:
        pass
    assert session.query(ScanEvent).filter(ScanEvent.scan_id == scan.id).count() == before