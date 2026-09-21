"""Phase 8.5 report additions: SIH area coverage + finding provenance.

The report must expose the seven SIH26163 security areas derived from the test
ledger, label every finding by provenance (validated vs observed), and keep the
ML advisory explicitly labelled as inferred guidance that never yields findings.
"""
import uuid

from tests.test_phase6_reporting import _seed_scan


def _report(client, session, email, scan_id, headers, fmt):
    resp = client.get(f"/scans/{scan_id}/report?format={fmt}", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["report"]


def test_report_contains_sih_area_coverage(client, session):
    email = f"p85-report-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, _c, _x = _seed_scan(session, email)

    report = _report(client, session, email, scan_id, headers, "json")
    sih = report["sections"]["sih_coverage"]
    assert sih["framework"] == "SIH26163"
    assert len(sih["areas"]) == 7
    xss_area = next(a for a in sih["areas"] if a["key"] == "input_validation")
    # the seeded xss test was executed, so the area is genuinely covered
    assert xss_area["executed"] == 1 and xss_area["coverage_percent"] == 100.0
    assert xss_area["status"] == "covered"
    headers_area = next(a for a in sih["areas"] if a["key"] == "client_side")
    assert "headers" in headers_area["categories"]


def test_report_labels_finding_provenance_and_ml_advisory(client, session):
    email = f"p85-prov-{uuid.uuid4().hex[:8]}@test.local"
    from tests.conftest import login_user, register_user

    register_user(client, email)
    headers = login_user(client, email)
    scan_id, confirmed_id, cand_id = _seed_scan(session, email)

    report = _report(client, session, email, scan_id, headers, "json")
    prov = {f["id"]: f["provenance"] for f in report["findings"]}
    assert prov[confirmed_id] == "validated"
    assert prov[cand_id] == "observed"

    md = _report(client, session, email, scan_id, headers, "markdown")
    assert "SIH26163 Security-Area Coverage" in md
    assert "SIH26163 security area" in md
    assert "**Provenance:** validated" in md
    assert "**Provenance:** observed" in md
