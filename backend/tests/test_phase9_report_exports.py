"""Phase 9: deterministic HTML + real stdlib PDF report exports.

These tests pin the two new report projections introduced in Phase 9:

  * ``pdf_writer.render_pdf`` produces a *real*, parseable PDF 1.4 document
    (valid xref offsets, required structure markers) without any third-party
    dependencies.
  * ``html_renderer.render_html`` produces a self-contained deterministic HTML
    document derived from the same section model as JSON/Markdown.
  * The API ``GET /scans/{id}/report?format=html|pdf`` serves both and records
    a ``ReportExport`` row with a content hash, exactly like the json/markdown
    exports.

Nothing here asserts content the report did not persist: it validates plumbing,
determinism and real-file format, not findings.
"""

import uuid

from app.reporting import html_renderer, pdf_writer
from database.models import Project, ReportExport, Scan, User, Vulnerability


_SECTIONS = [
    {"id": "executive_summary", "title": "Executive Summary",
     "markdown": "# Assessment report\n\n- **Target:** r.example\n- **Headline:** baseline\n"},
    {"id": "findings", "title": "Confirmed Findings",
     "markdown": "### F-1 (confirmed) - TLS header\n\n**Severity:** Medium\n-\tEvidence: persisted observation 10\n"},
]


def _seed_scan_with_report(db, owner_email="owner@test.local"):
    from database.models import User

    owner = db.query(User).filter(User.email == owner_email).first()
    if owner is None:
        owner = User(id=f"p9-{uuid.uuid4().hex[:8]}", email=owner_email, role="user")
        db.add(owner)
        db.commit()
    project = Project(name="p9", user_id=owner.id, scope_json=["r.example"])
    db.add(project)
    db.commit()
    scan = Scan(project_id=project.id, target="r.example", status="Completed", stage="completed")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(Vulnerability(
        scan_id=scan.id, title="TLS header", severity="Medium", description="d",
        state="NEW", category="headers", endpoint="https://r.example/",
        http_method="GET", source_test="http.security_headers",
        source_tool="native_http", status="confirmed", rule_id="missing-security-header",
        evidence_observation_ids=[10]))
    db.commit()
    return owner.id, scan.id


def test_pdf_writer_produces_parseable_pdf():
    pdf = pdf_writer.render_pdf(_SECTIONS, title="Assessment - r.example", fingerprint="fp-1")
    text = pdf.decode("latin-1")
    assert text.startswith("%PDF-1.4")
    assert text.rstrip().endswith("%%EOF")
    assert "startxref" in text
    assert "/MediaBox [0 0 595 842]" in text

    # xref offsets must resolve byte-exactly to each "N 0 obj".
    import re

    sx = int(text.split("startxref\n")[1].splitlines()[0])
    xref = text[sx:]
    count = int(re.search(r"xref\n0 (\d+)", xref).group(1))
    verified = 0
    for i in range(1, count):
        off = int(xref.splitlines()[2 + i].split()[0])
        if text[off:off + 20].startswith(f"{i} 0 obj"):
            verified += 1
    assert verified == count - 1, "every xref offset must point at its object header"


def test_pdf_writer_is_deterministic():
    ts = "2026-09-22T00:00:00+00:00"
    a = pdf_writer.render_pdf(_SECTIONS, title="t", fingerprint="fp", generated_at=ts)
    b = pdf_writer.render_pdf(_SECTIONS, title="t", fingerprint="fp", generated_at=ts)
    assert a == b, "identical input must produce identical bytes"


def test_html_renderer_is_deterministic_self_contained():
    html = html_renderer.render_html(_SECTIONS, title="r.example", fingerprint="fp-2",
                                     config_fingerprint="cfg-2")
    assert "<!DOCTYPE html>" in html
    assert "<html" in html and "</html>" in html
    assert "Confirmed Findings" in html
    assert "persisted observation 10" in html
    assert "fp-2" in html
    assert "<script" not in html.lower(), "report must be fully static/self-contained"

    again = html_renderer.render_html(_SECTIONS, title="r.example", fingerprint="fp-2",
                                      config_fingerprint="cfg-2")
    assert again == html, "identical input must produce identical HTML"


def test_report_export_api_html_and_pdf(client, auth_headers, session):
    owner_id, scan_id = _seed_scan_with_report(session)

    r_html = client.get(f"/scans/{scan_id}/report?format=html", headers=auth_headers)
    assert r_html.status_code == 200, r_html.text
    payload = r_html.json()
    assert payload["format"] == "html"
    assert payload["content_hash"]
    assert "<!DOCTYPE html>" in payload["report"]

    r_pdf = client.get(f"/scans/{scan_id}/report?format=pdf", headers=auth_headers)
    assert r_pdf.status_code == 200, r_pdf.text
    assert r_pdf.headers["content-type"].startswith("application/pdf")
    body = r_pdf.content
    assert body[:8] == b"%PDF-1.4"
    assert body.rstrip().endswith(b"%%EOF")

    # both exports were recorded with a content hash
    exports = session.query(ReportExport).filter(
        ReportExport.scan_id == scan_id).order_by(ReportExport.id.asc()).all()
    kinds = {e.format for e in exports}
    assert "html" in kinds and "pdf" in kinds
    for e in exports:
        assert e.content_hash and e.content_length and e.generated_at

    # invalid format rejected
    bad = client.get(f"/scans/{scan_id}/report?format=docx", headers=auth_headers)
    assert bad.status_code == 400


def test_report_export_requires_ownership(client, auth_headers, other_auth_headers, session):
    owner_id, scan_id = _seed_scan_with_report(session)

    r = client.get(f"/scans/{scan_id}/report?format=pdf", headers=other_auth_headers)
    assert r.status_code == 404, "non-owner must not be able to export another user's report"