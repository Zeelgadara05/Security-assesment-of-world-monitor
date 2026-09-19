from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, Response
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import Report, Scan, Project, User
from app.core.auth import get_current_user, get_owned_scan

router = APIRouter(prefix="/reports", tags=["reports"])


def _get_owned_report(db: Session, user: User, scan_id: int) -> Report:
    """Fetch a report whose scan belongs to the user (404 otherwise)."""
    get_owned_scan(db, user, scan_id)
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated for this scan.")
    return report


@router.get("/list")
def list_reports(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Lists reports compiled for the authenticated user's scans only."""
    project_ids = [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
    if not project_ids:
        return []
    scan_ids = [s.id for s in db.query(Scan).filter(Scan.project_id.in_(project_ids)).all()]
    if not scan_ids:
        return []
    reports = db.query(Report).filter(Report.scan_id.in_(scan_ids)).order_by(Report.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "scan_id": r.scan_id,
            "title": r.title,
            "created_at": r.created_at
        }
        for r in reports
    ]


@router.get("/{scan_id}/markdown", response_class=PlainTextResponse)
def get_markdown_report(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Downloads report in Raw Markdown format."""
    report = _get_owned_report(db, user, scan_id)
    return report.markdown_content


@router.get("/{scan_id}/json", response_class=JSONResponse)
def get_json_report(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Downloads structured JSON report."""
    report = _get_owned_report(db, user, scan_id)
    return report.json_content


@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_html_report(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Downloads report rendered in HTML layout."""
    report = _get_owned_report(db, user, scan_id)
    return report.html_content


@router.get("/{scan_id}/pdf")
def get_pdf_report(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Downloads PDF report (simulated by downloading octet raw bytes)."""
    report = _get_owned_report(db, user, scan_id)

    # In production, this can call a PDF generator library like ReportLab or Weasyprint.
    # We download the text bytes file with pdf content headers.
    return Response(
        content=report.pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyberagent_report_{scan_id}.pdf"}
    )