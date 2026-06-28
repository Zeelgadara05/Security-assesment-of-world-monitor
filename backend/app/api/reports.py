from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import Report, Scan

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/list")
def list_reports(db: Session = Depends(get_db)):
    """Lists available compiled reports in the database."""
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
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
def get_markdown_report(scan_id: int, db: Session = Depends(get_db)):
    """Downloads report in Raw Markdown format."""
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated for this scan.")
    return report.markdown_content

@router.get("/{scan_id}/json", response_class=JSONResponse)
def get_json_report(scan_id: int, db: Session = Depends(get_db)):
    """Downloads structured JSON report."""
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated for this scan.")
    return report.json_content

@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_html_report(scan_id: int, db: Session = Depends(get_db)):
    """Downloads report rendered in HTML layout."""
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated for this scan.")
    return report.html_content

@router.get("/{scan_id}/pdf")
def get_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    """Downloads PDF report (simulated by downloading octet raw bytes)."""
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated for this scan.")
    
    # In production, this can call a PDF generator library like ReportLab or Weasyprint.
    # We download the text bytes file with pdf content headers.
    from fastapi.responses import Response
    return Response(
        content=report.pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyberagent_report_{scan_id}.pdf"}
    )
