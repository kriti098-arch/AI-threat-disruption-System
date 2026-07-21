# app/routers/reports.py
# Add to main.py:
#   from app.routers import reports
#   app.include_router(reports.router)

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.database.models import Incident
from app.security.report_generator import generate_incident_report
import io

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/incident/{incident_id}")
def download_incident_report(incident_id: int, db: Session = Depends(get_db)):
    """Download a PDF report for a specific incident."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_dict = {
        "incident_id":       inc.incident_id,
        "src_ip":            inc.src_ip,
        "incident_type":     inc.incident_type,
        "description":       inc.description,
        "severity":          inc.severity,
        "risk_score":        inc.risk_score,
        "risk_level":        inc.risk_level,
        "mitigation_status": inc.mitigation_status,
        "timestamp":         str(inc.timestamp),
        "proof":             inc.proof or {}
    }

    try:
        pdf_bytes = generate_incident_report(incident_dict)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

    filename = f"incident_{incident_id}_{inc.src_ip.replace('.','_')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/incident/{incident_id}/preview")
def preview_incident_report(incident_id: int, db: Session = Depends(get_db)):
    """Preview PDF inline in browser."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_dict = {
        "incident_id":       inc.incident_id,
        "src_ip":            inc.src_ip,
        "incident_type":     inc.incident_type,
        "description":       inc.description,
        "severity":          inc.severity,
        "risk_score":        inc.risk_score,
        "risk_level":        inc.risk_level,
        "mitigation_status": inc.mitigation_status,
        "timestamp":         str(inc.timestamp),
        "proof":             inc.proof or {}
    }

    pdf_bytes = generate_incident_report(incident_dict)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "inline"}
    )