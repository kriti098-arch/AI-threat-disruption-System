from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.db import SessionLocal
from app.database import models

router = APIRouter(prefix="/incidents", tags=["Incidents"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ✅ Get all incidents
@router.get("/")
def get_incidents(db: Session = Depends(get_db)):

    incidents = (
        db.query(models.Incident)
        .order_by(models.Incident.timestamp.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "incident_id": i.incident_id,
            "src_ip": i.src_ip,
            "incident_type": i.incident_type,
            "description": i.description,
            "severity": i.severity,
            "risk_score": i.risk_score,
            "risk_level": i.risk_level,
            "mitigation_status": i.mitigation_status,
            "proof": i.proof,
            "timestamp": i.timestamp.isoformat() + "Z"
        }
        for i in incidents
    ]

# ✅ Get single incident with BEFORE / AFTER proof
@router.get("/{incident_id}")
def get_incident_details(incident_id: int, db: Session = Depends(get_db)):
    incident = (
        db.query(models.Incident)
        .filter(models.Incident.incident_id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "incident_id": incident.incident_id,
        "src_ip": incident.src_ip,
        "incident_type": incident.incident_type,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "risk_level": incident.risk_level,
        "timestamp": incident.timestamp.isoformat() + "Z",

        # 🔥 BEFORE / AFTER mitigation data
        "mitigation_status": incident.mitigation_status,
        "proof": incident.proof
    }
@router.post("/{incident_id}/mitigate")
def simulate_mitigation(incident_id: int, db: Session = Depends(get_db)):
    incident = (
        db.query(models.Incident)
        .filter(models.Incident.incident_id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # 🔥 Simulated AFTER mitigation values
    after_metrics = {
        "avg_packet_size": 420,
        "packet_rate": 35,
        "std_packet_size": 120,
        "reason": "Traffic stabilized after automated response"
    }

    # Update proof
    proof = incident.proof or {}
    proof["after"] = after_metrics

    incident.proof = proof
    incident.mitigation_status = "STABILIZED"

    db.commit()
    db.refresh(incident)

    return {
        "message": "Mitigation simulated successfully",
        "incident_id": incident.incident_id,
        "mitigation_status": incident.mitigation_status,
        "proof": incident.proof
    }

