from datetime import datetime
from app import schemas
from app.detection.config import INCIDENT_COOLDOWN

PACKET_THRESHOLD = 20

def detect_incidents(events, src_ip, last_incident=None):
    incidents = []

    if len(events) >= PACKET_THRESHOLD:
        if last_incident:
            time_diff = datetime.utcnow() - last_incident.timestamp
            if time_diff < INCIDENT_COOLDOWN:
                return incidents  # suppress duplicate

        incidents.append(
            schemas.IncidentCreate(
                src_ip=src_ip,
                incident_type="High Packet Rate",
                description="Unusually high number of packets detected from source IP",
                severity="MEDIUM",
                 risk_score=0.0,        # temporary
                 risk_level="MEDIUM"
            )
        )

    return incidents
