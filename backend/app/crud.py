from sqlalchemy.orm import Session
from app.database import models
from app import schemas


# ---------- SYSTEM LOG ----------

def create_log(db: Session, log: schemas.SystemLogCreate):
    db_log = models.SystemLog(**log.dict())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


# ---------- NETWORK EVENT ----------

def create_network_event(db: Session, event, features=None):
    db_event = models.NetworkEvent(
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        protocol=event.protocol,
        packet_size=event.packet_size,
        features=features
        # timestamp handled by DB default
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


def update_event_features(db: Session, event_id: int, features: dict):
    db_event = (
        db.query(models.NetworkEvent)
        .filter(models.NetworkEvent.event_id == event_id)
        .first()
    )

    if db_event:
        db_event.features = features
        db.commit()
        db.refresh(db_event)

    return db_event


def get_recent_events_by_ip(db: Session, src_ip: str, limit: int = 50):
    return (
        db.query(models.NetworkEvent)
        .filter(models.NetworkEvent.src_ip == src_ip)
        .order_by(models.NetworkEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


# ---------- INCIDENT ----------

def create_incident(db: Session, incident):
    db_incident = models.Incident(
        src_ip=incident.src_ip,
        incident_type=incident.incident_type,
        description=incident.description,
        severity=incident.severity,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


def get_recent_incident(db: Session, src_ip: str, incident_type: str):
    return (
        db.query(models.Incident)
        .filter(
            models.Incident.src_ip == src_ip,
            models.Incident.incident_type == incident_type
        )
        .order_by(models.Incident.timestamp.desc())
        .first()
    )


def count_recent_incidents(db: Session, src_ip: str):
    return (
        db.query(models.Incident)
        .filter(models.Incident.src_ip == src_ip)
        .count()
    )


# ---------- RESPONSE ACTION ----------

def create_response_action(db: Session, response: schemas.ResponseActionCreate):
    db_response = models.ResponseAction(
        incident_id=response.incident_id,
        action_type=response.action_type,
        status=response.status
    )
    db.add(db_response)
    db.commit()
    db.refresh(db_response)
    return db_response
