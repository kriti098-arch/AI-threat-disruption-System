# app/database/models.py

from sqlalchemy import Column, Integer, String, DateTime, Float, JSON
from datetime import datetime , timezone
from app.database.db import Base


# ---------- SYSTEM LOG ----------

class SystemLog(Base):
    __tablename__ = "system_logs"

    log_id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100))
    message = Column(String(255))
    severity = Column(String(50))
    timestamp = Column(
    DateTime(timezone=True),
    default=lambda: datetime.now(timezone.utc)
    )


# ---------- NETWORK EVENT ----------

class NetworkEvent(Base):
    __tablename__ = "network_events"

    event_id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    protocol = Column(String(20))
    packet_size = Column(Integer)
    timestamp = Column(
    DateTime(timezone=True),
    default=lambda: datetime.now(timezone.utc)
    )

    # 🔥 Phase 6: Feature storage
    features = Column(JSON, nullable=True)


# ---------- INCIDENT ----------

class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String(45))
    incident_type = Column(String(100))
    description = Column(String(255))
    severity = Column(String(50))
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    timestamp = Column(
    DateTime(timezone=True),
    default=lambda: datetime.now(timezone.utc)
    )
    mitigation_status = Column(String(30), default="PENDING")
    proof = Column(JSON, nullable=True)

# ---------- RESPONSE ACTION ----------

class ResponseAction(Base):
    __tablename__ = "response_actions"

    response_id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False)
    action_type = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    timestamp = Column(
    DateTime(timezone=True),
    default=lambda: datetime.now(timezone.utc)
    )
