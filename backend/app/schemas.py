from pydantic import BaseModel
from datetime import datetime
from typing import Optional
# ---------- SYSTEM LOG ----------

class SystemLogCreate(BaseModel):
    source: str
    message: str
    severity: str

class SystemLogResponse(SystemLogCreate):
    log_id: int
    timestamp: datetime

    class Config:
        from_attributes = True


# ---------- NETWORK EVENT ----------

class NetworkEventCreate(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    packet_size: int

class NetworkEventResponse(NetworkEventCreate):
    event_id: int
    timestamp: datetime

    class Config:
        from_attributes = True
# ---------- INCIDENT ----------

class IncidentCreate(BaseModel):
    src_ip: str
    incident_type: str
    description: str
    severity: str
    risk_score: Optional[float]=None
    risk_level: Optional[str] = None
class IncidentResponse(IncidentCreate):
    incident_id: int
    timestamp: datetime

    class Config:
        from_attributes = True
class ResponseActionCreate(BaseModel):
    incident_id: int
    action_type: str
    status: str


class ResponseActionResponse(ResponseActionCreate):
    response_id: int
    timestamp: datetime

    class Config:
        from_attributes = True
