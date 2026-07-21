# ============================================================
# FEATURE 2: SHAP API ENDPOINT
# File: backend/app/routers/evaluation.py
#
# ADD these two routes to your existing evaluation.py router
# ============================================================

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database.db import get_db
from ..database.models import NetworkEvent
from ..security.shap_explainer import shap_explainer

router = APIRouter(prefix="/evaluation", tags=["evaluation"])


@router.get("/shap-importance")
def get_global_shap_importance(db: Session = Depends(get_db)):
    """
    Compute global feature importance using SHAP across recent events.
    Used by the Model Evaluation frontend page.
    Returns mean absolute SHAP value per feature, ranked.
    """
    # Sample recent events for batch SHAP computation
    events = db.query(NetworkEvent).order_by(NetworkEvent.id.desc()).limit(200).all()

    if not events:
        return {"importance": [], "sample_size": 0, "message": "No events yet"}

    event_dicts = [
        {
            "packet_length": e.length or 0,
            "destination_port": e.destination_port or 0,
            "protocol_id": {"TCP": 6, "UDP": 17, "ICMP": 1}.get(e.protocol, 0),
        }
        for e in events
    ]

    importance = shap_explainer.explain_batch(event_dicts)

    return {
        "importance": importance,
        "sample_size": len(events),
        "message": f"SHAP importance computed over {len(events)} recent events",
    }


@router.get("/shap-single/{event_id}")
def get_single_event_shap(event_id: int, db: Session = Depends(get_db)):
    """
    Compute SHAP explanation for a specific network event by ID.
    Called when analyst clicks 'Explain' on any event in Live Traffic page.
    """
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    if not event:
        return {"error": "Event not found"}

    protocol_id = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(event.protocol, 0)

    result = shap_explainer.explain(
        packet_length=event.length or 0,
        port=event.destination_port or 0,
        protocol_id=protocol_id,
    )

    return {"event_id": event_id, "shap": result}
