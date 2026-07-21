# ============================================================
# FEATURE 4: HONEYPOT API ROUTER
# File: backend/app/routers/honeypot_router.py
#
# Register in main.py:
#   from .routers.honeypot_router import router as honeypot_router
#   app.include_router(honeypot_router)
# ============================================================

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database.db import get_db
from ..security.honeypot import honeypot

router = APIRouter(prefix="/honeypot", tags=["honeypot"])


@router.get("/stats")
def get_honeypot_stats():
    """Dashboard stats: total hits, active ports, retraining status."""
    return honeypot.get_stats()


@router.get("/hits")
def get_recent_hits(limit: int = 20):
    """Recent confirmed attacks captured by honeypot."""
    return {
        "hits": honeypot.get_recent_hits(limit),
        "total": honeypot.get_stats()["total_confirmed_attacks"],
    }


@router.post("/retrain")
def trigger_manual_retrain():
    """
    Manually trigger IF retraining with all confirmed honeypot hits.
    Useful for testing the self-improvement loop.
    """
    result = honeypot._retrain_isolation_forest()
    return result


@router.get("/ports")
def get_honeypot_ports():
    """Returns the list of active honeypot ports and their fake services."""
    return {
        "honeypot_ports": [
            {"port": port, "service": service}
            for port, service in honeypot.HONEYPOT_PORTS.items()
        ],
        "total_active": len(honeypot.HONEYPOT_PORTS),
    }
