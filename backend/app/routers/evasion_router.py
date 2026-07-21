# ============================================================
# FEATURE 3: EVASION DETECTION API ROUTER
# File: backend/app/routers/evasion.py
#
# NEW FILE — register in main.py:
#   from .routers.evasion import router as evasion_router
#   app.include_router(evasion_router)
# ============================================================

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database.db import get_db
from ..security.evasion_detector import evasion_detector

router = APIRouter(prefix="/evasion", tags=["evasion"])


@router.get("/suspects")
def get_evasion_suspects():
    """
    Returns all IPs currently suspected of threshold-aware evasion.
    Frontend Evasion page polls this every 30 seconds.
    """
    evaders = evasion_detector.get_all_evaders()
    return {
        "total_suspects": len(evaders),
        "confirmed_evaders": sum(1 for e in evaders if e["status"] == "CONFIRMED_EVADER"),
        "suspected_evaders": sum(1 for e in evaders if e["status"] == "SUSPECTED_EVADER"),
        "evaders": evaders,
    }


@router.get("/analyze/{ip}")
def analyze_ip_for_evasion(ip: str):
    """
    On-demand evasion analysis for a specific IP.
    Called when analyst clicks 'Analyze Evasion' on an IP.
    """
    result = evasion_detector.analyze(ip)
    result["ip"] = ip
    return result


@router.post("/reset/{ip}")
def reset_ip_evasion(ip: str):
    """Clear evasion profile for an IP after manual review."""
    evasion_detector.reset_ip(ip)
    return {"message": f"Evasion profile cleared for {ip}", "ip": ip}


@router.get("/stats")
def get_evasion_stats():
    """Summary statistics for the evasion detection system."""
    all_profiles = evasion_detector.profiles
    tracked = len(all_profiles)
    suspected = sum(1 for p in all_profiles.values() if p.evasion_score >= 0.40)
    confirmed = sum(1 for p in all_profiles.values() if p.evasion_score >= 0.70)

    return {
        "total_ips_tracked": tracked,
        "suspected_evaders": suspected,
        "confirmed_evaders": confirmed,
        "detection_methods": [
            "Z-score variance analysis",
            "Threshold proximity clustering",
            "Packet rate consistency analysis",
        ],
    }
