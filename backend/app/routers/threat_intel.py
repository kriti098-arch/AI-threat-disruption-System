# app/routers/threat_intel.py
# Add to main.py:
#   from app.routers import threat_intel
#   app.include_router(threat_intel.router)

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.database.models import Incident
from app.security.threat_intel import check_ip_reputation, get_cache_stats
from app.security.geolocation import geolocate_ip, geolocate_multiple, get_attack_map_data

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("/ip/{src_ip}")
async def get_ip_reputation(src_ip: str):
    """Check a single IP against AbuseIPDB + AlienVault OTX."""
    intel = await check_ip_reputation(src_ip)
    geo   = await geolocate_ip(src_ip)
    return {"reputation": intel, "geolocation": geo}


@router.get("/cache-stats")
def cache_stats():
    return get_cache_stats()


@router.get("/attack-map")
async def get_attack_map(db: Session = Depends(get_db)):
    """Returns geolocated attack data for map visualization."""
    incidents = db.query(Incident).order_by(Incident.timestamp.desc()).limit(200).all()
    map_data = get_attack_map_data(incidents)

    # If no geo data in proof yet, geolocate top IPs on the fly
    if not map_data:
        unique_ips = list({inc.src_ip for inc in incidents if inc.src_ip})[:20]
        geo_results = await geolocate_multiple(unique_ips)
        for inc in incidents[:50]:
            geo = geo_results.get(inc.src_ip, {})
            if geo.get("lat") and geo.get("country_code") != "LAN":
                map_data.append({
                    "ip":           inc.src_ip,
                    "country":      geo.get("country"),
                    "country_code": geo.get("country_code"),
                    "city":         geo.get("city"),
                    "lat":          geo.get("lat"),
                    "lon":          geo.get("lon"),
                    "isp":          geo.get("isp"),
                    "severity":     inc.severity,
                    "attack_type":  inc.incident_type,
                })
        # Deduplicate
        seen = set()
        unique_map = []
        for p in map_data:
            if p["ip"] not in seen:
                seen.add(p["ip"])
                unique_map.append(p)
        map_data = unique_map

    return {"total_points": len(map_data), "points": map_data}


@router.get("/country-summary")
async def country_summary(db: Session = Depends(get_db)):
    """Summarize attacks by country."""
    incidents = db.query(Incident).all()
    unique_ips = list({inc.src_ip for inc in incidents if inc.src_ip})[:30]
    geo_results = await geolocate_multiple(unique_ips)

    country_counts = {}
    for ip, geo in geo_results.items():
        country = geo.get("country", "Unknown")
        if geo.get("is_private"):
            country = "Private Network"
        country_counts[country] = country_counts.get(country, 0) + 1

    return sorted(
        [{"country": k, "count": v} for k, v in country_counts.items()],
        key=lambda x: x["count"], reverse=True
    )