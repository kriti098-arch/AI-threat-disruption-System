# app/security/geolocation.py
# Free IP geolocation using ip-api.com (no API key needed, 45 req/min)

import httpx
from datetime import datetime, timedelta

_geo_cache = {}
CACHE_TTL = timedelta(hours=24)


async def geolocate_ip(src_ip: str) -> dict:
    """Returns country, city, lat/lon for an IP address."""

    if _is_private(src_ip):
        return {
            "src_ip": src_ip,
            "is_private": True,
            "country": "Private Network",
            "country_code": "LAN",
            "city": "Local",
            "lat": 0, "lon": 0,
            "isp": "Local Network",
            "org": "Private"
        }

    if src_ip in _geo_cache:
        cached_at, result = _geo_cache[src_ip]
        if datetime.utcnow() - cached_at < CACHE_TTL:
            return result

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{src_ip}",
                params={"fields": "status,country,countryCode,region,city,lat,lon,isp,org,as,query"}
            )

        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "src_ip":       src_ip,
                    "is_private":   False,
                    "country":      data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "region":       data.get("region", ""),
                    "city":         data.get("city", "Unknown"),
                    "lat":          data.get("lat", 0),
                    "lon":          data.get("lon", 0),
                    "isp":          data.get("isp", "Unknown"),
                    "org":          data.get("org", ""),
                    "as":           data.get("as", ""),
                }
                _geo_cache[src_ip] = (datetime.utcnow(), result)
                return result

    except Exception as e:
        pass

    return {
        "src_ip": src_ip, "is_private": False,
        "country": "Unknown", "country_code": "??",
        "city": "Unknown", "lat": 0, "lon": 0,
        "isp": "Unknown", "org": "", "error": "lookup_failed"
    }


async def geolocate_multiple(ips: list) -> dict:
    """Geolocate multiple IPs. Returns dict keyed by IP."""
    import asyncio
    results = await asyncio.gather(*[geolocate_ip(ip) for ip in ips])
    return {r["src_ip"]: r for r in results}


def get_attack_map_data(incidents: list) -> list:
    """Build map data from incidents that have geolocation in proof."""
    points = []
    seen = set()
    for inc in incidents:
        proof = inc.proof or {}
        geo = proof.get("geolocation")
        if geo and geo.get("lat") and geo.get("country_code") != "LAN":
            ip = inc.src_ip
            if ip not in seen:
                seen.add(ip)
                points.append({
                    "ip":           ip,
                    "country":      geo.get("country"),
                    "country_code": geo.get("country_code"),
                    "city":         geo.get("city"),
                    "lat":          geo.get("lat"),
                    "lon":          geo.get("lon"),
                    "isp":          geo.get("isp"),
                    "severity":     inc.severity,
                    "attack_type":  inc.incident_type,
                })
    return points


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except Exception:
        return False