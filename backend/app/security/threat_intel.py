# app/security/threat_intel.py
# Checks IPs against AbuseIPDB and AlienVault OTX
# Free APIs — get keys from:
#   AbuseIPDB:   https://www.abuseipdb.com/account/api
#   AlienVault:  https://otx.alienvault.com/api

import httpx
import os
from datetime import datetime, timedelta

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
ALIENVAULT_KEY = os.getenv("ALIENVAULT_API_KEY", "")

# Simple in-memory cache to avoid hammering APIs
_cache = {}
CACHE_TTL = timedelta(hours=1)


async def check_ip_reputation(src_ip: str) -> dict:
    """Check IP against threat intel feeds. Returns enriched reputation data."""

    # Skip private IPs
    if _is_private(src_ip):
        return {"src_ip": src_ip, "is_private": True, "threat_intel_checked": False}

    # Return cached result if fresh
    if src_ip in _cache:
        cached_at, result = _cache[src_ip]
        if datetime.utcnow() - cached_at < CACHE_TTL:
            result["from_cache"] = True
            return result

    result = {
        "src_ip":               src_ip,
        "is_private":           False,
        "threat_intel_checked": True,
        "from_cache":           False,
        "abuseipdb":            None,
        "alienvault":           None,
        "is_known_malicious":   False,
        "threat_score":         0,
        "threat_categories":    [],
        "country":              None,
        "isp":                  None,
    }

    tasks = []
    if ABUSEIPDB_KEY:
        tasks.append(_check_abuseipdb(src_ip, result))
    if ALIENVAULT_KEY:
        tasks.append(_check_alienvault(src_ip, result))

    if tasks:
        import asyncio
        await asyncio.gather(*tasks, return_exceptions=True)

    # Determine if known malicious
    abuse_score = result.get("abuseipdb", {}) or {}
    otx_pulses  = result.get("alienvault", {}) or {}

    abuse_confidence = abuse_score.get("abuse_confidence_score", 0) if isinstance(abuse_score, dict) else 0
    otx_pulse_count  = otx_pulses.get("pulse_count", 0) if isinstance(otx_pulses, dict) else 0

    result["is_known_malicious"] = abuse_confidence > 25 or otx_pulse_count > 0
    result["threat_score"] = min(round(
        (abuse_confidence * 0.6) + (min(otx_pulse_count, 10) * 4)
    , 1), 100)

    _cache[src_ip] = (datetime.utcnow(), result)
    return result


async def _check_abuseipdb(src_ip: str, result: dict):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": src_ip, "maxAgeInDays": 90, "verbose": True}
            )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result["abuseipdb"] = {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports":          data.get("totalReports", 0),
                "last_reported":          data.get("lastReportedAt"),
                "country_code":           data.get("countryCode"),
                "isp":                    data.get("isp"),
                "domain":                 data.get("domain"),
                "is_tor":                 data.get("isTor", False),
                "usage_type":             data.get("usageType"),
            }
            result["country"] = data.get("countryCode")
            result["isp"]     = data.get("isp")
            cats = data.get("reports", [])
            all_cats = []
            for r in cats[:5]:
                all_cats.extend(r.get("categories", []))
            result["threat_categories"] = list(set(
                _abuse_category_name(c) for c in all_cats
            ))
    except Exception as e:
        result["abuseipdb"] = {"error": str(e)}


async def _check_alienvault(src_ip: str, result: dict):
    try:
        headers = {}
        if ALIENVAULT_KEY:
            headers["X-OTX-API-KEY"] = ALIENVAULT_KEY

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{src_ip}/general",
                headers=headers
            )
        if resp.status_code == 200:
            data = resp.json()
            result["alienvault"] = {
                "pulse_count":   data.get("pulse_info", {}).get("count", 0),
                "reputation":    data.get("reputation", 0),
                "country":       data.get("country_name"),
                "city":          data.get("city"),
                "asn":           data.get("asn"),
                "malware_count": len(data.get("malware_families", [])),
            }
            if not result["country"]:
                result["country"] = data.get("country_code")
    except Exception as e:
        result["alienvault"] = {"error": str(e)}


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


def _abuse_category_name(cat_id: int) -> str:
    categories = {
        3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
        6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
        9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
        12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
        15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
        18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
    }
    return categories.get(cat_id, f"Category {cat_id}")


def get_cache_stats() -> dict:
    return {
        "cached_ips": len(_cache),
        "api_keys_configured": {
            "abuseipdb":  bool(ABUSEIPDB_KEY),
            "alienvault": bool(ALIENVAULT_KEY)
        }
    }