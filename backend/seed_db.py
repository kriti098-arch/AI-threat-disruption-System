"""
seed_db.py
-----------
Replays crafted traffic patterns through your OWN running server
(http://127.0.0.1:8000/network-events/) so the dashboard fills up with
DIVERSE, correctly-named incidents (Port Scan, DDoS Attack, Brute Force,
Beaconing, Data Exfiltration) instead of one generic "Unknown Suspicious
Activity" bucket.

WHY NOT JUST REPLAY THE RAW CSV:
Your detector's baseline is an exponential moving average (EMA) built
live per-IP. CIC-IDS2017's flow-level "Average Packet Size" values
don't reliably separate benign vs attack rows against a fresh EMA
baseline, so raw replay tends to fall into the generic fallback.
Instead, this script sends CRAFTED packet-size sequences per fake IP,
each shaped to reliably trigger one specific rule in your
_classify_rules() logic (see attack_classifier.py).

IMPORTANT — before running this:
1. Add this line to backend/app/security/kill_chain.py's ATTACK_TO_STAGE dict:
       "DDoS Attack": "impact",
   (your rule-based classifier returns "DDoS Attack" but the kill chain
   map only recognized "DDoS Pattern" — a naming mismatch bug that made
   every DDoS incident show kill chain stage "discovery" no matter what.)

2. Make sure your server is running (uvicorn app.main:app --reload)
   and DO NOT restart it while this script runs — per-IP sample counts
   live in server memory only.

HOW TO RUN:
    cd backend
    python seed_db.py
"""

import time
import random
import requests

SERVER_URL = "https://ai-threat-disruption-system.onrender.com/network-events/"
REQUEST_DELAY_SECONDS = 0.15 


def send(src_ip, packet_size, dst_port=80, protocol="TCP"):
    payload = {
        "src_ip": src_ip,
        "dst_ip": "10.0.0.5",
        "protocol": protocol,
        "packet_size": max(int(packet_size), 1),
        "dst_port": dst_port,
    }
    try:
        # timeout=(connect_timeout, read_timeout) — read timeout is generous
        # because incidents trigger a Groq API call server-side, which can
        # take a few seconds. 20s read timeout keeps this bounded so the
        # script can never hang indefinitely on one request.
        r = requests.post(SERVER_URL, json=payload, timeout=(5, 20))
        return r.json() if r.status_code == 200 else None
    except requests.exceptions.Timeout:
        print(f"  ! TIMEOUT on {src_ip} (server took >20s — likely a slow Groq call)", flush=True)
        return None
    except requests.exceptions.RequestException as e:
        print(f"  ! request failed: {e}", flush=True)
        return None


def send_baseline(src_ip, base_size=60, count=60, jitter=5, delay=REQUEST_DELAY_SECONDS):
    """Establish a stable low-variance baseline so the EMA has real history."""
    for i in range(count):
        size = base_size + random.randint(-jitter, jitter)
        send(src_ip, size)
        time.sleep(delay)


# ----------------------------------------------------------------------
# Five attack profiles, each shaped to hit a specific rule in
# _classify_rules() (see attack_classifier.py)
# ----------------------------------------------------------------------

def profile_port_scan(src_ip):
    """Sharp small-packet outliers vs a stable baseline -> z>4, avg<100."""
    print(f"[{src_ip}] Port Scan profile", flush=True)
    send_baseline(src_ip, base_size=60, count=60)
    for port in [21, 22, 23, 25, 80, 443, 3389, 8080, 3306, 5432]:
        r = send(src_ip, packet_size=8, dst_port=port)
        if r:
            print(f"    port {port} -> z={r.get('confidence_pct')} stage={r.get('kill_chain_stage')}", flush=True)
        time.sleep(REQUEST_DELAY_SECONDS)


def profile_ddos(src_ip):
    """Sustained flood of large packets -> avg climbs above 1000, z>5, samples>30."""
    print(f"[{src_ip}] DDoS profile", flush=True)
    send_baseline(src_ip, base_size=150, count=60)
    last = None
    for i in range(25):
        last = send(src_ip, packet_size=random.randint(4500, 6500), dst_port=80)
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)


def profile_brute_force(src_ip):
    """Steadily increasing packet sizes -> 3+ consecutive rising z-scores -> escalation flag."""
    print(f"[{src_ip}] Brute Force / Escalating profile", flush=True)
    send_baseline(src_ip, base_size=60, count=60)
    last = None
    size = 200
    for i in range(12):
        last = send(src_ip, packet_size=size, dst_port=22)
        size = int(size * 1.4)  # each step bigger than the last
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)


def profile_beaconing(src_ip):
    """Consistent small elevation, low variance -> std<15, samples>20, z>2."""
    print(f"[{src_ip}] Beaconing / C2 profile", flush=True)
    send_baseline(src_ip, base_size=60, count=60)
    last = None
    for i in range(25):
        last = send(src_ip, packet_size=90 + random.randint(-3, 3), dst_port=443)
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)


def profile_exfiltration(src_ip):
    """Sustained moderately-large, non-increasing packets -> avg>800, z>3, no escalation."""
    print(f"[{src_ip}] Data Exfiltration profile", flush=True)
    send_baseline(src_ip, base_size=200, count=60)
    last = None
    for i in range(20):
        last = send(src_ip, packet_size=2200 + random.randint(-100, 100), dst_port=443)
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)
def profile_port_scan_light(src_ip):
    """Milder port scan — lower z-score, lands MEDIUM/HIGH instead of CRITICAL."""
    print(f"[{src_ip}] Port Scan (light) profile", flush=True)
    send_baseline(src_ip, base_size=60, count=60)
    for port in [22, 80, 443, 3389]:
        r = send(src_ip, packet_size=40, dst_port=port)
        if r:
            print(f"    port {port} -> z={r.get('confidence_pct')} stage={r.get('kill_chain_stage')}", flush=True)
        time.sleep(REQUEST_DELAY_SECONDS)


def profile_ddos_light(src_ip):
    """Milder DDoS — smaller flood, lower avg packet size."""
    print(f"[{src_ip}] DDoS (light) profile", flush=True)
    send_baseline(src_ip, base_size=150, count=60)
    last = None
    for i in range(15):
        last = send(src_ip, packet_size=random.randint(1800, 2500), dst_port=80)
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)


def profile_brute_force_light(src_ip):
    """Milder brute force — slower escalation."""
    print(f"[{src_ip}] Brute Force (light) profile", flush=True)
    send_baseline(src_ip, base_size=60, count=60)
    last = None
    size = 150
    for i in range(8):
        last = send(src_ip, packet_size=size, dst_port=22)
        size = int(size * 1.15)
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)


def profile_exfiltration_light(src_ip):
    """Milder exfiltration — smaller sustained packets."""
    print(f"[{src_ip}] Data Exfiltration (light) profile", flush=True)
    send_baseline(src_ip, base_size=200, count=60)
    last = None
    for i in range(15):
        last = send(src_ip, packet_size=900 + random.randint(-50, 50), dst_port=443)
        time.sleep(REQUEST_DELAY_SECONDS)
    if last:
        print(f"    final -> stage={last.get('kill_chain_stage')}", flush=True)
def profile_honeypot_hits(src_ip):
    """Directly hit honeypot decoy ports — instant CRITICAL, no baseline needed."""
    print(f"[{src_ip}] Honeypot trigger profile", flush=True)
    honeypot_ports = [2222, 3389, 1433, 3306, 5432, 6379, 27017, 9200, 4444, 31337]
    for port in honeypot_ports:
        r = send(src_ip, packet_size=100, dst_port=port)
        if r:
            print(f"    port {port} -> honeypot_confirmed={r.get('honeypot_confirmed')}", flush=True)
        time.sleep(REQUEST_DELAY_SECONDS)

def main():
    profiles = [
        # Port Scan
        ("192.168.10.11", profile_port_scan),
        ("192.168.10.21", profile_port_scan),
        ("192.168.10.31", profile_port_scan_light),

        # DDoS
        ("192.168.10.12", profile_ddos),
        ("192.168.10.32", profile_ddos_light),

        # Brute Force
        ("192.168.10.13", profile_brute_force),
        ("192.168.10.22", profile_brute_force),
        ("192.168.10.33", profile_brute_force_light),

        # Beaconing
        ("192.168.10.14", profile_beaconing),
        ("192.168.10.34", profile_beaconing),

        # Data Exfiltration
        ("192.168.10.15", profile_exfiltration),
        ("192.168.10.35", profile_exfiltration_light),
        ("192.168.10.41", profile_honeypot_hits),
        ("192.168.10.42", profile_honeypot_hits),
    ]

    for src_ip, fn in profiles:
        fn(src_ip)
        print(flush=True)

    print("Done. Refresh your dashboard — Incident Log should now show", flush=True)
    print("varied attack types, severities, and repeat-offender IPs.", flush=True)
    print("Next: run 'python spread_timestamps.py' to spread these", flush=True)
    print("incidents across a realistic 24h window.", flush=True)


if __name__ == "__main__":
    random.seed(7)
    main()