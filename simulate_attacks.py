# simulate_attacks.py
# ATDS — Safe Attack Simulator for Demo/Presentation
#
# HOW IT WORKS:
#   - Sends fake packet data to YOUR OWN backend at localhost:8000
#   - No real network attacks. No malicious traffic. No harm to your laptop.
#   - It's just HTTP POST requests with made-up numbers.
#   - 100% safe. Can be stopped anytime with Ctrl+C.
#
# HOW TO RUN:
#   1. Make sure your backend is running (uvicorn app.main:app --reload)
#   2. Open a NEW terminal in your backend/ folder
#   3. Run: python simulate_attacks.py
#   4. Watch your dashboard light up!

import requests
import time
import random
import json
from datetime import datetime

BASE_URL = "http://localhost:8000/network-events/"

# ─── FAKE IP POOLS ────────────────────────────────────────────────────────────
ATTACKER_IPS = [
    "192.168.1.6",    # repeat offender (already in your DB)
    "10.0.0.99",      # new attacker
    "172.16.0.55",    # new attacker
    "192.168.1.200",  # new attacker
]

VICTIM_IPS = [
    "192.168.1.1",
    "192.168.1.10",
    "10.0.0.1",
]

# ─── ATTACK SCENARIOS ─────────────────────────────────────────────────────────
SCENARIOS = {

    "ddos": {
        "name": "DDoS Flood",
        "description": "Massive packet flood from one IP to overwhelm the target",
        "packets": 30,
        "delay": 0.1,
        "packet_size_range": (1400, 1500),   # large packets, near MTU
        "protocol": "UDP",
        "dst_port": 80,
    },

    "port_scan": {
        "name": "Port Scan",
        "description": "Attacker scanning all ports looking for open services",
        "packets": 20,
        "delay": 0.3,
        "packet_size_range": (40, 60),        # tiny SYN packets
        "protocol": "TCP",
        "dst_port": None,                     # cycles through ports
    },

    "honeypot_hit": {
        "name": "Honeypot Trigger",
        "description": "Attacker hits a decoy port — 100% confirmed attack",
        "packets": 3,
        "delay": 1.0,
        "packet_size_range": (100, 200),
        "protocol": "TCP",
        "dst_port": 4444,                     # classic reverse shell port
    },

    "slow_evasion": {
        "name": "Threshold Evasion",
        "description": "Attacker carefully staying just below detection threshold",
        "packets": 25,
        "delay": 0.5,
        "packet_size_range": (200, 240),      # suspiciously consistent size
        "protocol": "TCP",
        "dst_port": 443,
    },

    "brute_force": {
        "name": "Brute Force SSH",
        "description": "Repeated login attempts against SSH port",
        "packets": 15,
        "delay": 0.4,
        "packet_size_range": (80, 120),
        "protocol": "TCP",
        "dst_port": 22,
    },

    "data_exfil": {
        "name": "Data Exfiltration",
        "description": "Large outbound transfers — attacker stealing data",
        "packets": 10,
        "delay": 0.8,
        "packet_size_range": (1200, 1500),    # large outbound packets
        "protocol": "TCP",
        "dst_port": 443,
    },

    "rdp_attack": {
        "name": "RDP Honeypot Hit",
        "description": "Attack on fake Remote Desktop Protocol decoy",
        "packets": 5,
        "delay": 0.5,
        "packet_size_range": (150, 300),
        "protocol": "TCP",
        "dst_port": 3389,                     # honeypot RDP port
    },

    "multi_ip": {
        "name": "Coordinated Multi-IP Attack",
        "description": "Multiple IPs attacking simultaneously — tests persona clustering",
        "packets": 10,
        "delay": 0.2,
        "packet_size_range": (800, 1200),
        "protocol": "TCP",
        "dst_port": 8080,
    },
}


# ─── SENDER ───────────────────────────────────────────────────────────────────
def send_event(src_ip, dst_ip, protocol, packet_size, dst_port=80):
    """Send one fake packet event to your ATDS backend."""
    payload = {
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    protocol,
        "packet_size": packet_size,
        "dst_port":    dst_port,
    }
    try:
        resp = requests.post(BASE_URL, json=payload, timeout=5)
        return resp.status_code, resp.json()
    except requests.exceptions.ConnectionError:
        print("  ✗ Cannot connect to backend. Is uvicorn running?")
        return None, None
    except Exception as e:
        return None, {"error": str(e)}


def run_scenario(scenario_key, src_ip=None, verbose=True):
    """Run one attack scenario."""
    s = SCENARIOS[scenario_key]
    ip = src_ip or random.choice(ATTACKER_IPS)
    dst = random.choice(VICTIM_IPS)

    print(f"\n{'='*60}")
    print(f"  SCENARIO : {s['name']}")
    print(f"  FROM IP  : {ip}")
    print(f"  WHAT     : {s['description']}")
    print(f"  PACKETS  : {s['packets']}")
    print(f"{'='*60}")

    incidents_created = 0
    honeypot_hits     = 0

    for i in range(s["packets"]):
        size = random.randint(*s["packet_size_range"])

        # Port scan cycles through ports
        if scenario_key == "port_scan":
            port = random.randint(1, 65535)
        elif scenario_key == "multi_ip":
            ip = random.choice(ATTACKER_IPS)   # rotate IPs
            port = s["dst_port"]
        else:
            port = s["dst_port"] or 80

        status, result = send_event(ip, dst, s["protocol"], size, port)

        if status is None:
            break

        if verbose:
            honeypot = result.get("honeypot_confirmed", False)
            incident  = result.get("incident_id")
            evasion   = result.get("evasion_suspected", False)

            flags = []
            if honeypot:
                flags.append("🍯 HONEYPOT HIT")
                honeypot_hits += 1
            if incident:
                flags.append(f"🚨 INCIDENT #{incident}")
                incidents_created += 1
            if evasion:
                flags.append("⚠ EVASION SUSPECTED")

            flag_str = "  ".join(flags) if flags else "✓ logged"
            print(f"  Pkt {i+1:02d} | size={size:4d}b | port={port:5d} | {flag_str}")

        time.sleep(s["delay"])

    print(f"\n  ✅ Done — {incidents_created} incident(s) created, "
          f"{honeypot_hits} honeypot hit(s)")
    return incidents_created


# ─── FULL DEMO SEQUENCE ───────────────────────────────────────────────────────
def run_full_demo():
    """
    Runs all scenarios in a logical order that tells a story:
    Reconnaissance → Evasion attempt → Brute force → Honeypot → DDoS → Exfil
    """
    print("\n" + "█"*60)
    print("  ATDS ATTACK SIMULATION — FULL DEMO SEQUENCE")
    print("  Safe: sends fake data to localhost:8000 only")
    print("  Watch your dashboard as each scenario runs!")
    print("█"*60)

    sequence = [
        ("port_scan",    ATTACKER_IPS[1], "Step 1: Attacker begins port scanning"),
        ("slow_evasion", ATTACKER_IPS[1], "Step 2: Same IP tries to evade detection"),
        ("brute_force",  ATTACKER_IPS[1], "Step 3: Brute forcing SSH"),
        ("honeypot_hit", ATTACKER_IPS[1], "Step 4: Attacker hits honeypot port — CAUGHT"),
        ("multi_ip",     None,            "Step 5: Coordinated attack from multiple IPs"),
        ("ddos",         ATTACKER_IPS[0], "Step 6: Known repeat offender launches DDoS"),
        ("data_exfil",   ATTACKER_IPS[0], "Step 7: Same IP attempts data exfiltration"),
        ("rdp_attack",   ATTACKER_IPS[2], "Step 8: New IP hits RDP honeypot"),
    ]

    total_incidents = 0
    for scenario_key, ip, description in sequence:
        print(f"\n\n{'─'*60}")
        print(f"  {description}")
        print(f"{'─'*60}")
        time.sleep(1)
        incidents = run_scenario(scenario_key, src_ip=ip, verbose=True)
        total_incidents += incidents
        print(f"\n  ⏳ Pausing 3 seconds before next scenario...")
        time.sleep(3)

    print(f"\n\n{'█'*60}")
    print(f"  DEMO COMPLETE")
    print(f"  Total incidents created: {total_incidents}")
    print(f"  Check your dashboard now!")
    print(f"{'█'*60}\n")


# ─── INTERACTIVE MENU ─────────────────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("  ATDS SAFE ATTACK SIMULATOR")
    print("  All traffic goes to localhost:8000 only")
    print("  No real attacks. No network harm. Safe to run.")
    print("="*60)
    print("\n  OPTIONS:")
    print("  0 — Run FULL DEMO (all scenarios in sequence) ← RECOMMENDED")
    for i, (key, s) in enumerate(SCENARIOS.items(), 1):
        print(f"  {i} — {s['name']}: {s['description']}")
    print("  q — Quit")

    choice = input("\n  Enter choice: ").strip().lower()

    if choice == "0":
        run_full_demo()
    elif choice == "q":
        print("  Bye!")
    else:
        try:
            idx = int(choice) - 1
            key = list(SCENARIOS.keys())[idx]
            ip  = input(f"  Source IP (press Enter for random): ").strip() or None
            run_scenario(key, src_ip=ip)
        except (ValueError, IndexError):
            print("  Invalid choice.")


if __name__ == "__main__":
    main()