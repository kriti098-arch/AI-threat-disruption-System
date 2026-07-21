# app/security/kill_chain.py

from collections import defaultdict
from datetime import datetime, timedelta

ATTACK_TO_STAGE = {
    "Beaconing / C2 Communication":     "command_and_control",
    "Brute Force / Escalating Attack":  "credential_access",
    "DDoS Pattern":                     "impact",
    "Data Exfiltration Pattern":        "exfiltration",
    "Unknown Suspicious Activity":      "discovery",
    "Port Scan":                        "reconnaissance",
    "Lateral Movement":                 "lateral_movement",
}

KILL_CHAIN_GRAPH = {
    "reconnaissance":       ["resource_development", "initial_access"],
    "resource_development": ["initial_access"],
    "initial_access":       ["execution", "persistence"],
    "execution":            ["persistence", "privilege_escalation"],
    "persistence":          ["privilege_escalation", "defense_evasion"],
    "privilege_escalation": ["defense_evasion", "credential_access"],
    "defense_evasion":      ["credential_access", "discovery"],
    "credential_access":    ["discovery", "lateral_movement"],
    "discovery":            ["lateral_movement", "collection"],
    "lateral_movement":     ["collection", "command_and_control"],
    "collection":           ["command_and_control", "exfiltration"],
    "command_and_control":  ["exfiltration", "impact"],
    "exfiltration":         ["impact"],
    "impact":               []
}

STAGE_DESCRIPTIONS = {
    "reconnaissance":       "Attacker is gathering information about targets",
    "resource_development": "Attacker is acquiring tools and infrastructure",
    "initial_access":       "Attacker is attempting to enter the network",
    "execution":            "Attacker is running malicious code",
    "persistence":          "Attacker is establishing a foothold",
    "privilege_escalation": "Attacker is gaining elevated permissions",
    "defense_evasion":      "Attacker is trying to avoid detection",
    "credential_access":    "Attacker is stealing credentials",
    "discovery":            "Attacker is exploring the network",
    "lateral_movement":     "Attacker is moving through the network",
    "collection":           "Attacker is gathering target data",
    "command_and_control":  "Attacker has established remote control",
    "exfiltration":         "Attacker is stealing data out of network",
    "impact":               "Attacker is disrupting or destroying systems"
}

STAGE_URGENCY = {
    "reconnaissance":       "LOW",
    "resource_development": "LOW",
    "initial_access":       "MEDIUM",
    "execution":            "MEDIUM",
    "persistence":          "HIGH",
    "privilege_escalation": "HIGH",
    "defense_evasion":      "HIGH",
    "credential_access":    "HIGH",
    "discovery":            "MEDIUM",
    "lateral_movement":     "CRITICAL",
    "collection":           "CRITICAL",
    "command_and_control":  "CRITICAL",
    "exfiltration":         "CRITICAL",
    "impact":               "CRITICAL"
}


class KillChainPredictor:
    def __init__(self, history_window_minutes: int = 30):
        self.ip_stage_history = defaultdict(list)
        self.history_window = timedelta(minutes=history_window_minutes)

    def _clean_old_history(self, src_ip: str):
        cutoff = datetime.utcnow() - self.history_window
        self.ip_stage_history[src_ip] = [
            (stage, ts) for stage, ts in self.ip_stage_history[src_ip]
            if ts > cutoff
        ]

    def update(self, src_ip: str, attack_type: str) -> dict:
        self._clean_old_history(src_ip)
        current_stage = ATTACK_TO_STAGE.get(attack_type, "discovery")
        now = datetime.utcnow()
        self.ip_stage_history[src_ip].append((current_stage, now))

        seen_stages = [s for s, _ in self.ip_stage_history[src_ip]]
        next_stages = KILL_CHAIN_GRAPH.get(current_stage, [])

        all_stages = list(KILL_CHAIN_GRAPH.keys())
        stage_index = all_stages.index(current_stage) if current_stage in all_stages else 0
        progression_pct = round((stage_index / max(len(all_stages) - 1, 1)) * 100, 1)

        return {
            "current_stage": current_stage,
            "current_stage_description": STAGE_DESCRIPTIONS.get(current_stage, ""),
            "current_stage_urgency": STAGE_URGENCY.get(current_stage, "MEDIUM"),
            "predicted_next_stages": next_stages,
            "next_stage_descriptions": [STAGE_DESCRIPTIONS.get(s, "") for s in next_stages],
            "kill_chain_progression_pct": progression_pct,
            "stages_seen_this_session": list(set(seen_stages)),
            "total_stage_events": len(seen_stages),
            "recommendation": self._get_recommendation(current_stage, next_stages)
        }

    def _get_recommendation(self, current_stage: str, next_stages: list) -> str:
        urgency = STAGE_URGENCY.get(current_stage, "MEDIUM")
        if urgency == "CRITICAL":
            return f"IMMEDIATE ACTION REQUIRED. Attacker at {current_stage} stage. Block and isolate now."
        elif urgency == "HIGH":
            next = next_stages[0] if next_stages else "unknown"
            return f"HIGH PRIORITY. Monitor for {next} indicators. Consider preemptive rate limiting."
        elif urgency == "MEDIUM":
            return f"Watch closely. Attacker may progress to {next_stages[0] if next_stages else 'next stage'}."
        else:
            return "Log and monitor. No immediate action required."

    def get_history(self, src_ip: str) -> list:
        self._clean_old_history(src_ip)
        return [
            {"stage": s, "timestamp": ts.isoformat()}
            for s, ts in self.ip_stage_history[src_ip]
        ]