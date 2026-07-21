# app/security/persona_engine.py

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from datetime import datetime


class PersonaEngine:
    def __init__(self, min_events_for_profile: int = 5):
        self.min_events = min_events_for_profile
        self.ip_profiles = {}
        self.ip_event_counts = defaultdict(int)
        self.persona_assignments = {}
        self.persona_metadata = {}

    def update_profile(self, src_ip: str, features: dict, attack_type: str, risk_score: float):
        self.ip_event_counts[src_ip] += 1
        count = self.ip_event_counts[src_ip]

        if src_ip not in self.ip_profiles:
            self.ip_profiles[src_ip] = {
                "avg_packet_size":   features.get("avg_packet_size", 0),
                "std_packet_size":   features.get("std_packet_size", 0),
                "total_packets":     features.get("total_packets", 0),
                "avg_risk_score":    risk_score,
                "attack_types":      {},
                "first_seen":        datetime.utcnow().isoformat(),
                "last_seen":         datetime.utcnow().isoformat(),
                "event_count":       1
            }
        else:
            p = self.ip_profiles[src_ip]
            alpha = 0.1
            p["avg_packet_size"] = (1 - alpha) * p["avg_packet_size"] + alpha * features.get("avg_packet_size", 0)
            p["std_packet_size"] = (1 - alpha) * p["std_packet_size"] + alpha * features.get("std_packet_size", 0)
            p["avg_risk_score"]  = (1 - alpha) * p["avg_risk_score"]  + alpha * risk_score
            p["last_seen"]       = datetime.utcnow().isoformat()
            p["event_count"]     = count

        atypes = self.ip_profiles[src_ip]["attack_types"]
        atypes[attack_type] = atypes.get(attack_type, 0) + 1

        if len(self.ip_profiles) > 3 and len(self.ip_profiles) % 10 == 0:
            self.cluster()

    def cluster(self):
        ips = list(self.ip_profiles.keys())
        if len(ips) < 3:
            return

        matrix = []
        for ip in ips:
            p = self.ip_profiles[ip]
            dominant_attack = max(p["attack_types"], key=p["attack_types"].get) if p["attack_types"] else "unknown"
            attack_encoded = self._encode_attack_type(dominant_attack)
            matrix.append([
                p["avg_packet_size"],
                p["std_packet_size"],
                p["avg_risk_score"],
                p["event_count"],
                attack_encoded
            ])

        matrix = np.array(matrix)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(matrix)

        db = DBSCAN(eps=1.2, min_samples=2)
        labels = db.fit_predict(scaled)

        for ip, label in zip(ips, labels):
            self.persona_assignments[ip] = f"UNIQUE_{ip}" if label == -1 else f"PERSONA_{label}"

        self._build_persona_metadata(ips, labels)

    def _build_persona_metadata(self, ips: list, labels: list):
        cluster_ips = defaultdict(list)
        for ip, label in zip(ips, labels):
            cluster_ips[label].append(ip)

        for label, cluster_ip_list in cluster_ips.items():
            if label == -1:
                continue
            risk_scores = [self.ip_profiles[ip]["avg_risk_score"] for ip in cluster_ip_list]
            all_attacks = defaultdict(int)
            for ip in cluster_ip_list:
                for atype, cnt in self.ip_profiles[ip]["attack_types"].items():
                    all_attacks[atype] += cnt

            dominant = max(all_attacks, key=all_attacks.get) if all_attacks else "unknown"

            self.persona_metadata[f"PERSONA_{label}"] = {
                "persona_id": f"PERSONA_{label}",
                "ip_count": len(cluster_ip_list),
                "member_ips": cluster_ip_list,
                "dominant_attack_type": dominant,
                "avg_risk_score": round(np.mean(risk_scores), 2),
                "threat_level": "HIGH" if np.mean(risk_scores) > 6 else "MEDIUM"
            }

    def get_persona(self, src_ip: str) -> dict:
        if src_ip not in self.ip_profiles:
            return {"persona_id": None, "status": "no_profile_yet"}

        persona_id = self.persona_assignments.get(src_ip)
        if not persona_id:
            return {"persona_id": None, "status": "not_yet_clustered", "profile": self.ip_profiles.get(src_ip)}

        is_unique = persona_id.startswith("UNIQUE_")
        meta = self.persona_metadata.get(persona_id, {})

        return {
            "persona_id": persona_id,
            "is_unique_actor": is_unique,
            "is_coordinated": not is_unique and meta.get("ip_count", 1) > 1,
            "persona_metadata": meta,
            "ip_profile": self.ip_profiles.get(src_ip),
            "status": "assigned"
        }

    def get_all_personas(self) -> dict:
        return self.persona_metadata

    def _encode_attack_type(self, attack_type: str) -> float:
        encoding = {
            "Beaconing / C2 Communication":     1.0,
            "Brute Force / Escalating Attack":  2.0,
            "DDoS Pattern":                     3.0,
            "Data Exfiltration Pattern":        4.0,
            "Unknown Suspicious Activity":      0.5,
        }
        return encoding.get(attack_type, 0.0)