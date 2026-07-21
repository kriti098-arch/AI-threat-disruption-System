# app/security/confidence_scorer.py

from dataclasses import dataclass
from typing import List


@dataclass
class EvidenceSignal:
    name: str
    triggered: bool
    weight: float
    description: str


class ConfidenceScorer:
    def score(
        self,
        *,
        ml_anomaly: bool,
        ml_score: float,
        isolation_forest_anomaly: bool,
        isolation_forest_score: float,
        escalation_detected: bool,
        kill_chain_stage: str,
        kill_chain_progression_pct: float,
        is_repeat_offender: bool,
        persona_is_known: bool,
        persona_is_coordinated: bool,
        risk_score: float
    ) -> dict:

        signals: List[EvidenceSignal] = [
            EvidenceSignal("Z-Score Anomaly",       ml_anomaly,                      0.15, "Statistical Z-score exceeded threshold"),
            EvidenceSignal("Isolation Forest",       isolation_forest_anomaly,        0.20, "Isolation Forest ML model flagged as outlier"),
            EvidenceSignal("High ML Score",          ml_score > 0.7,                  0.10, f"ML anomaly score {round(ml_score,2)} exceeds 0.7"),
            EvidenceSignal("High IF Score",          isolation_forest_score > 0.7,    0.10, f"IF score {round(isolation_forest_score,2)} exceeds 0.7"),
            EvidenceSignal("Escalation Pattern",     escalation_detected,             0.15, "Rising anomaly scores over consecutive events"),
            EvidenceSignal("Kill Chain Advanced",    kill_chain_progression_pct > 50, 0.10, f"Kill chain {kill_chain_progression_pct}% progressed"),
            EvidenceSignal("Repeat Offender",        is_repeat_offender,              0.10, "IP has triggered multiple high-severity incidents"),
            EvidenceSignal("Known Persona Match",    persona_is_known,                0.05, "IP matches a previously profiled attacker persona"),
            EvidenceSignal("Coordinated Attack",     persona_is_coordinated,          0.05, "IP belongs to a cluster of coordinated attackers"),
        ]

        total_weight = sum(s.weight for s in signals)
        triggered_weight = sum(s.weight for s in signals if s.triggered)
        confidence = round(triggered_weight / total_weight, 3)

        if confidence >= 0.75:
            label = "VERY HIGH"
        elif confidence >= 0.50:
            label = "HIGH"
        elif confidence >= 0.30:
            label = "MEDIUM"
        else:
            label = "LOW"

        return {
            "confidence_score": confidence,
            "confidence_pct": round(confidence * 100, 1),
            "confidence_label": label,
            "signals_triggered": [
                {"name": s.name, "description": s.description, "weight": s.weight}
                for s in signals if s.triggered
            ],
            "signals_missed": [
                {"name": s.name, "description": s.description}
                for s in signals if not s.triggered
            ],
            "total_signals_fired": sum(1 for s in signals if s.triggered),
            "total_signals_available": len(signals)
        }