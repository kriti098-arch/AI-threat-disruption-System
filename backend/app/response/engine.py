# app/response/engine.py
from app import schemas

# -----------------------------
# PHASE 8: ESCALATION LOGIC
# -----------------------------

def decide_escalation(
    *,
    ml_anomaly: bool = False,
    ml_score: float = 0.0,
    deviation_score: float = 0.0,
    recent_incident_count: int = 0
):
    """
    Decide escalation level BEFORE response.

    Inputs:
    - ml_anomaly: True if ML flagged anomaly
    - ml_score: anomaly confidence (0–1)
    - deviation_score: behavioral deviation (0–1 or scaled)
    - recent_incident_count: how often this IP triggered incidents

    Output:
    - (risk_level, risk_score, reason)
    """

    # CRITICAL: confirmed ML anomaly + history
    if ml_anomaly and ml_score >= 0.9 and recent_incident_count >= 3:
        return (
            "CRITICAL",
            10.0,
            "Repeated ML-detected anomaly with high confidence"
        )

    # HIGH: ML anomaly OR strong deviation
    if ml_anomaly or ml_score >= 0.8 or deviation_score >= 0.7:
        return (
            "HIGH",
            8.0,
            "Anomalous behavior detected via ML or deviation analysis"
        )

    # MEDIUM: noticeable deviation, no ML confirmation
    if deviation_score >= 0.4 or recent_incident_count >= 1:
        return (
            "MEDIUM",
            5.0,
            "Suspicious deviation from baseline traffic"
        )

    # LOW: baseline or expected traffic
    return (
        "LOW",
        2.0,
        "Traffic within normal behavioral baseline"
    )


# -----------------------------
# RESPONSE DECISION LOGIC
# -----------------------------

def decide_response(incident):
    """
    Decide response action based on incident risk_level.
    This is executed AFTER escalation.
    """

    if incident.risk_level == "CRITICAL":
        action_type = "BLOCK_IP"
        status = "EXECUTED"

    elif incident.risk_level == "HIGH":
        action_type = "BLOCK_IP"
        status = "EXECUTED"

    elif incident.risk_level == "MEDIUM":
        action_type = "RATE_LIMIT"
        status = "EXECUTED"

    else:  # LOW
        action_type = "MONITOR"
        status = "LOGGED"

    return schemas.ResponseActionCreate(
        incident_id=incident.incident_id,
        action_type=action_type,
        status=status
    )
