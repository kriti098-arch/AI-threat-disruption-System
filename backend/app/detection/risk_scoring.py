def calculate_risk_score(severity: str, incident_count: int):
    severity_weights = {
        "LOW": 2,
        "MEDIUM": 5,
        "HIGH": 8
    }

    base_score = severity_weights.get(severity.upper(), 1)

    # Risk increases with repeated incidents
    risk_score = base_score + (incident_count * 0.5)

    return round(min(risk_score, 10.0), 2) 
def map_risk_level(risk_score: float) -> str:
    """
    Map numerical risk score to categorical risk level.
    """

    if risk_score >= 7.0:
        return "HIGH"
    elif risk_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"