# app/ml/deviation.py

import math

def deviation_score(current_features: dict, baseline: dict):
    """
    Calculates how abnormal current behavior is compared to baseline.
    Returns score between 0.0 and 1.0
    """

    if baseline is None:
        return 0.0  # not enough data yet

    score = 0.0
    weights = {
        "avg_packet_size": 0.5,
        "packet_rate": 0.5
    }

    # 1️⃣ Packet size deviation
    if baseline["std_packet_size"] > 0:
        z_size = abs(
            current_features["avg_packet_size"] -
            baseline["avg_packet_size"]
        ) / baseline["std_packet_size"]

        score += min(z_size / 5, 1.0) * weights["avg_packet_size"]

    # 2️⃣ Packet rate deviation
    rate_diff = abs(
        current_features["packet_rate"] -
        baseline["packet_rate"]
    ) / max(baseline["packet_rate"], 1)

    score += min(rate_diff / 5, 1.0) * weights["packet_rate"]

    return round(score, 3)
