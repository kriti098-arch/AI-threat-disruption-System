from datetime import datetime, timedelta

class GlobalRiskManager:
    def __init__(self):
        self.recent_anomalies = []
        self.current_level = "NORMAL"

    def update(self, anomaly_detected: bool):
        now = datetime.utcnow()

        # Keep only last 60 seconds anomalies
        self.recent_anomalies = [
            t for t in self.recent_anomalies
            if now - t < timedelta(seconds=60)
        ]

        if anomaly_detected:
            self.recent_anomalies.append(now)

        count = len(self.recent_anomalies)

        if count >= 5:
            self.current_level = "CRITICAL"
        elif count >= 3:
            self.current_level = "HIGH"
        elif count >= 1:
            self.current_level = "ELEVATED"
        else:
            self.current_level = "NORMAL"

        return self.current_level

    def get_level(self):
        return self.current_level
