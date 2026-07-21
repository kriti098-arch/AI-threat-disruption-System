from collections import deque
from datetime import datetime, timedelta

class CorrelationEngine:
    def __init__(self, window_seconds=60, threshold=3):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.anomaly_log = deque()

    def add_anomaly(self, src_ip):
        now = datetime.utcnow()
        self.anomaly_log.append((src_ip, now))

        # remove old entries
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self.anomaly_log and self.anomaly_log[0][1] < cutoff:
            self.anomaly_log.popleft()

    def check_correlation(self):
        unique_ips = set(ip for ip, _ in self.anomaly_log)

        if len(unique_ips) >= self.threshold:
            return {
                "coordinated_attack": True,
                "ip_count": len(unique_ips)
            }

        return {
            "coordinated_attack": False,
            "ip_count": len(unique_ips)
        }
