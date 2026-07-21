# backend/app/ml/stream_detector.py

from collections import deque
from statistics import mean, stdev
from app.ml.baseline import BaselineManager  


class StreamDetector:
    def __init__(self, window_size=20, anomaly_threshold=2.5):
        self.window_size = window_size
        self.anomaly_threshold = anomaly_threshold
        self.packet_window = deque(maxlen=window_size)
        self.score_window = deque(maxlen=5)
        # baseline manager
        self.baseline_manager = BaselineManager()

    def add_event(self, packet_size: int, src_ip: str | None = None):
        """
        Add packet size to sliding window
        """
        self.packet_window.append(packet_size)

        # Update baseline only if src_ip is available
        if src_ip:
            self.baseline_manager.update(src_ip, packet_size)

    def extract_features(self):
        if len(self.packet_window) < 5:
            return None

        avg_size = mean(self.packet_window)
        std_dev = stdev(self.packet_window) if len(self.packet_window) > 1 else 0

        return {
            "avg_packet_size": avg_size,
            "std_packet_size": std_dev,
            "packet_count": len(self.packet_window),
        }

    def detect(self, src_ip: str):
        if not self.packet_window:
            return None

        current_packet = self.packet_window[-1]

        baseline = self.baseline_manager.get(src_ip)

        avg = baseline["avg_packet_size"]
        std = baseline["std_packet_size"]

    # Not enough baseline learning yet
        if baseline["total_samples"] < 10 or std == 0:
            return {
            "anomaly": False,
            "score": 0,
            "escalation": False,
            "features": baseline
        }

        z_score = abs(current_packet - avg) / std

        anomaly = z_score > self.anomaly_threshold

        self.score_window.append(z_score)

    # Check escalation pattern
        escalation = False
        if len(self.score_window) >= 3:
            if (
            self.score_window[-1] > self.score_window[-2] and
            self.score_window[-2] > self.score_window[-3]
        ):
                escalation = True

        return {
        "anomaly": anomaly,
        "score": round(z_score, 2),
        "escalation": escalation,
        "features": baseline
    }

    # FIXED: delegate baseline logic
    def get_baseline(self, src_ip: str):
        return self.baseline_manager.get(src_ip)

