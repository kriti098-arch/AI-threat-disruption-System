# app/ml/baseline.py
from collections import defaultdict
from statistics import mean, stdev

class BaselineManager:
    def __init__(self):
        # Store per-IP baseline
        self.baselines = defaultdict(lambda: {
            "avg_packet_size": 0,
            "std_packet_size": 0,
            "total_samples": 0
        })

        # Learning rate (small = slow adaptation)
        self.alpha = 0.05

    def update(self, src_ip: str, packet_size: int):
        baseline = self.baselines[src_ip]

        baseline["total_samples"] += 1

        if baseline["total_samples"] == 1:
            baseline["avg_packet_size"] = packet_size
            baseline["std_packet_size"] = 0
            return

        # Exponential Moving Average
        old_avg = baseline["avg_packet_size"]
        new_avg = (1 - self.alpha) * old_avg + self.alpha * packet_size

        # Update std deviation approximately
        deviation = abs(packet_size - new_avg)
        old_std = baseline["std_packet_size"]
        new_std = (1 - self.alpha) * old_std + self.alpha * deviation

        baseline["avg_packet_size"] = new_avg
        baseline["std_packet_size"] = new_std

    def get(self, src_ip: str):
        return self.baselines[src_ip]
