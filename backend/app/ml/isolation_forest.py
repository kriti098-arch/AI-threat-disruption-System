# app/ml/isolation_forest.py

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import joblib
import os

class IsolationForestDetector:
    def __init__(self, min_samples=50, contamination=0.1):
        self.min_samples = min_samples
        self.contamination = contamination
        self.models = {}
        self.scalers = {}
        self.buffers = defaultdict(list)
        self.feature_names = [
            "packet_size",
            "avg_packet_size",
            "std_packet_size",
            "packet_rate_proxy"
        ]

    def _extract_feature_vector(self, packet_size: int, baseline: dict) -> list:
        return [
            packet_size,
            baseline.get("avg_packet_size", 0),
            baseline.get("std_packet_size", 0),
            baseline.get("total_samples", 0)
        ]

    def add_sample(self, src_ip: str, packet_size: int, baseline: dict):
        vector = self._extract_feature_vector(packet_size, baseline)
        self.buffers[src_ip].append(vector)
        if len(self.buffers[src_ip]) >= self.min_samples and src_ip not in self.models:
            self._train(src_ip)

    def _train(self, src_ip: str):
        data = np.array(self.buffers[src_ip])
        scaler = StandardScaler()
        scaled = scaler.fit_transform(data)
        model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        model.fit(scaled)
        self.models[src_ip] = model
        self.scalers[src_ip] = scaler
        self.buffers[src_ip] = self.buffers[src_ip][-200:]

    def detect(self, src_ip: str, packet_size: int, baseline: dict) -> dict:
        vector = self._extract_feature_vector(packet_size, baseline)

        if src_ip not in self.models:
            samples_needed = max(0, self.min_samples - len(self.buffers[src_ip]))
            return {
                "anomaly": False,
                "score": 0.0,
                "confidence": 0.0,
                "feature_contributions": {},
                "status": f"collecting_samples ({samples_needed} more needed)"
            }

        model = self.models[src_ip]
        scaler = self.scalers[src_ip]
        scaled_vector = scaler.transform([vector])

        prediction = model.predict(scaled_vector)[0]
        raw_score = model.decision_function(scaled_vector)[0]

        anomaly_score = round(1 - (raw_score + 0.5), 3)
        anomaly_score = max(0.0, min(1.0, anomaly_score))

        mean = scaler.mean_
        contributions = {}
        for i, fname in enumerate(self.feature_names):
            diff = abs(vector[i] - mean[i])
            contributions[fname] = round(float(diff), 3)

        return {
            "anomaly": prediction == -1,
            "score": anomaly_score,
            "confidence": round(anomaly_score * 100, 1),
            "feature_contributions": contributions,
            "status": "active"
        }

    def save_models(self, path: str = "models/"):
        os.makedirs(path, exist_ok=True)
        for ip, model in self.models.items():
            safe_ip = ip.replace(".", "_")
            joblib.dump(model, f"{path}/if_model_{safe_ip}.pkl")
            joblib.dump(self.scalers[ip], f"{path}/scaler_{safe_ip}.pkl")

    def load_models(self, path: str = "models/"):
        if not os.path.exists(path):
            return
        for fname in os.listdir(path):
            if fname.startswith("if_model_"):
                safe_ip = fname.replace("if_model_", "").replace(".pkl", "")
                src_ip = safe_ip.replace("_", ".")
                self.models[src_ip] = joblib.load(f"{path}/{fname}")
            elif fname.startswith("scaler_"):
                safe_ip = fname.replace("scaler_", "").replace(".pkl", "")
                src_ip = safe_ip.replace("_", ".")
                self.scalers[src_ip] = joblib.load(f"{path}/{fname}")