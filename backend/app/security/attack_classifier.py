# app/security/attack_classifier.py
# Hybrid classifier: ML (Random Forest) + rule-based fallback

import os
import numpy as np

# Try to load ML model at startup
_rf_model   = None
_rf_scaler  = None
_rf_labels  = None
_rf_features = None
_ml_ready   = False

def _load_ml_model():
    global _rf_model, _rf_scaler, _rf_labels, _rf_features, _ml_ready
    try:
        import joblib
        models_path = "models/"
        model_path    = f"{models_path}/attack_classifier_rf.pkl"
        scaler_path   = f"{models_path}/attack_classifier_scaler.pkl"
        labels_path   = f"{models_path}/attack_classifier_labels.pkl"
        features_path = f"{models_path}/attack_classifier_features.pkl"

        if all(os.path.exists(p) for p in [model_path, scaler_path, labels_path, features_path]):
            _rf_model    = joblib.load(model_path)
            _rf_scaler   = joblib.load(scaler_path)
            _rf_labels   = joblib.load(labels_path)
            _rf_features = joblib.load(features_path)
            _ml_ready    = True
            print("✓ ML Attack Classifier loaded successfully")
        else:
            print("⚠ ML Attack Classifier not found — using rule-based fallback")
            print("  Run: python scripts/train_attack_classifier.py")
    except Exception as e:
        print(f"⚠ ML Attack Classifier load failed: {e} — using rule-based fallback")

# Load at import time
_load_ml_model()


class AttackClassifier:

    def classify(self, features: dict, z_score: float, escalation: bool, current_size: float = None) -> str:
        """
        Classify attack type using ML model if available,
        falling back to rule-based classification.
        """
        # Try ML classification first
        if _ml_ready:
            ml_result = self._classify_ml(features, z_score)
            if ml_result:
                return ml_result

        # Fall back to rule-based
        return self._classify_rules(features, z_score, escalation, current_size)

    def classify_with_confidence(self, features: dict, z_score: float, escalation: bool) -> dict:
        """Returns attack type + confidence + method used."""
        if _ml_ready:
            result = self._classify_ml_detailed(features, z_score)
            if result:
                return result

        attack_type = self._classify_rules(features, z_score, escalation)
        return {
            "attack_type":  attack_type,
            "confidence":   0.6,
            "method":       "rule_based",
            "top_classes":  []
        }

    def _classify_ml(self, features: dict, z_score: float) -> str:
        """Use Random Forest to classify. Returns None if confidence too low."""
        result = self._classify_ml_detailed(features, z_score)
        if result and result["confidence"] >= 0.65:
            return result["attack_type"]
        return None

    def _classify_ml_detailed(self, features: dict, z_score: float) -> dict:
        """Full ML classification with confidence scores."""
        try:
            # Build feature vector matching training features
            vector = []
            for fname in _rf_features:
                # Map our features to CICIDS feature names
                val = self._map_feature(fname, features, z_score)
                vector.append(val)

            import pandas as pd
            vector_df = pd.DataFrame([vector], columns=_rf_features)
            vector_scaled = _rf_scaler.transform(vector_df)

            # Get probabilities
            proba = _rf_model.predict_proba(vector_scaled)[0]
            pred_idx = np.argmax(proba)
            confidence = float(proba[pred_idx])
            attack_type = _rf_labels.classes_[pred_idx]

            # Top 3 predictions
            top3_idx = np.argsort(proba)[-3:][::-1]
            top3 = [
                {"attack": _rf_labels.classes_[i], "confidence": round(float(proba[i]), 3)}
                for i in top3_idx
            ]

            return {
                "attack_type": attack_type,
                "confidence":  round(confidence, 3),
                "method":      "ml_random_forest",
                "top_classes": top3
            }
        except Exception as e:
            return None

    def _map_feature(self, cicids_name: str, features: dict, z_score: float) -> float:
        """Map our live features to CICIDS feature names."""
        mapping = {
            "Average Packet Size":          features.get("avg_packet_size", 0),
            "Packet Length Mean":           features.get("avg_packet_size", 0),
            "Packet Length Std":            features.get("std_packet_size", 0),
            "Packet Length Variance":       features.get("std_packet_size", 0) ** 2,
            "Total Fwd Packets":            features.get("total_samples", 0),
            "Total Backward Packets":       features.get("total_samples", 0) * 0.5,
            "Flow Duration":                features.get("total_samples", 0) * 1000,
            "Fwd Packet Length Mean":       features.get("avg_packet_size", 0),
            "Bwd Packet Length Mean":       features.get("avg_packet_size", 0) * 0.8,
            "Fwd Packet Length Max":        features.get("avg_packet_size", 0) * 1.5,
            "Bwd Packet Length Max":        features.get("avg_packet_size", 0) * 1.2,
            "Fwd Packet Length Min":        max(0, features.get("avg_packet_size", 0) * 0.5),
            "Bwd Packet Length Min":        max(0, features.get("avg_packet_size", 0) * 0.4),
            "Fwd Packet Length Std":        features.get("std_packet_size", 0),
            "Bwd Packet Length Std":        features.get("std_packet_size", 0) * 0.8,
            "Total Length of Fwd Packets":  features.get("avg_packet_size", 0) * features.get("total_samples", 1),
            "Total Length of Bwd Packets":  features.get("avg_packet_size", 0) * features.get("total_samples", 1) * 0.5,
            "Flow Bytes/s":                 features.get("avg_packet_size", 0) * 10,
            "Flow Packets/s":               features.get("total_samples", 0) * 0.1,
            "Fwd Packets/s":                features.get("total_samples", 0) * 0.06,
            "Bwd Packets/s":                features.get("total_samples", 0) * 0.04,
            "Min Packet Length":            max(0, features.get("avg_packet_size", 0) - features.get("std_packet_size", 0)),
            "Max Packet Length":            features.get("avg_packet_size", 0) + features.get("std_packet_size", 0),
            "SYN Flag Count":               1 if z_score > 3 else 0,
            "RST Flag Count":               0,
            "ACK Flag Count":               1,
            "PSH Flag Count":               1 if features.get("avg_packet_size", 0) > 500 else 0,
            "FIN Flag Count":               0,
            "URG Flag Count":               0,
            "CWE Flag Count":               0,
            "ECE Flag Count":               0,
            "Avg Fwd Segment Size":         features.get("avg_packet_size", 0),
            "Avg Bwd Segment Size":         features.get("avg_packet_size", 0) * 0.8,
            "Subflow Fwd Packets":          features.get("total_samples", 0),
            "Subflow Fwd Bytes":            features.get("avg_packet_size", 0) * features.get("total_samples", 1),
            "Subflow Bwd Packets":          features.get("total_samples", 0) * 0.5,
            "Subflow Bwd Bytes":            features.get("avg_packet_size", 0) * features.get("total_samples", 1) * 0.5,
            "Init_Win_bytes_forward":       features.get("avg_packet_size", 0) * 2,
            "Init_Win_bytes_backward":      features.get("avg_packet_size", 0),
            "act_data_pkt_fwd":             features.get("total_samples", 0),
            "min_seg_size_forward":         20,
            "Down/Up Ratio":                0.5,
        }
        return float(mapping.get(cicids_name, 0))

    def _classify_rules(self, features: dict, z_score: float, escalation: bool, current_size: float = None) -> str:
        avg_size = features.get("avg_packet_size", 0)
        std_size = features.get("std_packet_size", 0)
        samples  = features.get("total_samples", 0)
        size = current_size if current_size is not None else avg_size

        if z_score > 4 and size < 100:
            return "Port Scan"
        elif z_score > 3 and size > 3000 and samples > 30:
            return "DDoS Attack"
        elif size > 800 and size <= 3000 and z_score > 3:
            return "Data Exfiltration Pattern"
        elif std_size < 15 and samples > 20 and z_score > 2 and size < 800:
            return "Beaconing / C2 Communication"
        elif escalation and z_score > 3:
            return "Brute Force / Escalating Attack"
        elif z_score > 3:
            return "Brute Force / Escalating Attack"
        elif z_score > 2:
            return "Beaconing / C2 Communication"
        else:
            return "Unknown Suspicious Activity"

    @property
    def ml_available(self) -> bool:
        return _ml_ready