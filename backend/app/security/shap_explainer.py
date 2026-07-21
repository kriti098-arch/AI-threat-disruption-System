# ============================================================
# FEATURE 2: SHAP EXPLAINABILITY
# File: backend/app/security/shap_explainer.py
#
# NEW FILE — add to your security/ folder
#
# WHAT IT DOES:
# After your Random Forest classifies an attack, SHAP tells you
# EXACTLY which features caused that classification and by how much.
# Every incident now shows: "flagged because port 4444 (+0.34),
# packet_length anomaly (+0.28), protocol UDP (+0.19)"
#
# WHY THIS IS A RESEARCH CONTRIBUTION:
# The 2025 NIDS survey (your ref [13]) explicitly lists XAI as
# an open gap. You cite the gap, then fill it. That's publishable.
#
# INSTALL REQUIREMENT:
# pip install shap --break-system-packages
# ============================================================

import shap
import numpy as np
import joblib
import json
from pathlib import Path
from typing import Optional

# Path to your trained Random Forest model
MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "attack_classifier.pkl"
EXPLAINER_CACHE_PATH = Path(__file__).parent.parent.parent / "models" / "shap_explainer.pkl"


class SHAPExplainer:
    """
    Wraps your existing Random Forest with SHAP TreeExplainer.
    TreeExplainer is fast (milliseconds per prediction) and exact
    for tree-based models — no approximations needed.
    """

    def __init__(self):
        self.model = None
        self.explainer = None
        self.feature_names = ["packet_length", "destination_port", "protocol_id"]
        self._load()

    def _load(self):
        """Load model and initialize explainer. Cache explainer for speed."""
        try:
            self.model = joblib.load(MODEL_PATH)

            # Try loading cached explainer first (much faster on startup)
            if EXPLAINER_CACHE_PATH.exists():
                self.explainer = joblib.load(EXPLAINER_CACHE_PATH)
            else:
                # Build TreeExplainer — only needs the model, not training data
                self.explainer = shap.TreeExplainer(self.model)
                # Cache it
                EXPLAINER_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                joblib.dump(self.explainer, EXPLAINER_CACHE_PATH)

        except FileNotFoundError:
            self.model = None
            self.explainer = None

    def explain(self, packet_length: float, port: int, protocol_id: int) -> Optional[dict]:
        """
        Compute SHAP values for a single network event.

        Returns a dict like:
        {
            "top_features": [
                {"feature": "destination_port", "shap_value": 0.34, "actual_value": 4444, "direction": "increased_risk"},
                {"feature": "packet_length",    "shap_value": 0.28, "actual_value": 1480, "direction": "increased_risk"},
                {"feature": "protocol_id",      "shap_value": -0.05, "actual_value": 6,   "direction": "decreased_risk"},
            ],
            "base_value": 0.15,
            "predicted_probability": 0.77,
            "explanation_text": "Flagged primarily because destination_port=4444 (+0.34) and packet_length=1480 (+0.28)",
            "feature_values": {"packet_length": 1480, "destination_port": 4444, "protocol_id": 6}
        }
        """
        if self.explainer is None or self.model is None:
            return None

        try:
            features = np.array([[packet_length, port, protocol_id]])

            # Compute SHAP values
            # For multi-class RF, shap_values is a list (one array per class)
            # We take the "attack" class (index 1 if binary, or the predicted class)
            shap_values = self.explainer.shap_values(features)

            # Get predicted class and probability
            predicted_proba = self.model.predict_proba(features)[0]
            predicted_class_idx = int(np.argmax(predicted_proba))
            predicted_probability = float(predicted_proba[predicted_class_idx])

            # Get SHAP values for predicted class
            if isinstance(shap_values, list):
                # Multi-class: pick the predicted class's SHAP values
                sv = shap_values[predicted_class_idx][0]
            else:
                sv = shap_values[0]

            base_value = float(self.explainer.expected_value[predicted_class_idx]
                               if isinstance(self.explainer.expected_value, (list, np.ndarray))
                               else self.explainer.expected_value)

            # Build feature contribution list
            contributions = []
            for i, fname in enumerate(self.feature_names):
                contributions.append({
                    "feature": fname,
                    "shap_value": round(float(sv[i]), 4),
                    "actual_value": [packet_length, port, protocol_id][i],
                    "direction": "increased_risk" if sv[i] > 0 else "decreased_risk",
                })

            # Sort by absolute SHAP value (most impactful first)
            top_features = sorted(contributions, key=lambda x: abs(x["shap_value"]), reverse=True)

            # Build human-readable explanation text
            top2 = top_features[:2]
            parts = []
            for f in top2:
                sign = "+" if f["shap_value"] > 0 else ""
                parts.append(f"{f['feature']}={f['actual_value']} ({sign}{f['shap_value']:.3f})")
            explanation_text = "Flagged primarily because " + " and ".join(parts)

            return {
                "top_features": top_features,
                "base_value": round(base_value, 4),
                "predicted_probability": round(predicted_probability, 4),
                "explanation_text": explanation_text,
                "feature_values": {
                    "packet_length": packet_length,
                    "destination_port": port,
                    "protocol_id": protocol_id,
                },
            }

        except Exception as e:
            return {"error": str(e), "explanation_text": "SHAP explanation unavailable"}

    def explain_batch(self, events: list[dict]) -> list[dict]:
        """
        Explain a batch of events at once (more efficient for evaluation).
        Used for the Model Evaluation page to show aggregate feature importance.
        """
        if self.explainer is None:
            return []

        try:
            X = np.array([
                [e["packet_length"], e["destination_port"], e["protocol_id"]]
                for e in events
            ])

            shap_values = self.explainer.shap_values(X)

            # For multi-class, use class 1 (attack)
            if isinstance(shap_values, list):
                sv = shap_values[1]  # attack class
            else:
                sv = shap_values

            # Global mean absolute SHAP per feature
            mean_abs = np.mean(np.abs(sv), axis=0)

            return [
                {
                    "feature": self.feature_names[i],
                    "mean_abs_shap": round(float(mean_abs[i]), 4),
                    "rank": i + 1,
                }
                for i in np.argsort(mean_abs)[::-1]
            ]

        except Exception as e:
            return [{"error": str(e)}]


# ── Singleton instance ────────────────────────────────────────────────────────
# Import this in network_events.py:  from .shap_explainer import shap_explainer
shap_explainer = SHAPExplainer()


# ============================================================
# HOW TO PLUG THIS INTO YOUR PIPELINE (network_events.py)
# ============================================================
# In your Step 4 (attack classification), AFTER you get the
# attack_type from your classifier, add:
#
#   from .shap_explainer import shap_explainer
#
#   shap_result = shap_explainer.explain(
#       packet_length=event.length,
#       port=event.destination_port,
#       protocol_id=protocol_id_map.get(event.protocol, 0)
#   )
#
#   # Store in incident proof
#   incident.proof["shap_explanation"] = shap_result
#
# That's it. The frontend reads incident.proof["shap_explanation"]
# and renders the bar chart (see shap_widget.js below)
# ============================================================
