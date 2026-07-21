# app/ml/model_evaluator.py
# Evaluates Isolation Forest vs Random Forest on CICIDS 2017
# Generates Table 1 for research paper

import numpy as np
import json
import os
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.model_selection import StratifiedKFold

MODELS_PATH = "models/"


class ModelEvaluator:
    def __init__(self):
        self.results = {}

    def evaluate_isolation_forest(self, X_train, X_test, y_test,
                                   contamination=0.1) -> dict:
        print("\n=== Evaluating Isolation Forest (Unsupervised) ===")

        model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train)

        raw_preds = model.predict(X_test)
        y_pred = (raw_preds == -1).astype(int)

        metrics = self._compute_metrics(y_test, y_pred, model_name="Isolation Forest")
        self.results["isolation_forest"] = metrics

        os.makedirs(MODELS_PATH, exist_ok=True)
        joblib.dump(model, f"{MODELS_PATH}/isolation_forest_cicids.pkl")
        print(f"Model saved to {MODELS_PATH}/isolation_forest_cicids.pkl")

        return metrics

    def evaluate_random_forest(self, X_train, X_test, y_train, y_test) -> dict:
        print("\n=== Evaluating Random Forest (Supervised Baseline) ===")

        model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        metrics = self._compute_metrics(y_test, y_pred, model_name="Random Forest")

        try:
            y_prob = model.predict_proba(X_test)[:, 1]
            metrics["roc_auc"] = round(float(roc_auc_score(y_test, y_prob)), 4)
        except Exception:
            pass

        self.results["random_forest"] = metrics

        joblib.dump(model, f"{MODELS_PATH}/random_forest_cicids.pkl")
        print(f"Model saved to {MODELS_PATH}/random_forest_cicids.pkl")

        return metrics

    def cross_validate_isolation_forest(self, X, y, n_splits=5,
                                         contamination=0.1) -> dict:
        print(f"\n=== {n_splits}-Fold Cross Validation: Isolation Forest ===")

        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        fold_metrics = []

        for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
            X_tr, X_te = X[train_idx], X[test_idx]
            y_te = y[test_idx]

            model = IsolationForest(
                contamination=contamination,
                n_estimators=100,
                random_state=42
            )
            model.fit(X_tr)

            raw = model.predict(X_te)
            y_pred = (raw == -1).astype(int)

            m = self._compute_metrics(y_te, y_pred, model_name=f"Fold {fold+1}")
            fold_metrics.append(m)
            print(f"  Fold {fold+1}: F1={m['f1']:.4f}  Precision={m['precision']:.4f}  Recall={m['recall']:.4f}")

        # Average across folds
        avg = {}
        for key in ["precision", "recall", "f1", "accuracy", "fpr", "fnr"]:
            vals = [m[key] for m in fold_metrics if key in m]
            if vals:
                avg[key] = round(float(np.mean(vals)), 4)
                avg[f"{key}_std"] = round(float(np.std(vals)), 4)

        avg["n_folds"] = n_splits
        self.results["isolation_forest_cv"] = avg

        print(f"\nCV Results: F1={avg['f1']:.4f} ± {avg['f1_std']:.4f}")
        return avg

    def _compute_metrics(self, y_true, y_pred, model_name="Model") -> dict:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

        precision = round(float(precision_score(y_true, y_pred, zero_division=0)), 4)
        recall    = round(float(recall_score(y_true, y_pred, zero_division=0)), 4)
        f1        = round(float(f1_score(y_true, y_pred, zero_division=0)), 4)
        accuracy  = round(float(accuracy_score(y_true, y_pred)), 4)
        fpr       = round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4)
        fnr       = round(float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0, 4)

        try:
            roc_auc = round(float(roc_auc_score(y_true, y_pred)), 4)
        except Exception:
            roc_auc = None

        metrics = {
            "model":     model_name,
            "precision": precision,
            "recall":    recall,
            "f1":        f1,
            "accuracy":  accuracy,
            "roc_auc":   roc_auc,
            "fpr":       fpr,
            "fnr":       fnr,
            "tp": int(tp), "tn": int(tn),
            "fp": int(fp), "fn": int(fn),
            "total_samples": int(len(y_true)),
            "classification_report": classification_report(
                y_true, y_pred,
                target_names=["Benign", "Attack"],
                output_dict=True,
                zero_division=0
            )
        }

        print(f"\n{model_name} Results:")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1 Score:  {f1:.4f}")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  ROC-AUC:   {roc_auc}")
        print(f"  FPR:       {fpr:.4f}")
        print(f"  FNR:       {fnr:.4f}")
        print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}")

        return metrics

    def comparison_table(self) -> str:
        """Generate paper-ready Table 1"""
        if not self.results:
            return "No results yet. Run evaluations first."

        header = f"\n{'='*70}"
        header += f"\nTable 1: Model Comparison on CICIDS-2017 Dataset"
        header += f"\n{'='*70}"
        header += f"\n{'Metric':<25} {'Isolation Forest':>20} {'Random Forest':>20}"
        header += f"\n{'-'*70}"

        metrics = ["precision", "recall", "f1", "accuracy", "roc_auc", "fpr", "fnr"]
        labels  = ["Precision", "Recall", "F1 Score", "Accuracy", "ROC-AUC", "FPR", "FNR"]

        rows = ""
        for metric, label in zip(metrics, labels):
            if_val = self.results.get("isolation_forest", {}).get(metric, "N/A")
            rf_val = self.results.get("random_forest", {}).get(metric, "N/A")
            if_str = f"{if_val:.4f}" if isinstance(if_val, float) else str(if_val)
            rf_str = f"{rf_val:.4f}" if isinstance(rf_val, float) else str(rf_val)
            rows += f"\n{label:<25} {if_str:>20} {rf_str:>20}"

        cv = self.results.get("isolation_forest_cv", {})
        if cv:
            rows += f"\n{'-'*70}"
            rows += f"\n{'IF CV F1 (5-fold)':<25} {cv.get('f1', 'N/A'):>20} {'N/A':>20}"
            rows += f"\n{'IF CV F1 Std':<25} {cv.get('f1_std', 'N/A'):>20} {'N/A':>20}"

        footer = f"\n{'='*70}\n"
        return header + rows + footer

    def save_results(self, path: str = None):
        save_path = path or f"{MODELS_PATH}/evaluation_results.json"
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # Convert classification_report dicts to serializable
        results_clean = json.loads(json.dumps(self.results, default=str))

        with open(save_path, "w") as f:
            json.dump(results_clean, f, indent=2)

        print(f"\nResults saved to {save_path}")
        return save_path

    def load_results(self, path: str = None) -> dict:
        load_path = path or f"{MODELS_PATH}/evaluation_results.json"
        if not os.path.exists(load_path):
            return {}
        with open(load_path, "r") as f:
            self.results = json.load(f)
        return self.results