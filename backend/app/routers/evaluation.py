# app/routers/evaluation.py
# Exposes model evaluation results via API
# Add to main.py: from app.routers import evaluation
#                 app.include_router(evaluation.router)

from fastapi import APIRouter
from app.ml.model_evaluator import ModelEvaluator
import os

router = APIRouter(prefix="/evaluation", tags=["Model Evaluation"])

evaluator = ModelEvaluator()
_results_loaded = False


def _try_load():
    global _results_loaded
    if not _results_loaded:
        evaluator.load_results()
        _results_loaded = True


@router.get("/results")
def get_full_results():
    _try_load()
    if not evaluator.results:
        return {
            "status": "no_results",
            "message": "Run 'python scripts/train_and_evaluate.py' first to generate evaluation results."
        }
    return evaluator.results


@router.get("/summary")
def get_summary():
    _try_load()
    if not evaluator.results:
        return {"status": "no_results"}

    summary = {}
    for model_key in ["isolation_forest", "random_forest"]:
        r = evaluator.results.get(model_key, {})
        if r:
            summary[model_key] = {
                "precision": r.get("precision"),
                "recall":    r.get("recall"),
                "f1":        r.get("f1"),
                "accuracy":  r.get("accuracy"),
                "roc_auc":   r.get("roc_auc"),
                "fpr":       r.get("fpr"),
                "fnr":       r.get("fnr")
            }

    cv = evaluator.results.get("isolation_forest_cv", {})
    if cv:
        summary["isolation_forest_cv"] = {
            "f1_mean": cv.get("f1"),
            "f1_std":  cv.get("f1_std"),
            "n_folds": cv.get("n_folds")
        }

    return summary


@router.get("/confusion-matrix/{model}")
def get_confusion_matrix(model: str):
    _try_load()
    valid = ["isolation_forest", "random_forest"]
    if model not in valid:
        return {"error": f"model must be one of {valid}"}

    r = evaluator.results.get(model, {})
    if not r:
        return {"status": "no_results_for_model"}

    return {
        "model": model,
        "tp": r.get("tp"), "tn": r.get("tn"),
        "fp": r.get("fp"), "fn": r.get("fn"),
        "matrix": [[r.get("tn"), r.get("fp")],
                   [r.get("fn"), r.get("tp")]],
        "labels": ["Benign", "Attack"]
    }


@router.get("/classification-report/{model}")
def get_classification_report(model: str):
    _try_load()
    valid = ["isolation_forest", "random_forest"]
    if model not in valid:
        return {"error": f"model must be one of {valid}"}

    r = evaluator.results.get(model, {})
    return r.get("classification_report", {"status": "not_available"})


@router.get("/models-available")
def models_available():
    models_path = "models/"
    if not os.path.exists(models_path):
        return {"models": [], "status": "models_directory_not_found"}

    files = os.listdir(models_path)
    return {
        "models": files,
        "isolation_forest_ready": "isolation_forest_cicids.pkl" in files,
        "random_forest_ready":    "random_forest_cicids.pkl" in files,
        "results_ready":          "evaluation_results.json" in files
    }


@router.post("/predict")
def predict_sample(features: dict):
    """Test prediction on a single feature vector"""
    import numpy as np
    import joblib

    models_path = "models/"
    if_path = f"{models_path}/isolation_forest_cicids.pkl"
    scaler_path = f"{models_path}/cicids_scaler.pkl"
    features_path = f"{models_path}/cicids_features.pkl"

    if not all(os.path.exists(p) for p in [if_path, scaler_path, features_path]):
        return {"error": "Models not trained yet. Run train_and_evaluate.py first."}

    model = joblib.load(if_path)
    scaler = joblib.load(scaler_path)
    feature_cols = joblib.load(features_path)

    vector = [features.get(col, 0) for col in feature_cols]
    scaled = scaler.transform([vector])
    pred = model.predict(scaled)[0]
    score = model.decision_function(scaled)[0]

    return {
        "prediction": "attack" if pred == -1 else "benign",
        "anomaly_score": round(float(1 - (score + 0.5)), 3),
        "raw_score": round(float(score), 3)
    }