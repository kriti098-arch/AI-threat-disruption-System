# scripts/train_and_evaluate.py
# Run this ONCE after downloading CICIDS 2017 dataset
# Usage: python scripts/train_and_evaluate.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.cicids_loader import CICIDSLoader
from app.ml.model_evaluator import ModelEvaluator
import numpy as np

def main():
    print("=" * 60)
    print("AI Threat Disruption System — Model Evaluation")
    print("Dataset: CICIDS 2017")
    print("=" * 60)

    # Step 1: Load dataset
    loader = CICIDSLoader(max_samples_per_class=10000)
    success = loader.load()

    if not success:
        print("\nFailed to load dataset.")
        print("Download from: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("Place CSV files in: backend/data/cicids/")
        return

    X_train, X_test = loader.get_features()
    y_train, y_test = loader.get_binary_labels()

    print(f"\nDataset loaded successfully.")
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    # Step 2: Evaluate models
    evaluator = ModelEvaluator()

    # Isolation Forest (our model)
    if_metrics = evaluator.evaluate_isolation_forest(X_train, X_test, y_test)

    # Random Forest (supervised baseline for comparison)
    rf_metrics = evaluator.evaluate_random_forest(X_train, X_test, y_train, y_test)

    # 5-fold cross validation
    X_all = np.vstack([X_train, X_test])
    y_all = np.concatenate([y_train, y_test])
    cv_metrics = evaluator.cross_validate_isolation_forest(X_all, y_all, n_splits=5)

    # Step 3: Print comparison table (paper Table 1)
    print(evaluator.comparison_table())

    # Step 4: Save results
    evaluator.save_results()

    print("\nDone! You can now:")
    print("  - View results at GET /evaluation/summary")
    print("  - View confusion matrix at GET /evaluation/confusion-matrix/isolation_forest")
    print("  - Use Table 1 output above for your research paper Section 5")


if __name__ == "__main__":
    main()