# scripts/train_attack_classifier.py
# Run ONCE to train the multiclass attack classifier
# Usage: python scripts/train_attack_classifier.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

DATA_PATH   = "data/cleaned_cicids2017.csv"
MODELS_PATH = "models/"

FEATURE_COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# Map CICIDS labels to clean attack type names
LABEL_MAP = {
    "BENIGN":                        "Benign",
    "DDoS":                          "DDoS Attack",
    "PortScan":                      "Port Scan",
    "Bot":                           "Beaconing / C2 Communication",
    "Infiltration":                  "Data Exfiltration Pattern",
    "Web Attack - Brute Force":      "Brute Force / Escalating Attack",
    "Web Attack - XSS":              "Web Application Attack",
    "Web Attack - Sql Injection":    "SQL Injection Attack",
    "FTP-Patator":                   "Brute Force / Escalating Attack",
    "SSH-Patator":                   "Brute Force / Escalating Attack",
    "DoS slowloris":                 "DoS / Slow Attack",
    "DoS Slowhttptest":              "DoS / Slow Attack",
    "DoS Hulk":                      "DDoS Attack",
    "DoS GoldenEye":                 "DDoS Attack",
    "Heartbleed":                    "Exploit Attack",
}


def main():
    print("=" * 60)
    print("Training Multiclass Attack Classifier")
    print("Dataset: CICIDS 2017")
    print("=" * 60)

    # Load data
    print(f"\nLoading {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    print(f"Loaded {len(df)} rows")

    # Find label column
    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    if not label_col:
        print("ERROR: No label column found")
        return

    # Map labels
    df["attack_type"] = df[label_col].str.strip().map(LABEL_MAP)
    df["attack_type"] = df["attack_type"].fillna("Unknown Suspicious Activity")

    print(f"\nAttack type distribution:")
    print(df["attack_type"].value_counts())

    # Get available features
    available = [c for c in FEATURE_COLUMNS if c in df.columns]
    print(f"\nUsing {len(available)} features")

    # Sample to balance classes (max 10k per class)
    sampled = []
    for label in df["attack_type"].unique():
        subset = df[df["attack_type"] == label]
        n = min(len(subset), 10000)
        sampled.append(subset.sample(n=n, random_state=42))
    df_balanced = pd.concat(sampled, ignore_index=True).sample(frac=1, random_state=42)

    print(f"\nBalanced dataset: {len(df_balanced)} rows")

    # Prepare features
    X = df_balanced[available].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    for col in X.columns:
        cap = X[col].quantile(0.999)
        X[col] = X[col].clip(upper=cap)
    X = X.fillna(X.median())

    y = df_balanced["attack_type"]

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    print(f"\nClasses: {list(le.classes_)}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # Train
    print("\nTraining Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        max_depth=20,
        min_samples_split=5
    )
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    acc    = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Save
    os.makedirs(MODELS_PATH, exist_ok=True)
    joblib.dump(model,   f"{MODELS_PATH}/attack_classifier_rf.pkl")
    joblib.dump(scaler,  f"{MODELS_PATH}/attack_classifier_scaler.pkl")
    joblib.dump(le,      f"{MODELS_PATH}/attack_classifier_labels.pkl")
    joblib.dump(available, f"{MODELS_PATH}/attack_classifier_features.pkl")

    print(f"\nModels saved to {MODELS_PATH}")
    print("\nDone! The attack classifier is ready.")
    print("It will be automatically loaded by attack_classifier.py")


if __name__ == "__main__":
    main()