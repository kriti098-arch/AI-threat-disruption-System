# app/ml/cicids_loader.py
# Loads and preprocesses the CICIDS 2017 dataset for model evaluation

import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

CICIDS_DATA_PATH = "data/"
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

LABEL_COLUMN = "Label"


class CICIDSLoader:
    def __init__(self, data_path=CICIDS_DATA_PATH, max_samples_per_class=10000):
        self.data_path = data_path
        self.max_samples_per_class = max_samples_per_class
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.label_counts = {}

    def load(self) -> bool:
        if not os.path.exists(self.data_path):
            print(f"ERROR: Data path not found: {self.data_path}")
            print("Please download CICIDS 2017 from: https://www.unb.ca/cic/datasets/ids-2017.html")
            print("Place CSV files in: backend/data/cicids/")
            return False

        csv_files = [f for f in os.listdir(self.data_path) if f.endswith(".csv")]
        if not csv_files:
            print(f"ERROR: No CSV files found in {self.data_path}")
            return False

        print(f"Found {len(csv_files)} CSV files: {csv_files}")
        dfs = []

        for fname in csv_files:
            fpath = os.path.join(self.data_path, fname)
            try:
                df = pd.read_csv(fpath, low_memory=False)
                df.columns = df.columns.str.strip()
                dfs.append(df)
                print(f"  Loaded {fname}: {len(df)} rows")
            except Exception as e:
                print(f"  Warning: Could not load {fname}: {e}")

        if not dfs:
            return False

        combined = pd.concat(dfs, ignore_index=True)
        print(f"\nTotal rows loaded: {len(combined)}")

        # Find label column
        label_col = None
        for col in combined.columns:
            if "label" in col.lower():
                label_col = col
                break

        if label_col is None:
            print("ERROR: No label column found")
            return False

        # Find available feature columns
        available_features = [c for c in FEATURE_COLUMNS if c in combined.columns]
        if len(available_features) < 10:
            available_features = [c for c in combined.columns if c != label_col]

        self.feature_columns = available_features
        print(f"Using {len(self.feature_columns)} features")

        # Label distribution
        label_counts = combined[label_col].value_counts()
        print(f"\nLabel distribution:\n{label_counts}")
        self.label_counts = label_counts.to_dict()

        # Sample per class to avoid imbalance
        sampled = []
        for label, count in label_counts.items():
            subset = combined[combined[label_col] == label]
            n = min(count, self.max_samples_per_class)
            sampled.append(subset.sample(n=n, random_state=42))

        data = pd.concat(sampled, ignore_index=True).sample(frac=1, random_state=42)

        X = data[self.feature_columns].copy()
        y_raw = data[label_col].copy()

        # Clean
        X = X.replace([np.inf, -np.inf], np.nan)
        for col in X.columns:
            cap = X[col].quantile(0.999)
            X[col] = X[col].clip(upper=cap)
        X = X.fillna(X.median())

        y_binary = (y_raw.str.upper() != "BENIGN").astype(int)

        # Split 80/20
        split = int(len(X) * 0.8)
        X_scaled = self.scaler.fit_transform(X)

        self.X_train = X_scaled[:split]
        self.X_test  = X_scaled[split:]
        self.y_train = y_binary.values[:split]
        self.y_test  = y_binary.values[split:]

        print(f"\nTrain set: {len(self.X_train)} samples")
        print(f"Test set:  {len(self.X_test)} samples")
        print(f"Attack ratio (test): {self.y_test.mean():.2%}")

        os.makedirs(MODELS_PATH, exist_ok=True)
        joblib.dump(self.scaler, f"{MODELS_PATH}/cicids_scaler.pkl")
        joblib.dump(self.feature_columns, f"{MODELS_PATH}/cicids_features.pkl")

        return True

    def get_binary_labels(self):
        return self.y_train, self.y_test

    def get_features(self):
        return self.X_train, self.X_test

    def get_label_counts(self):
        return self.label_counts