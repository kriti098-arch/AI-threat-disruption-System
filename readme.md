# AI Threat Disruption System (ATDS)

An AI-powered network intrusion and anomaly-based threat detection system that analyzes live and historical network traffic, classifies attacks, and provides explainable, real-time security insights through an interactive dashboard.

Built as an anomaly-based threat detection platform trained on the **CIC-IDS2017** dataset, ATDS combines classical machine learning (Isolation Forest, Random Forest) with rule-based correlation, evasion detection, and honeypot logic to identify and respond to malicious network activity.

---

## Features

- **Anomaly & Signature-Based Detection** — Isolation Forest for unsupervised anomaly detection alongside a Random Forest attack classifier for known attack types
- **Live Packet Capture** — Real-time network traffic ingestion and analysis via PyShark
- **Explainable AI** — SHAP-based explanations for model predictions, surfaced through a dedicated dashboard widget
- **Attack Classification** — Multi-class classification of network traffic into specific attack categories
- **Evasion Detection** — Identifies adversarial attempts to bypass detection
- **Honeypot Module** — Deceptive endpoints to lure and log attacker behavior
- **Threat Intelligence & Correlation Engine** — Correlates events, scores risk, and tracks threat memory over time
- **Kill Chain Mapping** — Maps detected activity to stages of the cyber kill chain
- **Alert Fatigue Reduction** — Confidence scoring and risk aggregation to reduce noisy/duplicate alerts
- **Geolocation & Global Risk Scoring** — Enriches incidents with source geolocation and global risk context
- **Automated Reporting** — Generates incident reports from detected threats
- **Interactive Dashboard** — Web-based frontend for live monitoring, incident review, and reporting

---

## Tech Stack

**Backend**
- Python, FastAPI
- scikit-learn (Isolation Forest, Random Forest)
- PyShark (packet capture/analysis)
- SHAP (model explainability)
- SQL-based storage (SQLAlchemy models)

**Frontend**
- HTML, CSS, JavaScript (vanilla)
- Modular JS for dashboard, live view, incidents, and navigation

**Data**
- CIC-IDS2017 network intrusion dataset

---

## Project Structure

```
ai-threat-disruption-system/
├── backend/
│   ├── app/
│   │   ├── database/          # DB models and connection setup
│   │   ├── detection/         # Rule-based detection, correlation, risk scoring
│   │   ├── features/          # Feature extraction from network data
│   │   ├── ml/                # ML models: Isolation Forest, baseline, stream detector
│   │   ├── response/          # Automated response engine
│   │   ├── routers/           # API routes (incidents, live capture, logs, reports, etc.)
│   │   ├── security/          # Core detection logic (classifier, evasion, honeypot, SHAP, etc.)
│   │   ├── crud.py
│   │   ├── main.py
│   │   └── schemas.py
│   ├── capture/                # Live packet capture scripts
│   ├── data/                   # Dataset (CIC-IDS2017)
│   ├── experiments/            # Experimental scripts
│   ├── models/                 # Trained model artifacts (.pkl)
│   └── scripts/                # Training & evaluation scripts
├── frontend/
│   ├── css/
│   ├── js/                     # Dashboard, live view, incidents, navigation, SHAP widget
│   └── index.html
├── requirements.txt
└── simulate_attacks.py         # Attack simulation for testing detection
```

---

## Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/kriti098-arch/AI-threat-disruption-System.git
cd AI-threat-disruption-System
pip install -r requirements.txt
```

### Running the Backend

```bash
cd backend
uvicorn app.main:app --reload
```

### Running the Frontend

Open `frontend/index.html` in a browser, or serve it with a simple local server:

```bash
cd frontend
python -m http.server 5500
```

### Training / Evaluating Models

```bash
cd backend/scripts
python train_and_evaluate.py
python train_attack_classifier.py
```

### Simulating Attacks (for testing)

```bash
python simulate_attacks.py
```

---

## Dataset

This project uses the **CIC-IDS2017** dataset for training and evaluating anomaly detection and classification models. Due to file size limits, the full dataset is not tracked in this repository — see `backend/data/` for the expected location if you add it locally.

---

## Notes

- Trained model artifacts are stored in `backend/models/`.
- Environment variables (e.g. secrets, DB config) should be kept in a local `.env` file and are **not** committed to version control.

---

## Author

Developed by [kriti098-arch](https://github.com/kriti098-arch)
