# NetPulse IDS 📊🔒

NetPulse IDS is an adaptive, machine learning-based Network Intrusion Detection System designed to monitor the statistical "pulse" and shape of network traffic to identify and classify malicious activities in real time.

## 🚀 Key Features
* **Modular Pipeline:** Dedicated engines for data generation, core ML training, visualization, and continuous monitoring.
* **Imbalance Resolution:** Uses both algorithmic class weighting and SMOTE (Synthetic Minority Over-Sampling Technique) to handle rare attack classes.
* **Concept Drift Defense:** Includes a Principal Component Analysis (PCA) engine to map adversarial attack drift and features an automated self-healing retraining loop.
* **Centralized Dashboard:** A terminal-based UI to seamlessly control and evaluate every piece of the pipeline.

---

## 🛠️ Project Structure
```text
NetPulse IDS/
├── generate_data.py       # Simulates network flow distributions (Benign, DDoS, PortScan)
├── pipeline.py            # Random Forest baseline with stratified splitting
├── pipeline_smote.py      # Resampled ML engine handling extreme data imbalance
├── visualize.py           # Extracts and charts model feature importance
├── visualize_drift.py     # Captures cluster migrations via 2D PCA mappings
├── monitor_and_retrain.py # Production guardrail threshold & self-healing trigger loop
├── dashboard.py           # Interactive terminal control center console
└── requirements.txt       # Dependencies (pandas, numpy, scikit-learn, imblearn, etc.)