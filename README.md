# NetPulse IDS 📊🔒

NetPulse IDS is an enterprise-grade, hybrid Machine Learning-based Network Intrusion Detection System. It is engineered to monitor the statistical "pulse" and shape of network traffic to identify malicious threat signatures in real time, handle extreme dataset class imbalances, map adversarial concept drift, and instantly export low-latency firewall rules.

## 🚀 Core Features
* **Dual-Control Interface:** Features both an interactive Command-Line Control Center (`dashboard.py`) and a beautiful browser-based Web UI App (`app.py`).
* **Real Benchmark Dataset Integration:** Supports dual processing for both custom synthetic data profiles and authentic multi-class corporate traffic profiles via the **CICIDS2017** dataset.
* **Imbalance Resolution (SMOTE):** Integrates Synthetic Minority Over-sampling to preserve model sensitivity against rare attack vectors.
* **Concept Drift Defense Engine:** Leverages Principal Component Analysis (PCA) to map 2D spatial cluster migrations and implements an automated self-healing retraining trigger loop.
* **Incident Audit Logger:** Maintains a persistent, structured, and immutable forensic security ledger (`netpulse_security_incidents.log`) for post-incident auditing.
* **Hybrid Latency Alleviation:** Traverses model branches to extract and export lightweight static text firewall rules (`.rules`) to bypass high-volume processing overheads.

---

## 🛠️ Project Structure Map
```text
NetPulse IDS/
├── app.py                 # Premium Web App Browser Dashboard UI (Streamlit)
├── dashboard.py           # Command-Line Control Center Console UI
├── generate_data.py       # Simulates network flow distributions (Benign, DDoS, PortScan)
├── download_dataset.py    # Automatic ingestion utility for real CICIDS2017 profiles
├── pipeline.py            # Random Forest baseline with robust metadata stripping
├── pipeline_smote.py      # Resampled ML engine handling extreme data imbalance
├── visualize.py           # Extracts and charts model feature importance rankings
├── visualize_drift.py     # Captures cluster migrations via 2D PCA mappings
├── monitor_and_retrain.py # Persistent event monitoring & self-healing trigger loop
├── logger.py              # Centralized logging engine framework
├── generate_report.py     # Compiles Markdown Executive Summaries from log histories
└── requirements.txt       # Unified library dependencies manifest