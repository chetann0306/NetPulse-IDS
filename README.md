# 🛡️ NetPulse IDPS (Intrusion Detection & Prevention System)

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-UI-FF4B4B.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E.svg)](https://scikit-learn.org/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)](https://www.docker.com/)

**NetPulse** is an enterprise-grade, machine-learning-powered network security platform. It combines real-time asynchronous packet sniffing with advanced Random Forest and LSTM neural network classifiers to detect, visualize, and actively block malicious network traffic before it compromises host infrastructure.

---

## ⚡ Core Features

* **Real-Time Traffic Sniffing:** Multi-threaded packet ingestion using Scapy/Npcap, capable of analyzing live network flows with minimal latency.
* **Machine Learning Inference:** Dynamic anomaly classification using Scikit-Learn (Random Forest) and deep sequential learning (PyTorch LSTM).
* **Active Firewall Mitigation:** Automated, OS-level firewall blocking (Windows `netsh` / Linux `iptables`) with a dynamic Time-To-Live (TTL) lease pruning engine.
* **SIEM Integration:** Out-of-band JSON Syslog streaming over UDP port 514 for centralized logging in Splunk, ElasticSearch, or Wazuh.
* **Role-Based Web Dashboard:** A secure Streamlit control center for live telemetry metrics, feature importance maps, and adversarial drift visualizations.
* **Automated Self-Healing:** Adaptive retraining loops that monitor for concept drift and automatically generate high-speed signature rules.

---

## 🏗️ Architecture Overview

The system is separated into three distinct operational planes:

1. **The Ingestion Plane:** Async producer threads capture raw sockets and compile them into statistical flow metrics (duration, forward/backward packets, inter-arrival times).
2. **The Intelligence Plane:** Standardized flows are passed through serialized preprocessors and evaluated by a balanced ML classification engine.
3. **The Mitigation Plane:** Malicious classifications trigger OS-level kernel drops, register temporary lease tokens, and broadcast JSON incident logs to a central SIEM.

---

## 🚀 Quick Start (Docker Deployment)

The easiest way to deploy NetPulse in a production or lab environment is via Docker, ensuring isolated dependencies and host-network packet visibility.

```bash
# 1. Clone the repository
git clone [https://github.com/yourusername/NetPulse-IDPS.git](https://github.com/yourusername/NetPulse-IDPS.git)
cd NetPulse-IDPS

# 2. Build and launch the container ecosystem
docker compose up --build