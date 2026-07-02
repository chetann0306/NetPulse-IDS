import os
import re
import time
import pandas as pd
import numpy as np
from logger import log_incident

def compute_realtime_dashboard_metrics():
    """Parses data frames and logs to extract core operational pipeline telemetry."""
    metrics = {
        "total_flows_processed": 0,
        "benign_count": 0,
        "threat_count": 0,
        "avg_flow_duration_ms": 0.0,
        "avg_packet_count": 0.0,
        "system_status": "Healthy",
        "latency_history": []
    }

    # 1. Gather baseline data dimensions if available
    target_file = "network_traffic_sample.csv"
    if os.path.exists(target_file):
        df = pd.read_csv(target_file)
        df.columns = df.columns.str.strip()
        
        metrics["total_flows_processed"] = len(df)
        if 'Label' in df.columns:
            counts = df['Label'].value_counts()
            metrics["benign_count"] = int(counts.get("BENIGN", 0))
            metrics["threat_count"] = int(len(df) - metrics["benign_count"])
            
        if 'Flow_Duration' in df.columns:
            metrics["avg_flow_duration_ms"] = float(df['Flow_Duration'].mean())
            
        if 'Total_Fwd_Packets' in df.columns and 'Total_Bwd_Packets' in df.columns:
            metrics["avg_packet_count"] = float((df['Total_Fwd_Packets'] + df['Total_Bwd_Packets']).mean())

    # 2. Parse operational log history for runtime alarms
    log_file = "netpulse_security_incidents.log"
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            log_content = f.read()
            critical_alerts = log_content.count("[CRITICAL]")
            warnings = log_content.count("[WARNING]")
            
            if critical_alerts > 5 or warnings > 10:
                metrics["system_status"] = "Under Attack / Degraded"

    # 3. Simulate a sliding timeline window of model inference speeds (in milliseconds)
    np.random.seed(int(time.time()) % 1000)
    # Generates a realistic baseline latency fluctuating between 1.2ms and 3.5ms
    metrics["latency_history"] = list(np.random.uniform(1.2, 3.5, size=20))

    log_incident("INFO", "Unified telemetry metrics updated successfully.")
    return metrics

if __name__ == "__main__":
    print("Testing dashboard telemetry computation modules...")
    results = compute_realtime_dashboard_metrics()
    print(f"Computed Live Status: {results['system_status']} | History Samples: {len(results['latency_history'])}")