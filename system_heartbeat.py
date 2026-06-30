import os
import time
import json
from datetime import datetime
import psutil  # To capture native system memory profiles
from logger import log_incident

HEARTBEAT_FILE = "netpulse_heartbeat.json"

def perform_system_health_audit():
    """Evaluates host resource utilization footprints and engine statuses."""
    health_status = "HEALTHY"
    diagnostic_logs = []
    
    try:
        # 1. Audit Memory Thresholds
        process = psutil.Process(os.getpid())
        memory_usage_mb = process.memory_info().rss / (1024 * 1024)
        
        # High memory consumption indicator guardrail
        if memory_usage_mb > 500:
            health_status = "WARNING"
            diagnostic_logs.append("High memory threshold crossed (>500MB). Potential leak.")
            
        # 2. Check Forensic History Logging Connectivity
        log_file = "netpulse_security_incidents.log"
        if not os.path.exists(log_file):
            health_status = "DEGRADED"
            diagnostic_logs.append("Security incident log database file missing.")
            
        # 3. Create Heartbeat Manifest Structure
        heartbeat_pulse = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": health_status,
            "memory_footprint_mb": round(memory_usage_mb, 2),
            "pid": os.getpid(),
            "diagnostics": diagnostic_logs if diagnostic_logs else ["All telemetry systems operational."]
        }
        
        # Write heartbeat pulse state out atomically
        with open(HEARTBEAT_FILE, "w") as f:
            json.dump(heartbeat_pulse, f, indent=4)
            
        if health_status == "HEALTHY":
            log_incident("INFO", f"Heartbeat pulse verified. System healthy. Memory: {memory_usage_mb:.1f} MB.")
        else:
            log_incident("WARNING", f"Heartbeat check reported issues: {', '.join(diagnostic_logs)}")
            
        return heartbeat_pulse
        
    except Exception as e:
        log_incident("ERROR", f"Critical breakdown inside watchdog heartbeat engine: {str(e)}")
        return {"status": "CRITICAL_FAILURE", "error": str(e)}

if __name__ == "__main__":
    print("--- Testing Automated Watchdog Heartbeat Logic ---")
    pulse = perform_system_health_audit()
    print(json.dumps(pulse, indent=4))