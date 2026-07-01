import os
import json
import socket
from datetime import datetime

LOG_FILE = "netpulse_security_incidents.log"

# Production SIEM Endpoint Configuration (Defaults to localhost loopback for testing)
SIEM_HOST = "127.0.0.1"
SIEM_PORT = 514  # Standard Enterprise Syslog Port

def log_incident(level, message, attacker_ip=None, flow_metrics=None):
    """
    Appends a local forensic trace copy and instantly streams structured 
    JSON network syslog metrics out-of-band to a centralized SIEM collector.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_line = f"[{timestamp}] [{level}] {message}\n"
    
    # 1. Write the traditional local safety copy
    with open(LOG_FILE, "a") as f:
        f.write(formatted_line)
        
    # 2. Build the industry-standard structured SIEM JSON object
    siem_payload = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "log.level": level,
        "message": message,
        "service.name": "NetPulse_IDPS",
        "source.ip": attacker_ip if attacker_ip else "N/A",
        "event.category": "network_anomaly" if level in ["WARNING", "CRITICAL"] else "system_telemetry"
    }
    
    # Inject extra data layers if flow dictionaries are supplied by the ML engine
    if flow_metrics:
        siem_payload["network.flow.metrics"] = flow_metrics

    # 3. Ship the log asynchronously via UDP socket to the SIEM destination
    try:
        payload_bytes = json.dumps(siem_payload).encode('utf-8')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload_bytes, (SIEM_HOST, SIEM_PORT))
        sock.close()
    except Exception:
        # Fail silently in the background so network sniffing stays fast even if SIEM is down
        pass