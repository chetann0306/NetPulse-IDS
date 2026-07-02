import os
import json
import socket
from datetime import datetime
from webhook_alerter import send_soc_alert

LOG_FILE = "netpulse_security_incidents.log"

# Production SIEM Endpoint Configuration
SIEM_HOST = "127.0.0.1"
SIEM_PORT = 514  

def log_incident(level, message, attacker_ip=None, flow_metrics=None):
    """
    Appends a local forensic trace, streams JSON syslog metrics out-of-band to a 
    centralized SIEM, and pushes instant mobile/desktop webhook notifications.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_line = f"[{timestamp}] [{level}] {message}\n"
    
    # 1. Write the traditional local safety copy
    with open(LOG_FILE, "a") as f:
        f.write(formatted_line)
        
    # 2. Build and ship the structured SIEM JSON object via UDP
    siem_payload = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "log.level": level,
        "message": message,
        "service.name": "NetPulse_IDPS",
        "source.ip": attacker_ip if attacker_ip else "N/A",
        "event.category": "network_anomaly" if level in ["WARNING", "CRITICAL"] else "system_telemetry"
    }
    
    if flow_metrics:
        siem_payload["network.flow.metrics"] = flow_metrics

    try:
        payload_bytes = json.dumps(siem_payload).encode('utf-8')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload_bytes, (SIEM_HOST, SIEM_PORT))
        sock.close()
    except Exception:
        pass

    # 3. Trigger Instant Webhook Notifications for high-severity events
    if level in ["CRITICAL", "WARNING"]:
        send_soc_alert(level, message, attacker_ip, flow_metrics)