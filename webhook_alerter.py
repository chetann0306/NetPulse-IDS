import os
import json
import urllib.request
from datetime import datetime

# Replace this with your actual Slack, Discord, or Teams Webhook URL
# Example Discord format: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
WEBHOOK_URL = "YOUR_WEBHOOK_URL_HERE"

def send_soc_alert(level, message, attacker_ip=None, metrics=None):
    """
    Pushes a formatted rich-text alert to an external SOC team channel via HTTP Webhook.
    """
    if WEBHOOK_URL == "YOUR_WEBHOOK_URL_HERE" or not WEBHOOK_URL:
        return  # Silently bypass if the user hasn't configured a URL yet

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Color coding for Discord/Slack embeds
    color = 16711680 if level == "CRITICAL" else 16753920 # Red for Critical, Orange for Warning

    # Constructing a rich embed payload (Discord compatible format)
    payload = {
        "username": "NetPulse IDPS Overlord",
        "avatar_url": "https://img.icons8.com/color/512/shield.png",
        "embeds": [{
            "title": f"🚨 {level} NETWORK ALERT FLAG",
            "description": message,
            "color": color,
            "fields": [
                {"name": "Timestamp", "value": timestamp, "inline": True},
                {"name": "Target IP / Actor", "value": attacker_ip if attacker_ip else "Unknown", "inline": True}
            ],
            "footer": {"text": "NetPulse Automated Mitigation Pipeline"}
        }]
    }

    if metrics:
        metrics_str = f"Duration: {metrics.get('duration_ms', 0)}ms\nPackets (F/B): {metrics.get('forward_packets', 0)} / {metrics.get('backward_packets', 0)}"
        payload["embeds"][0]["fields"].append({"name": "Flow Metrics", "value": metrics_str, "inline": False})

    try:
        req = urllib.request.Request(
            WEBHOOK_URL, 
            data=json.dumps(payload).encode('utf-8'), 
            headers={'Content-Type': 'application/json', 'User-Agent': 'NetPulse-IDS/1.0'}
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        # We catch and print locally so a webhook failure doesn't crash the fast packet sniffer
        print(f"[WEBHOOK ERROR] Failed to push notification: {str(e)}")

if __name__ == "__main__":
    print("Testing Webhook Notification Pipeline...")
    dummy_metrics = {"duration_ms": 145.2, "forward_packets": 22, "backward_packets": 18}
    send_soc_alert("CRITICAL", "Simulated DDoS pattern detected on Port 443.", "192.168.1.205", dummy_metrics)
    print("Test fired. Check your messaging channel!")