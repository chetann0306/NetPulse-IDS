import os
import re
import json
import urllib.request
from logger import log_incident

LOG_FILE_PATH = "netpulse_security_incidents.log"
GEO_REPORT_PATH = "netpulse_threat_geography.json"

def fetch_ip_geography(ip_address):
    """Queries a secure public API mirror to resolve IP addresses to spatial coordinates."""
    # Exclude non-routable private addresses from lookup loops
    if ip_address.startswith(("10.", "192.168.", "172.16.")) or ip_address == "127.0.0.1":
        return {
            "country": "Internal Network",
            "city": "Private Subnet",
            "lat": 0.0,
            "lon": 0.0
        }
        
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0)
                }
    except Exception:
        pass
        
    return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}

def parse_logs_and_map_threats():
    print("--- Running Network Forensic Geo-IP Extraction ---")
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[ERROR] Log file '{LOG_FILE_PATH}' missing. Run some pipeline modules first!")
        return

    unique_ips = set()
    # Match standard IPv4 extraction formats embedded inside CRITICAL security alerts
    ip_regex = re.compile(r"Src:\s+([\d\.]+)")

    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            if "[CRITICAL]" in line:
                match = ip_regex.search(line)
                if match:
                    unique_ips.add(match.group(1))

    if not unique_ips:
        print("✅ No critical anomaly signatures currently mapped in the active log database.")
        return

    print(f"Extracted {len(unique_ips)} unique malicious addresses. Querying geo-intelligence...")
    
    geo_registry = {}
    for ip in unique_ips:
        geo_data = fetch_ip_geography(ip)
        geo_registry[ip] = geo_data
        print(f" -> Bound {ip} to [{geo_data['city']}, {geo_data['country']}]")

    # Serialize results to a clean structured JSON file
    with open(GEO_REPORT_PATH, "w") as out:
        json.dump(geo_registry, out, indent=4)
        
    log_incident("INFO", f"Successfully mapped forensic attack coordinates for {len(unique_ips)} threat sources.")
    print(f"\nSuccess! Spatial coordinates saved cleanly to '{GEO_REPORT_PATH}'")

if __name__ == "__main__":
    parse_logs_and_map_threats()