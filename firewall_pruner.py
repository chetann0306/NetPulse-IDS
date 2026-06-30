import os
import json
import platform
import subprocess
from datetime import datetime, timedelta
from logger import log_incident

LEASES_MANIFEST_FILE = "netpulse_firewall_leases.json"

def register_new_block_lease(ip_address, lease_duration_minutes=30):
    """Registers a time-bound lease tracking token for a blocked IP address."""
    if not os.path.exists(LEASES_MANIFEST_FILE):
        leases_db = {}
    else:
        with open(LEASES_MANIFEST_FILE, "r") as f:
            try:
                leases_db = json.load(f)
            except json.JSONDecodeError:
                leases_db = {}

    expiration_time = datetime.now() + timedelta(minutes=lease_duration_minutes)
    leases_db[ip_address] = {
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": expiration_time.strftime("%Y-%m-%d %H:%M:%S"),
        "rule_name": f"NetPulse_Block_{ip_address.replace('.', '_')}"
    }

    with open(LEASES_MANIFEST_FILE, "w") as f:
        json.dump(leases_db, f, indent=4)
        
    log_incident("INFO", f"Firewall lease registered for {ip_address}. TTL: {lease_duration_minutes} minutes.")

def prune_expired_firewall_rules():
    """Scans the manifest file and dynamically lifts blocks that have outlived their lease TTL."""
    print("--- Initiating Firewall Active Ban Table Pruning sweep ---")
    if not os.path.exists(LEASES_MANIFEST_FILE):
        return

    with open(LEASES_MANIFEST_FILE, "r") as f:
        try:
            leases_db = json.load(f)
        except json.JSONDecodeError:
            return

    current_time = datetime.now()
    expired_ips = []
    os_type = platform.system().upper()

    for ip_address, meta in list(leases_db.items()):
        expires_at = datetime.strptime(meta["expires_at"], "%Y-%m-%d %H:%M:%S")
        
        if current_time > expires_at:
            print(f"Lease expired for attacker signature tracking token: {ip_address}. Lifting restriction...")
            log_incident("WARNING", f"Lease expired for {ip_address}. Revoking kernel packet drop rule.")
            
            success = False
            # OS-Specific Revocation Routing Command Matrices
            if os_type == "WINDOWS":
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={meta['rule_name']}"]
                try:
                    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                    success = True
                except subprocess.CalledProcessError:
                    pass # Safely bypass if rule was manually lifted early
                    
            elif os_type == "LINUX":
                cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                try:
                    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                    success = True
                except subprocess.CalledProcessError:
                    pass
            
            expired_ips.append(ip_address)

    # Flush expired tokens out of our operational database
    for ip in expired_ips:
        del leases_db[ip]

    with open(LEASES_MANIFEST_FILE, "w") as f:
        json.dump(leases_db, f, indent=4)
        
    if expired_ips:
        log_incident("INFO", f"Successfully pruned and revoked {len(expired_ips)} expired firewall rules.")
    else:
        print("All active firewall leases are verified fresh. No structural pruning required.")

if __name__ == "__main__":
    prune_expired_firewall_rules()