import os
import platform
import subprocess
from logger import log_incident
from firewall_pruner import register_new_block_lease

def execute_system_command(command_list):
    """Safely executes low-level system shell operations via subprocess arrays."""
    try:
        result = subprocess.run(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except Exception as ex:
        return False, str(ex)

def block_malicious_ip(ip_address, lease_minutes=15):
    """
    Detects host OS topology, issues immediate active kernel packet blocks 
    targeting the offending source machine, and schedules a lease window duration.
    """
    if not ip_address or ip_address in ["127.0.0.1", "0.0.0.0"]:
        return False
        
    os_type = platform.system().upper()
    log_incident("WARNING", f"INITIATING ACTIVE ENDPOINT DEFENSE: Generating block rule for attacker IP: {ip_address}")
    
    if os_type == "WINDOWS":
        rule_name = f"NetPulse_Block_{ip_address.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes"
        ]
        
    elif os_type == "LINUX":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        
    else:
        log_incident("ERROR", f"Firewall automation mapping failed: Unsupported OS type detected ({platform.system()})")
        return False

    success, output = execute_system_command(cmd)
    
    if success:
        log_incident("INFO", f"SUCCESS: Active firewall patch deployed. Attacker IP {ip_address} is now restricted.")
        # LEASING INTEGRATION: Register the lease token immediately inside the tracking database manifest
        register_new_block_lease(ip_address, lease_duration_minutes=lease_minutes)
        return True
    else:
        log_incident("ERROR", f"Firewall insertion failed (Verify Elevation/Privileges): {output.strip()}")
        return False

if __name__ == "__main__":
    print("Testing active system firewall mitigation routing maps with leasing loops...")
    block_malicious_ip("192.0.2.1", lease_minutes=5)