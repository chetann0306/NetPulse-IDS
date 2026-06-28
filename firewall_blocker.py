import os
import platform
import subprocess
from logger import log_incident

def execute_system_command(command_list):
    """Safely executes low-level system shell operations via subprocess arrays."""
    try:
        # shell=False prevents command injection vulnerabilities
        result = subprocess.run(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except Exception as ex:
        return False, str(ex)

def block_malicious_ip(ip_address):
    """
    Detects host OS topology and issues immediate active kernel packet blocks 
    targeting the offending source machine.
    """
    if not ip_address or ip_address in ["127.0.0.1", "0.0.0.0"]:
        return False
        
    os_type = platform.system().upper()
    log_incident("WARNING", f"INITIATING ACTIVE ENDPOINT DEFENSE: Generating block rule for attacker IP: {ip_address}")
    
    if os_type == "WINDOWS":
        # Target Windows Advanced Firewall context paths
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
        # Target Linux iptables kernel netfilter rule append states
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        
    else:
        log_incident("ERROR", f"Firewall automation mapping failed: Unsupported OS type detected ({platform.system()})")
        return False

    # Execute active defensive configuration matrix
    success, output = execute_system_command(cmd)
    
    if success:
        log_incident("INFO", f"SUCCESS: Active firewall patch deployed. Attacker IP {ip_address} is now restricted.")
        return True
    else:
        # Note: Will log a failure safely locally if terminal console lacks Administrator/root permissions
        log_incident("ERROR", f"Firewall insertion failed (Verify Elevation/Privileges): {output.strip()}")
        return False

if __name__ == "__main__":
    print("Testing active system firewall mitigation routing maps...")
    # Test path execution tracing using a safe non-routable documentation address
    block_malicious_ip("192.0.2.1")