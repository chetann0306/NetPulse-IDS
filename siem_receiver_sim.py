import socket
import json
import sys

def run_siem_receiver_server():
    host = "127.0.0.1"
    port = 514 # Standard Enterprise Syslog Port
    
    # Initialize a network socket configured for UDP packet handling
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        server_socket.bind((host, port))
        print("=" * 60)
        print("     NETPULSE IDPS - CENTRALIZED SIEM RECEIVER SIMULATOR   ")
        print("=" * 60)
        print(f"Listening for production JSON syslog traffic on {host}:{port}...")
        print("Standby for raw telemetry stream packets... (Press Ctrl+C to stop)\n")
    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to bind to syslog port 514: {str(e)}")
        print("Note: On some systems, running services on port 514 requires Administrator/root privileges.")
        return

    try:
        while True:
            # Buffer size of 4096 bytes handles dense network flow context dumps
            data, addr = server_socket.recvfrom(4096)
            raw_payload = data.decode('utf-8')
            
            try:
                # Attempt to parse and pretty-print the structured JSON log file format
                parsed_json = json.loads(raw_payload)
                print(f"📥 [SIEM INGESTION MATCHED] From Endpoint: {addr[0]}:{addr[1]}")
                print(json.dumps(parsed_json, indent=4))
                print("-" * 60)
            except json.JSONDecodeError:
                # Fallback for plain-text legacy alerts
                print(f"📥 [RAW ALARM INGESTED] From {addr[0]}:{addr[1]} -> {raw_payload.strip()}")
                print("-" * 60)
                
    except KeyboardInterrupt:
        print("\nSafely winding down SIEM collector endpoint matrix streams.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    run_siem_receiver_server()