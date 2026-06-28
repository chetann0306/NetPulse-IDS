import time
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from logger import log_incident

# Global dictionary to track active network flows in-memory
# Key structure: (Source_IP, Dest_IP, Source_Port, Dest_Port, Protocol)
active_flows = {}

def process_packet(packet):
    """Callback function executed for every intercepted raw packet."""
    if not packet.haslayer(IP):
        return

    # Extract protocol type
    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Extract basic packet metadata
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_length = len(packet)
    current_time = packet.time

    # Generate unique bidirectional flow identifier keys
    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)

    # Check if this packet belongs to an existing active flow stream
    if flow_key in active_flows:
        target_key = flow_key
        is_forward = True
    elif reverse_key in active_flows:
        target_key = reverse_key
        is_forward = False
    else:
        # Initialize a brand new network flow tracking record
        active_flows[flow_key] = {
            'start_time': current_time,
            'last_time': current_time,
            'fwd_packets': 1 if protocol != "OTHER" else 1,
            'bwd_packets': 0,
            'fwd_lengths': [packet_length] if protocol != "OTHER" else [packet_length],
            'bwd_lengths': [],
            'iat_times': [],
            'dst_port': dst_port
        }
        return

    # Update metrics for an existing flow stream
    flow = active_flows[target_key]
    iat = current_time - flow['last_time']
    flow['iat_times'].append(iat)
    flow['last_time'] = current_time

    if is_forward:
        flow['fwd_packets'] += 1
        flow['fwd_lengths'].append(packet_length)
    else:
        flow['bwd_packets'] += 1
        flow['bwd_lengths'].append(packet_length)

    # Evaluation Trigger: Once a flow collects 20 packets, compile its statistics
    if (flow['fwd_packets'] + flow['bwd_packets']) >= 20:
        compile_and_log_flow(target_key, flow)
        # Flush from memory cache after processing
        del active_flows[target_key]

def compile_and_log_flow(flow_key, flow_data):
    """Transforms raw packet aggregates into structured ML features."""
    duration = (flow_data['last_time'] - flow_data['start_time']) * 1000 # Milliseconds
    fwd_mean_len = sum(flow_data['fwd_lengths']) / len(flow_data['fwd_lengths']) if flow_data['fwd_lengths'] else 0
    mean_iat = (sum(flow_data['iat_times']) / len(flow_data['iat_times'])) * 1000 if flow_data['iat_times'] else 0

    # Build feature structure dict matching model signatures
    structured_flow = {
        'Flow_Duration': duration,
        'Total_Fwd_Packets': flow_data['fwd_packets'],
        'Total_Bwd_Packets': flow_data['bwd_packets'],
        'Fwd_Packet_Length_Mean': fwd_mean_len,
        'Flow_IAT_Mean': mean_iat,
        'Destination_Port': flow_data['dst_port']
    }
    
    msg = f"Live Flow Extracted | Src: {flow_key[0]} -> Dst: {flow_key[1]} | Port: {structured_flow['Destination_Port']} | Duration: {structured_flow['Flow_Duration']:.2f}ms"
    log_incident("INFO", msg)

def start_live_sniffing(packet_count=100):
    log_incident("INFO", f"Starting live network packet interception layer. Capturing {packet_count} packets...")
    # store=0 forces scapy to discard processed raw packets immediately to protect memory
    sniff(prn=process_packet, count=packet_count, store=0)
    log_incident("INFO", "Live network sniffing sweep complete.")

if __name__ == "__main__":
    # Test script locally by sniffing 50 packets on the active interface
    start_live_sniffing(packet_count=50)