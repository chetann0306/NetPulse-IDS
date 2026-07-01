import os
import time
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from logger import log_incident
from firewall_blocker import block_malicious_ip

# Global structures to track active connections and the ML model components
active_flows = {}
trained_model = None
data_scaler = None

def train_and_initialize_live_model():
    global trained_model, data_scaler
    log_incident("INFO", "Initializing live machine learning classification layers...")
    
    if not os.path.exists("network_traffic_sample.csv"):
        import generate_data
        generate_data.generate_mock_traffic()
        
    df = pd.read_csv("network_traffic_sample.csv")
    df.columns = df.columns.str.strip()
    
    forbidden_cols = ['Flow ID', 'Source IP', 'Source IP Address', 'Destination IP', 'Destination IP Address', 'Timestamp']
    df.drop(columns=[col for col in forbidden_cols if col in df.columns], errors='ignore', inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    data_scaler = StandardScaler()
    X_scaled = data_scaler.fit_transform(X)
    
    trained_model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    trained_model.fit(X_scaled, y)
    log_incident("INFO", "Live machine learning classification layers successfully armed.")

def process_packet(packet):
    if not packet.haslayer(IP):
        return

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

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_length = len(packet)
    current_time = packet.time

    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)

    if flow_key in active_flows:
        target_key = flow_key
        is_forward = True
    elif reverse_key in active_flows:
        target_key = reverse_key
        is_forward = False
    else:
        active_flows[flow_key] = {
            'start_time': current_time,
            'last_time': current_time,
            'fwd_packets': 1,
            'bwd_packets': 0,
            'fwd_lengths': [packet_length],
            'bwd_lengths': [],
            'iat_times': [],
            'dst_port': dst_port
        }
        return

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

    if (flow['fwd_packets'] + flow['bwd_packets']) >= 20:
        evaluate_live_flow_prediction(target_key, flow)
        del active_flows[target_key]

def evaluate_live_flow_prediction(flow_key, flow_data):
    global trained_model, data_scaler
    
    duration = (flow_data['last_time'] - flow_data['start_time']) * 1000  
    fwd_mean_len = sum(flow_data['fwd_lengths']) / len(flow_data['fwd_lengths']) if flow_data['fwd_lengths'] else 0
    mean_iat = (sum(flow_data['iat_times']) / len(flow_data['iat_times'])) * 1000 if flow_data['iat_times'] else 0

    feature_row = np.array([[
        duration,
        flow_data['fwd_packets'],
        flow_data['bwd_packets'],
        fwd_mean_len,
        mean_iat,
        flow_data['dst_port']
    ]])
    
    scaled_row = data_scaler.transform(feature_row)
    prediction = trained_model.predict(scaled_row)[0]
    
    log_msg = f"LIVE DETECTION -> [Src: {flow_key[0]} -> Dst: {flow_key[1]} | Port: {flow_data['dst_port']}] -> CLASSIFICATION: {prediction}"
    
    if prediction == "BENIGN":
        log_incident("INFO", log_msg)
    else:
        # Build a detailed diagnostic metrics layer for SIEM analysis dashboards
        flow_context = {
            "duration_ms": round(duration, 2),
            "forward_packets": flow_data['fwd_packets'],
            "backward_packets": flow_data['bwd_packets'],
            "mean_forward_length": round(fwd_mean_len, 2),
            "mean_iat_ms": round(mean_iat, 2)
        }
        
        log_incident(
            level="CRITICAL", 
            message=f"🚨 ANOMALY FLAGGED! {log_msg}", 
            attacker_ip=flow_key[0], 
            flow_metrics=flow_context
        )
        
        attacker_ip = flow_key[0]
        block_malicious_ip(attacker_ip)

def start_live_sniffing(packet_count=100):
    if trained_model is None:
        train_and_initialize_live_model()
    log_incident("INFO", f"Starting live network packet interception layer. Capturing {packet_count} packets...")
    sniff(prn=process_packet, count=packet_count, store=0)
    log_incident("INFO", "Live network sniffing sweep complete.")

if __name__ == "__main__":
    start_live_sniffing(packet_count=50)