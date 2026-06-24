import pandas as pd
import numpy as np

def generate_mock_traffic(n_samples=10000):
    print(f"Generating {n_samples} synthetic network flows for NetPulse IDS...")
    np.random.seed(42)
    
    # Simulating a realistic class imbalance (85% Benign, 10% DDoS, 5% Port Scan)
    n_benign = int(n_samples * 0.85)
    n_ddos = int(n_samples * 0.10)
    n_portscan = int(n_samples * 0.05)
    
    data = []

    # 1. BENIGN TRAFFIC: Varied, irregular flow patterns
    for _ in range(n_benign):
        data.append({
            'Flow_Duration': np.random.exponential(scale=5000),
            'Total_Fwd_Packets': np.random.randint(2, 50),
            'Total_Bwd_Packets': np.random.randint(2, 50),
            'Fwd_Packet_Length_Mean': np.random.uniform(100, 800),
            'Flow_IAT_Mean': np.random.exponential(scale=200),
            'Destination_Port': np.random.choice([80, 443, 22, 53]),
            'Label': 'BENIGN'
        })
        
    # 2. DDOS ATTACK: Extreme packet rates, short durations, regular intervals
    for _ in range(n_ddos):
        data.append({
            'Flow_Duration': np.random.uniform(1, 50),
            'Total_Fwd_Packets': np.random.randint(100, 1000),
            'Total_Bwd_Packets': np.random.randint(0, 5),
            'Fwd_Packet_Length_Mean': np.random.uniform(20, 60),
            'Flow_IAT_Mean': np.random.uniform(0.1, 2),
            'Destination_Port': 80,
            'Label': 'DDoS'
        })

    # 3. PORT SCANNING: Fast connection attempts across random ports, low payload
    for _ in range(n_portscan):
        data.append({
            'Flow_Duration': np.random.uniform(0.5, 5),
            'Total_Fwd_Packets': np.random.choice([1, 2]),
            'Total_Bwd_Packets': np.random.choice([0, 1]),
            'Fwd_Packet_Length_Mean': np.random.uniform(0, 10),
            'Flow_IAT_Mean': np.random.uniform(1, 10),
            'Destination_Port': np.random.randint(1, 65535),
            'Label': 'PortScan'
        })

    df = pd.DataFrame(data)
    # Shuffle dataset rows to mix normal traffic and attacks
    df = df.sample(frac=1).reset_index(drop=True)
    
    df.to_csv('network_traffic_sample.csv', index=False)
    print("Dataset saved to 'network_traffic_sample.csv'!")

if __name__ == "__main__":
    generate_mock_traffic()