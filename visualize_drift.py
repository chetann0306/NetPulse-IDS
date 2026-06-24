import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

def run_drift_visualization():
    print("--- 1. Loading Historical and Drifted Data ---")
    # Load historical traffic
    df_hist = pd.read_csv("network_traffic_sample.csv")
    
    # Isolate just the Benign and original DDoS to see the clean starting state
    df_benign = df_hist[df_hist['Label'] == 'BENIGN'].sample(500, random_state=42)
    df_ddos_old = df_hist[df_hist['Label'] == 'DDoS'].sample(500, random_state=42)
    df_ddos_old['Label'] = 'DDoS (Original)'
    
    # 2. Re-create a small batch of the stealthy adversarial "drifted" DDoS traffic
    np.random.seed(42)
    drifted_data = []
    for _ in range(500):
        drifted_data.append({
            'Flow_Duration': np.random.uniform(500, 2000),      
            'Total_Fwd_Packets': np.random.randint(50, 200),    
            'Total_Bwd_Packets': np.random.randint(2, 20),
            'Fwd_Packet_Length_Mean': np.random.uniform(40, 150), 
            'Flow_IAT_Mean': np.random.uniform(20, 100),        
            'Destination_Port': 80,
            'Label': 'DDoS (Adversarial Drifted)'
        })
    df_ddos_new = pd.DataFrame(drifted_data)
    
    # Combine everything into a single dataset for comparison
    df_combined = pd.concat([df_benign, df_ddos_old, df_ddos_new], ignore_index=True)
    
    X = df_combined.drop(columns=['Label'])
    y = df_combined['Label']
    
    print("--- 2. Normalizing Features & Applying PCA ---")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Reduce dimensions down to 2 principal components
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    
    # Build a plotting DataFrame
    df_pca = pd.DataFrame(X_pca, columns=['Principal Component 1', 'Principal Component 2'])
    df_pca['Traffic Type'] = y
    
    print("--- 3. Generating 2D Cluster Graph ---")
    plt.figure(figsize=(10, 7))
    sns.scatterplot(
        x='Principal Component 1', 
        y='Principal Component 2', 
        hue='Traffic Type', 
        data=df_pca, 
        palette={'BENIGN': '#2ca02c', 'DDoS (Original)': '#d62728', 'DDoS (Adversarial Drifted)': '#ff7f0e'},
        alpha=0.7
    )
    
    plt.title('NetPulse IDS - Visualizing Adversarial Concept Drift via PCA')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    
    output_image = 'concept_drift_pca.png'
    plt.savefig(output_image)
    print(f"Success! Map saved locally as '{output_image}'")

if __name__ == "__main__":
    run_drift_visualization()