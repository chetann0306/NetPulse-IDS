import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

def simulate_concept_drift():
    print("--- 1. Training Baseline Model on Normal Historical Traffic ---")
    # Load our original baseline sample data
    df_historical = pd.read_csv("network_traffic_sample.csv")
    X = df_historical.drop(columns=['Label'])
    y = df_historical['Label']
    
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train our standard baseline classifier
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    print("Baseline model successfully trained.")

    print("\n--- 2. Generating 'Drifted' Production Traffic (Adversarial Attacks) ---")
    # We simulate a futuristic environment where attackers stealthily slow down their rates
    # to bypass detection rules.
    n_drifted_samples = 2000
    drifted_data = []
    
    for _ in range(n_drifted_samples):
        # ADVERSARIAL DDOS: Attackers spread out packets over a longer duration
        # making it look less sudden, and use slightly more varied packet arrival timings.
        drifted_data.append({
            'Flow_Duration': np.random.uniform(500, 2000),      # Significantly longer than normal DDoS
            'Total_Fwd_Packets': np.random.randint(50, 200),    # Less dense packet counts
            'Total_Bwd_Packets': np.random.randint(2, 20),
            'Fwd_Packet_Length_Mean': np.random.uniform(40, 150), # Slightly larger payloads to mimic benign web pages
            'Flow_IAT_Mean': np.random.uniform(20, 100),        # Slower arrival rate (drifting signature)
            'Destination_Port': 80,
            'Label': 'DDoS'
        })

    df_drifted = pd.DataFrame(drifted_data)
    X_drifted = df_drifted.drop(columns=['Label'])
    y_drifted = df_drifted['Label']
    
    print(f"Created {n_drifted_samples} adversarial drifted DDoS attack flows.")

    print("\n--- 3. Evaluating Old Model Against Stealthier Drifted Attacks ---")
    # Scale new production features using our historical scale matrix
    X_drifted_scaled = scaler.transform(X_drifted)
    
    # Predict using our original model
    y_pred = model.predict(X_drifted_scaled)
    
    print("\nProduction Test Performance on Drifted Traffic:")
    print(classification_report(y_drifted, y_pred, zero_division=0))

if __name__ == "__main__":
    simulate_concept_drift()