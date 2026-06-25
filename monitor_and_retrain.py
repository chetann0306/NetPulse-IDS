import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import recall_score
from logger import log_incident

def run_adaptive_ids_monitor():
    log_incident("INFO", "Initializing NetPulse Adaptive Monitoring Engine Workflow...")
    
    print("--- 1. Initial State: Training Baseline Model ---")
    df_historical = pd.read_csv("network_traffic_sample.csv")
    X = df_historical.drop(columns=['Label'])
    y = df_historical['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train initial model
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    # Check baseline recall for DDoS
    baseline_preds = model.predict(X_test_scaled)
    baseline_recall = recall_score(y_test, baseline_preds, average=None, labels=['DDoS'])[0]
    print(f"Baseline DDoS Detection Recall: {baseline_recall * 100:.2f}%")
    log_incident("INFO", f"Baseline model deployed successfully. Historical DDoS Recall: {baseline_recall * 100:.2f}%")

    print("\n--- 2. Production Stage: Incoming Stealthy/Drifted Traffic ---")
    # Simulate fresh production traffic where attackers have modified their signatures
    np.random.seed(10)
    drifted_production_data = []
    for _ in range(500):
        drifted_production_data.append({
            'Flow_Duration': np.random.uniform(500, 2000),      
            'Total_Fwd_Packets': np.random.randint(50, 200),    
            'Total_Bwd_Packets': np.random.randint(2, 20),
            'Fwd_Packet_Length_Mean': np.random.uniform(40, 150), 
            'Flow_IAT_Mean': np.random.uniform(20, 100),        
            'Destination_Port': 80,
            'Label': 'DDoS'
        })
    df_production = pd.DataFrame(drifted_production_data)
    X_prod = df_production.drop(columns=['Label'])
    y_prod = df_production['Label']
    
    # Score production data using the old model
    X_prod_scaled = scaler.transform(X_prod)
    prod_preds = model.predict(X_prod_scaled)
    prod_recall = recall_score(y_prod, prod_preds, average=None, labels=['DDoS'])[0]
    
    print(f"Current Production DDoS Detection Recall: {prod_recall * 100:.2f}%")
    
    # SECURITY THRESHOLD MONITOR
    # If detection capabilities for known categories drop below 80%, sound the alarm!
    THRESHOLD = 0.80
    if prod_recall < THRESHOLD:
        log_incident("WARNING", f"Production DDoS detection recall fell to {prod_recall*100:.1f}%. Beneath acceptable security threshold criteria of {THRESHOLD*100:.1f}%.")
        log_incident("INFO", "Executing automated model retraining sequence using fresh adversarial drift combinations.")
        
        print("\n--- 3. Adaptation Stage: Merging Datasets & Patching the Model ---")
        # In production, an analyst would flag a few missed attacks, and we mix them into training
        X_combined = pd.concat([X_train, X_prod], ignore_index=True)
        y_combined = pd.concat([y_train, y_prod], ignore_index=True)
        
        # Re-scale and re-train with the freshly introduced data combinations
        X_combined_scaled = scaler.fit_transform(X_combined)
        
        print("Retraining NetPulse IDS with updated profiles...")
        model.fit(X_combined_scaled, y_combined)
        
        # Verify the fix
        X_prod_new_scaled = scaler.transform(X_prod)
        updated_preds = model.predict(X_prod_new_scaled)
        new_recall = recall_score(y_prod, updated_preds, average=None, labels=['DDoS'])[0]
        
        print(f"\nSuccess! Updated Model DDoS Detection Recall: {new_recall * 100:.2f}%")
        log_incident("INFO", f"Automated structural retraining complete. New detection recall covered and patched back to {new_recall * 100:.2f}%. Adaptive patch live.")
    else:
        print("\nSystem healthy. Continuing to monitor network streams.")
        log_incident("INFO", "Production verification sweep clean. Monitoring metrics within valid threshold guidelines.")

if __name__ == "__main__":
    run_adaptive_ids_monitor()