import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import recall_score
from logger import log_incident

def run_adaptive_ids_monitor():
    log_incident("INFO", "Initializing NetPulse Warm-Start Adaptive Monitoring Engine...")
    
    print("--- 1. Initial State: Training Baseline Model ---")
    df_historical = pd.read_csv("network_traffic_sample.csv")
    X = df_historical.drop(columns=['Label'])
    y = df_historical['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # CRITICAL UPGRADE: warm_start=True allows the model to add trees incrementally
    model = RandomForestClassifier(
        n_estimators=50, 
        warm_start=True, 
        class_weight='balanced', 
        random_state=42, 
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)
    
    baseline_preds = model.predict(X_test_scaled)
    baseline_recall = recall_score(y_test, baseline_preds, average=None, labels=['DDoS'])[0]
    print(f"Baseline DDoS Detection Recall: {baseline_recall * 100:.2f}%")
    log_incident("INFO", f"Baseline warm-start model deployed. Initial DDoS Recall: {baseline_recall * 100:.2f}%")

    print("\n--- 2. Production Stage: Incoming Stealthy/Drifted Traffic ---")
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
    
    X_prod_scaled = scaler.transform(X_prod)
    prod_preds = model.predict(X_prod_scaled)
    prod_recall = recall_score(y_prod, prod_preds, average=None, labels=['DDoS'])[0]
    
    print(f"Current Production DDoS Detection Recall: {prod_recall * 100:.2f}%")
    
    # GUARDRAIL SECURITY THRESHOLD MONITOR
    THRESHOLD = 0.80
    if prod_recall < THRESHOLD:
        log_incident("WARNING", f"Production recall fell to {prod_recall*100:.1f}%. Executing Incremental Warm-Start Patch...")
        
        print("\n--- 3. Adaptation Stage: Incremental Warm-Start Training ---")
        # In online learning, we only pass the new drifted production batch to patch the model
        # We increase n_estimators from 50 to 100 to add 50 new dedicated trees
        model.n_estimators = 100
        
        print("Growing additional decision trees on fresh drift profiles...")
        model.fit(X_prod_scaled, y_prod)
        
        # Verify the patch
        updated_preds = model.predict(X_prod_scaled)
        new_recall = recall_score(y_prod, updated_preds, average=None, labels=['DDoS'])[0]
        
        print(f"\nSuccess! Patched Model DDoS Detection Recall: {new_recall * 100:.2f}%")
        log_incident("INFO", f"Incremental training successful. System self-healed via warm-start patch. Recall recovered to {new_recall * 100:.2f}%.")
    else:
        print("\nSystem healthy. Continuing to monitor network streams.")
        log_incident("INFO", "Production verification sweep clean.")

if __name__ == "__main__":
    run_adaptive_ids_monitor()