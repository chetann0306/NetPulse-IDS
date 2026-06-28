import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, recall_score
from model_registry import save_model_snapshot

def clean_production_dataset(filepath):
    print("--- 1. Initiating Industrial Data Deep Clean ---")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()
    
    forbidden_shortcuts = [
        'Flow ID', 'Source IP', 'Source IP Address', 
        'Destination IP', 'Destination IP Address', 
        'Timestamp', 'External Code'
    ]
    df.drop(columns=[col for col in forbidden_shortcuts if col in df.columns], errors='ignore', inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    if 'Label' in df.columns:
        df['Label'] = df['Label'].str.strip().str.upper()
        
    df.dropna(inplace=True)
    return df

def run_netpulse_pipeline(filepath):
    df = clean_production_dataset(filepath)
    
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    print("\n--- 2. Partitioning Stratified Sets ---")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    print("\n--- 3. Standardizing Dynamic Ranges ---")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("\n--- 4. Initializing Core Classifier ---")
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    print("\n--- 5. Security Metric Audit ---")
    y_pred = model.predict(X_test_scaled)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Calculate recall performance index dynamically to pass onto registry manifest tags
    labels_present = np.unique(y_test)
    ddos_label = 'DDOS' if 'DDOS' in labels_present else labels_present[0]
    rec_score = recall_score(y_test, y_pred, average=None, labels=[ddos_label])[0]
    
    # Automatically snapshot model configuration attributes to disk
    save_model_snapshot(model, scaler, "STANDARD_RANDOM_FOREST", rec_score)
    
if __name__ == "__main__":
    run_netpulse_pipeline("network_traffic_sample.csv")