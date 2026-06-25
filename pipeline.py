import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

def clean_production_dataset(filepath):
    print("--- 1. Initiating Industrial Data Deep Clean ---")
    # Using low_memory=False handles parsing variation columns smoothly
    df = pd.read_csv(filepath, low_memory=False)
    
    # Trim accidental spaces from column strings
    df.columns = df.columns.str.strip()
    
    # Remove metadata shortcuts to prevent model cheating
    forbidden_shortcuts = [
        'Flow ID', 'Source IP', 'Source IP Address', 
        'Destination IP', 'Destination IP Address', 
        'Timestamp', 'External Code'
    ]
    df.drop(columns=[col for col in forbidden_shortcuts if col in df.columns], errors='ignore', inplace=True)
    
    # Handle mathematical Infinity entries (e.g., zero-division packet rates)
    print("Replacing mathematical infinity strings and null fields...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Clean string labels to avoid case discrepancies (e.g., 'benign' vs 'BENIGN')
    if 'Label' in df.columns:
        df['Label'] = df['Label'].str.strip().str.upper()
    
    # Purge NaN rows cleanly
    pre_drop_count = len(df)
    df.dropna(inplace=True)
    post_drop_count = len(df)
    
    if pre_drop_count != post_drop_count:
        print(f"Purged {pre_drop_count - post_drop_count} unstable rows containing NaN values.")
        
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
    
if __name__ == "__main__":
    # Backwards compatible fallback to our sample data
    run_netpulse_pipeline("network_traffic_sample.csv")