import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE

def run_smote_pipeline(filepath):
    print("--- 1. Loading Network Data ---")
    df = pd.read_csv(filepath)
    
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    print("\n--- 2. Splitting Data (Stratified) ---")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    print("Original training class distribution:")
    print(y_train.value_counts())
    
    print("\n--- 3. Applying SMOTE to Balance Classes ---")
    # SMOTE synthesizes new examples for minority attack classes in the training data
    smote = SMOTE(random_state=42)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    
    print("Resampled training class distribution:")
    print(y_train_resampled.value_counts())
    
    print("\n--- 4. Standardizing Features ---")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_resampled)
    X_test_scaled = scaler.transform(X_test)
    
    print("\n--- 5. Training Random Forest Classifier ---")
    # No class_weight needed now since SMOTE balanced our underlying dataset
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train_resampled)
    
    print("\n--- 6. Evaluating SMOTE NetPulse IDS ---")
    y_pred = model.predict(X_test_scaled)
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    run_smote_pipeline("network_traffic_sample.csv")