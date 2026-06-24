import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

def run_pipeline(filepath):
    print("--- Loading Network Data ---")
    df = pd.read_csv(filepath)
    
    # Handle clean data splits
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    # Using stratify=y to properly handle class imbalance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Standardize numerical ranges
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("--- Training NetPulse Classifier ---")
    # Using balanced class weights to compensate for rare attack instances
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    print("--- Model Performance Metrics ---")
    y_pred = model.predict(X_test_scaled)
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    run_pipeline("network_traffic_sample.csv")