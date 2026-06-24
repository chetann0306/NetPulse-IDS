import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

def plot_feature_importance(filepath):
    print("--- Loading Data for Visualization ---")
    df = pd.read_csv(filepath)
    
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    # Quick train-test split
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    print("--- Training Temporary Model to Extract Weights ---")
    model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Calculate feature importances
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    # Create DataFrame for plotting
    feature_ranking = pd.DataFrame({
        'Feature': [X.columns[i] for i in indices],
        'Importance': [importances[i] for i in indices]
    })
    
    print("\n--- Generating Importance Plot ---")
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Importance', y='Feature', data=feature_ranking, palette='viridis')
    plt.title('NetPulse IDS - Feature Importance Ranking')
    plt.xlabel('Relative Importance Score')
    plt.ylabel('Network Traffic Metric')
    plt.tight_layout()
    
    # Save chart to root folder
    output_image = 'feature_importance.png'
    plt.savefig(output_image)
    print(f"Success! Chart saved locally as '{output_image}'")

if __name__ == "__main__":
    plot_feature_importance("network_traffic_sample.csv")