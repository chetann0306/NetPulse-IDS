import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
from logger import log_incident

# Ensure reproducibility
torch.manual_seed(42)
np.random.seed(42)

# Define the LSTM Architecture
class NetPulseLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes):
        super(NetPulseLSTM, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        # batch_first=True expects input shape: (batch, sequence_length, features)
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, num_classes)
        
    def forward(self, x):
        # Initialize hidden state and cell state
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        
        # Forward propagate LSTM
        out, _ = self.lstm(x, (h0, c0))
        
        # Decode the hidden state of the last time step
        out = self.fc(out[:, -1, :])
        return out

def create_sequences(X, y, time_steps=5):
    """Reshapes raw 2D tabular flows into 3D sequential time windows."""
    X_seq, y_seq = [], []
    for i in range(len(X) - time_steps + 1):
        X_seq.append(X[i : (i + time_steps)])
        # Label the entire sequence by its final event token
        y_seq.append(y[i + time_steps - 1])
    return np.array(X_seq), np.array(y_seq)

def run_lstm_pipeline(filepath):
    log_incident("INFO", f"Initiating Deep Learning Sequence Pipeline on target: {filepath}")
    
    # 1. Load and clean dataset
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()
    
    forbidden_shortcuts = ['Flow ID', 'Source IP', 'Source IP Address', 'Destination IP', 'Destination IP Address', 'Timestamp']
    df.drop(columns=[col for col in forbidden_shortcuts if col in df.columns], errors='ignore', inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Encode categorical text labels to numeric values
    encoder = LabelEncoder()
    df['Label'] = encoder.fit_transform(df['Label'].str.strip().str.upper())
    num_classes = len(encoder.classes_)
    
    X = df.drop(columns=['Label']).values
    y = df['Label'].values
    
    # 2. Standardize features before sequence cutting
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 3. Create Sequence Matrix Windows
    TIME_STEPS = 5
    X_seq, y_seq = create_sequences(X_scaled, y, time_steps=TIME_STEPS)
    
    # Stratified split based on sequential labels
    X_train, X_test, y_train, y_test = train_test_split(
        X_seq, y_seq, test_size=0.3, random_state=42, stratify=y_seq
    )
    
    # Convert vectors into explicit PyTorch Tensors
    train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train))
    test_dataset = TensorDataset(torch.FloatTensor(X_test), torch.LongTensor(y_test))
    
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)
    
    # 4. Initialize Network parameters
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = NetPulseLSTM(input_size=X.shape[1], hidden_size=32, num_layers=2, num_classes=num_classes).to(device)
    
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005)
    
    # 5. Execution Training Loop
    print(f"--- Training Sequence Model on {device} ---")
    model.train()
    for epoch in range(3): # Short optimization pass for local processing speed
        epoch_loss = 0
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        print(f"Epoch {epoch+1}/3 | Cumulative Sequence Loss: {epoch_loss:.4f}")
        
    # 6. Evaluation metrics audit
    print("\n--- Deep Sequence Performance Audit ---")
    model.eval()
    all_preds, all_targets = [], []
    
    with torch.no_grad():
        for batch_X, batch_y in test_loader:
            batch_X = batch_X.to(device)
            outputs = model(batch_X)
            preds = torch.argmax(outputs, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(batch_y.numpy())
            
    # Decode integers back into human-readable target labels
    target_names = [str(cls) for cls in encoder.classes_]
    print(classification_report(all_targets, all_preds, target_names=target_names, zero_division=0))
    log_incident("INFO", "LSTM Sequential Neural Network training session complete.")

if __name__ == "__main__":
    if os.path.exists("network_traffic_sample.csv"):
        run_lstm_pipeline("network_traffic_sample.csv")
    else:
        print("[ERROR] Please generate baseline traffic via the dashboard interface first.")