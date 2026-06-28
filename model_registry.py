import os
import json
import joblib
from datetime import datetime
from logger import log_incident

REGISTRY_DIR = "model_registry"
MANIFEST_FILE = os.path.join(REGISTRY_DIR, "registry_manifest.json")

def initialize_registry():
    """Creates the structural folder environments for model snapshots."""
    if not os.path.exists(REGISTRY_DIR):
        os.makedirs(REGISTRY_DIR)
    if not os.path.exists(MANIFEST_FILE):
        with open(MANIFEST_FILE, "w") as f:
            json.dump({"active_version": None, "models": {}}, f, indent=4)

def save_model_snapshot(model, scaler, pipeline_type, performance_recall):
    """Serializes model and scaler arrays to disk, indexing metadata manifests."""
    initialize_registry()
    
    # Generate unique semantic version tags using precise timestamps
    version_id = datetime.now().strftime("v_%Y%m%d_%H%M%S")
    model_filename = f"netpulse_model_{version_id}.pkl"
    scaler_filename = f"netpulse_scaler_{version_id}.pkl"
    
    model_path = os.path.join(REGISTRY_DIR, model_filename)
    scaler_path = os.path.join(REGISTRY_DIR, scaler_filename)
    
    # Serialize binary objects to local file storage paths
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    # Update JSON manifest database records
    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)
        
    manifest["models"][version_id] = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pipeline_type": pipeline_type,
        "ddos_recall_score": f"{performance_recall * 100:.2f}%",
        "model_file": model_path,
        "scaler_file": scaler_path
    }
    manifest["active_version"] = version_id
    
    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=4)
        
    log_incident("INFO", f"Saved new model snapshot to registry registry: {version_id} ({pipeline_type})")
    return version_id

def load_active_model_snapshot():
    """Loads the designated operational model and scaling objects directly from disk."""
    initialize_registry()
    
    if not os.path.exists(MANIFEST_FILE):
        return None, None
        
    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)
        
    active_version = manifest.get("active_version")
    if not active_version or active_version not in manifest["models"]:
        return None, None
        
    model_meta = manifest["models"][active_version]
    
    log_incident("INFO", f"Loading active operational model blueprint version: {active_version}")
    model = joblib.load(model_meta["model_file"])
    scaler = joblib.load(model_meta["scaler_file"])
    return model, scaler

if __name__ == "__main__":
    # Test execution trace
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    
    print("Testing operational model registry pathways...")
    mock_model = RandomForestClassifier(n_estimators=10)
    mock_scaler = StandardScaler()
    
    v_tag = save_model_snapshot(mock_model, mock_scaler, "TEST_BASELINE", 0.985)
    print(f"Verified Serialization. Registered entry tag output: {v_tag}")