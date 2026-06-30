import hashlib
import json
import os
from logger import log_incident

USER_DB_FILE = "netpulse_users.json"

def hash_password(password):
    """Generates a secure SHA-256 hash of a plain text password."""
    return hashlib.sha256(password.encode()).hexdigest()

def initialize_user_database():
    """Initializes default admin and analyst credentials securely if missing."""
    if not os.path.exists(USER_DB_FILE):
        default_db = {
            "admin": {
                "password_hash": hash_password("admin123"),
                "role": "Admin"
            },
            "analyst": {
                "password_hash": hash_password("analyst123"),
                "role": "Analyst"
            }
        }
        with open(USER_DB_FILE, "w") as f:
            json.dump(default_db, f, indent=4)
        log_incident("INFO", "Secured User Credential Database initialized with default profiles.")

def authenticate_user(username, password):
    """
    Validates entered credentials against the secure database ledger.
    Returns (True, role) if valid, or (False, None) if validation fails.
    """
    initialize_user_database()
    username = username.strip().lower()
    
    with open(USER_DB_FILE, "r") as f:
        user_db = json.load(f)
        
    if username in user_db:
        target_hash = hash_password(password)
        if user_db[username]["password_hash"] == target_hash:
            role = user_db[username]["role"]
            log_incident("INFO", f"User '{username}' successfully authenticated with role: [{role}]")
            return True, role
            
    log_incident("WARNING", f"FAILED AUTHENTICATION ATTEMPT: Invalid login signature for username: '{username}'")
    return False, None

if __name__ == "__main__":
    print("Testing cryptographic authentication engine mappings...")
    initialize_user_database()
    success, role = authenticate_user("admin", "admin123")
    print(f"Auth Success Status: {success} | Bound Role Vector: {role}")