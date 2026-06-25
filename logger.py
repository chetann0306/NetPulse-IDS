import os
import logging
from datetime import datetime

# Define path for our permanent incident ledger
LOG_FILE_PATH = "netpulse_security_incidents.log"

def setup_netpulse_logger():
    """Configures the persistent logging file handler framework."""
    logger = logging.getLogger("NetPulse_IDS")
    
    # Avoid duplicate handlers if script is imported multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Create file handler which appends data logs permanently
        file_handler = logging.FileHandler(LOG_FILE_PATH, mode='a')
        
        # Structure formatting: Timestamp | Log Level | Module Message
        log_format = logging.Formatter('%(asctime)s | [%(levelname)s] | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(log_format)
        
        logger.addHandler(file_handler)
    return logger

def log_incident(severity, message):
    """
    Exposes a global helper function to easily record events across scripts.
    Severities: INFO, WARNING, ERROR, CRITICAL
    """
    logger = setup_netpulse_logger()
    severity = severity.upper()
    
    if severity == "INFO":
        logger.info(message)
    elif severity == "WARNING":
        logger.warning(message)
    elif severity == "ERROR":
        logger.error(message)
    elif severity == "CRITICAL":
        logger.critical(message)
        
    # Also print to terminal console screen simultaneously
    print(f"-> [LOGGED ALLOCATION]: {message}")

if __name__ == "__main__":
    print("Testing security logging framework configuration...")
    log_incident("INFO", "NetPulse IDS Logging Core Engine successfully initialized.")
    log_incident("CRITICAL", "Simulated intrusion spike vector detected on destination port 80!")