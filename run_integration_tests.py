import os
import sys
import json
import time
from logger import log_incident
import generate_data
import pipeline
import auth_manager
import metrics_engine
import system_heartbeat

def execute_netpulse_test_suite():
    print("=" * 60)
    print("        NETPULSE IDPS - AUTOMATED INTEGRATION TEST SUITE       ")
    print("=" * 60)
    log_incident("INFO", "Starting automated system-wide integration tests...")

    # TEST PASS 1: Data Simulation Verification
    print("\n[TEST 1/5] Verifying Network Flow Data Generation Engine...")
    try:
        generate_data.generate_mock_traffic()
        if os.path.exists("network_traffic_sample.csv"):
            print("🟢 PASS: Sample traffic data successfully synthesized.")
        else:
            print("🔴 FAIL: Traffic data file generation target missed.")
            return False
    except Exception as e:
        print(f"🔴 FAIL: Data engine crashed: {str(e)}")
        return False

    # TEST PASS 2: Preprocessing and Core Modeling Evaluation
    print("\n[TEST 2/5] Verifying ML Ingestion & Preprocessing Training Pipelines...")
    try:
        # Pass the newly created synthetic data to our baseline trainer
        pipeline.run_netpulse_pipeline("network_traffic_sample.csv")
        print("🟢 PASS: Machine Learning model successfully trained and serialized.")
    except Exception as e:
        print(f"🔴 FAIL: Model pipeline training exception encountered: {str(e)}")
        return False

    # TEST PASS 3: Cryptographic Authentication and Role Validation Checks
    print("\n[TEST 3/5] Verifying Access Management & Credential Guardrails...")
    try:
        auth_manager.initialize_user_database()
        valid_auth, role = auth_manager.authenticate_user("admin", "admin123")
        invalid_auth, _ = auth_manager.authenticate_user("admin", "wrong_password_test")
        
        if valid_auth and role == "Admin" and not invalid_auth:
            print("🟢 PASS: Cryptographic token validation operating within secure boundaries.")
        else:
            print("🔴 FAIL: Authentication logic bypass window detected.")
            return False
    except Exception as e:
        print(f"🔴 FAIL: Access controller exception thrown: {str(e)}")
        return False

    # TEST PASS 4: Telemetry Metrics Calculation Integrity
    print("\n[TEST 4/5] Verifying Operational Telemetry Metrics Extraction...")
    try:
        metrics = metrics_engine.compute_realtime_dashboard_metrics()
        if metrics["total_flows_processed"] > 0 and metrics["system_status"] != "":
            print(f"🟢 PASS: Metrics compiled smoothly. Flows tracked: {metrics['total_flows_processed']}")
        else:
            print("🔴 FAIL: Telemetry engine extracted unparsed empty signatures.")
            return False
    except Exception as e:
        print(f"🔴 FAIL: Telemetry engine failed to pull calculations: {str(e)}")
        return False

    # TEST PASS 5: Host Diagnostics and Heartbeat Verifications
    print("\n[TEST 5/5] Verifying System Watchdog Heartbeat Status Output...")
    try:
        pulse = system_heartbeat.perform_system_health_audit()
        if pulse["status"] in ["HEALTHY", "WARNING"] and pulse["memory_footprint_mb"] > 0:
            print(f"🟢 PASS: System heartbeat daemon working. Registered PID: {pulse['pid']}")
        else:
            print("🔴 FAIL: Watchdog generated compromised state manifests.")
            return False
    except Exception as e:
        print(f"🔴 FAIL: Watchdog engine failed to analyze host resources: {str(e)}")
        return False

    print("\n" + "=" * 60)
    print(" ✅ ALL SYSTEM INTEGRATION TESTS PASSED FUNCTIONALLY! SYSTEM SECURE. ")
    print("=" * 60)
    log_incident("INFO", "Automation tests completed. All system metrics verified green.")
    return True

if __name__ == "__main__":
    success = execute_netpulse_test_suite()
    if not success:
        sys.exit(1) # Signal failure states to system execution shell runners