import os
import json
import pandas as pd
import numpy as np
import streamlit as st
import io
import sys

# Import functional modules cleanly
import generate_data
import download_dataset
import pipeline
import pipeline_smote
import visualize
import visualize_drift
import monitor_and_retrain
import export_signatures
import generate_report
import pipeline_lstm
import sniffer
import packet_queue_manager
import model_registry
import threat_geo_mapper
import auth_manager
import metrics_engine
import system_heartbeat
import firewall_pruner

st.set_page_config(page_title="NetPulse IDS Hub", page_icon="🛡️", layout="wide")

# --- USER AUTHENTICATION STATE TRACKING ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
    st.session_state["user_role"] = None

if not st.session_state["authenticated"]:
    st.title("🔒 NetPulse IDPS - Gatekeeper Secure Login")
    st.markdown("Authorized Security Personnel Only. Access attempts are recorded inside the immutable operational log ledger.")
    
    col1, col2 = st.columns(2)
    with col1:
        login_user = st.text_input("Username:")
        login_pass = st.text_input("Password:", type="password")
        
        if st.button("Authenticate and Enter Console"):
            success, role = auth_manager.authenticate_user(login_user, login_pass)
            if success:
                st.session_state["authenticated"] = True
                st.session_state["user_role"] = role
                st.success(f"Access Granted. Profile Role: {role}")
                st.rerun()
            else:
                st.error("Access Denied. Invalid credential signature combination.")
    st.stop()

# --- SECURED APPLICATION REGION ---
user_role = st.session_state["user_role"]

st.title("🛡️ NetPulse IDS - Interactive Security Control Center")
st.markdown(f"Logged in as: **{user_role}** Profile")

if st.sidebar.button("Logout of System"):
    st.session_state["authenticated"] = False
    st.session_state["user_role"] = None
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("🕹️ Module Operations")

menu_options = ["System Overview & Data Status"]

if user_role in ["Admin", "Analyst"]:
    menu_options.extend([
        "3. Run ML Pipeline Analytics",
        "8. Feature Importance Visualization",
        "9. Adversarial PCA Drift Map",
        "12. Threat Geographic Mapping Radar",
        "13. Compile Executive Audit Report"
    ])

if user_role == "Admin":
    menu_options.extend([
        "1. Generate Synthetic Data",
        "2. Download Real Dataset (CICIDS2017)",
        "4. Model Registry & Version Rollbacks",
        "5. Run Deep Learning Sequence Engine (LSTM)",
        "6. Start Live Sniffing & Real-Time ML Alerts",
        "7. Asynchronous Multi-threaded Capture UI",
        "10. Adaptive Retraining Control Loop",
        "11. Export Firewall Signatures",
        "14. Active Firewall Lease Manager"
    ])

overview = [menu_options[0]]
rest = sorted(menu_options[1:])
menu_options = overview + rest

operation = st.sidebar.selectbox("Choose an authorized system component to execute:", menu_options)

def get_file_status():
    has_synthetic = os.path.exists("network_traffic_sample.csv")
    has_real = os.path.exists("Friday-WorkingHours-Afternoon-PortScan.csv")
    return has_synthetic, has_real

has_synth, has_real = get_file_status()

# --- OPERATION PATHWAYS ---

if operation == "System Overview & Data Status":
    st.header("📊 Executive Telemetry Hub")
    
    heartbeat_pulse = system_heartbeat.perform_system_health_audit()
    live_metrics = metrics_engine.compute_realtime_dashboard_metrics()
    
    status_color = "green"
    if heartbeat_pulse["status"] == "WARNING":
        status_color = "orange"
    elif heartbeat_pulse["status"] in ["DEGRADED", "CRITICAL_FAILURE"]:
        status_color = "red"
        
    st.markdown(f"### Watchdog Pulse: :{status_color}[{heartbeat_pulse['status']}] (PID: {heartbeat_pulse['pid']})")
    
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric(label="Total Connections Processed", value=f"{live_metrics['total_flows_processed']:,}")
    with m_col2:
        st.metric(label="Detected Malicious Attack Vectors", value=f"{live_metrics['threat_count']:,}")
    with m_col3:
        st.metric(label="Average Flow Duration", value=f"{live_metrics['avg_flow_duration_ms']:.1f} ms")
    with m_col4:
        st.metric(label="Memory Footprint", value=f"{heartbeat_pulse['memory_footprint_mb']} MB")

    if heartbeat_pulse["diagnostics"]:
        st.info(f"**Diagnostic Output:** {heartbeat_pulse['diagnostics'][0]}")

    st.markdown("---")
    st.header("📋 Environmental Diagnostics")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Synthetic Traffic Profile")
        if has_synth:
            st.success("🟢 Available (`network_traffic_sample.csv`)")
            st.dataframe(pd.read_csv("network_traffic_sample.csv", nrows=5))
        else:
            st.warning("🟡 Missing. Run Module 1 to generate simulated profiles.")
    with col2:
        st.subheader("Real Production Profile (CICIDS2017)")
        if has_real:
            st.success("🟢 Available (`Friday-WorkingHours-Afternoon-PortScan.csv`)")
            st.dataframe(pd.read_csv("Friday-WorkingHours-Afternoon-PortScan.csv", nrows=5))
        else:
            st.warning("🟡 Missing. Run Module 2 to download from live mirrors.")

elif operation == "1. Generate Synthetic Data":
    st.header("⚙️ Synthetic Network Data Synthesis")
    if st.button("Execute Data Generator Engine"):
        with st.spinner("Simulating network flows..."):
            generate_data.generate_mock_traffic()
            st.success("Dataset compiled successfully in root folder!")

elif operation == "2. Download Real Dataset (CICIDS2017)":
    st.header("📥 Live Benchmark Data Ingestion")
    if st.button("Trigger Downloader Link"):
        with st.spinner("Downloading (this may take a moment)..."):
            download_dataset.fetch_cicids_subset()
            st.success("CICIDS2017 subset verified and locked locally!")

elif operation == "3. Run ML Pipeline Analytics":
    st.header("🧠 Classifier Model Performance Profiles")
    options = []
    if has_real: options.append("Real Production Data (CICIDS2017)")
    if has_synth: options.append("Synthetic Traffic Sample")
    
    if not options:
        st.error("No source data found in root folder! Please run Module 1 or 2 first.")
    else:
        target_sel = st.radio("Select Target Dataset for Training:", options, key="ml_target")
        target_file = "Friday-WorkingHours-Afternoon-PortScan.csv" if "Real" in target_sel else "network_traffic_sample.csv"
        mode = st.selectbox("Select Core Algorithm Handling Mode:", ["Standard Preprocessor (Balanced Weights)", "Advanced SMOTE Over-sampling"])
        
        if st.button("Train Framework Classifier"):
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            if mode == "Standard Preprocessor (Balanced Weights)":
                pipeline.run_netpulse_pipeline(target_file)
            else:
                pipeline_smote.run_smote_pipeline(target_file)
            sys.stdout = old_stdout
            st.text_area("Model Training Logs & Final Classification Audit", buffer.getvalue(), height=400)

elif operation == "4. Model Registry & Version Rollbacks":
    st.header("🗄️ Model Registry Manifest Auditing")
    model_registry.initialize_registry()
    if os.path.exists(model_registry.MANIFEST_FILE):
        with open(model_registry.MANIFEST_FILE, "r") as f:
            manifest = json.load(f)
        active_v = manifest.get("active_version")
        st.metric(label="Active Production Version", value=str(active_v))
        models_dict = manifest.get("models", {})
        if models_dict:
            df_manifest = pd.DataFrame.from_dict(models_dict, orient='index')
            st.subheader("Saved Snapshot History Database")
            st.dataframe(df_manifest)
            st.subheader("🔧 Trigger Version Switch Rollback")
            available_versions = list(models_dict.keys())
            selected_v = st.selectbox("Select target model version tag to activate:", available_versions, index=available_versions.index(active_v) if active_v in available_versions else 0)
            if st.button("Deploy Selected Version to Active Stream"):
                manifest["active_version"] = selected_v
                with open(model_registry.MANIFEST_FILE, "w") as f:
                    json.dump(manifest, f, indent=4)
                st.success(f"Production pipeline successfully swapped to engine version {selected_v}!")
                st.rerun()
        else:
            st.info("No serialized snapshots found in the local registry files yet.")

elif operation == "5. Run Deep Learning Sequence Engine (LSTM)":
    st.header("🧬 Recurrent Neural Network Sequential Assessment")
    options = []
    if has_real: options.append("Real Production Data (CICIDS2017)")
    if has_synth: options.append("Synthetic Traffic Sample")
    
    if not options:
        st.error("No source data found in root folder! Please run Module 1 or 2 first.")
    else:
        target_sel = st.radio("Select Target Dataset for Deep Learning:", options, key="dl_target")
        target_file = "Friday-WorkingHours-Afternoon-PortScan.csv" if "Real" in target_sel else "network_traffic_sample.csv"
        if st.button("Initialize and Train LSTM Model"):
            with st.spinner("Allocating tensors and running optimization loops..."):
                old_stdout = sys.stdout
                sys.stdout = buffer = io.StringIO()
                pipeline_lstm.run_lstm_pipeline(target_file)
                sys.stdout = old_stdout
                st.text_area("PyTorch LSTM Recurrent Performance Matrix Logs", buffer.getvalue(), height=400)

elif operation == "6. Start Live Sniffing & Real-Time ML Alerts":
    st.header("📡 Live Interface Network Sniffer & ML Evaluator")
    packets_to_sniff = st.slider("Select Packet Window Count to Capture:", min_value=20, max_value=500, value=100, step=20, key="single_sniff")
    if st.button("Engage Real-Time Packet Capture Loop"):
        st.warning("Listening to live local card traffic interface...")
        with st.spinner("Capturing live flow frames..."):
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            sniffer.start_live_sniffing(packet_count=packets_to_sniff)
            sys.stdout = old_stdout
            st.text_area("Real-Time ML Intrusion Detection Log Stream", buffer.getvalue(), height=400)

elif operation == "7. Asynchronous Multi-threaded Capture UI":
    st.header("🔀 Asynchronous Producer-Consumer Pipeline Dashboard")
    parallel_packets = st.slider("Select Concurrent Packet Capture Size:", min_value=50, max_value=1000, value=200, step=50, key="multi_sniff")
    if st.button("Launch Concurrent Thread Pool"):
        st.info("Spawning parallel threads. Wire Ingestion active.")
        with st.spinner("Processing asynchronous queue pipelines..."):
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            packet_queue_manager.run_multithreaded_capture(packet_count=parallel_packets)
            sys.stdout = old_stdout
            st.text_area("Multi-threaded Pipeline Execution Ledger", buffer.getvalue(), height=400)

elif operation == "8. Feature Importance Visualization":
    st.header("🎨 Interpretability Dashboard: Feature Rankings")
    target_file = "network_traffic_sample.csv" if has_synth else ("Friday-WorkingHours-Afternoon-PortScan.csv" if has_real else None)
    if not target_file:
        st.error("Generate or download a file to visualize metrics.")
    else:
        if st.button("Extract & Render Importances"):
            with st.spinner("Plotting metric shapes..."):
                visualize.plot_feature_importance(target_file)
                if os.path.exists("feature_importance.png"):
                    st.image("feature_importance.png", caption="Model Feature Importance Chart")

elif operation == "9. Adversarial Concept Drift PCA Map":
    st.header("📉 Multi-dimensional Concept Drift Visualizer")
    if not has_synth:
        st.error("Please run Option 1 first. Drift vectors require the default baseline file structure.")
    else:
        if st.button("Generate PCA Scatter Plot"):
            with st.spinner("Computing dimensional components..."):
                visualize_drift.run_drift_visualization()
                if os.path.exists("concept_drift_pca.png"):
                    st.image("concept_drift_pca.png", caption="Adversarial Vector Convergence Map")

elif operation == "10. Adaptive Retraining Control Loop":
    st.header("🔄 Self-Healing Telemetry Loop Dashboard")
    if not has_synth:
        st.error("Baseline dataset sample required to benchmark live drift transitions.")
    else:
        if st.button("Launch Adaptive Stream Verification"):
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            monitor_and_retrain.run_adaptive_ids_monitor()
            sys.stdout = old_stdout
            st.text_area("Self-Healing System Execution Matrix Logs", buffer.getvalue(), height=350)

elif operation == "11. Export Firewall Signatures":
    st.header("💾 High-Speed Low-Latency Signature Rule Builder")
    if st.button("Compile ML Boundaries Into Text Rules"):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        export_signatures.run_signature_exporter()
        sys.stdout = old_stdout
        st.text_area("Exporter Operational Logs", buffer.getvalue(), height=150)
        if os.path.exists("netpulse_exported_signatures.rules"):
            with open("netpulse_exported_signatures.rules", "r") as f:
                st.code(f.read(), language="text")

elif operation == "12. Threat Geographic Mapping Radar":
    st.header("🌍 Forensic Attack Distribution Map")
    if st.button("Parse Forensic Logs & Refresh Map Coordinates"):
        with st.spinner("Querying secure geolocation intelligence mirrors..."):
            threat_geo_mapper.parse_logs_and_map_threats()
            
    if os.path.exists(threat_geo_mapper.GEO_REPORT_PATH):
        with open(threat_geo_mapper.GEO_REPORT_PATH, "r") as f:
            geo_data = json.load(f)
        if geo_data:
            map_points = []
            for ip, info in geo_data.items():
                if info["lat"] != 0.0 and info["lon"] != 0.0:
                    map_points.append({"latitude": info["lat"], "longitude": info["lon"], "IP": ip, "Location": f"{info['city']}, {info['country']}"})
            if map_points:
                df_map = pd.DataFrame(map_points)
                st.subheader("Live Threat Location Plotter")
                st.map(df_map)
                st.subheader("Geographic Intelligence Audit Log")
                st.dataframe(df_map[["IP", "Location", "latitude", "longitude"]])
            else:
                st.info("Log database entries contain internal or non-routable private addresses.")
        else:
            st.info("Geographic manifest is currently empty.")
    else:
        st.info("No geographic registry log found.")

elif operation == "14. Active Firewall Lease Manager":
    st.header("🧱 Active Firewall Lease Configuration Control")
    st.write("Tracks time-to-live (TTL) allocations applied to blocked threat nodes and manages active rule removals.")
    
    if st.button("Execute Active Table Pruning Sweep"):
        with st.spinner("Sweeping operating system firewall tables..."):
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            firewall_pruner.prune_expired_firewall_rules()
            sys.stdout = old_stdout
            st.text_area("Pruner Execution Output Logs", buffer.getvalue(), height=150)

    if os.path.exists(firewall_pruner.LEASES_MANIFEST_FILE):
        with open(firewall_pruner.LEASES_MANIFEST_FILE, "r") as f:
            try:
                leases_data = json.load(f)
            except json.JSONDecodeError:
                leases_data = {}
        if leases_data:
            df_leases = pd.DataFrame.from_dict(leases_data, orient='index')
            st.subheader("Current Active Ban Lease Ledger")
            st.dataframe(df_leases)
        else:
            st.info("No active firewall IP ban leases recorded in the database manifest.")
    else:
        st.info("No active firewall tracking manifest found on disk.")

elif operation == "13. Compile Executive Audit Report":
    st.header("📄 Executive Security Audit Documentation Generator")
    if st.button("Parse Logs & Generate Executive Markdown"):
        generate_report.parse_logs_and_generate_report()
        if os.path.exists("netpulse_executive_summary.md"):
            st.success("Markdown summary compiled successfully!")
            with open("netpulse_executive_summary.md", "r") as f:
                st.markdown(f.read())