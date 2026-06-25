import os
import streamlit as pd
import pandas as pd
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

# Import our existing functional modules cleanly
import generate_data
import download_dataset
import pipeline
import pipeline_smote
import visualize
import visualize_drift
import monitor_and_retrain
import export_signatures
import generate_report

# Configure page layouts
st.set_page_config(page_title="NetPulse IDS Hub", page_icon="🛡️", layout="wide")

st.title("🛡️ NetPulse IDS - Interactive Security Control Center")
st.markdown("An adaptive Machine Learning framework built to counter network anomalies, adversarial concept drift, and severe class imbalances.")

st.sidebar.header("🕹️ Module Operations")
operation = st.sidebar.selectbox(
    "Choose a system component to execute:",
    [
        "System Overview & Data Status",
        "1. Generate Synthetic Data",
        "2. Download Real Dataset (CICIDS2017)",
        "3. Run ML Pipeline Analytics",
        "4. Feature Importance Visualization",
        "5. Adversarial PCA Drift Map",
        "6. Adaptive Retraining Control Loop",
        "7. Export Firewall Signatures",
        "8. Compile Executive Audit Report"
    ]
)

# Shared helper function to see what files exist
def get_file_status():
    has_synthetic = os.path.exists("network_traffic_sample.csv")
    has_real = os.path.exists("Friday-WorkingHours-Afternoon-PortScan.csv")
    return has_synthetic, has_real

has_synth, has_real = get_file_status()

# --- OPERATION PATHWAYS ---

if operation == "System Overview & Data Status":
    st.header("📊 Environmental Diagnostics")
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Synthetic Traffic Profile")
        if has_synth:
            st.success("🟢 Available (`network_traffic_sample.csv`)")
            df = pd.read_csv("network_traffic_sample.csv", nrows=5)
            st.dataframe(df)
        else:
            st.warning("🟡 Missing. Run Module 1 to generate simulated profiles.")
            
    with col2:
        st.subheader("Real Production Profile (CICIDS2017)")
        if has_real:
            st.success("🟢 Available (`Friday-WorkingHours-Afternoon-PortScan.csv`)")
            df = pd.read_csv("Friday-WorkingHours-Afternoon-PortScan.csv", nrows=5)
            st.dataframe(df)
        else:
            st.warning("🟡 Missing. Run Module 2 to download from live mirrors.")

elif operation == "1. Generate Synthetic Data":
    st.header("⚙️ Synthetic Network Data Synthesis")
    st.write("Generates a balanced distribution profile mapping Benign connections alongside simulated DDoS and PortScan signatures.")
    if st.button("Execute Data Generator Engine"):
        with st.spinner("Simulating network flows..."):
            generate_data.generate_mock_traffic()
            st.success("Dataset compiled successfully in root folder!")

elif operation == "2. Download Real Dataset (CICIDS2017)":
    st.header("📥 Live Benchmark Data Ingestion")
    st.write("Fetches the official corporate PortScan evaluation dataset profile from open repositories.")
    if st.button("Trigger Downloader Link"):
        with st.spinner("Downloading (this may take a moment)..."):
            download_dataset.fetch_cicids_subset()
            st.success("CICIDS2017 subset verified and locked locally!")

elif operation == "3. Run ML Pipeline Analytics":
    st.header("🧠 Classifier Model Performance Profiles")
    
    # Let user select which dataset to train on
    options = []
    if has_real: options.append("Real Production Data (CICIDS2017)")
    if has_synth: options.append("Synthetic Traffic Sample")
    
    if not options:
        st.error("No source data found in root folder! Please run Module 1 or 2 first.")
    else:
        target_sel = st.radio("Select Target Dataset for Training:", options)
        target_file = "Friday-WorkingHours-Afternoon-PortScan.csv" if "Real" in target_sel else "network_traffic_sample.csv"
        
        mode = st.selectbox("Select Core Algorithm Handling Mode:", ["Standard Preprocessor (Balanced Weights)", "Advanced SMOTE Over-sampling"])
        
        if st.button("Train Framework Classifier"):
            st.text("Processing logs and executing matrices...")
            # Redirect stdout briefly or manually handle string output capture for classification reports
            import io
            import sys
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            
            if mode == "Standard Preprocessor (Balanced Weights)":
                pipeline.run_netpulse_pipeline(target_file)
            else:
                pipeline_smote.run_smote_pipeline(target_file)
                
            sys.stdout = old_stdout
            st.text_area("Model Training Logs & Final Classification Audit", buffer.getvalue(), height=400)

elif operation == "4. Feature Importance Visualization":
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

elif operation == "5. Adversarial PCA Drift Map":
    st.header("📉 Multi-dimensional Concept Drift Visualizer")
    st.write("Maps your high-dimensional network attributes into reduced 2D spatial coordinates to expose attack migrations.")
    if not has_synth:
        st.error("Please run Option 1 first. Drift vectors require the default baseline file structure.")
    else:
        if st.button("Generate PCA Scatter Plot"):
            with st.spinner("Computing dimensional components..."):
                visualize_drift.run_drift_visualization()
                if os.path.exists("concept_drift_pca.png"):
                    st.image("concept_drift_pca.png", caption="Adversarial Vector Convergence Map")

elif operation == "6. Adaptive Retraining Control Loop":
    st.header("🔄 Self-Healing Telemetry Loop Dashboard")
    if not has_synth:
        st.error("Baseline dataset sample required to benchmark live drift transitions.")
    else:
        if st.button("Launch Adaptive Stream Verification"):
            import io, sys
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            
            monitor_and_retrain.run_adaptive_ids_monitor()
            
            sys.stdout = old_stdout
            st.text_area("Self-Healing System Execution Matrix Logs", buffer.getvalue(), height=350)

elif operation == "7. Export Firewall Signatures":
    st.header("💾 High-Speed Low-Latency Signature Rule Builder")
    if st.button("Compile ML Boundaries Into Text Rules"):
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        
        export_signatures.run_signature_exporter()
        
        sys.stdout = old_stdout
        st.text_area("Exporter Operational Logs", buffer.getvalue(), height=150)
        
        if os.path.exists("netpulse_exported_signatures.rules"):
            with open("netpulse_exported_signatures.rules", "r") as f:
                st.code(f.read(), language="text")

elif operation == "8. Compile Executive Audit Report":
    st.header("📄 Executive Security Audit Documentation Generator")
    if st.button("Parse Logs & Generate Executive Markdown"):
        generate_report.parse_logs_and_generate_report()
        if os.path.exists("netpulse_executive_summary.md"):
            st.success("Markdown summary compiled successfully!")
            with open("netpulse_executive_summary.md", "r") as f:
                st.markdown(f.read())