import os
import sys

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_target_file():
    real_dataset = "Friday-WorkingHours-Afternoon-PortScan.csv"
    synthetic_dataset = "network_traffic_sample.csv"
    
    if os.path.exists(real_dataset):
        print("\nAvailable datasets detected in root:")
        print(f"[1] Real Production Data ({real_dataset})")
        print(f"[2] Synthetic Traffic Sample ({synthetic_dataset})")
        
        file_choice = input("Select dataset to target (default is 1): ").strip()
        if file_choice == '2':
            return synthetic_dataset
        return real_dataset
        
    return synthetic_dataset

def main_menu():
    while True:
        clear_screen()
        print("=" * 60)
        print("                NETPULSE IDS - CONTROL CENTER                ")
        print("=" * 60)
        print("[1] Generate Synthetic Network Traffic Data")
        print("[2] Download Real-World CICIDS2017 Dataset (PortScan)")
        print("[3] Run Core ML Pipeline (Clean/Standard Preprocessor)")
        print("[4] Run Advanced Balanced Pipeline (SMOTE Handling)")
        print("[5] Generate Feature Importance Visualizations")
        print("[6] Execute Adversarial Concept Drift PCA Map")
        print("[7] Run Adaptive Monitoring & Retrain Trigger Loop")
        print("[8] Export High-Speed Static Rule Signatures")
        print("[9] Generate Executive Security Audit Report")
        print("[10] Run Deep Learning Sequential Engine (LSTM network)")
        print("[11] Start Live Network Sniffing & Real-Time ML Alerts")
        print("[12] Launch Multi-threaded Asynchronous Queue Processing")
        print("[13] Run Threat Geographic IP Mapping Audit")
        print("[14] Execute Firewall Lease Pruning & Table Sweep")
        print("[15] Execute System-Wide Automated Integration Tests")
        print("[0] Exit Dashboard")
        print("=" * 60)
        
        choice = input("Select a module to execute: ").strip()
        print("\n" + "-" * 60)
        
        if choice == '1':
            import generate_data
            generate_data.generate_mock_traffic()
            
        elif choice == '2':
            import download_dataset
            download_dataset.fetch_cicids_subset()
            
        elif choice == '3':
            import pipeline
            target = get_target_file()
            if not os.path.exists(target):
                print(f"[ERROR] Target file '{target}' missing! Run Option 1 or 2 first.")
            else:
                pipeline.run_netpulse_pipeline(target)
                
        elif choice == '4':
            import pipeline_smote
            target = get_target_file()
            if not os.path.exists(target):
                print(f"[ERROR] Target file '{target}' missing! Run Option 1 or 2 first.")
            else:
                pipeline_smote.run_smote_pipeline(target)
                
        elif choice == '5':
            import visualize
            target = get_target_file()
            if not os.path.exists(target):
                print(f"[ERROR] Target file '{target}' missing! Run Option 1 or 2 first.")
            else:
                visualize.plot_feature_importance(target)
                
        elif choice == '6':
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Drift simulation relies on 'network_traffic_sample.csv'. Please run Option 1 first.")
            else:
                import visualize_drift
                visualize_drift.run_drift_visualization()
                
        elif choice == '7':
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Continuous monitoring framework relies on 'network_traffic_sample.csv'. Please run Option 1 first.")
            else:
                import monitor_and_retrain
                monitor_and_retrain.run_adaptive_ids_monitor()
                
        elif choice == '8':
            import export_signatures
            export_signatures.run_signature_exporter()
            
        elif choice == '9':
            import generate_report
            generate_report.parse_logs_and_generate_report()
            
        elif choice == '10':
            target = get_target_file()
            if not os.path.exists(target):
                print(f"[ERROR] Target file '{target}' missing! Run Option 1 or 2 first.")
            else:
                import pipeline_lstm
                pipeline_lstm.run_lstm_pipeline(target)
                
        elif choice == '11':
            import sniffer
            sniffer.start_live_sniffing(packet_count=100)
            
        elif choice == '12':
            import packet_queue_manager
            packet_queue_manager.run_multithreaded_capture(packet_count=150)
            
        elif choice == '13':
            import threat_geo_mapper
            threat_geo_mapper.parse_logs_and_map_threats()
            
        elif choice == '14':
            import firewall_pruner
            firewall_pruner.prune_expired_firewall_rules()
            
        elif choice == '15':
            import run_integration_tests
            run_integration_tests.execute_netpulse_test_suite()
                
        elif choice == '0':
            print("Shutting down NetPulse IDS Console. Stay secure!")
            break
            
        else:
            print("Invalid selection. Please input a digit from 0 to 15.")
            
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main_menu()