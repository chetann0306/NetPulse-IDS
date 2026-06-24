import os
import sys

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    while True:
        clear_screen()
        print("=" * 50)
        print("          NETPULSE IDS - MANAGEMENT DASHBOARD          ")
        print("=" * 50)
        print("[1] Generate Synthetic Network Traffic Data")
        print("[2] Run Core ML Pipeline (Random Forest baseline)")
        print("[3] Run Advanced Balanced Pipeline (SMOTE)")
        print("[4] Generate Feature Importance Visualizations")
        print("[5] Execute Adversarial Concept Drift PCA Map")
        print("[6] Run Adaptive Monitoring & Retrain Trigger Loop")
        print("[0] Exit Dashboard")
        print("=" * 50)
        
        choice = input("Select a module to execute: ").strip()
        
        print("\n" + "-" * 50)
        if choice == '1':
            import generate_data
            generate_data.generate_mock_traffic()
        elif choice == '2':
            import pipeline
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Please run Option 1 first to generate data!")
            else:
                pipeline.run_netpulse_pipeline("network_traffic_sample.csv")
        elif choice == '3':
            import pipeline_smote
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Please run Option 1 first to generate data!")
            else:
                pipeline_smote.run_smote_pipeline("network_traffic_sample.csv")
        elif choice == '4':
            import visualize
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Please run Option 1 first to generate data!")
            else:
                visualize.plot_feature_importance("network_traffic_sample.csv")
        elif choice == '5':
            import visualize_drift
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Please run Option 1 first to generate data!")
            else:
                visualize_drift.run_drift_visualization()
        elif choice == '6':
            if not os.path.exists("network_traffic_sample.csv"):
                print("[ERROR] Please run Option 1 first to generate data!")
            else:
                import monitor_and_retrain
                monitor_and_retrain.run_adaptive_ids_monitor()
        elif choice == '0':
            print("Shutting down NetPulse IDS Console. Stay secure!")
            break
        else:
            print("Invalid selection. Try again.")
            
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main_menu()