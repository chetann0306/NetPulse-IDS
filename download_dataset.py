import os
import urllib.request

def fetch_cicids_subset():
    # URL targeting a verified data mirror for the Friday PortScan CSV profile
    dataset_url = "https://raw.githubusercontent.com/jubaer-b-a/CICIDS2017-CSV-Dataset/master/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    output_filename = "Friday-WorkingHours-Afternoon-PortScan.csv"
    
    if os.path.exists(output_filename):
        print(f"[{output_filename}] already exists in root folder. Skipping download.")
        return
        
    print(f"--- Downloading Real CICIDS2017 PortScan Subset ---")
    print("This might take a minute depending on your network connection...")
    
    try:
        urllib.request.urlretrieve(dataset_url, output_filename)
        print(f"Success! Real dataset saved locally as '{output_filename}'")
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        print("Please check your internet connection or URL mirror availability.")

if __name__ == "__main__":
    fetch_cicids_subset()