import os
import time
from shared_intel import intel
from goalie import AntiScammerGoalie
from sentinel import RedCardSentinel

def run_patrol():
    goalie = AntiScammerGoalie()
    sentinel = RedCardSentinel()
    data_dir = "data/"
    
    print("--- LIVE PATROL ACTIVE: WATCHING DATA SECTOR ---")
    print("Drop a .txt file into the /data folder to test the agents...")
    
    while True:
        files = [f for f in os.listdir(data_dir) if f.endswith('.txt')]
        for file in files:
            file_path = os.path.join(data_dir, file)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print(f"\n[!] ALERT: New Data Detected in {file}")
            # Run Multilingual Analysis
            analysis = goalie.scan_intent(content)
            print(analysis)
            
            # Archive the file after analysis
            os.rename(file_path, f"data/archived_{int(time.time())}_{file}")
            print(f"[*] Report logged to Forensic Timeline. System Clear.")
            
        time.sleep(2) # Scan every 2 seconds

if __name__ == '__main__':
    run_patrol()
