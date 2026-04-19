import requests
import time
from datetime import datetime

TARGET = "https://httpbin.org/get"

BURST_REQUESTS = 30
BURST_DELAY = 0.2   # fast requests
IDLE_TIME = 20      # silence period
CYCLES = 5

print("\n[INFO] Starting Burst + Idle Simulation\n")

for cycle in range(CYCLES):
    print(f"\n[INFO] Cycle {cycle+1}/{CYCLES} → BURST PHASE\n")

    # 🔴 BURST PHASE
    for i in range(BURST_REQUESTS):
        try:
            response = requests.get(TARGET, timeout=5)
            print(f"[{datetime.now()}] Burst Req {i+1} | Status: {response.status_code}")
        except Exception as e:
            print(f"[{datetime.now()}] Request Failed")

        time.sleep(BURST_DELAY)

    # 🔵 IDLE PHASE
    print(f"\n[INFO] IDLE PHASE → Sleeping for {IDLE_TIME} seconds\n")
    time.sleep(IDLE_TIME)

print("\n[INFO] Simulation Complete\n")