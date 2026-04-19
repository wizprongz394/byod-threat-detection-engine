import requests
import time
from datetime import datetime

SEQUENCE = [
    "https://httpbin.org/headers",
    "https://httpbin.org/ip",
    "https://httpbin.org/user-agent"
]

CYCLES = 15
DELAY_BETWEEN_REQUESTS = 1
DELAY_BETWEEN_CYCLES = 5

print("\n[INFO] Starting Session Replay Simulation\n")

for cycle in range(CYCLES):
    print(f"\n[INFO] Cycle {cycle+1}/{CYCLES} → Running Sequence\n")

    for step, url in enumerate(SEQUENCE):
        try:
            response = requests.get(url, timeout=5)
            print(f"[{datetime.now()}] Step {step+1} → {url} | Status: {response.status_code}")
        except Exception:
            print(f"[{datetime.now()}] FAILED → {url}")

        time.sleep(DELAY_BETWEEN_REQUESTS)

    print(f"[INFO] Cycle complete → sleeping {DELAY_BETWEEN_CYCLES}s\n")
    time.sleep(DELAY_BETWEEN_CYCLES)

print("\n[INFO] Simulation Complete\n")