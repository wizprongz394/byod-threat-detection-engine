import requests
import time
from datetime import datetime

TARGET = "https://httpbin.org/delay/5"

REQUESTS = 12
DELAY_BETWEEN = 15  # long gap

print("\n[INFO] Starting Low & Slow Simulation\n")

for i in range(REQUESTS):
    try:
        response = requests.get(TARGET, timeout=10)
        print(f"[{datetime.now()}] Req {i+1}/{REQUESTS} | Status: {response.status_code}")
    except Exception:
        print(f"[{datetime.now()}] Request Failed")

    print(f"[INFO] Sleeping for {DELAY_BETWEEN} seconds\n")
    time.sleep(DELAY_BETWEEN)

print("\n[INFO] Simulation Complete\n")