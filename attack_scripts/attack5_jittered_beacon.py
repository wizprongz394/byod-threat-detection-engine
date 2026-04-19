import time
import random
import requests
from datetime import datetime

# ==============================
# CONFIGURATION
# ==============================
TARGET_URL = "http://127.0.0.1:8000"
MIN_INTERVAL = 20
MAX_INTERVAL = 60
TOTAL_REQUESTS = 20
TIMEOUT = 5

# ==============================
# FUNCTION: Jittered Beacon
# ==============================
def jittered_beacon():
    print("\n[INFO] Starting Jittered Beacon Simulation\n")

    for i in range(TOTAL_REQUESTS):
        try:
            start_time = datetime.now()

            response = requests.get(TARGET_URL, timeout=TIMEOUT)

            print(f"[{start_time}] Request {i+1}/{TOTAL_REQUESTS} | Status: {response.status_code}")

        except Exception as e:
            print(f"[ERROR] Request failed: {e}")

        # Random sleep interval
        sleep_time = random.uniform(MIN_INTERVAL, MAX_INTERVAL)
        print(f"[INFO] Sleeping for {sleep_time:.2f} seconds\n")
        time.sleep(sleep_time)

    print("\n[INFO] Simulation Complete\n")


# ==============================
# ENTRY POINT
# ==============================
if __name__ == "__main__":
    jittered_beacon()