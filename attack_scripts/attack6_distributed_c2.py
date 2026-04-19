import requests
import random
import time
from datetime import datetime

TARGETS = [
    "http://127.0.0.1:8000",   # local server (your control)
    "https://httpbin.org/get",
    "https://example.com"
]

REQUEST_COUNT = 30
DELAY = 5

print("\n[INFO] Starting Multi-Endpoint Simulation\n")

for i in range(REQUEST_COUNT):
    target = random.choice(TARGETS)
    
    try:
        response = requests.get(target, timeout=5)
        print(f"[{datetime.now()}] Req {i+1}/{REQUEST_COUNT} → {target} | Status: {response.status_code}")
    except Exception as e:
        print(f"[{datetime.now()}] Req {i+1}/{REQUEST_COUNT} → FAILED | {target}")

    time.sleep(DELAY)

print("\n[INFO] Simulation Complete\n")