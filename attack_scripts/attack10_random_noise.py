import requests
import random
import time
from datetime import datetime

SITES = [
    "https://example.com",
    "https://httpbin.org/get",
    "https://jsonplaceholder.typicode.com/posts",
    "https://api.github.com",
    "https://www.wikipedia.org",
    "https://www.bing.com/search?q=network+security"
]

HEADERS = [
    {"User-Agent": "Mozilla/5.0"},
    {"User-Agent": "Chrome/120.0"},
    {"User-Agent": "Safari/537.36"}
]

def simulate_noise(total_requests=80):
    print("\n[INFO] Starting Random Noise Traffic Simulation\n")

    for i in range(total_requests):
        url = random.choice(SITES)
        headers = random.choice(HEADERS)

        try:
            r = requests.get(url, headers=headers, timeout=5)
            print(f"[{datetime.now()}] Req {i+1} → {url} | Status: {r.status_code}")
        except Exception as e:
            print(f"[ERROR] {e}")

        sleep_time = random.uniform(1, 6)
        print(f"[INFO] Sleeping {round(sleep_time,2)} sec\n")
        time.sleep(sleep_time)

    print("\n[INFO] Noise Simulation Completed\n")


if __name__ == "__main__":
    simulate_noise()