import time
import requests

while True:
    print("Sending beacon...")
    requests.get("http://127.0.0.1:8000")
    time.sleep(10)