from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows
import json
import os

# 🔹 NEW: file input (CLI + GUI fallback)
def get_file_path():
    path = input("Enter PCAP path (or press Enter to browse): ").strip()

    if path:
        return path

    try:
        from tkinter import Tk
        from tkinter.filedialog import askopenfilename

        Tk().withdraw()
        file_path = askopenfilename(title="Select PCAP File")

        return file_path

    except Exception as e:
        print("[ERROR] File picker not available:", e)
        return None


# 🔹 Get file path
file_path = get_file_path()

if not file_path or not os.path.exists(file_path):
    print("[ERROR] Invalid file path")
    exit()


# 🔹 Extract attack type
attack_type = file_path.split("/")[-1].split(".")[0]

# 🔹 Pipeline
packets = read_pcap(file_path)
flows = build_flows(packets)

print(f"Total flows: {len(flows)}")


# 🔹 Convert flows to JSON
flows_json = []

for (key, flow_id), packet_list in flows.items():
    src, dst = key

    flow_start = {
        "attack_type": attack_type,
        "flow_id": flow_id,
        "src_ip": src,
        "dst_ip": dst,
        "packet_count": len(packet_list),
        "packets": []
    }

    for timestamp, size in packet_list:
        flow_start["packets"].append({
            "timestamp": timestamp,
            "size": size
        })

    flows_json.append(flow_start)


# 🔹 Load existing file safely
file_name = "flow_output.json"

if os.path.exists(file_name):
    try:
        with open(file_name, "r") as f:
            existing_data = json.load(f)
    except Exception:
        existing_data = []
else:
    existing_data = []


# 🔹 Append new data
existing_data.append({
    "attack_type": attack_type,
    "flow_count": len(flows_json),
    "flows": flows_json
})


# 🔹 Save output
with open(file_name, "w") as f:
    json.dump(existing_data, f, indent=4)

print(f"[SUCCESS] Flows saved to {file_name}")