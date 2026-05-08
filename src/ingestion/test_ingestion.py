from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows

import json
import os

# CONFIGURATION

OUTPUT_DIR = "data/processed"
OUTPUT_FILE = "flow_output.json"

os.makedirs(OUTPUT_DIR, exist_ok=True)

output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

# FILE PICKER

def get_file_path():

    path = input("Enter PCAP path (or press Enter to browse): ").strip()

    if path:
        return path

    try:
        from tkinter import Tk
        from tkinter.filedialog import askopenfilename

        Tk().withdraw()

        return askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP Files", "*.pcapng *.pcap")]
        )

    except Exception as e:
        print("[ERROR] File picker not available:", e)
        return None

# GET INPUT FILE

file_path = get_file_path()

if not file_path or not os.path.exists(file_path):
    print("[ERROR] Invalid file path")
    exit()

# ATTACK LABEL

attack_type = os.path.splitext(
    os.path.basename(file_path)
)[0]

# PCAP TO PACKETS

packets = read_pcap(file_path)

print(f"Total packets: {len(packets)}")


# PACKETS TO FLOWS

flows = build_flows(packets)

print(f"Total flows: {len(flows)}")

# FLOWS TO JSON

flows_json = []

for flow in flows:

    (ip_pair, protocol, port_pair) = flow["key"]

    src_ip, dst_ip = ip_pair
    src_port, dst_port = port_pair

    flow_obj = {

        "flow_id": flow["flow_id"],

        "src_ip": src_ip,
        "dst_ip": dst_ip,

        "protocol": protocol,

        "src_port": src_port,
        "dst_port": dst_port,

        "packet_count": len(flow["packets"]),

        "packets": flow["packets"]
    }

    flows_json.append(flow_obj)

# LOAD EXISTING JSON

if os.path.exists(output_path):

    try:
        with open(output_path, "r") as f:
            existing_data = json.load(f)

    except:
        existing_data = []

else:
    existing_data = []

# APPEND NEW DATA

existing_data.append({

    "attack_type": attack_type,

    "flow_count": len(flows_json),

    "flows": flows_json
})

# SAVE UPDATED JSON

with open(output_path, "w") as f:
    json.dump(existing_data, f, indent=4)

print(f"\n[SUCCESS] Flows saved to: {output_path}")