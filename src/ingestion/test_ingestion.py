from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows

import json
import os


# CONFIGURATION

OUTPUT_DIR = "data/processed"
OUTPUT_FILE = "flow_output.json"

os.makedirs(OUTPUT_DIR, exist_ok=True)

output_path = os.path.join(
    OUTPUT_DIR,
    OUTPUT_FILE
)


# FILE PICKER

def get_file_path():

    path = input(
        "Enter PCAP path "
        "(or press Enter to browse): "
    ).strip()

    if path:
        return path

    try:

        from tkinter import Tk
        from tkinter.filedialog import askopenfilename

        Tk().withdraw()

        return askopenfilename(

            title="Select PCAP File",

            filetypes=[
                ("PCAP Files", "*.pcapng *.pcap")
            ]
        )

    except Exception as e:

        print(
            "[ERROR] File picker not available:",
            e
        )

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

print("\n[INFO] Reading packets...")

packets = read_pcap(file_path)

print(f"[INFO] Total packets: {len(packets)}")


# TESTING: PRINT SAMPLE PACKETS

print("\n SAMPLE PACKETS \n")

sample_count = min(5, len(packets))

for i in range(sample_count):

    print(f"Packet {i+1}:\n")

    print(
        json.dumps(
            packets[i],
            indent=4
        )
    )

    print("-" * 50)


#  PACKETS TO FLOWS

print("\n[INFO] Building flows...")

flows = build_flows(packets)

print(f"[INFO] Total flows: {len(flows)}")


# -TESTING: PRINT SAMPLE FLOWS

print("\n========== SAMPLE FLOWS ==========\n")

sample_flow_count = min(3, len(flows))

for i in range(sample_flow_count):

    flow = flows[i]

    flow_preview = {

        "flow_id": flow["flow_id"],

        "source_ip": flow["source_ip"],
        "destination_ip": flow[
            "destination_ip"
        ],

        "source_port": flow[
            "source_port"
        ],

        "destination_port": flow[
            "destination_port"
        ],

        "protocol": flow["protocol"],

        "packet_count": len(
            flow["packets"]
        ),

        "start_time": flow[
            "start_time"
        ],

        "end_time": flow[
            "end_time"
        ]
    }

    print(f"Flow {i+1}:\n")

    print(
        json.dumps(
            flow_preview,
            indent=4
        )
    )

    print("-" * 50)


# FLOWS TO JSON

flows_json = []

for flow in flows:

    flow_obj = {

        "flow_id": flow["flow_id"],

        "source_ip": flow["source_ip"],
        "destination_ip": flow[
            "destination_ip"
        ],

        "source_port": flow[
            "source_port"
        ],

        "destination_port": flow[
            "destination_port"
        ],

        "protocol": flow["protocol"],

        "packet_count": len(
            flow["packets"]
        ),

        "start_time": flow[
            "start_time"
        ],

        "end_time": flow[
            "end_time"
        ],

        "packets": flow["packets"]
    }

    flows_json.append(flow_obj)


# LOAD EXISTING JSON

if os.path.exists(output_path):

    try:

        with open(output_path, "r") as f:

            existing_data = json.load(f)

    except Exception:

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

    json.dump(
        existing_data,
        f,
        indent=4
    )


print(
    f"\n[SUCCESS] Flows saved to: "
    f"{output_path}"
)