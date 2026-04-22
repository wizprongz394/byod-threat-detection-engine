from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows
import json
import os


def get_file_path():
    path = input("Enter PCAP path (or press Enter to browse): ").strip()

    if path:
        return path

    try:
        from tkinter import Tk
        from tkinter.filedialog import askopenfilename

        Tk().withdraw()
        return askopenfilename(title="Select PCAP File")

    except Exception as e:
        print("[ERROR] File picker not available:", e)
        return None


file_path = get_file_path()

if not file_path or not os.path.exists(file_path):
    print("[ERROR] Invalid file path")
    exit()


attack_type = os.path.basename(file_path).split(".")[0]

#The packets to flow pipeline
packets = read_pcap(file_path)
print(f"Total packets: {len(packets)}")

flows = build_flows(packets)
print(f"Total flows: {len(flows)}")


#Converting to JSON
flows_json = []

for flow in flows:
    (ip_pair, protocol, port_pair) = flow["key"]
    src_ip, dst_ip = ip_pair
    src_port, dst_port = port_pair

    flow_obj = {
        "attack_type": attack_type,
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


#output
file_name = "flow_output.json"

if os.path.exists(file_name):
    try:
        with open(file_name, "r") as f:
            existing_data = json.load(f)
    except:
        existing_data = []
else:
    existing_data = []

existing_data.append({
    "attack_type": attack_type,
    "flow_count": len(flows_json),
    "flows": flows_json
})

with open(file_name, "w") as f:
    json.dump(existing_data, f, indent=4)

print(f"[SUCCESS] Flows saved to {file_name}")