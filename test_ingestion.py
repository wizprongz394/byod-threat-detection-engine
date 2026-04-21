from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows
import json
import os

file_path="attack_pcaps/10_random.pcapng"
packets = read_pcap(file_path)
attack_type=file_path.split("/")[-1].split(".")[0]
flows = build_flows(packets)

print(f"Total flows: {len(flows)}")

flows_json=[]
for (src,dst), packet_list in flows.items():
    flow_start={
        "attack_type":attack_type,
        "src_ip":src,
        "dst_ip":dst,
        "packet_count":len(packet_list),
        "packets":[]
    }
    for timestamp,size in packet_list:
        flow_start["packets"].append({
            "timestamp":timestamp,
            "size":size
        })
    flows_json.append(flow_start)
file_name="flow_output.json"
if os.path.exists(file_name):
    try:
        with open(file_name,"r") as f:
            existing_data=json.load(f)
    except:
        existing_data=[]
else:
    existing_data=[]

existing_data.append({
    "attack_type":attack_type,
    "flows":flows_json
})
with open("flow_output.json","w") as f:
    json.dump(existing_data,f,indent=4)
print("Flows have been saved to flow_output.json")