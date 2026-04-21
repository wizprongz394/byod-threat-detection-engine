from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows

packets = read_pcap("attack_pcaps/1_beacon_capture.pcapng")
flows = build_flows(packets)

print(f"Total flows: {len(flows)}")

# Print one flow
for k, v in list(flows.items())[:1]:
    print("\nFlow:", k)
    print("First 5 packets:", v[:5])