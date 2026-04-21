from collections import defaultdict

def build_flows(packets):
    """
    Groups packets into flows based on (src_ip, dst_ip)
    """
    flows = defaultdict(list)

    for pkt in packets:
        key = (pkt["src_ip"], pkt["dst_ip"])

        flows[key].append(
            (pkt["timestamp"], pkt["length"])
        )

    return flows