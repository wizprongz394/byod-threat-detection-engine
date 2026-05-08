FLOW_TIMEOUT = 60  # seconds

def build_flows(packets):
    flows = []
    active_flows = {}
    flow_id = 0

    packets = sorted(packets, key=lambda x: x["timestamp"])

    for pkt in packets:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        protocol = pkt.get("protocol")

        #Normalize direction
        if src_ip <= dst_ip:
            ip_pair = (src_ip, dst_ip)
            port_pair = (src_port, dst_port)
        else:
            ip_pair = (dst_ip, src_ip)
            port_pair = (dst_port, src_port)

        key = (ip_pair, protocol, port_pair)

        current_time = pkt["timestamp"]

        if key not in active_flows:
            active_flows[key] = {
                "flow_id": flow_id,
                "packets": [],
                "last_seen": current_time
            }
            flow_id += 1

        flow = active_flows[key]

        #Splitting the sessions on timeout basid
        if current_time - flow["last_seen"] > FLOW_TIMEOUT:
            flows.append({
                "flow_id": flow["flow_id"],
                "key": key,
                "packets": flow["packets"],
                "start_time": flow["packets"][0]["timestamp"],
                "end_time": flow["packets"][-1]["timestamp"]
            })

            active_flows[key] = {
                "flow_id": flow_id,
                "packets": [],
                "last_seen": current_time
            }
            flow_id += 1

            flow = active_flows[key]

        flow["packets"].append({
            "timestamp": current_time,
            "length": pkt["length"],
            "direction": (pkt["src_ip"], pkt["dst_ip"])
        })

        flow["last_seen"] = current_time

    #Flush thr remaining flows
    for key, flow in active_flows.items():
        if flow["packets"]:
            flows.append({
                "protocol": protocol,
                "flow_id": flow["flow_id"],
                "key": key,
                "packets": flow["packets"],
                "start_time": flow["packets"][0]["timestamp"],
                "end_time": flow["packets"][-1]["timestamp"]
            })

    return flows