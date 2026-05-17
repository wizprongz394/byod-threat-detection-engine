FLOW_TIMEOUT = 60  # seconds


def build_flows(packets):

    flows = []

    active_flows = {}

    # -----------------------------------------------------
    # SESSION TRACKING
    # -----------------------------------------------------

    session_map = {}

    session_counter = 0

    flow_id = 0

    # -----------------------------------------------------
    # SORT PACKETS BY TIME
    # -----------------------------------------------------

    packets = sorted(
        packets,
        key=lambda x: (
            x["timestamp"]
            if x["timestamp"] is not None
            else 0
        )
    )

    # -----------------------------------------------------
    # PROCESS EACH PACKET
    # -----------------------------------------------------

    for pkt in packets:

        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")

        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")

        protocol = pkt.get("protocol")

        current_time = pkt.get("timestamp")

        # -------------------------------------------------
        # SKIP INVALID PACKETS
        # -------------------------------------------------

        if (
            src_ip is None
            or dst_ip is None
            or current_time is None
        ):
            continue

        # -------------------------------------------------
        # BIDIRECTIONAL FLOW NORMALIZATION
        # -------------------------------------------------

        if (src_ip, src_port) <= (dst_ip, dst_port):

            source_ip = src_ip
            destination_ip = dst_ip

            source_port = src_port
            destination_port = dst_port

        else:

            source_ip = dst_ip
            destination_ip = src_ip

            source_port = dst_port
            destination_port = src_port

        # -------------------------------------------------
        # FLOW KEY
        # -------------------------------------------------

        flow_key = (

            source_ip,
            destination_ip,

            source_port,
            destination_port,

            protocol
        )

        # -------------------------------------------------
        # SESSION KEY
        # -------------------------------------------------

        session_key = (

            source_ip,
            destination_ip,

            protocol
        )

        # -------------------------------------------------
        # SESSION CREATION
        # -------------------------------------------------

        if session_key not in session_map:

            session_map[session_key] = (
                f"session_{session_counter}"
            )

            session_counter += 1

        session_id = session_map[
            session_key
        ]

        # -------------------------------------------------
        # CREATE NEW FLOW
        # -------------------------------------------------

        if flow_key not in active_flows:

            active_flows[flow_key] = {

                "flow_id": flow_id,

                "session_id": session_id,

                "source_ip": source_ip,
                "destination_ip": destination_ip,

                "source_port": source_port,
                "destination_port": destination_port,

                "protocol": protocol,

                "packets": [],

                "last_seen": current_time
            }

            flow_id += 1

        flow = active_flows[flow_key]

        # -------------------------------------------------
        # FLOW TIMEOUT SPLITTING
        # -------------------------------------------------

        if (
            current_time - flow["last_seen"]
            > FLOW_TIMEOUT
        ):

            flows.append({

                "flow_id": flow["flow_id"],

                "session_id": flow[
                    "session_id"
                ],

                "source_ip": flow[
                    "source_ip"
                ],

                "destination_ip": flow[
                    "destination_ip"
                ],

                "source_port": flow[
                    "source_port"
                ],

                "destination_port": flow[
                    "destination_port"
                ],

                "protocol": flow[
                    "protocol"
                ],

                "packets": flow[
                    "packets"
                ],

                "start_time": flow[
                    "packets"
                ][0]["timestamp"],

                "end_time": flow[
                    "packets"
                ][-1]["timestamp"]
            })

            # ---------------------------------------------
            # CREATE NEW FLOW INSTANCE
            # ---------------------------------------------

            active_flows[flow_key] = {

                "flow_id": flow_id,

                "session_id": session_id,

                "source_ip": source_ip,
                "destination_ip": destination_ip,

                "source_port": source_port,
                "destination_port": destination_port,

                "protocol": protocol,

                "packets": [],

                "last_seen": current_time
            }

            flow_id += 1

            flow = active_flows[
                flow_key
            ]

        # -------------------------------------------------
        # STORE PACKET
        # -------------------------------------------------

        flow["packets"].append({

            "timestamp": current_time,

            "length": pkt.get("length"),

            "src_ip": pkt.get("src_ip"),
            "dst_ip": pkt.get("dst_ip"),

            "src_port": pkt.get("src_port"),
            "dst_port": pkt.get("dst_port"),

            "protocol": pkt.get("protocol")
        })

        # -------------------------------------------------
        # UPDATE LAST SEEN
        # -------------------------------------------------

        flow["last_seen"] = current_time

    # -----------------------------------------------------
    # FLUSH REMAINING FLOWS
    # -----------------------------------------------------

    for flow in active_flows.values():

        if flow["packets"]:

            flows.append({

                "flow_id": flow["flow_id"],

                "session_id": flow[
                    "session_id"
                ],

                "source_ip": flow[
                    "source_ip"
                ],

                "destination_ip": flow[
                    "destination_ip"
                ],

                "source_port": flow[
                    "source_port"
                ],

                "destination_port": flow[
                    "destination_port"
                ],

                "protocol": flow[
                    "protocol"
                ],

                "packets": flow[
                    "packets"
                ],

                "start_time": flow[
                    "packets"
                ][0]["timestamp"],

                "end_time": flow[
                    "packets"
                ][-1]["timestamp"]
            })

    return flows
