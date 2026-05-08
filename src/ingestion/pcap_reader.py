import pyshark
import os

# CONFIGURATION

DEFAULT_TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# PCAP READER

def read_pcap(file_path, tshark_path=None):
    """
    Reads a PCAP/PCAPNG file using PyShark
    and extracts structured packet information.

    Parameters:
    file_path : str
    Path to the PCAP file

    tshark_path : str
    Custom tshark executable path

    Returns:

    list
        List of packet dictionaries
    """

    # VALIDATION

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"[ERROR] PCAP file not found: {file_path}"
        )

    # custom tshark path 
    if tshark_path:
        tshark_executable = tshark_path
    else:
        tshark_executable = DEFAULT_TSHARK_PATH

    if not os.path.exists(tshark_executable):
        raise FileNotFoundError(
        f"[ERROR] tshark not found: {tshark_executable}"
        )

    # CREATE CAPTURE

    capture = pyshark.FileCapture(
        file_path,
        tshark_path=tshark_executable,
        keep_packets=False
    )

    packets = []

    # PACKET PROCESSING

    try:

        for pkt in capture:

            try:
                #  HANDLE IPv4 / IPv6

                if hasattr(pkt, "ip"):

                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst

                elif hasattr(pkt, "ipv6"):

                    src_ip = pkt.ipv6.src
                    dst_ip = pkt.ipv6.dst

                else:
                    continue

                #  METADATA

                timestamp = float(pkt.sniff_timestamp)

                length = int(pkt.length)

                # PROTOCOL

                protocol = (
                    pkt.transport_layer
                    if hasattr(pkt, "transport_layer")
                    else None
                )

                src_port = None
                dst_port = None

                # PORT EXTRACTION

                if protocol:

                    try:

                        layer = pkt[protocol]

                        src_port = getattr(
                            layer,
                            "srcport",
                            None
                        )

                        dst_port = getattr(
                            layer,
                            "dstport",
                            None
                        )

                    except:
                        pass

                # STORE PACKET

                packet_obj = {

                    "src_ip": src_ip,
                    "dst_ip": dst_ip,

                    "timestamp": timestamp,

                    "length": length,

                    "protocol": protocol,

                    "src_port": (
                        int(src_port)
                        if src_port
                        else None
                    ),

                    "dst_port": (
                        int(dst_port)
                        if dst_port
                        else None
                    )
                }

                packets.append(packet_obj)

            except Exception:
                continue

    finally:

        capture.close()

    return packets