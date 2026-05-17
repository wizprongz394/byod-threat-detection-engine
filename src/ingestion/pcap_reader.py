import pyshark
import os


# CONFIGURATION

DEFAULT_TSHARK_PATH = (
    r"C:\Program Files\Wireshark\tshark.exe"
)


# PCAP READER

def read_pcap(file_path, tshark_path=None):
    """
    Reads a PCAP/PCAPNG file using PyShark
    and returns normalized packet dictionaries.

    Parameters
    ----------
    file_path : str
        Path to PCAP/PCAPNG file

    tshark_path : str
        Optional custom tshark executable path

    Returns
    -------
    list
        List of normalized packet objects
    """

    # VALIDATION

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            f"[ERROR] PCAP file not found: {file_path}"
        )

    # CUSTOM TSHARK PATH

    tshark_executable = (
        tshark_path
        if tshark_path
        else DEFAULT_TSHARK_PATH
    )

    if not os.path.exists(tshark_executable):

        raise FileNotFoundError(
            f"[ERROR] tshark not found: "
            f"{tshark_executable}"
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

                # DEFAULT SAFE VALUES

                src_ip = None
                dst_ip = None

                src_port = None
                dst_port = None

                protocol = None

                timestamp = None
                length = None

                # TIMESTAMP

                try:
                    timestamp = float(
                        pkt.sniff_timestamp
                    )

                except Exception:
                    timestamp = None

                # PACKET LENGTH

                try:
                    length = int(pkt.length)

                except Exception:
                    length = None

                # IPv4 / IPv6 EXTRACTION

                if hasattr(pkt, "ip"):

                    try:
                        src_ip = pkt.ip.src
                        dst_ip = pkt.ip.dst

                    except Exception:
                        pass

                elif hasattr(pkt, "ipv6"):

                    try:
                        src_ip = pkt.ipv6.src
                        dst_ip = pkt.ipv6.dst

                    except Exception:
                        pass

                # PROTOCOL EXTRACTION

                try:

                    protocol = (
                        pkt.transport_layer
                        if hasattr(
                            pkt,
                            "transport_layer"
                        )
                        else None
                    )

                except Exception:
                    protocol = None

                # PORT EXTRACTION ONLY FOR TCP / UDP

                if protocol in ["TCP", "UDP"]:

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

                        # Convert safely to int

                        src_port = (
                            int(src_port)
                            if src_port
                            else None
                        )

                        dst_port = (
                            int(dst_port)
                            if dst_port
                            else None
                        )

                    except Exception:

                        src_port = None
                        dst_port = None

                # NORMALIZED PACKET OBJECT

                packet_obj = {

                    "timestamp": timestamp,

                    "length": length,

                    "src_ip": src_ip,
                    "dst_ip": dst_ip,

                    "src_port": src_port,
                    "dst_port": dst_port,

                    "protocol": protocol
                }

                packets.append(packet_obj)

            # Skip malformed packets safely
            except Exception:
                continue

    finally:

        capture.close()

    return packets