import pyshark

def read_pcap(file_path):
    """
    Reads PCAP using pyshark
    """

    capture = pyshark.FileCapture(
        file_path,
        tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
        keep_packets=False
    )

    packets = []

    try:
        for pkt in capture:
            try:
                #Handle IPv4 & IPv6
                if hasattr(pkt, 'ip'):
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                elif hasattr(pkt, 'ipv6'):
                    src_ip = pkt.ipv6.src
                    dst_ip = pkt.ipv6.dst
                else:
                    continue

                timestamp = float(pkt.sniff_timestamp)
                length = int(pkt.length)

                #Protocol (TCP / UDP)
                protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None

                src_port = None
                dst_port = None

                if protocol:
                    try:
                        layer = pkt[protocol]
                        src_port = getattr(layer, 'srcport', None)
                        dst_port = getattr(layer, 'dstport', None)
                    except:
                        pass

                packets.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "timestamp": timestamp,
                    "length": length,
                    "protocol": protocol,
                    "src_port": int(src_port) if src_port else None,
                    "dst_port": int(dst_port) if dst_port else None
                })

            except:
                continue

    finally:
        capture.close()

    return packets