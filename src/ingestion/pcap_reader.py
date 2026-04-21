import pyshark

def read_pcap(file_path):
    """
    Reads a PCAP file and extracts basic packet info
    """
    capture = pyshark.FileCapture(file_path)

    packets =[]

    for pkt in capture:
        try:
            if 'IP' in pkt:
                packet_data = {
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "timestamp": float(pkt.sniff_timestamp),
                    "length": int(pkt.length)
                }
                packets.append(packet_data)
        except:
            continue

    return packets