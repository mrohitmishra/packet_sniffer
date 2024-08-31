from scapy.utils import rdpcap

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)
    for packet in packets:
        print(packet.show())

if __name__ == "__main__":
    analyze_packets("../captured_packets/captured_packets.pcap")
