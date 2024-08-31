from scapy.all import sniff, TCP, IP
from scapy.utils import wrpcap
import os

def packet_callback(packet):
    if packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        print(f"[+] Src IP: {ip_layer.src} | Dst IP: {ip_layer.dst}")
        print(f"[+] Src Port: {tcp_layer.sport} | Dst Port: {tcp_layer.dport}")
        print(f"[+] Payload: {str(bytes(packet[TCP].payload))}\n")

def start_sniffing():
    # Perform Nmap scan
    os.system("nmap -sS -p 1-1024 192.168.1.1")

    # Start sniffing packets
    packets = sniff(filter="tcp", prn=packet_callback, count=50)

    # Save packets to a file
    wrpcap("../captured_packets/captured_packets.pcap", packets)

if __name__ == "__main__":
    start_sniffing()
