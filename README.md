# Packet Sniffer Tool

## Overview
This project is a packet sniffer tool that captures TCP packets, saves them to a `.pcap` file, and allows for further analysis using Scapy.

## Folder Structure
- `src/`: Contains the source code for sniffing and analyzing packets.
- `captured_packets/`: Stores the captured packets file in `.pcap` format.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/mrohitmishra/packet_sniffer.git
    cd packet_sniffer_tool
    ```

2. Install dependencies:
    ```bash
    pip install -r src/requirements.txt
    ```

## Usage

### 1. Capture Packets
To start sniffing packets, run:

```bash

python src/sniffer.py

Captured packets will be saved to captured_packets/captured_packets.pcap

2. Analyze Captured Packets
To analyze captured packets, run:

python src/analyze.py


