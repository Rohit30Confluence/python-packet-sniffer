# Python Packet Sniffer

A minimal educational packet sniffer written in Python using Scapy.  
This project is intended for learning and lab use only.

> **Safety & Legal**  
> Packet sniffing can capture sensitive data. Only run this software on systems and networks you own or have explicit permission to test. The author is not responsible for misuse.

## Features
- Capture TCP/UDP/IP packets
- Console logging of key metadata
- Optionally write captures to PCAP files
- Testable parsing function for unit tests

## Requirements
- Python 3.8+
- scapy
- Root/admin privileges to capture packets on most platforms

## Quick start (local, terminal)
```bash
# install dependencies
pip install -r requirements.txt

# run on default interface, capture 10 packets and write to file
sudo python3 packet_sniffer.py -p tcp --count 10 --pcap sample.pcap
