# Python Packet Sniffer

[![CI](https://github.com/Rohit30Confluence/python-packet-sniffer/actions/workflows/ci.yaml/badge.svg)](https://github.com/Rohit30Confluence/python-packet-sniffer/actions)


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

# install dependencies
pip install -r requirements.txt

# run on default interface, capture 10 packets and write to file
sudo python3 packet_sniffer.py -p tcp --count 10 --pcap sample.pcap

## Usage
python3 packet_sniffer.py --interface eth0 --protocol tcp --count 0 --timeout 60 --pcap out.pcap


## Key options:

-i, --interface interface name

-p, --protocol tcp|udp|ip|all

--count stop after N packets

--timeout stop after T seconds

--pcap write captured packets to file

-v verbose logging

## Contributing

Contributions are welcome. Suggested first PRs:

Add more unit tests

Add PCAP replay capability

Add Windows support notes

Please read CONTRIBUTING.md before submitting PRs.

## `CONTRIBUTING.md`

# Contributing

Welcome. Keep changes focused and small. Branch name format: `feat/<short-desc>` or `fix/<short-desc>`.

- Create a branch from `main`
- Make your changes
- Add tests where possible
- Open a Pull Request describing the change and how to test it

We run tests via GitHub Actions. Thank you for contributing.

## License

MIT
