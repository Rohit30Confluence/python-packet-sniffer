#!/usr/bin/env python3
"""
Python Packet Sniffer - refactored for clarity, safety and testability.

WARNING: This tool captures network traffic. Use only on networks and machines
you own or where you have explicit authorization. The author is not responsible
for misuse.
"""

from __future__ import annotations
import argparse
import logging
import sys
import os
from typing import Dict, Optional
from scapy.all import sniff, PcapWriter, IP, IPv6, TCP, UDP, Raw, Packet

LOG = logging.getLogger("packet_sniffer")


def check_privileges() -> bool:
    """
    Return True if looks like we have root privileges (Unix) or running on Windows admin.
    """
    try:
        # Unix-like: effective UID 0 means root
        if os.name != "nt":
            return os.geteuid() == 0  # type: ignore
        # Windows: best-effort (scapy capture will fail if insufficient)
        return True
    except Exception:
        return False


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="packet_sniffer", description="Simple packet sniffer (lab use only)")
    parser.add_argument("-i", "--interface", help="Network interface to listen on (default: scapy's default)", default=None)
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "ip", "all"], default="all", help="Protocol filter")
    parser.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = infinite)")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after T seconds (0 = no timeout)")
    parser.add_argument("--pcap", help="Write captured packets to this pcap file", default=None)
    parser.add_argument("--promisc", action="store_true", help="Enable promiscuous mode if supported")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args(argv)


def build_filter(protocol: str) -> Optional[str]:
    if protocol == "tcp":
        return "tcp"
    if protocol == "udp":
        return "udp"
    if protocol == "ip":
        return "ip"
    return None


def parse_packet(pkt: Packet) -> Dict[str, Optional[str]]:
    """
    Parse a scapy packet into a serializable dictionary with key metadata.
    Kept small and deterministic so tests can exercise it.
    """
    out = {
        "timestamp": None,
        "src": None,
        "dst": None,
        "proto": None,
        "sport": None,
        "dport": None,
        "length": None,
        "payload": None,
    }

    try:
        out["timestamp"] = getattr(pkt, "time", None)
        # IP / IPv6
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is not None:
            out["src"] = ip_layer.src
            out["dst"] = ip_layer.dst
            out["length"] = getattr(ip_layer, "len", None)

        # Transport
        tcp = pkt.getlayer(TCP)
        udp = pkt.getlayer(UDP)

        if tcp:
            out["proto"] = "TCP"
            out["sport"] = str(tcp.sport)
            out["dport"] = str(tcp.dport)
        elif udp:
            out["proto"] = "UDP"
            out["sport"] = str(udp.sport)
            out["dport"] = str(udp.dport)
        elif ip_layer:
            out["proto"] = "IP"
        else:
            out["proto"] = pkt.name

        # payload (safe: show size and first bytes if present)
        raw = pkt.getlayer(Raw)
        if raw:
            payload_bytes = bytes(raw.load)
            out["payload"] = payload_bytes[:128].hex()  # first 128 bytes as hex
            out["length"] = out["length"] or len(payload_bytes)

    except Exception as exc:
        LOG.debug("parse_packet exception: %s", exc)

    return out


def pretty_log(parsed: Dict[str, Optional[str]]) -> str:
    parts = []
    ts = parsed.get("timestamp")
    if ts:
        parts.append(f"[{ts:.6f}]")
    if parsed.get("src") and parsed.get("dst"):
        parts.append(f"SRC={parsed['src']} DST={parsed['dst']}")
    if parsed.get("proto"):
        parts.append(parsed["proto"])
    if parsed.get("sport") or parsed.get("dport"):
        parts.append(f"sport={parsed.get('sport')} dport={parsed.get('dport')}")
    if parsed.get("length"):
        parts.append(f"len={parsed.get('length')}")
    return " ".join(parts)


def packet_callback(pkt: Packet, writer: Optional[PcapWriter] = None) -> None:
    parsed = parse_packet(pkt)
    LOG.info(pretty_log(parsed))
    if writer:
        try:
            writer.write(pkt)
        except Exception as exc:
            LOG.debug("Failed to write pcap: %s", exc)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if not check_privileges():
        LOG.warning("Insufficient privileges; capturing may fail. On Unix run as root or with sudo.")
    bpf_filter = build_filter(args.protocol)

    writer = None
    if args.pcap:
        try:
            writer = PcapWriter(args.pcap, append=True, sync=True)
            LOG.info("Writing PCAP to %s", args.pcap)
        except Exception as exc:
            LOG.warning("Could not create PCAP writer: %s", exc)
            writer = None

    try:
        LOG.info("Starting sniff on interface=%s filter=%s", args.interface or "default", bpf_filter or "none")
        sniff(iface=args.interface, filter=bpf_filter, prn=lambda p: packet_callback(p, writer), count=args.count or 0, timeout=args.timeout or None, promisc=args.promisc)
    except KeyboardInterrupt:
        LOG.info("Interrupted by user")
    except Exception as exc:
        LOG.exception("Capture failed: %s", exc)
        return 2
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass

    LOG.info("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
