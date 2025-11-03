from scapy.all import IP, TCP, Raw
from packet_sniffer import parse_packet

def test_parse_packet_tcp_simple():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80)/Raw(load=b"GET / HTTP/1.1")
    parsed = parse_packet(pkt)
    assert parsed["src"] == "10.0.0.1"
    assert parsed["dst"] == "10.0.0.2"
    assert parsed["proto"] == "TCP"
    assert parsed["sport"] == "1234"
    assert parsed["dport"] == "80"
    assert parsed["payload"] is not None
