
# Import the necessary functions from the Scapy library
from scapy.all import sniff, IP, TCP, UDP

# This function will be called for each packet captured
def process_packet(packet):
    """
    This function processes each captured packet and prints its details.
    """
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        # Extract the source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Default protocol and port info
        protocol_info = ""

        # Check for TCP layer
        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            protocol_info = f"TCP Packet: {source_ip}:{source_port} -> {destination_ip}:{destination_port}"

        # Check for UDP layer
        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            protocol_info = f"UDP Packet: {source_ip}:{source_port} -> {destination_ip}:{destination_port}"

        # If it's another IP protocol (like ICMP), just print IP info
        else:
            protocol_info = f"IP Packet: {source_ip} -> {destination_ip}"
            
        print(protocol_info)


def main():
    """
    Main function to start the packet sniffer.
    """
    print("🚀 Starting Packet Sniffer...")
    print("Press Ctrl+C to stop.")

    # Start sniffing. The 'prn' argument specifies the callback function.
    # The 'store=0' means we don't keep the packets in memory.
    try:
        sniff(prn=process_packet, store=0)
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
