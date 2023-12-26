import scapy.all as scapy
import psutil
import pyshark

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def select_network_interface():
    interfaces = get_network_interfaces()

    print("Available network interfaces:")
    for i, interface in enumerate(interfaces, start=1):
        print(f"{i}. {interface}")

    try:
        index = int(input("Enter the number of the network interface to sniff: "))
        selected_interface = interfaces[index - 1]
        return selected_interface
    except (ValueError, IndexError):
        print("Invalid selection. Exiting.")
        exit(1)

def sniff(interface, file_path):
    scapy.sniff(iface=interface, store=False, prn=process_packet, filter="ip")
    analyze_pcap(file_path)

def process_packet(packet):
    # Get the current timestamp
    current_timestamp = scapy.time.time()

    # Write the packet to the PCAP file
    scapy.wrpcap("packet_data.pcap", packet, append=True)

    # Display organized information about each packet
    print("\n" + "="*40 + " Packet Information " + "="*40)
    print(f"Timestamp: {current_timestamp}")
    print(f"Source IP: {packet[scapy.IP].src}")
    print(f"Destination IP: {packet[scapy.IP].dst}")

    # Display detailed information about the packet
    print("\nPacket Summary:")
    print(packet.summary())
    print("\nPacket Details:")
    print(packet.show(dump=True))

    # Count packets by protocol
    if packet.haslayer(scapy.IP):
        protocol = packet[scapy.IP].get_field('proto').i2s[packet[scapy.IP].proto]
        print(f"\nProtocol: {protocol}")

        # Extract and display payload data
        if packet.haslayer(scapy.Raw):
            print(f"Payload: {packet[scapy.Raw].load}")

def analyze_pcap(file_path):
    try:
        # Open the PCAP file for reading
        cap = pyshark.FileCapture(file_path)

        # Initialize counters
        total_packets = 0
        tcp_packets = 0
        udp_packets = 0

        # Analyze each packet
        for packet in cap:
            total_packets += 1

            if 'IP' in packet and 'TCP' in packet:
                tcp_packets += 1
            elif 'IP' in packet and 'UDP' in packet:
                udp_packets += 1

        # Display analysis results
        print("Analysis Results:")
        print(f"Total Packets: {total_packets}")
        print(f"TCP Packets: {tcp_packets}")
        print(f"UDP Packets: {udp_packets}")

    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")

if __name__ == "__main__":
    selected_interface = select_network_interface()
    pcap_file_path = "packet_data.pcap"
    sniff(selected_interface, pcap_file_path)
