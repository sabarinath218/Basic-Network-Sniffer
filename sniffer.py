from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Function to process each captured packet
def analyze_packet(packet):

    print("\n" + "="*60)

    # Check if packet contains IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")
        print(f"Protocol       : {protocol}")

        # TCP Packet
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol Name  : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        # UDP Packet
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol Name  : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # ICMP Packet
        elif packet.haslayer(ICMP):
            print("Protocol Name  : ICMP")

        # Payload Data
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload Data   : {payload[:50]}")

        print(f"Packet Length  : {len(packet)} bytes")

# Start sniffing packets
print("Starting packet capture... Press Ctrl+C to stop.")

sniff(prn=analyze_packet, store=False)
