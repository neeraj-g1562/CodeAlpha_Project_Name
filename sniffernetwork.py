from scapy.all import sniff, Ether,IP, TCP, UDP


def packet_handler(packet):
    if Ether in packet:
        print('Ethernet Frame:')
        print(f"Source MAC Address: {packet[Ether].src},Destination MAC Address: {packet[Ether].dst}")


    if IP in packet:
        print("IP Packet:")
        print(f"Source IP Adress: {packet[IP].src}, destination IP Address: {packet[IP].dst}")


    if TCP in packet:
        print("TCP Segment:")
        print(f"Source port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
    
    if UDP in packet:
        print("UDP Datagram:")
        print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")


def start_sniffer():
    print("Starting network sniffer ...")
    print("This program will capture and display detailed information about network packets. ")
    print("Press Ctrl+C to stop the sniffer.")
    sniff(prn=packet_handler, store=0)

if __name__ == "__main__":
    start_sniffer()
