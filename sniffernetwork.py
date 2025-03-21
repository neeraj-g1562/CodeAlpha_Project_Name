from scapy.all import sniff, Ether, IP, TCP, UDP
import datetime
import logging
from collections import defaultdict
import argparse
import sys


logging.basicConfig(filename='network_traffic.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')


traffic_tracker = defaultdict(int)
suspicious_ips = set()

def packet_handler(packet, threshold):
    """Handle and analyze each captured packet."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Ethernet Layer
    if Ether in packet:
        eth_info = f"Ethernet Frame - Src MAC: {packet[Ether].src}, Dst MAC: {packet[Ether].dst}"
        print(eth_info)
        logging.info(eth_info)

    # IP Layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_info = f"IP Packet - Src IP: {src_ip}, Dst IP: {dst_ip}"
        print(ip_info)
        logging.info(ip_info)

        
        traffic_tracker[src_ip] += 1
        if traffic_tracker[src_ip] > threshold and src_ip not in suspicious_ips:
            alert = f"ALERT: Potential suspicious activity from {src_ip} - {traffic_tracker[src_ip]} packets"
            print(alert)
            logging.warning(alert)
            suspicious_ips.add(src_ip)

    # TCP Layer
    if TCP in packet:
        tcp_info = f"TCP Segment - Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
        flags = packet[TCP].flags  # TCP flags (e.g., SYN, ACK)
        print(f"{tcp_info}, Flags: {flags}")
        logging.info(f"{tcp_info}, Flags: {flags}")

        # Detect potential SYN flood (port scanning or DDoS)
        if flags == 'S' and packet[TCP].dport in [22, 80, 443]:  # Common ports
            syn_alert = f"WARNING: Possible SYN scan detected from {src_ip} to port {packet[TCP].dport}"
            print(syn_alert)
            logging.warning(syn_alert)

    
    if UDP in packet:
        udp_info = f"UDP Datagram - Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
        print(udp_info)
        logging.info(udp_info)

def start_sniffer(interface, duration, threshold):
    """Start the network sniffer with optional interface and duration."""
    print(f"Starting network sniffer on {interface}...")
    print("Monitoring for suspicious activity. Press Ctrl+C to stop.")
    
    try:
        
        sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, threshold), store=0, timeout=duration)
    except PermissionError:
        print("Error: Run this script with sudo/admin privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Sniffer stopped.")
        summary = f"Traffic summary: {dict(traffic_tracker)}"
        print(summary)
        logging.info(summary)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Network Sniffer - A cybersecurity tool for packet analysis")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff (e.g., eth0, wlan0)")
    parser.add_argument("-d", "--duration", type=int, default=300, help="Duration to run in seconds (default: 300)")
    parser.add_argument("-t", "--threshold", type=int, default=100, help="Packet threshold for suspicious activity alerts (default: 100)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    start_sniffer(interface=args.interface, duration=args.duration, threshold=args.threshold)
