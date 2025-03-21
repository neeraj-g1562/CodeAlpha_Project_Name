
A packet sniffer — also known as a packet analyzer, protocol analyzer or network analyzer — is a piece of hardware or software used to monitor network traffic. Sniffers work by examining streams of data packets that flow between computers on a network as well as between networked computers and the larger Internet. These packets are intended for — and addressed to — specific machines, but using a packet sniffer in "promiscuous mode" allows IT professionals, end users or malicious intruders to examine any packet, regardless of destination. It's possible to configure sniffers in two ways. The first is "unfiltered," meaning they will capture all packets possible and write them to a local hard drive for later examination. Next is "filtered" mode, meaning analyzers will only capture packets that contain specific data elements.
# Custom packet_sniffer Module

This project is a Python implementation of a **packet_sniffer**-like tool for packet sniffing tasks. The provided network sniffer code is designed for monitoring network traffic in real-time. It captures packets from a specified network interface, analyzes them, and logs relevant information for security and forensic purposes. Here’s a detailed breakdown of what the code is used for

## Features

**Packet Sniffing:

  Captures network packets in real-time from a specified network interface.
**Customizable Interface:

  Allows users to specify the network interface to sniff (e.g., eth0, wlan0) via command-line arguments.
**Duration Control:

  Users can set a duration for how long the sniffer should run, with a default of 300 seconds (5 minutes).
**Threshold for Alerts:

  Users can define a threshold for the number of packets from a single IP address that triggers an alert for potential suspicious activity (e.g., port scanning or flooding).
**Traffic Analysis:
  Analyzes Ethernet, IP, TCP, and UDP layers of captured packets, providing detailed information about source and destination MAC addresses, IP addresses, and port numbers.
**Suspicious Activity Detection:
  Tracks packet counts per source IP address to identify potential scanning or flooding attacks.
**Graceful Shutdown:
  Handles shutdown signals (e.g., Ctrl+C) gracefully, ensuring that the sniffer stops properly and logs a summary of the captured traffic.

  
## Usage
 sudo python3 network_sniffer.py -i eth0 -d 500 -t 150 
### Command-Line Options

| Option | Description |
|--------|-------------|
| `-l, --listen`         | Network interface to sniff (e.g., eth0, wlan0). |
| `-d / --duration` | Duration to run in seconds |
| `-c, --command`        | Enable an interactive shell for executing commands. |
| `-t / --threshold`  | Packet threshold for suspicious activity alerts |
| `-h / --help`  |Show help message |


##Example 1: Custom Interface and Duration:
  python network_sniffer.py -i wlan0 -d 600
  This runs the sniffer on the wlan0 interface for 600 seconds (10 minutes).
Example 2: Custom Threshold:
  python network_sniffer.py -t 150
     This runs the sniffer with a threshold of 150 packets for suspicious activity.
Step 2: Monitor Output
    As the script runs, it will print information about captured packets to the console, including Ethernet, IP, TCP, and UDP details.
Check the Log File:
Step 3:Open network_traffic.log in a text editor to review the logged packet information and alerts.
Step 4: Generate Normal Traffic
  On the same or another device on the network, browse the web (e.g., visit google.com) or ping a server:
              ping 8.8.8.8

Expected Output: The sniffer should display packet details, e.g.:

Ethernet Frame - Src MAC: aa:bb:cc:dd:ee:ff, Dst MAC: 11:22:33:44:55:66
IP Packet - Src IP: 192.168.1.100, Dst IP: 8.8.8.8
ICMP Packet (ping traffic)


Step 5: Test Error Handling
Run without sudo:
    python3 sniffer.py

Expected Output:
Error: Run this script with sudo/admin privileges.



##Troubleshooting Tips
  No Output: Ensure the correct interface is set and traffic is reaching it (use tcpdump or Wireshark to verify).

  Permission Denied: Double-check you’re using sudo.

  No Alerts: Increase the THRESHOLD value if your network has high normal traffic, or decrease it for testing.

  Interface Not Found: List interfaces with scapy.all.get_if_list() in a Python shell.



## Requirements

- Python 3.x
- Standard Python libraries (`datetime`, `logging`, `argparse`, `sys`,).

---

## Error Handling

- Handles exceptions for network errors (e.g., connection reset, eth0,wlan0).
- Manages errors during file operations or command execution.

---

