# Network Analyzer

This network analyzer tool captures and monitors network traffic on a specified interface, displaying real-time packet statistics and providing WHOIS/Nmap information for IP addresses.
Features

    Packet Sniffing: Continuously monitors network traffic and captures packets.
    Traffic Statistics: Displays the top source IPs with protocol counts (TCP, UDP, ICMP).
    WHOIS Lookup: Provides WHOIS information for a given IP address.
    Interactive Mode: Allows you to control the monitoring and WHOIS lookups through simple commands.

Usage

To start the network analyzer:

    Run the main.py script:

    sudo python3 main.py

    The script will prompt you to enter the network interface to monitor (e.g., eth0, wlan0).

    After selecting the interface, you will be able to interact with the program. The tool listens for user commands in the terminal:
        monitor: Start monitoring traffic and displaying statistics.
        stop: Stop monitoring traffic and displaying statistics.
        whois [ip]: Retrieve and display the WHOIS information for a specific IP address.

    Example commands:
        monitor: Start displaying traffic stats.
        stop: Stop displaying traffic stats.
        whois 8.8.8.8: Get WHOIS information for IP 8.8.8.8.

Example Output

When running the program, you will see the following types of outputs:

    Traffic Statistics (after running monitor):

=== Traffic Summary (Top 5 Source IPs) ===

Source IP: 192.168.1.1
  TCP: 45 packets
  UDP: 10 packets
  ICMP: 3 packets
  Domain Info: example.com

Source IP: 192.168.1.2
  TCP: 30 packets
  UDP: 5 packets
  ICMP: 2 packets
  Domain Info: anotherexample.com

========================================

WHOIS Information (after running whois [ip]):

    [*] WHOIS information for 8.8.8.8:
    [WHOIS data for the IP]

How It Works

The tool captures packets using Scapy. It processes the packets to display source IPs and the protocols they use (TCP, UDP, ICMP). It then allows the user to request WHOIS information for any IP address, which is retrieved using the whois command.
Threading

    Packet Sniffing: Runs in the background and continuously monitors the network interface for incoming packets.
    Traffic Statistics Display: Runs in a separate thread, refreshing every 10 seconds with updated packet statistics.
    User Commands: Accepts user commands (monitor, stop, whois [ip]) to control the tool’s behavior.

Contributing

Feel free to fork this project and submit issues or pull requests. If you have suggestions for new features or improvements, please open an issue.
