# main.py

import time
import threading
from monitor import start_sniffing, display_stats, toggle_monitoring
from whois import whois
from myip import get_interface_ip
from nmap import nmap

# Global flag to control program execution
running = True

def monitor_mode(interface):
    global running
    while running:
        command = input(
            "Enter 'monitor' to start monitoring\n"
            "      'stop' to stop the monitoring\n"
            "      'whois [ip]' for WHOIS \n"
            "      'my ip' to check your IP address \n"
            "      'ip [ip]' to gather information about the target\n"
            "      'exit' to exit\n"
            ": "
        ).strip().lower()

        if command.startswith("whois "):
            ip = command.split(" ", 1)[1].strip()
            print(f"[*] WHOIS information for {ip}:\n{whois(ip)}")

        elif command.startswith("ip "):
            ip = command.split(" ", 1)[1].strip()
            print(f"[*] General information for {ip}:\n{nmap(ip)}")

        elif command == "my ip":
            ip_address = get_interface_ip(interface)
            print(f"[*] IP address of {interface}: {ip_address}")

        elif command in ["monitor", "stop"]:
            toggle_monitoring(command)

        elif command == "exit":
            print("[*] Exiting...")
            running = False
            break

        else:
            print("[!] Invalid command. Enter 'help' for usage.")

if __name__ == "__main__":
    interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
    print(f"[*] Sniffing on {interface}...")

    # Start the sniffing and stats display threads
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()

    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    sniff_thread.start()

    # Start the monitor mode input loop
    monitor_thread = threading.Thread(target=monitor_mode, args=(interface,), daemon=True)
    monitor_thread.start()

    # Keep the main thread alive while the program is running
    while running:
        time.sleep(1)

    print("[*] Program terminated.")