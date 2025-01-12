# main.py

import time
import threading
from monitor import start_sniffing, display_stats, toggle_monitoring
from whois import whois

def monitor_mode():
    while True:
        command = input("Enter 'monitor' to start monitoring, \n      'whois [ip]' for WHOIS \n      'stop' to stop \n : ").strip().lower()

        if command.startswith("whois "):
            ip = command.split(" ", 1)[1].strip()
            print(f"[*] WHOIS information for {ip}:\n{whois(ip)}")

        elif command in ["monitor", "stop"]:
            toggle_monitoring(command)
        
        else:
            print("[!] Invalid command. Use 'monitor', 'stop', or 'whois [ip]'.")

if __name__ == "__main__":
    interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
    print(f"[*] Sniffing on {interface}...")

    # Start the sniffing and stats display threads
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()

    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    sniff_thread.start()

    # Start the monitor mode input loop
    monitor_thread = threading.Thread(target=monitor_mode, daemon=True)
    monitor_thread.start()

    # Keep the main thread alive to let other threads run
    while True:
        time.sleep(1)
