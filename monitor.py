# monitor.py

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
import threading
import time
import platform
import subprocess
import re

# 소스 IP별로 프로토콜 카운트를 저장할 변수
traffic_stats = defaultdict(Counter)
# 소스 IP별 트래픽 수를 추적하는 변수
src_traffic_count = Counter()

monitoring_active = False  # 모니터링 상태 추적 변수

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto

        # 소스 IP별로 프로토콜 카운트 업데이트
        traffic_stats[src_ip].update([proto])

        # 트래픽 수를 카운팅
        src_traffic_count.update([src_ip])

def get_host_info(ip):
    system_platform = platform.system().lower()

    try:
        if system_platform == "windows":
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        if system_platform == "linux":
            result = subprocess.run(["host", ip], capture_output=True, text=True)
        else:
            return "The OS is neither windows nor linux."

        if result.returncode == 0:
            output = result.stdout.strip()

            # Windows의 경우, 'Name: ' 다음에 나오는 정보를 추출
            if system_platform == "windows":
                domain_info = re.search(r"Name:\s+([^\n]+)", output)
                if domain_info:
                    return domain_info.group(1).strip()
                else:
                    return "No domain information found"

            # Linux의 경우, 'name pointer' 다음에 나오는 정보 추출
            if system_platform == "linux":
                domain_info = re.search(r"pointer\s+([^\n]+)", output)
                if domain_info:
                    return domain_info.group(1).strip()
                else:
                    return "No domain information found"
        else:
            return "No domain information found"
    except Exception as e:
        return f"Error: {str(e)}"

def display_stats():
    while True:
        time.sleep(10)
        if monitoring_active:  # 모니터링이 활성화된 경우에만 통계 출력
            print("\n=== Traffic Summary (Top 5 Source IPs) ===")

            top_5_sources = src_traffic_count.most_common(5)

            for src_ip, _ in top_5_sources:
                print(f"\nSource IP: {src_ip}")
                for proto, count in traffic_stats[src_ip].items():
                    protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
                        proto, f"Protocol {proto}"
                    )
                    print(f"  {protocol_name}: {count} packets")
                host_info = get_host_info(src_ip)
                print(f"  Domain Info: {host_info}")

            print("========================================\n")
            traffic_stats.clear()
            src_traffic_count.clear()

def start_sniffing(interface):
    global monitoring_active
    sniff(iface=interface, prn=packet_callback, store=False)

def toggle_monitoring(command):
    global monitoring_active
    if command == "monitor":
        if not monitoring_active:
            monitoring_active = True
            print("[*] Monitoring started.")
        else:
            print("[!] Monitoring is already active.")
    elif command == "stop":
        if monitoring_active:
            monitoring_active = False
            print("[*] Monitoring stopped.")
        else:
            print("[!] Monitoring is not active.")
