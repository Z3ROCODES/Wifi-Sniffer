import scapy.all as scapy
from scapy.layers import http
from getmac import get_mac_address
from colorama import Fore, Style, init
import os
import time
import requests
import re

os.system('cls' if os.name == 'nt' else 'clear')
init(autoreset=True)
print(Fore.RED + r"""
██╗    ██╗██╗███████╗██╗██╗  ██╗
██║    ██║██║██╔════╝██║╚██╗██╔╝
██║ █╗ ██║██║█████╗  ██║ ╚███╔╝ 
██║███╗██║██║██╔══╝  ██║ ██╔██╗ 
╚███╔███╔╝██║██║     ██║██╔╝ ██╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
                                                                                            
""" + Fore.GREEN + "Wi-Fi Network Sniffer\n" + Fore.YELLOW + "-----------------------")
LOG_FILE = "logs.txt"
unique_ips = set()
pcap_file = "packets.pcap"

def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except:
        return "Unknown Vendor"

def log_data(data):
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {data}\n")

def extract_data_from_raw_packet(raw_data):
    try:
        urls = re.findall(r'(https?://[^\s]+)', raw_data)
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_data)
        creds = re.findall(r'(username|user|login|email|pass|password)[=\s]*([^&\s]+)', raw_data, re.IGNORECASE)
        return urls, emails, creds
    except Exception as e:
        return [], [], []

def packet_callback(packet):
    try:
        timestamp = time.strftime("%H:%M:%S")
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            vendor = get_vendor(mac)
            if ip not in unique_ips:
                unique_ips.add(ip)
                print(Fore.CYAN + f"[{timestamp}] Device: IP={ip}, MAC={mac}, Vendor={vendor}")
                log_data(f"Device connected: IP={ip}, MAC={mac}, Vendor={vendor}")
        if packet.haslayer(http.HTTPRequest):
            method = packet[http.HTTPRequest].Method.decode(errors="ignore")
            host = packet[http.HTTPRequest].Host.decode(errors="ignore")
            path = packet[http.HTTPRequest].Path.decode(errors="ignore") if hasattr(packet[http.HTTPRequest], "Path") else "/"
            user_agent = "Unknown"
            if packet.haslayer(scapy.Raw):
                raw_data = packet[scapy.Raw].load.decode(errors="ignore")
                urls, emails, creds = extract_data_from_raw_packet(raw_data)
                print(Fore.GREEN + f"[{timestamp}] [HTTP] {method} {host}{path}")
                print(Fore.YELLOW + f"User-Agent: {user_agent}")
                if urls:
                    print(Fore.MAGENTA + f"URLs found: {', '.join(urls)}")
                if emails:
                    print(Fore.CYAN + f"Emails found: {', '.join(emails)}")
                if creds:
                    print(Fore.RED + f"Possible credentials found: {creds}")
                log_data(f"[HTTP Request] {method} {host}{path} | URLs={', '.join(urls)} | Emails={', '.join(emails)} | Credentials={creds}")
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 443:
            print(Fore.RED + f"[{timestamp}] [HTTPS] Encrypted traffic detected from {packet[scapy.IP].src}")
            log_data(f"[HTTPS] Encrypted traffic from {packet[scapy.IP].src}")
        if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
            dns_query = packet[scapy.DNSQR].qname.decode(errors="ignore") if packet[scapy.DNSQR].qname else "Unknown"
            print(Fore.MAGENTA + f"[{timestamp}] [DNS] {packet[scapy.IP].src} -> {dns_query}")
            log_data(f"[DNS Query] {packet[scapy.IP].src} -> {dns_query}")
        if packet.haslayer(scapy.ICMP):
            print(Fore.BLUE + f"[{timestamp}] [ICMP] Ping request from {packet[scapy.IP].src}")
            log_data(f"[ICMP] Ping from {packet[scapy.IP].src}")
        scapy.wrpcap(pcap_file, packet, append=True)
    except Exception as e:
        print(Fore.RED + f"[ERROR] {str(e)}")
        log_data(f"Error: {str(e)}")

def start_sniffing(interface="Wi-Fi"):
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=0, filter="tcp or udp or arp or icmp")
    except PermissionError:
        print(Fore.RED + "Run this script as Administrator or use sudo on Linux!")
    except Exception as e:
        print(Fore.RED + f"Error: {str(e)}")

if __name__ == "__main__":
    start_sniffing()
