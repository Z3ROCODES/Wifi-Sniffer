import scapy.all as scapy
from scapy.layers import http
import os
from getmac import get_mac_address
from colorama import Fore, Style, init
import time

init(autoreset=True)

def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.RED + r"""
██╗    ██╗██╗███████╗██╗██╗  ██╗
██║    ██║██║██╔════╝██║╚██╗██╔╝
██║ █╗ ██║██║█████╗  ██║ ╚███╔╝ 
██║███╗██║██║██╔══╝  ██║ ██╔██╗ 
╚███╔███╔╝██║██║     ██║██╔╝ ██╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
                                                                                            
""" + Fore.GREEN + "Wi-Fi Network Sniffer\n" + Fore.YELLOW + "-----------------------")

# Callback function for sniffing packets
def packet_callback(packet):
    try:
        # Show devices connected to the network (ARP packets)
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            print(Fore.CYAN + f"Device connected: IP = {ip}, MAC = {mac}")

        # Capture HTTP request packets (port 80)
        if packet.haslayer(http.HTTPRequest):
            host = packet[http.HTTPRequest].Host.decode(errors="ignore") if packet[http.HTTPRequest].Host else "Unknown"
            method = packet[http.HTTPRequest].Method.decode(errors="ignore") if packet[http.HTTPRequest].Method else "Unknown"
            path = packet[http.HTTPRequest].Path.decode(errors="ignore") if packet[http.HTTPRequest].Path else "Unknown"
            user_agent = packet[http.HTTPRequest].User-Agent.decode(errors="ignore") if packet[http.HTTPRequest].User-Agent else "Unknown"

            print(Fore.GREEN + f"\n[HTTP Request] {method} {host}{path}")
            print(Fore.YELLOW + f"User-Agent: {user_agent}")
        
        # Capture HTTPS response packets (port 443)
        if packet.haslayer(http.HTTPResponse):
            # HTTP Responses are not easily decoded if they are HTTPS traffic
            if hasattr(packet[http.HTTPResponse], 'StatusCode'):
                status_code = packet[http.HTTPResponse].StatusCode
            else:
                status_code = "Unknown"
            
            status_line = packet[http.HTTPResponse].StatusLine.decode(errors="ignore") if hasattr(packet[http.HTTPResponse], 'StatusLine') else "Unknown"
            print(Fore.YELLOW + f"[HTTPS Response] Status: {status_code} {status_line}")

        # For packets that are neither HTTP nor HTTPS, print a summary
        else:
            print(Fore.RED + f"Unhandled Packet: {packet.summary()}")
        
    except Exception as e:
        print(Fore.RED + f"Error processing packet: {e}")
        print(Fore.RED + f"Packet: {packet.summary()}")

# Sniffing the packets
def start_sniffing():
    print(Fore.GREEN + "Starting to sniff packets...\n")
    print(Fore.YELLOW + "Press CTRL + C to stop.\n")
    try:
        scapy.sniff(prn=packet_callback, store=0, filter="tcp port 80 or tcp port 443")  # HTTP and HTTPS traffic
    except Exception as e:
        print(Fore.RED + f"Error during sniffing: {e}")

if __name__ == "__main__":
    print_header()
    start_sniffing()