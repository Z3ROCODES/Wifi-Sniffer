
# **Wi-Fi Network Sniffer**  
_A Python-based Wi-Fi network sniffer to capture HTTP/HTTPS traffic, detect devices, and provide insights into your local network._

![Wi-Fi Sniffer](https://img.shields.io/badge/Powered%20By-Python-brightgreen)

## **Features**

- 🚨 **Device Detection**  
  Capture ARP packets to display devices connected to your network along with their **IP** and **MAC** addresses and **vendor information**.

- 🌐 **HTTP Request Capture**  
  Capture and display **HTTP request details** including request method (GET, POST), host, path, and **User-Agent**.

- 🔒 **HTTPS Response Capture**  
  Capture **HTTPS responses** (status code & status line) — note that the content of HTTPS traffic remains encrypted. The URL will be captured and saved in logs for analysis.

- 📜 **Logging**  
  All captured traffic (including HTTP requests, device connections, and errors) is logged to a **log file** for future reference.

- 📦 **PCAP File Saving**  
  Save the network packets in a **PCAP** file format for analysis using tools like **Wireshark**.

---

## **Prerequisites**  
Before running this script, ensure the following:

- Python 3.x (Preferably Python 3.6+)
- **WinPcap/Npcap** (for Windows users)  
  Download and install [Npcap](https://nmap.org/npcap/) for packet capture.

---

## **Required Libraries**  
Install these libraries using `pip`:

```bash
pip install scapy getmac colorama requests
```

---

## **Installation**

### Clone the repository:

```bash
git clone https://github.com/Z3ROCODES/Wifi-Sniffer.git
cd Wifi-Sniffer
```

### Install dependencies:

```bash
pip install -r requirements.txt
```

Or install individually:

```bash
pip install scapy getmac colorama requests
```

---

## **Usage**

1. **Run the script**  
   Open a terminal or command prompt, navigate to the folder containing the script, and run:

   ```bash
   python main.py
   ```

2. **Output Example**  
   The program will show connected devices along with their **IP** and **MAC** addresses, any captured HTTP/HTTPS traffic, and vendor information.

   **Example Output:**

   ```
   ██╗    ██╗██╗███████╗██╗██╗  ██╗
   ██║    ██║██║██╔════╝██║╚██╗██╔╝
   ██║ █╗ ██║██║█████╗  ██║ ╚███╔╝ 
   ██║███╗██║██║██╔══╝  ██║ ██╔██╗ 
   ╚███╔███╔╝██║██║     ██║██╔╝ ██╗
    ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

   Wi-Fi Network Sniffer
   -----------------------
   Starting to sniff packets...
   Press CTRL + C to stop.

   Device connected: IP = 10.0.0.5, MAC = 00:23:45:67:89:AB, Vendor = SomeVendor
   [HTTP Request] GET testphp.vulnweb.com/
   User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Edge/91.0.864.67
   [HTTPS Response] Status: 200 OK
   ```

3. **Stop Sniffing**  
   Press **CTRL + C** to stop the sniffer at any time.

4. **Log Files**  
   The script logs captured information to a file called `logs.txt`. You can review this file for detailed logs of the traffic and device connections.

5. **PCAP File**  
   The captured packets are saved in a **PCAP file** (`packets.pcap`) for analysis using tools like **Wireshark**.

---

## **Network Interfaces**

For **Linux** or **MacOS** users, you might need to specify the network interface for sniffing:

```python
scapy.sniff(iface="wlan0", prn=packet_callback, store=0, filter="tcp port 80 or tcp port 443")
```

---

## **Troubleshooting**

- **Npcap/Wireshark**  
  If you encounter errors related to **WinPcap** or **Npcap**, make sure **Npcap** is properly installed on your system.

- **Permission Issues (Linux/macOS)**  
  On Linux/macOS, you might need **root** access to capture network packets. Run the script with `sudo`:

  ```bash
  sudo python main.py
  ```

---

## **License**

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

---

## **Acknowledgments**

- **Scapy**: A powerful Python library for network packet manipulation and sniffing.
- **Colorama**: For adding color and improving terminal output.
- **getmac**: For obtaining MAC addresses.
- **requests**: For querying external services like MAC vendor lookup.
