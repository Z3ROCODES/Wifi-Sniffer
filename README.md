
# **Wi-Fi Network Sniffer**  
_A Python-based Wi-Fi network sniffer to capture HTTP/HTTPS traffic and provide device insights on your local network._

![Wi-Fi Sniffer](https://img.shields.io/badge/Powered%20By-Python-brightgreen)

## **Features**

- 🚨 **Device Detection**  
  Capture ARP packets to display devices connected to your network along with their **IP** and **MAC** addresses.
  
- 🌐 **HTTP Request Capture**  
  Display **HTTP request details** including request method (GET, POST), host, path, and **User-Agent**.

- 🔒 **HTTPS Response Capture**  
  Capture **HTTPS responses** (status code & status line) — note that the content of HTTPS traffic remains encrypted.

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
pip install scapy getmac colorama
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
pip install scapy getmac colorama
```

---

## **Usage**

1. **Run the script**  
   Open a terminal or command prompt, navigate to the folder containing the script, and run:

   ```bash
   python main.py
   ```

2. **Output Example**  
   The program will show connected devices along with their **IP** and **MAC** addresses and any captured HTTP/HTTPS traffic.

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

   Device connected: IP = 10.0.0.5, MAC = 00:23:45:67:89:AB
   [HTTP Request] GET testphp.vulnweb.com/
   User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Edge/91.0.864.67
   [HTTPS Response] Status: 200 OK
   ```

3. **Stop Sniffing**  
   Press **CTRL + C** to stop the sniffer at any time.

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

---