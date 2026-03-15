# CamRadar – Hidden Camera Detection Tool

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Cryptography-red?style=for-the-badge&logo=gitbook&logoColor=white)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=for-the-badge)

<p align="center">
  <strong>CamRadar</strong> is a professional CLI cybersecurity tool that scans local networks to identify potential IP cameras, DVR systems, and other suspicious surveillance devices.
</p>

<p align="center">
  <em>by Vision → <a href="https://visionkc.com.np">View</a></em>
</p>

---

## Features

- **Network Device Discovery** – ARP-based scanning (scapy) with python-nmap fallback
- **Surveillance Port Detection** – Scans for RTSP, HTTP, DVR, and streaming ports
- **Camera Vendor Identification** – MAC address lookup against known surveillance manufacturers (Hikvision, Dahua, Axis, Foscam, and more)
- **Deep Scan Mode** – Extended port list for thorough analysis
- **Packet Monitoring** – Real-time traffic sniffing for RTSP and streaming protocols
- **Colorful CLI Output** – Green / yellow / red alerts using colorama
- **Logging** – All findings saved to `logs/camradar.log`
- **Cross-Platform** – Works on Windows, macOS, and Linux

---

## Installation

```bash
git clone https://github.com/vision-dev1/camradar
cd camradar
pip install -r requirements.txt
```

### Dependencies

| Library            | Purpose                    |
| ------------------ | -------------------------- |
| scapy              | ARP scanning & sniffing    |
| python-nmap        | Fallback host discovery    |
| mac-vendor-lookup  | MAC → vendor resolution    |
| colorama           | Cross-platform CLI colors  |

---

## Usage

```bash
# Standard scan
python main.py scan

# Deep scan (extended port list)
python main.py scan --deep

# Scan a specific subnet
python main.py scan --subnet 10.0.0.0/24

# Monitor network traffic for streaming protocols
python main.py monitor

# Show help
python main.py help
```

> **Note:** ARP scanning and packet monitoring require **elevated privileges** (Administrator on Windows, `sudo` on Linux/macOS).

---

## CLI Output Example

```
   ____                 ____           _
  / ___|__ _ _ __ ___  |  _ \ __ _  __| | __ _ _ __
 | |   / _` | '_ ` _ \ | |_) / _` |/ _` |/ _` | '__|
 | |__| (_| | | | | | ||  _ < (_| | (_| | (_| | |
  \____\__,_|_| |_| |_||_| \_\__,_|\__,_|\__,_|_|

  CamRadar - Hidden Camera Detection Tool
  by Vision --> github.com/vision-dev1

[+] Starting Standard Scan ...

[+] Performing ARP scan on 192.168.1.0/24 using scapy ...
[+] Discovered 5 device(s) on the network.

──────────────────────────────────────────────────
[+] Device Discovered
    IP      : 192.168.1.25
    MAC     : AA:BB:CC:DD:EE:FF
    Vendor  : Hikvision
    Ports   : 554, 8080

    [!] Possible Surveillance Device Detected
    Reason: Streaming port(s) open: 554; Vendor 'Hikvision' is a known surveillance manufacturer
──────────────────────────────────────────────────

══════════════════════════════════════════════════
[+] Scan complete in 12.34s
    Total devices  : 5
    Suspicious devices : 1
══════════════════════════════════════════════════
```

---

## Project Structure

```
camradar/
├── main.py                        # CLI entry point
├── banner.py                      # ASCII banner display
├── requirements.txt               # Python dependencies
├── README.md                      # This file
│
├── scanner/
│   ├── network_scan.py            # ARP / nmap device discovery
│   └── port_scan.py               # Surveillance port scanning
│
├── detection/
│   ├── camera_identifier.py       # Camera flagging engine
│   └── mac_vendor_lookup.py       # MAC vendor resolution
│
├── monitoring/
│   └── packet_sniffer.py          # Real-time traffic monitor
│
├── utils/
│   └── logger.py                  # Logging utility
│
└── logs/
    └── camradar.log               # Auto-generated log file
```

---

## How It Works

1. **Discover** – Sends ARP requests across the local subnet to enumerate all connected devices.
2. **Scan** – Probes each discovered device for ports commonly used by IP cameras and DVRs.
3. **Identify** – Resolves the MAC address to a manufacturer name and cross-references with a list of known surveillance vendors.
4. **Report** – Displays a color-coded report and logs flagged devices to `logs/camradar.log`.
5. **Monitor** *(optional)* – Sniffs network packets in real time for RTSP/streaming traffic signatures.

---

## Known Surveillance Vendors

CamRadar checks for these manufacturers (and more):

Hikvision · Dahua · TP-Link · Xiaomi · Wyze · Axis · Foscam · Amcrest · Reolink · Annke · Swann · Lorex · Vivotek · Hanwha · Uniview · EZVIZ · Imou

---

## License

This project is for **educational and authorized security testing purposes only**. Always obtain proper authorization before scanning networks you do not own.

---

## Author
[Github](https://github.com/vision-dev1)<br>
[Portfolio](https://visionkc.com.np)

---
