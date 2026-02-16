# Nanachi Pentest Tool

A comprehensive penetration testing toolkit with an interactive TUI (Text User Interface) built with Python and Rich library.

## Features

### Network Scanning
- **Nmap Integration**: Full network discovery with timing controls
- **WiFi Scanner**: Detect and analyze wireless networks with signal strength and security info
- **Hidden Network Detection**: Identify and flag hidden SSIDs
- **MAC Vendor Lookup**: Automatic manufacturer identification via OUI database

### WiFi Attacks
- **Deauth Attack**: Disconnect clients from access points
  - Monitor mode scanning
  - Client targeting (broadcast or specific MAC)
  - Continuous or fixed packet count modes
- **DNS Monitoring**: Capture and analyze DNS queries on local network
  - mDNS support
  - Device fingerprinting
  - ARP spoofing for MitM
- **Fake AP (Evil Twin)**: Create rogue access points
- **WPA Handshake Capture**: Capture 4-way handshakes for offline cracking

### Web Exploitation
- **SQLMap Integration**: Automated SQL injection testing
- **Payload Manager**: Load and use pre-defined payloads (XSS, SQL, PHP, HTML)
- **HTTP/HTTPS Browser**: Quick access to discovered web services

### SSH Exploitation
- **LinPEAS Integration**: Automated privilege escalation enumeration
- **File Scanner**: Search for interesting files (.txt, binaries, scripts, SUID)
- **Permission Auditor**: Check sudo rights, groups, and user info
- **Shadow File Access**: Enumerate system users

### Network Manipulation
- **MAC Spoofing**: Change MAC addresses (random or custom)
- **IP Spoofing**: Modify IP addresses
- **Netcat Listener**: Built-in network listener

## Installation

### Automatic Installation

Run the installation script to install all dependencies:

```bash
sudo bash install_nanachi.sh
```

This will install:
- aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)
- nmap
- sqlmap
- netcat
- hostapd (for Fake AP)
- dnsmasq (DHCP/DNS server)
- LinPEAS
- OUI database (MAC vendor lookup)
- Python libraries (rich, scapy, paramiko, pyperclip)

### Manual Installation

#### System Tools
```bash
sudo apt update
sudo apt install -y aircrack-ng nmap sqlmap netcat-openbsd iw wireless-tools \
                    network-manager hostapd dnsmasq sshpass net-tools iproute2
```

#### Python Dependencies
```bash
pip3 install --break-system-packages rich scapy pyperclip paramiko requests urllib3
```

#### LinPEAS
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
```

#### OUI Database
```bash
curl -L https://standards-oui.ieee.org/oui/oui.txt -o oui.txt
```

## Usage

### Basic Launch
```bash
sudo python3 nanachi.py
```

Or make it executable:
```bash
chmod +x nanachi.py
sudo ./nanachi.py
```

### Main Menu Options

1. **Network Scanner (Nmap)**: Discover hosts on network with port scanning
2. **Load Payloads**: Access pre-defined payloads for various attacks
3. **SQLMap Scanner**: Test web applications for SQL injection vulnerabilities
4. **SSH Access & Exploitation**: Connect to SSH hosts and run enumeration
5. **MAC/IP Spoofing**: Change network identifiers
6. **Open HTTP/HTTPS URL**: Launch browser for discovered services
7. **WiFi Scanner**: Scan for wireless networks
8. **DNS Monitoring**: Capture DNS queries on local network
9. **WiFi Deauth**: Disconnect clients from access points
10. **Netcat Listener**: Set up network listeners
11. **Fake AP (Evil Twin)**: Create rogue access points
12. **WPA Handshake Capture**: Capture authentication handshakes

## WiFi Deauth Attack

The deauth feature supports two modes:

### Mode 1: Passive AP Scan (Monitor Mode)
Scans all WiFi networks in range without connecting to any network. Uses airodump-ng to discover APs and clients.

### Mode 2: Active Network Scan (Connected)
Connects to a WiFi network and scans for devices on the local network using nmap. Useful for targeting specific IPs.

### Usage Example
```
1. Select Mode 1 (Passive AP Scan)
2. Choose WiFi interface
3. Wait for AP scan (10 seconds default)
4. Select target AP from list
5. Choose target:
   - 0 = Broadcast (disconnect all clients)
   - # = Specific client MAC address
6. Set packet count:
   - 0 = Continuous (press ENTER to stop)
   - N = Send N frames then stop
```

## DNS Monitoring

Captures DNS queries on local network to identify:
- Devices making DNS requests
- Websites and services being accessed
- DNS servers in use
- mDNS/Bonjour services

Supports ARP spoofing for Man-in-the-Middle capture of all network traffic.

## Payload Files

The tool expects CSV files containing payloads:
- `jspayload.csv` - JavaScript payloads
- `sqlpayload.csv` - SQL injection payloads
- `phppayload.csv` - PHP code execution payloads
- `htmlpayload.csv` - HTML/XSS payloads

Format: `payload,description`

## Requirements

- Linux (tested on Ubuntu 24)
- Root/sudo privileges
- WiFi adapter supporting monitor mode (for WiFi attacks)
- Python 3.10+

## File Structure

```
nanachi.py              # Main application
install_nanachi.sh      # Installation script
linpeas.sh              # Privilege escalation enumeration script
oui.txt                 # MAC vendor database
jspayload.csv           # JavaScript payloads
sqlpayload.csv          # SQL payloads
phppayload.csv          # PHP payloads
htmlpayload.csv         # HTML payloads
```

## Network Interface Recovery

If WiFi stops working after using monitor mode, the tool creates a recovery script:

```bash
sudo ./wifi_recovery.sh
```

Or manually:
```bash
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

## Troubleshooting

### WiFi adapter not found
Check that your adapter supports monitor mode:
```bash
iw list | grep "monitor"
```

### Permission denied errors
Ensure you're running with sudo:
```bash
sudo python3 nanachi.py
```

### Terminal display corrupted
Run the reset command:
```bash
reset
```

### Deauth not working
- Verify the channel is correct
- Ensure monitor mode is active
- Check distance to target AP
- Some devices ignore deauth frames

## Legal Notice

This tool is for educational and authorized security testing only. Unauthorized access to computer systems and networks is illegal. The authors assume no liability for misuse.

## Credits

- Built with Python and Rich library
- Uses aircrack-ng suite for WiFi operations
- Integrates nmap for network scanning
- SQLMap for SQL injection testing
- LinPEAS by Carlos Polop for privilege escalation

## Version

Current version: 1.0

## License

For educational and authorized penetration testing use only.
