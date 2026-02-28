# Nanachi Pentest Tool

A comprehensive penetration testing toolkit with an interactive TUI (Text User Interface) built with Python and Rich library.

![Demo](.nanachi.gif)

## Features

## Prushka
![Demo](.prushka.gif)
### How it work
Prushka will take the content you provide and will attempt to reverse the ciphering by testing about a hundred encryption methods. Each time, Prushka will analyse the unciphered string, and will attribute a score to it, the score is determined by the antropy and the presence or not of common words in the string such as password flag ... 
###made and use for decrypting strings 
### OPTIONS:
- `-r` recursive mode combine differents encryptions method to decrypt hard-ciphered messages
- `-v` show a top of the highest decryption scores
- `-h` add a detection of hashes type for each string decrypted using haiti
- `-w` add a wordlist that detects words and add a more accurate score
- `-f` analyse instead of a string the content of a file
### USAGE:
- `-r "x"` where x is the number of recursion. When 3 < x it can take a serious amount of time
- `-v "x"` where x is the Top x, for example -v 10 shows the top 10 highest score
- `-w "wordlist"` where wordlist is the path of the wordlist
- `-f "file"` where file is the path of the file
### WHEN RUNNING
- `s` typing s permit to see the status, time remaining, top 5 ...
- `q` typing q permit you to quit and print the actual state of the top
### /!\ Good to Know (Power)
analysing with the option -h slows down a lot the search
analysing with a recusrion above 3 is often an impossible task cause the difference of time-search between recursions is a X to the power ok recursions:
- 1 recursion ~ 2 to 3 seconds
- 2 recursions ~ 10 to 25 minutes
- 3 recursions ~ 900 minutes to 2700 minutes
- 4 and more recursions ~ 60 000 minutes and more
You usually dont need to wait the end to find the result, oftenly the result is showed the first 10% of the search
but 10% of 60 000 is still 6 000 minutes
### /!\ Good to Know (Score)
How to spot a good score ?
Basically you dont need most of the time to watch the score the result is oftenly obvious in the top, the score is mostly made for the computer.

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

### Recommended WiFi Adapters

For WiFi attacks (deauth, fake AP, handshake capture), you need a wireless adapter that supports **monitor mode** and **packet injection**. Built-in laptop WiFi cards often do NOT support these features.

#### Recommended USB WiFi Dongles:

**ALFA Network Adapters** (Most Popular):
- **ALFA AWUS036ACH** - Dual-band (2.4GHz + 5GHz), Realtek RTL8812AU chipset
- **ALFA AWUS036ACM** - Dual-band, MediaTek MT7612U chipset, excellent range
- **ALFA AWUS036NHA** - 2.4GHz only, Atheros AR9271 chipset, very reliable
- **ALFA AWUS036ACHM** - Dual-band, MediaTek chipset, compact design

**TP-Link Adapters**:
- **TP-Link TL-WN722N v1** (Version 1 ONLY - v2/v3 do NOT support monitor mode)
- **TP-Link Archer T3U Plus** - MediaTek chipset

**Panda Wireless**:
- **Panda PAU09** - Ralink RT5572 chipset
- **Panda PAU0D** - Dual-band

**Other Options**:
- **EDUP EP-AC1605** - RTL8812AU chipset
- **COMFAST CF-912AC** - Dual-band

#### Chipset Compatibility

Look for adapters with these chipsets (best support in Linux):
- **Atheros AR9271** - Excellent for 2.4GHz
- **Ralink RT3070/RT5370/RT5572** - Good compatibility
- **Realtek RTL8812AU** - Dual-band support
- **MediaTek MT7612U/MT7610U** - Modern, good performance

#### How to Check if Your Adapter Supports Monitor Mode

```bash
# Check if adapter is detected
iw dev

# Check if monitor mode is supported
iw list | grep -A 10 "Supported interface modes" | grep monitor

# Check if packet injection works
sudo aireplay-ng --test wlan0
```

#### Important Notes

- **Built-in laptop WiFi**: Usually does NOT support monitor mode
- **USB 3.0**: Recommended for better performance and range
- **Driver installation**: Some adapters require additional driver installation
- **Kali Linux**: Most adapters work out-of-the-box on Kali
- **Ubuntu/Debian**: May require driver compilation from GitHub

#### Driver Installation Resources

For RTL8812AU chipset:
```bash
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
make
sudo make install
```

For MT7612U chipset:
```bash
git clone https://github.com/gnab/rt2870.git
cd rt2870
make
sudo make install
```

**Where to Buy**:
- Amazon
- eBay  
- Official ALFA Network website
- Hak5 shop
- Local electronics stores

**Price Range**: $20-80 USD depending on model and features.

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
