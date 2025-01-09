## Network Enumeration Tools

### Nmap Commands

```bash
# Basic Network Scanning
nmap -T4 -A 192.168.1.0/24                    # Aggressive scan with OS detection
nmap -sV -p- 192.168.1.100                    # Service version detection
nmap -sC                                      # Default script scan
nmap -sP 192.168.1.0/24                       # Ping scan
nmap -sL                                      # List scan (hostnames)
nmap -O                                       # OS detection
nmap -oN output.txt                           # Save output to file
nmap -T4 -A -p 389,636,3268,3269 192.168.x.x/2x  #foot print Domain
or
nmap -p 389 --script ldap-rootdse <target_IP>
nmap -T4 -A -p 80,443 192.168.x.x/2x          # Looking for web servers

# SMB Enumeration
nmap --script smb-os-discovery.nse -p445 <IP>
nmap --script smb-enum-users.nse -p445 <IP>
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>

```

### SMB Tools

```bash
# SMBClient Commands
smbclient //<IP>/share_name                   # Connect to SMB share
smbget -R smb://<IP>/share_name              # Download files recursively

# Enum4Linux Commands
enum4linux -u user -p pass -U <IP>            # User enumeration
enum4linux -u user -p pass -o <IP>            # OS information
enum4linux -u user -p pass -P <IP>            # Password policy
enum4linux -u user -p pass -G <IP>            # Group information
enum4linux -u user -p pass -S <IP>            # Share enumeration
enum4linux -u user -p pass -a <IP>            # All enumeration

```

## Web Application Testing

### Directory Enumeration

```bash
# Dirsearch
dirsearch -u <https://target.com>
dirsearch -e php,html,js,txt -u <https://target.com>
dirsearch -w /usr/share/wordlists/dirb/common.txt -u <https://target.com>

# Gobuster
gobuster dir -u <http://target> -w wordlist.txt

```

### SQL Injection

```bash
# SQLMap Commands
sqlmap -u "<http://target.com/page.php?id=1>" --dbs
sqlmap -u "<http://target.com/page.php?id=1>" -D database_name --tables
sqlmap -u "<http://target.com/page.php?id=1>" -D database_name -T table_name --columns
sqlmap -u "<http://target.com/page.php?id=1>" -D database_name -T table_name --dump

```

## Password Cracking & Hashing

### Hash Analysis

```bash
# Hash Identification
hashid -m hash_value
hash-identifier

# Hashcat
hashcat -m hash_mode -a 0 hash.txt wordlist.txt

```

### Common Tools

- HashCalc - For calculating file hashes
- MD5 Calculator - For MD5 hash verification
- Veracrypt - For encrypted volume management
- BCTextEncoder - For text encryption/decryption

## Mobile Security Testing

### ADB Commands

```bash
# Android Debug Bridge
adb devices                                   # List connected devices
adb connect IP:5555                          # Connect over network
adb -d shell                                 # Access shell
adb pull /remote/path /local/path            # Download files
adb push /local/path /remote/path            # Upload files

```

## Wireless Security

### Aircrack-ng Suite

```bash
# WPA/WPA2 Cracking
aircrack-ng capture.cap -w wordlist.txt
# WEP Cracking
aircrack-ng capture.cap

```

## Steganography Tools & Commands

### Steghide

```bash
# Hide Data
steghide embed -ef secret.txt -cf image.jpg -p password

# Extract Data
steghide extract -sf image.jpg

```

### Other Stego Tools

- OpenStego - For hiding data in images
- Snow - For whitespace steganography
  ```bash
  snow.exe -C -p “password” file.txt
  ```
- Stegcracker - For cracking steghide passwords

```bash
stegcracker image.jpg wordlist.txt

```

## Essential Tools by Category

### Network Analysis

- Wireshark - Traffic analysis
- TCPDump - Packet capture
- Netcat - Network utility

# Wireshark PCAP Analysis Guide

## DOS Attack Analysis

### SYN Flood Detection

1. Apply these filters:

```
tcp.flags.syn == 1 and tcp.flags.ack == 0

```

1. Check Statistics > IPv4 Statistics > Source and Destination Addresses
2. Look for:
    - High number of SYN packets from same source
    - Multiple SYN packets without ACK responses
    - Single source IP sending to single destination
    - Unusually high packet frequency

### Common DOS Indicators

- High volume of identical packets
- Single source sending mass traffic
- Incomplete TCP handshakes
- Abnormal protocol behavior

### Analysis Steps

1. Open capture file in Wireshark
2. Navigate to Statistics menu
3. Check "Conversations" and "Endpoints"
4. Sort by packet count or bytes
5. Identify top talkers
6. Look for disproportionate traffic patterns

### Useful Wireshark Filters

```
# SYN Flood
tcp.flags.syn == 1

# TCP Reset Flood
tcp.flags.reset == 1

# ICMP Flood
icmp

# UDP Flood
udp

# High packet rate from single IP
ip.addr == x.x.x.x && frame.time_delta <= 0.1

```

## MQTT IoT Traffic Analysis

### MQTT Protocol Overview

- Default Port: 1883 (non-encrypted)
- Default Port: 8883 (encrypted)
- Protocol ID: MQTT in Wireshark

### MQTT Filters

```
# Basic MQTT filter
mqtt

# MQTT Publish Messages
mqtt.msgtype == 3

# MQTT Subscribe Messages
mqtt.msgtype == 8

# MQTT Control Packets
mqtt.msgtype

```

### Key MQTT Fields to Examine

1. Message Type:
    - CONNECT (1)
    - CONNACK (2)
    - PUBLISH (3)
    - SUBSCRIBE (8)
    - UNSUBSCRIBE (10)
2. Important Fields:
    - Topic
    - Message Length
    - QoS Level
    - Client ID
    - Payload

### Analysis Steps for MQTT

1. Apply MQTT filter
2. Look for PUBLISH messages
3. Right-click > Follow > MQTT Stream
4. Check Message Length field
5. Examine Topic structure
6. Review Payload content

### Finding Message Length

1. Filter for MQTT PUBLISH:

```
mqtt.msgtype == 3

```

1. Look in packet details for:
    - "Message Length" field
    - Usually under MQTT > PUBLISH Message

### Tips for MQTT Analysis

- Check connection patterns
- Review topic structures
- Examine message frequencies
- Look for authentication attempts
- Monitor QoS levels
- Check payload sizes

## General Analysis Tips

### Performance Optimization

- Use display filters effectively
- Limit capture size if possible
- Focus on relevant protocols
- Use statistical tools

### Common Issues

- Large file sizes
- Mixed protocol traffic
- Encrypted communications
- Missing packets

### Best Practices

1. Start with broad filters
2. Narrow down to specific traffic
3. Use statistics for overview
4. Export suspicious packets
5. Document findings
6. Note timestamps of events

Remember: When analyzing PCAP files, always work with copies of the original files to maintain evidence integrity.

### Vulnerability Assessment

- Nikto - Web vulnerability scanner

```bash
nikto -h <http://target.com> -Tuning 1

```

- OpenVAS - Vulnerability scanner
- OWASP ZAP - Web app security

### Remote Access Tools

### ProRat

- Default Port: 5110
- Usage:

```bash
# Scan for ProRat
nmap -p 5110 target_ip
# Connection steps:
1. Launch ProRat
2. Set target IP
3. Set port to 5110
4. Click Connect
5. Use File Manager to search for files

```

### Theef

- Default Ports:
    - Primary: 6703
    - Secondary: 2968
- Usage:

```bash
# Scan for Theef
nmap -p 6703,2968 target_ip
# Connection steps:
1. Open Theef
2. Input target IP
3. Set ports (6703 and 2968)
4. Establish connection
5. Access File Manager

```

### NjRat

- Default Port: 5552
- Alternative Ports: 1177, 5552, 8552
- Usage:

```bash
# Scan for NjRat
nmap -p 1177,5552,8552 target_ip
# Connection steps:
1. Launch NjRat
2. Configure IP and port
3. Click connect
4. Use Manager to browse directories

```

### General RAT Detection

```bash
# Scan all common RAT ports
nmap -p 5110,6703,2968,5552,1177,8552 target_ip

# More thorough scan with version detection
nmap -sV -p 5110,6703,2968,5552,1177,8552 target_ip

# Full port scan to find non-standard RAT ports
nmap -sV -p- target_ip

```

Important Notes:

1. RATs may use different ports if reconfigured
2. Always verify port numbers through scanning
3. Look for suspicious network connections
4. Check for unusual service names
5. Monitor for unexpected outbound connections

### Brute Force Tools

```bash
# Hydra
hydra -L users.txt -P passes.txt target_ip protocol
hydra -l user -P passes.txt ftp://target_ip

```

### Forensics Tools

- Autopsy - Digital forensics
- FTK Imager - Disk imaging
- Registry Viewer - Windows registry analysis

### Malware Analysis 
- PEiD tool
- PEView
