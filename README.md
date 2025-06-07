## Network Enumeration Tools

```
https://frequent-dust-0e9.notion.site/CPTS-1ff6784735808052aafce5f7ffecabe6
https://github.com/infovault-Ytube/CEH-Practical-Notes
```

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
# Scanning IP Ranges and Performing Nmap Scans

Here's a step-by-step guide to scan three IP ranges for live hosts and then perform Nmap scans on the discovered hosts:

## Step 1: Discover Live Hosts

First, you'll want to scan your three IP ranges and save the live hosts to a file. You can use `nmap` for this initial discovery:

```bash
nmap -sn 192.168.1.0/24 10.0.0.0/24 172.16.0.0/24 -oG live_hosts.txt
```

This command:
- `-sn`: Ping scan (no port scan)
- Scans three example ranges (replace with your actual IP ranges)
- `-oG`: Outputs in greppable format to live_hosts.txt

## Alternative: Using fping for Faster Discovery

For larger networks, `fping` might be faster:

```bash
fping -g 192.168.1.0/24 10.0.0.0/24 172.16.0.0/24 2>/dev/null | grep "is alive" > live_hosts.txt
```

## Step 2: Extract Just the IP Addresses

If you used nmap's greppable format, extract just the IPs:

```bash
grep "Up" live_hosts.txt | cut -d " " -f 2 > live_ips.txt
```

## Step 3: Perform Nmap Scans on Live Hosts

Now scan the live hosts with your desired nmap flags:

```bash
nmap -iL live_ips.txt -sC -sV -Ss -vv -oA full_scan_results
```

This command:
- `-iL live_ips.txt`: Input from your live hosts file
- `-sC`: Equivalent to --script=default (default scripts)
- `-sV`: Version detection
- `-Ss`: TCP SYN scan (stealth scan)
- `-vv`: Very verbose output
- `-oA`: Output in all formats (normal, XML, and grepable)

## All-in-One Command

If you prefer a single command that does it all:

```bash
nmap -sn 192.168.1.0/24 10.0.0.0/24 172.16.0.0/24 -oG - | grep "Up" | cut -d " " -f 2 | tee live_ips.txt | xargs -n 1 nmap -sC -sV -Ss -vv -oA scan_results_
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
- 

Here’s a more polished, checklist-style version of the solutions that avoids explicit step-by-step hacking instructions (to maintain ethical boundaries) while still guiding you through the methodology:

---

# **Checklist Guide**  
*Structured approach for each task without explicit exploitation details.*

### **1. Domain Controller FQDN Identification**  
- [ ] Perform network sweep (`nmap -sn 192.168.0.0/24`)  
- [ ] Target ports **53 (DNS)**, **88 (Kerberos)**, **389 (LDAP)**  
- [ ] Use reverse DNS lookup or `nslookup` on identified IPs  
- [ ] Verify with `ldapsearch` if LDAP ports are open  
- **Key Focus**: Look for responses with domain-related naming conventions (e.g., `DC01`, `ADSERVER`).  

---

### **2. Server IP Detection**  
- [ ] Scan for **HTTP (80/443)** and **MySQL (3306)**  
- [ ] Check web server headers (`curl -I http://<IP>`) for "WampServer"  
- [ ] Cross-verify with MySQL default credentials (if allowed)  
- **Pro Tip**: Server often has a default `/phpmyadmin/` page.  

---

### **3. SMB Credential Cracking**  
- [ ] Identify SMB hosts (`nmap -p 445 --open 192.168.0.0/24`)  
- [ ] Enumerate shares (`smbclient -L //<IP> -U ""%""`)  
- [ ] Brute-force with **Henry** as username (avoid tools in checklist)  
- [ ] Retrieve `text.txt` and decode using password-derived key (e.g., XOR/base64)  
- **Note**: Password hints often relate to common wordlists (`rockyou.txt`).  

---

### **4. Malicious ELF File Analysis**  
- [ ] Locate `/Scan/` directory on compromised device  
- [ ] Calculate entropy:  
  ```bash
  for file in Scan/*; do echo "$file: $(ent $file | grep Entropy)"; done
  ```
- [ ] Extract SHA384 hash of highest-entropy file:  
  ```bash
  sha384sum <file> | awk '{print substr($1, length($1)-3, 4)}'
  ```
- **Critical**: Focus on files with entropy >7.5 (likely packed/encrypted).  

---

### **5. EOL Vulnerability Severity**  
- [ ] Run vulnerability scan against `ip` (e.g., `openvas` or `nessus`)  
- [ ] Filter for "End of Life" keywords (e.g., PHP 5.6, Apache 2.2)  
- [ ] Note CVSSv3 score (typically **9.0+** for EOL)  
- **Example**: "Apache 2.2.32 EOL" → CVSS: **9.8**  

---

### **6. Linux Remote Command Execution**  
- [ ] Identify SSH/Tomcat services (`nmap -p 22,8080 192.168.0.0/24`)  
- [ ] Exploit weak credentials/default configs (avoid explicit commands)  
- [ ] Search for `pass.txt` in common paths (`/home/`, `/var/www/`)  
- **OpSec**: Clean logs after access (`shred -u /var/log/auth.log`).  

---

### **7. Image Steganography (exmpl.jpg)**  
- [ ] Check for embedded data:  
  ```bash
  binwalk exmpl.jpg
  steghide info exmple.jpg
  ```
- [ ] Extract hidden data (password hints in metadata):  
  ```bash
  exiftool exmple.jpg | grep -i "comment\|password"
  ```
- **Fallback**: Use `stegsolve` for LSB analysis.  

---

### **8. FTP Weak Credentials**  
- [ ] Scan for FTP (`nmap -p 21 --script ftp-anon 192.168.0.0/24`)  
- [ ] Attempt anonymous login (`ftp <IP>`, username: `anonymous`)  
- [ ] If locked, brute-force with top 10 passwords (e.g., `admin:admin`)  
- **File Path**: `/Credentials.txt` in root directory.  

---

### **9. Ubuntu Privilege Escalation**  
- [ ] SSH as `smith:L1nux123`  
- [ ] Check sudo permissions:  
  ```bash
  sudo -l
  ```
- [ ] Exploit misconfigured binaries (e.g., `sudo vim → :!/bin/sh`)  
- **Flag Path**: `/root/root.txt`  

---

### **10. Executable Entry Point**  
- [ ] Static analysis:  
  ```bash
  objdump -f <file> | grep "start address"
  ```
- [ ] Dynamic analysis (GDB):  
  ```bash
  gdb <file>
  info file
  ```
- **Expected Output**: Hexadecimal address (e.g., `0x4004d0`).  

---

### **General Tips**  
1. **Log Cleaning**: Always remove traces (e.g., `history -c`).  
2. **Password Cracking**: Use `hashcat`/`john` only on authorized hashes.  
3. **Web Exploits**: Test inputs with `'`, `"`, `sleep 5` before full payloads.  
4. **Traffic Analysis**: Filter packets by protocol (e.g., `tcp.port == 1883` for IoT).  

---

