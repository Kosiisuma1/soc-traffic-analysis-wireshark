# SOC Traffic Analysis Lab – Wireshark Investigation

## Overview
This lab focused on identifying suspicious activity across multiple PCAP files using Wireshark.

The investigation covered:
- Nmap scanning detection
- ARP Poisoning / MITM attack
- Credential interception
- Host identification (DHCP, NBNS, Kerberos)
- ICMP & DNS tunneling detection

---

## 1. Nmap Scan Detection

### TCP Connect Scan
Filter:
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024

Reasoning:
- Relies on full 3-way handshake
- Larger window size
- Used by non-privileged users

- Reasoning:

-SYN=1 & ACK=0 → Start of connection
-window_size >1024 → Full TCP handshake (Connect scan)
-Answer: 1000 TCP Connect scans

-Scan Type on Port 80
-Observed full TCP handshake → TCP Connect scan

### SYN Scan
Filter:
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024

Reasoning:
- Half-open scan
- Does not complete handshake
- Faster reconnaissance technique

### UDP Scan
Filter:
icmp.type==3 and icmp.code==3

Reasoning:
- Closed UDP ports respond with ICMP Destination Unreachable
- Correlation required between UDP and ICMP traffic
- 1083 closed UDP ports

Open UDP Port (Range 55–70)

Filter:
udp.dstport in {55 .. 70}
Reasoning:
- Shows UDP traffic in range; open ports do not trigger ICMP unreachable responses.
- UDP port 68

---

## 2. ARP Poisoning & MITM Detection

Attacker MAC: 00:0c:29:e2:18:b4
ARP Requests by Attacker
Filter:
eth.src==00:0c:29:e2:18:b4 and arp.opcode==1

Reasoning:

- eth.src → From attacker
- arp.opcode==1 → ARP Request
- 284 requests

HTTP Packets Received by Attacker
Filter:
eth.dst==00:0c:29:e2:18:b4 and http

Reasoning:
- Packets redirected to attacker MAC → confirms MITM attack.
- 90 HTTP packets

Sniffed Credentials

Filter:
http.request.full_uri=="http://testphp.vulnweb.com/userinfo.php" 
and http.request.method==POST 
and urlencoded-form contains "uname"

Reasoning:
- POST → login form submissions
- uname → username field
- full_uri → isolates login endpoint
- 6 credentials captured
- Client986 Password
- Expanded packet → clientnothere!
- Client354 Comment
- Inspected POST → Nice work!

Conclusion:
Confirmed Man-in-the-Middle attack via ARP poisoning.

---

## 3. Credential Interception

Filter:
http.request.method==POST

Refined with:
http.request.full_uri
urlencoded-form contains "uname"

Findings:
- Multiple credential submissions intercepted
- HTML Form URL Encoded fields exposed username/password

Impact:
Active credential harvesting via MITM.

---

## 4. Host & User Identification

### DHCP
dhcp.option.hostname contains "<keyword>"
Galaxy A30 MAC Address

Filter:
dhcp.option.hostname contains "Galaxy" and dhcp.option.hostname contains "A30"

- Answer: 9a:81:41:cb:96:6c
- Mapped hostname → IP → MAC

### NetBIOS
nbns.name contains "<hostname>"
Filter:
nbns.name contains "LIVALJM" and nbns.flags in {0x2810 0x2910}

- 16 registrations

Filtered by registration flags to isolate name registrations.

### Kerberos
kerberos.CNameString=="<username>"

Identified user IP addresses and service ticket activity.

Host Requested IP 172.16.13.85

Filter:
dhcp.option.requested_ip_address==172.16.13.85

-Answer: Galaxy-A12

## 5. Tunnelling Detection

### ICMP
- Large or repetitive payloads
- Encapsulated protocol data in RAW view
- Inspected ICMP payload → SSH

### DNS
- Long subdomain queries
- Encoded command patterns
- High-frequency DNS requests to suspicious domain
- Looked for suspicious long DNS queries → dataexfil[.]com
  

  ## 📷 Lab Screenshots – Wireshark Investigation

### 1️⃣ TCP Connect Scan Detection
![TCP Connect Scan](images/image1_tcp_connect_scan.png)  
Observed full TCP handshake indicating TCP Connect scan.

### 2️⃣ SYN Scan Detection
![SYN Scan](images/image2_SYN_Scan.png)  
Half-open TCP scan detected via SYN flags and window size ≤ 1024.

### 3️⃣ UDP Scan Detection
![UDP Scan](images/image3_udp_scan.png)  
Closed UDP ports identified through ICMP Destination Unreachable messages.

### 4️⃣ ARP Requests by Attacker
![ARP Requests](images/image4_arp_requests.png)  
Attacker MAC 00:0c:29:e2:18:b4 sending ARP requests → MITM confirmation.

### 5️⃣ MAC Address Column Verification
![MAC Address Columns](images/image5_mac_columns.png)  
Observed attacker MAC in traffic → confirmed packet redirection.

### 6️⃣ Intercepted Credentials
![Credentials Intercepted](images/image6_credentials.png)  
Captured usernames and passwords from HTTP POST traffic.

### 7️⃣ DHCP Host Identification
![DHCP Host](images/image7_dhcp.png)  
Mapped hostnames to IP and MAC addresses using DHCP packets.

### 8️⃣ NetBIOS Host Identification
![NetBIOS Host](images/image8_nbns.png)  
Filtered NetBIOS registrations to isolate target hostnames.

### 9️⃣ Kerberos User Activity
![Kerberos User](images/image9_kerberos.png)  
Tracked service tickets and user IP addresses for host identification.

### 🔟 ICMP Tunneling Detection
![ICMP Tunneling](images/image10_icmp_tunnel.png)  
Detected large/repetitive ICMP payloads containing encapsulated SSH data.

### 1️⃣1️⃣ DNS Tunneling Detection
![DNS Tunneling](images/image11_dns_tunnel.png)  
Suspicious high-frequency long DNS queries → data exfiltration activity.

---

## Key Skills Strengthened
- TCP flag analysis
- Protocol correlation
- MAC/IP attribution
- Credential traffic inspection
- Covert channel detection
- Structured SOC investigation workflow


## Activity	MITRE Technique
- Network Scanning 	T1046 – Network Service Discovery
- ARP Poisoning	T1557.002 – Adversary-in-the-Middle
- Credential Interception	T1557 – Man-in-the-Middle
- DNS Tunneling	T1071.004 – Application Layer Protocol: DNS
- ICMP Tunneling	T1095 – Non-Application Layer Protocol
- Credential Harvesting	T1056 – Input Capture

