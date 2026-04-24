# Security Assessment Report: Directory

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** `traffic-1725627206938.pcap` (DFIR PCAP challenge)
- **Room Type:** Digital Forensics / Incident Response
- **Date Solved:** 2026-04-24

**Objectives & Status:**
- [x] Identify open ports discovered by threat actor
- [x] Enumerate valid usernames and identify foothold account
- [x] Extract and crack captured AS-REP hash
- [x] Determine commands executed by threat actor
- [x] Recover the flag

---

## Executive Summary & Key Findings

This assessment is a DFIR challenge analyzing a PCAP capture from a compromised Active Directory environment. A threat actor (10.0.2.74) conducted a full port scan against a Domain Controller (10.0.2.75), enumerated valid usernames via Kerberos AS-REQ probing, discovered that `larry.doe` had Kerberos pre-authentication disabled, performed an AS-REP roasting attack to capture and crack the user's hash, and authenticated via WinRM/Evil-WinRM to execute commands and dump the SAM/SYSTEM hives.

- **Exposed Services:** 53 (DNS), 80 (HTTP), 88 (Kerberos), 135 (RPC), 139 (NetBIOS), 389 (LDAP), 445 (SMB), 464 (kpasswd), 593 (RPC over HTTP), 636 (LDAPS), 3268/3269 (Global Catalog), 5357 (WSD), 5985 (WinRM)
- **Interesting Paths:** Kerberos user enumeration → AS-REP roast → hash cracking → Evil-WinRM foothold → registry hive dumping
- **Credentials Discovered:** `larry.doe` / `Password1!`
- **Users Enumerated:** john.doe, ranith.kays, joan.ray, larry.doe
- **Loot & Flags:**
  - `THM{Ya_G0t_R0aSt3d!}`
- **Answers/Misc:**
  - Open ports: `53,80,88,135,139,389,445,464,593,636,3268,3269,5357,5985`
  - Foothold user: `directory.thm\larry.doe`
  - Hash last 30 chars: `55616532b664cd0b50cda8d4ba469f`
  - Commands: `reg save HKLM\SYSTEM C:\SYSTEM,reg save HKLM\SAM C:\SAM`

---

## Exploitation Chain

1. **Reconnaissance (Port Scanning):** The threat actor ran a comprehensive TCP SYN scan (`nmap -p-`) against the Domain Controller, identifying 14 open ports including Kerberos (88), LDAP (389), SMB (445), and WinRM (5985).
2. **User Enumeration (Kerberos):** The attacker sent hundreds of Kerberos AS-REQs with username permutations. Three users returned `KRB5KDC_ERR_PREAUTH_REQUIRED` (valid but require pre-auth), while `larry.doe` returned a full AS-REP — indicating the account does not require pre-authentication.
3. **Hash Capture (AS-REP Roasting):** The attacker captured the AS-REP response for `larry.doe` (etype 23, RC4-HMAC). The encrypted cipher was extracted and cracked offline.
4. **Initial Access (WinRM):** Using the cracked password (`Password1!`), the attacker authenticated to WinRM on port 5985 via Evil-WinRM and established an interactive PowerShell session.
5. **Post-Exploitation:** The attacker executed `whoami`, then dumped the registry hives with `reg save HKLM\SYSTEM C:\SYSTEM` and `reg save HKLM\SAM C:\SAM` for offline credential extraction.

---

## Vulnerability Details

### VULN-01: Kerberos AS-REP Roasting (Disabled Pre-Authentication)
- **Vulnerable Location:** `larry.doe` Active Directory account
- **Overview:** The `larry.doe` user account had the "Do not require Kerberos preauthentication" setting enabled. This allows any unauthenticated attacker to request an AS-REP for the user and receive an encrypted blob that can be cracked offline to recover the user's password.
- **Impact:** Complete account compromise. An attacker on the network (or with UDP/88 access) can capture a crackable hash for any user with this setting, bypassing the need for valid credentials.
- **Severity:** High
- **Remediation:** Disable "Do not require Kerberos preauthentication" on all user accounts. Use Group Policy to enforce pre-authentication. Monitor for AS-REQs without corresponding pre-auth data using Windows Event ID 4768 with encryption type 0x17/0x18.
- **Proof of Impact (Execution):**
  - Sent Kerberos AS-REQ for `larry.doe` without pre-auth data.
  - Received AS-REP (frame 4817) with RC4-HMAC encrypted cipher.
  - Extracted `$krb5asrep$23$larry.doe@DIRECTORY.THM:cipher` and cracked with hashcat mode 18200 / john.
  - Recovered plaintext password: `Password1!`.

### VULN-02: WinRM Exposed to Untrusted Networks
- **Vulnerable Location:** TCP/5985 on 10.0.2.75
- **Overview:** Windows Remote Management (WinRM) was exposed without IP restrictions or multi-factor authentication. Once the attacker obtained `larry.doe`'s password, they authenticated directly to the server's management interface and gained an interactive PowerShell session with the user's privileges.
- **Impact:** Immediate remote code execution. WinRM provides a direct administrative channel; compromising any valid user's credentials yields an instant foothold.
- **Severity:** High
- **Remediation:** Restrict WinRM access via Windows Firewall or host-based firewall rules. Require network-level authentication (NLA) and enforce multi-factor authentication for privileged accounts. Consider disabling WinRM if not required, or restrict to jump hosts / bastion hosts only.
- **Proof of Impact (Execution):**
  - Authenticated to `http://10.0.2.75:5985/wsman` using `larry.doe` / `Password1!`.
  - Established Evil-WinRM session.
  - Executed `whoami`, `reg save HKLM\SYSTEM C:\SYSTEM`, and `reg save HKLM\SAM C:\SAM`.

### VULN-03: Cleartext Credential Storage in Registry (SAM/SYSTEM)
- **Vulnerable Location:** `HKLM\SAM` and `HKLM\SYSTEM` registry hives
- **Overview:** The attacker used standard Windows `reg save` commands to dump the SAM and SYSTEM hives. These hives contain password hashes for all local accounts and can be used to extract cached domain credentials or crack local account passwords offline.
- **Impact:** Credential material exfiltration. With the SAM and SYSTEM hives, an attacker can extract NTLM hashes for all local accounts and attempt Pass-the-Hash or offline cracking.
- **Severity:** Medium
- **Remediation:** Enable Credential Guard on Windows 10/11 and Server 2016+ to protect LSASS and prevent SAM/SYSTEM dumping. Monitor for `reg save` commands targeting SAM/SYSTEM (Sysmon Event ID 1 with command lines containing `reg save`). Apply least-privilege principles to prevent standard users from accessing sensitive registry hives.
- **Proof of Impact (Execution):**
  - Observed `reg save HKLM\SYSTEM C:\SYSTEM` and `reg save HKLM\SAM C:\SAM` in decrypted WinRM traffic.
  - These commands successfully dumped the registry hives for offline analysis.

---

## Lessons Learned

### 1. AS-REP roasting is a silent but severe misconfiguration
Disabling Kerberos pre-authentication is sometimes done for legacy compatibility or service accounts, but it creates an unauthenticated attack surface. Attackers can request AS-REPs for affected accounts from anywhere on the network and crack them offline. Audit your AD for accounts with `DONT_REQ_PREAUTH` set.

### 2. WinRM is a high-value attack surface
Port 5985/5986 provides a direct path to remote code execution. If exposed without strict access controls, any compromised domain credential becomes an instant foothold. Treat WinRM like SSH or RDP — restrict source IPs, require MFA, and monitor for anomalous connections.

### 3. Registry hive dumping is a post-exploitation goldmine
Once an attacker has any foothold, `reg save` of SAM/SYSTEM is a trivial next step. Credential Guard and Windows Defender Credential Guard can mitigate this by isolating LSASS. Detection rules for `reg.exe save` targeting `HKLM\SAM` or `HKLM\SYSTEM` are high-signal alerts.

### 4. Kerberos user enumeration leaks the attacker's intent
The hundreds of AS-REQs with varying username permutations are noisy and detectable. Windows Event ID 4768 with `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` is a clear indicator of Kerberos user enumeration. Monitor for bursts of failed AS-REQs from a single source IP.

### 5. PCAP analysis reveals the full kill chain
In environments without EDR or centralized logging, a well-timed Wireshark capture can preserve the entire attack narrative. PCAPs are invaluable for DFIR — they capture the raw network behavior that logs might miss, including encrypted handshake metadata and timing patterns.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Kerberos hardening is critical.** AS-REP roasting and Kerberoasting are both consequences of weak Kerberos configuration. Pre-authentication should be mandatory for all user accounts. Service accounts should use Managed Service Accounts (gMSAs) with random 120-character passwords that rotate automatically.
- **WinRM exposure = lateral movement highway.** WinRM is the Windows equivalent of SSH. If an attacker compromises any account and WinRM is open, they can pivot instantly. Network segmentation and Just Enough Administration (JEA) endpoints can limit the blast radius.
- **DFIR without endpoint telemetry is still viable.** This challenge demonstrates that a single PCAP can reveal the full attack chain: reconnaissance, enumeration, credential abuse, authentication, and post-exploitation. Organizations should ensure PCAP capture is enabled at key network chokepoints.

### Real-World Context & Defense
- **Threat Landscape:** AS-REP roasting is a standard technique in red-team and ransomware playbooks. Tools like `Rubeus`, `impacket-GetNPUsers`, and `kerbrute` automate the process. Real attackers often pair AS-REP roasting with Kerberoasting (TGS-REQ for SPNs) to maximize credential harvesting.
- **Detection Engineering:**
  - Monitor Windows Event ID 4768 for AS-REQs without pre-auth (TicketOptions will not include `0x40000000` — PA_ENC_TIMESTAMP).
  - Alert on Event ID 4624 (Logon) with LogonType 3 (Network) to WinRM port 5985 from unusual source IPs.
  - Sysmon Event ID 1: detect `reg.exe` with command line containing `save` and `SAM` or `SYSTEM`.
- **System Hardening:**
  - Disable Kerberos pre-auth only when absolutely necessary (legacy Unix clients). Audit with PowerShell: `Get-ADUser -Filter 'useraccountcontrol -band 4194304'`.
  - Restrict WinRM with `winrm configsdl` and Windows Firewall Group Policy.
  - Enable Credential Guard on all Windows 10/11 and Server 2016+ endpoints.
  - Deploy Attack Surface Reduction (ASR) rules to block credential theft from LSASS.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Recon — Identify open ports from SYN-ACK responses
tshark -r traffic.pcap -Y "ip.src==10.0.2.75 and ip.dst==10.0.2.74 and tcp.flags.syn==1 and tcp.flags.ack==1" -T fields -e tcp.srcport | sort -n | uniq

# Kerberos user enumeration — Show AS-REQ usernames
tshark -r traffic.pcap -Y "kerberos.msg_type==10" -T fields -e kerberos.CNameString | sort | uniq -c | sort -rn

# Identify valid users — PREAUTH_REQUIRED (error 25) vs PRINCIPAL_UNKNOWN (error 6)
tshark -r traffic.pcap -Y "kerberos" -T fields -e frame.number -e kerberos.msg_type -e kerberos.CNameString -e kerberos.error_code

# Extract AS-REP hash for offline cracking (Python + scapy)
# See extract_asrep.py or use tshark with custom dissectors
# Hashcat format: $krb5asrep$23$larry.doe@DIRECTORY.THM:<cipher_hex>
# hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt

# WinRM traffic overview
tshark -r traffic.pcap -Y "tcp.port==5985" -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri

# Decrypt WinRM session (requires session key derived from password)
# Use winrm_decrypt.py or similar with the cracked password
```
