# Security Assessment Report: Forensics — Network & Malicious Processes (Task 2)

## Assessment Overview

- **Platform:** TryHackMe
- **Target:** `victim.raw` — Windows 7 SP1 x64 memory dump
- **Room Type:** Forensics / Memory DFIR
- **Date Solved:** 2026-05-02

**Objectives & Status:**

- [x] Q1 — Identify the suspicious open port
- [x] Q2 — Identify malicious process PIDs via VAD/execute protection

---

## Executive Summary & Key Findings

Network scan (`windows.netscan`) revealed an anomalous UDP socket on port 5005 bound to PID 2464 (`wmpnetwk.exe`). The `windows.malfind` plugin detected three processes with VAD-tagged memory regions and `PAGE_EXECUTE_READWRITE` protection — a classic code injection signature. These three PIDs (1860, 1820, 2464) represent the compromised processes on the system.

- **Exposed Services:** UDP/5005 (anomalous — wmpnetwk.exe), standard Windows RPC/DCOM ports
- **Interesting Paths:** Memory regions at `0x3ee0000` (explorer.exe), `0x24f0000` (svchost.exe), `0x280000` (wmpnetwk.exe)
- **Credentials Discovered:** None
- **Users Enumerated:** victim, VICTIM-PC$
- **Loot & Flags:**
  - `Q1: udp:5005`
  - `Q2: 1860;1820;2464`
- **Answers/Misc:** Suspicious port found via netscan; malicious PIDs confirmed via malfind

---

## Exploitation Chain

_Forensic analysis methodology for detecting malicious processes._

1. **Network Artifact Analysis:** Ran `windows.netscan` to enumerate all active and listening sockets. Identified UDP port 5005 bound to PID 2464 (`wmpnetwk.exe`) — anomalous because Windows Media Player does not normally listen on this port.
2. **Code Injection Detection:** Ran `windows.malfind` to scan all processes for memory regions with VAD tags (`VadS`) and `PAGE_EXECUTE_READWRITE` protection. Three PIDs flagged: 1860 (explorer.exe), 1820 (svchost.exe), 2464 (wmpnetwk.exe).
3. **Cross-Verification:** Correlated the suspicious PID (2464) from netscan with malfind findings — PID 2464 appears in both, confirming the process is both injected and listening on an anomalous port.

---

## Vulnerability Details

### VULN-01: Code Injection into Legitimate Windows Processes

- **Vulnerable Location:** Process memory — explorer.exe (PID 1860), svchost.exe (PID 1820), wmpnetwk.exe (PID 2464)
- **Overview:** Three Windows system processes had memory regions with `VadS` tag and `PAGE_EXECUTE_READWRITE` protection flags. This is a definitive indicator of code injection — an attacker wrote malicious shellcode into the address space of these processes and marked the memory as executable.
- **Impact:** Complete attacker control over injected processes. PID 1820 (svchost.exe) had the largest injected regions (CommitCharge 256 pages ≈ 1MB of shellcode). PID 1860 (explorer.exe) injection allows keystroke logging, screenshot capture, and desktop interaction. PID 2464 (wmpnetwk.exe) provides network-persistent C2 via UDP/5005.
- **Severity:** Critical
- **Remediation:**
  - Deploy EDR with API monitoring (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread chain detection)
  - Enable Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess)
  - Implement Windows Defender Application Control (WDAC) or AppLocker to block unauthorized DLL loads
  - Apply principle of least privilege — reduce the attack surface of svchost.exe instances
  - Upgrade from Windows 7 EOL (see CISA KEV: [CVE-2025-21418](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-21418), [CVE-2024-49039](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-49039))
- **Proof of Impact (Execution):**
  - `malfind` output confirms VadS + PAGE_EXECUTE_READWRITE on three PIDs
  - PID 1820 injected regions contain executable code (`48 8b 45 28 c7 00...`)
  - PID 2464 bound to UDP/5005 — provides network access to injected code
  - Vulnerabilities cross-referenced via [NVD Search](https://nvd.nist.gov/vuln/search), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [GitHub Advisory Database](https://github.com/advisories), [OSV.dev](https://osv.dev/)

### VULN-02: Anomalous Network Service on UDP/5005

- **Vulnerable Location:** Network — UDP port 5005, bound to PID 2464 (wmpnetwk.exe)
- **Overview:** `wmpnetwk.exe` (Windows Media Player Network Sharing Service) had a listening socket on UDP port 5005 — a non-standard port not associated with any legitimate Windows Media Player functionality. This is a strong indicator of C2 backdoor or covert data exfiltration channel.
- **Impact:** Persistent C2 communication channel. The injected code in PID 2464 can send/receive data over UDP/5005, bypassing TCP-centric firewall rules. Potential for data exfiltration, secondary payload download, or remote control.
- **Severity:** High
- **Remediation:**
  - Block unsolicited outbound UDP at network perimeter firewalls
  - Configure Windows Firewall to restrict wmpnetwk.exe outbound connections
  - Deploy IDS/IPS signatures for UDP/5005 traffic to known-malicious IPs
  - Monitor DNS queries from wmpnetwk.exe for C2 domain resolution (goporn.ru, ikaka.com, icsalabs.com)
- **Proof of Impact (Execution):**
  - `netscan` output: `UDPv4 0.0.0.0:5005 * 0 2464 wmpnetwk.exe`
  - Process memory of PID 2464 contains VadS PAGE_EXECUTE_READWRITE at 0x280000
  - C2 domains (goporn.ru, ikaka.com, icsalabs.com) and IPs found in raw dump via strings

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways

1. **malfind is the code injection detector of first resort** — It flags VAD nodes with `PAGE_EXECUTE_READWRITE` protection, which legitimate processes almost never have (they use `PAGE_EXECUTE_WRITECOPY` or `PAGE_READWRITE`). All three flagged PIDs had this exact signature.
2. **Network + process correlation catches what either alone misses** — PID 2464 (wmpnetwk.exe) on UDP/5005 is suspicious by itself, but malfind confirming code injection in the same PID makes the finding conclusive. Always correlate netscan with malfind.
3. **svchost.exe injection is particularly dangerous** — PID 1820 had the largest injected regions (CommitCharge 256). Since svchost.exe hosts multiple Windows services, an injection here can impersonate legitimate network traffic, making detection harder for signature-based tools.

### Real-World Context & Defense

- **Threat Landscape:** Code injection into svchost.exe and explorer.exe is a technique used by major malware families (Emotet, TrickBot, Cobalt Strike). The memory dump showed the user was analyzing Emotet samples (`Life Virus Samples\18 April\Emotet\`), suggesting this system was compromised by the very malware being analyzed.
- **Detection Engineering:**
  - **Sysmon Event ID 8** (CreateRemoteThread) — detect cross-process injection
  - **Sysmon Event ID 10** (ProcessAccess) — detect lsass.exe or svchost.exe handle duplication
  - **Sigma rule: `process_injection_vad`** — detect PAGE_EXECUTE_READWRITE regions in non-browser processes
  - **Zeek/Suricata signature** for UDP/5005 traffic
  - **Windows Defender ASR Rule:** "Block Office communication application from creating child processes"
- **System Hardening:**
  - **CIS Benchmark for Windows 10/11** — disable Windows Media Player Network Sharing service if not needed
  - **NIST SP 800-53 Rev. 5** — SI-4 (System Monitoring), SC-7 (Boundary Protection)
  - **Microsoft D3FEND** — technique `D3-PIA` (Process Injection Attack) defense via API monitoring
  - **Vulnerability references:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [NVD](https://nvd.nist.gov/vuln/search), [GitHub Advisories](https://github.com/advisories), [OSV.dev](https://osv.dev/)

---

## Technical Appendix: Commands Worth Keeping

```bash
# 1 — Network connections (find suspicious ports)
vol -f victim.raw windows.netscan

# 2 — Malicious process detection (VAD / code injection)
vol -f victim.raw windows.malfind

# 3 — Process environment variables (find unique vars)
vol -f victim.raw windows.envars --pid 2464

# 4 — Dump process memory for strings analysis (Volatility 2)
# volatility_2.6 -f victim.raw --profile=Win7SP1x64 memdump --pid=1820 --dump-dir dump/

# 5 — Extract C2 domains/IPs from dumped process memory (or raw dump)
strings victim.raw | grep -E "www\.(goporn|ikaka|icsalabs)"
strings victim.raw | grep -E "202\.107\.233\.211|209\.200\.12\.164|209\.190\.122\.186"

# 6 — View specific injected memory regions via VAD walk
vol -f victim.raw windows.vadinfo --pid 1820
vol -f victim.raw windows.vadwalk --pid 1820
```
