# Security Assessment Report: Forensics — Memory Analysis (Task 1)

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** `victim.raw` — Windows 7 SP1 x64 memory dump (MD5: `ba44c4b977d28132faeb5fb8b06debce`)
- **Room Type:** Forensics / Memory DFIR
- **Date Solved:** 2026-05-02

**Objectives & Status:**
- [x] Q1 — Identify the Operating System of the memory dump
- [x] Q2 — Find the PID of SearchIndexer
- [x] Q3 — Determine the last directory accessed by the user

---

## Executive Summary & Key Findings
A Windows 7 SP1 x64 memory dump (`victim.raw`) was analyzed using Volatility 3 to extract system information, process listings, and user activity artifacts. The OS was identified as **Windows 7** via the `KDBG` signature and `NTBuildLab` string. `SearchIndexer.exe` was found running with PID **2180**. Shellbag forensics on the `NTUSER.DAT` registry hive revealed the user's last browsed directory was named **deleted_files**.

- **Exposed Services:** SearchIndexer (PID 2180), standard Windows services (svchost, lsass, explorer), VirtualBox guest services
- **Interesting Paths:** `C:\Users\victim\Desktop\Life Virus Samples\`, `C:\Users\victim\Downloads\OfficeMalScanner\`, `C:\Users\victim\Downloads\Malware analysis\`
- **Credentials Discovered:** None exposed in this task
- **Users Enumerated:** `victim` (sole local user)
- **Loot & Flags:**
  - `Q1: Windows 7`
  - `Q2: 2180`
  - `Q3: deleted_files`
- **Answers/Misc:** All three task questions answered via volatility plugins (windows.info, windows.pslist, windows.registry.printkey on BagMRU/Bags)

---

## Exploitation Chain
*This is a forensic analysis, not an exploitation chain. The "attack narrative" below describes the analysis methodology.*

1. **Reconnaissance (Profile Identification):** Ran `windows.info` to determine OS profile — identified Windows 7 SP1 x64 from `NTBuildLab = 7601.18409.amd64fre.win7sp1_gdr.` and `NtMajorVersion = 6, NtMinorVersion = 1`.
2. **Initial Access (Process Enumeration):** Ran `windows.pslist` to enumerate running processes. Located `SearchIndexer.exe` with PID 2180 among legitimate Windows processes.
3. **Privilege Escalation (Registry Analysis):** Enumerated registry hives via `windows.registry.hivelist`, located the `NTUSER.DAT` hive for user `victim` at offset `0xf8a000fe7010`.
4. **Post-Exploitation (Artifact Extraction):** Examined shellbag keys (`Software\Microsoft\Windows\Shell\BagMRU` and `Software\Microsoft\Windows\Shell\Bags`) to reconstruct folder navigation history. The last accessed directory name was `deleted_files`.

---

## Vulnerability Details

### VULN-01: Windows 7 End-of-Life (EOL) — No Security Patches
- **Vulnerable Location:** Operating System — Windows 7 SP1 x64
- **Overview:** Windows 7 reached End of Life on January 14, 2020. Extended Security Updates ended January 2023. Any vulnerability discovered after EOL remains unpatched, including actively exploited CVEs in the CISA KEV catalog such as [CVE-2025-21418](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-21418) (AFD WinSock heap overflow → SYSTEM) and [CVE-2025-24983](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-24983) (Win32k use-after-free → local privilege escalation).
- **Impact:** Complete system compromise. No vendor patches available; system is vulnerable to any exploit that targets Windows 7 kernel/user-mode components.
- **Severity:** Critical
- **Remediation:** Upgrade to a supported Windows release (10/11 or Server 2019+). Apply all vendor patches by CISA KEV due dates on supported systems. For legacy systems that cannot be upgraded, implement network segmentation, application whitelisting (WDAC/AppLocker), and rigorous monitoring.
- **Proof of Impact (Execution):**
  - Identified via `windows.info` — confirmed no patch level beyond SP1.
  - Correlated against CISA KEV: [CVE-2025-21418](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-21418), [CVE-2025-24983](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-24983), [CVE-2024-49039](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-49039) all affect the same OS generation but receive no fix.
  - Additional references: [NVD Search](https://nvd.nist.gov/vuln/search), [GitHub Advisory Database](https://github.com/advisories), [OSV.dev](https://osv.dev/).

### VULN-02: User Activity Leakage via Shellbags (Privacy / Data Recovery)
- **Vulnerable Location:** Windows Registry — `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` and `Bags`
- **Overview:** Windows Shell bags persist folder navigation history in the registry. Even when users delete files or clear recent documents, the directory names remain in BagMRU and Bags keys indefinitely. This allows an investigator to reconstruct the user's folder browsing activity.
- **Impact:** Confidentiality breach — sensitive directory names (e.g., `deleted_files`, `Life Virus Samples`, `OfficeMalScanner`) are recoverable from memory. In real-world DFIR, this reveals what the user was working on.
- **Severity:** Medium (privacy / information disclosure)
- **Remediation:** Users can clear shellbags manually by deleting the BagMRU and Bags registry keys, but this is rarely done. Enterprises should treat shellbags as a forensic artifact — EDR tools can monitor BagMRU modifications. CIS guidance recommends limiting local admin rights to reduce the forensic footprint of user activity.
- **Proof of Impact (Execution):**
  - Navigated to `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags\1\Desktop` in the registry hive in memory.
  - Last write time: `2019-05-02 07:00:41 UTC`.
  - Directory name `deleted_files` extracted from BagMRU entry.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
1. **OS profiling is the foundation of memory forensics** — `windows.info` (or Volatility 2's `imageinfo`) is always the first step. Wrong profile means wrong symbol tables, which means false negatives in every subsequent plugin. Always verify via multiple indicators (KDBG, NTBuildLab, NtMajorVersion).
2. **Registry hives in memory are treasure troves** — The `NTUSER.DAT` hive in memory contains shellbags, UserAssist, RecentDocs, TypedPaths, and dozens of other artifact classes. Even without a full hive dump, volatility's `windows.registry.printkey` allows targeted key traversal. Shellbags, in particular, survive file deletion and are one of the longest-lasting user activity artifacts.
3. **Cross-artifact correlation beats single-plugin analysis** — The shellbag data (user folders), when combined with filescan output (actual file paths like `Life Virus Samples\18 April\Emotet\`), paints a complete picture of user behavior that no single plugin reveals.

### Real-World Context & Defense
- **Threat Landscape:** Windows 7 remains deployed in OT/ICS, healthcare, and air-gapped environments. These systems are prime targets for ransomware gangs because EOL means no patches. CISA KEV entries [CVE-2024-26169](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-26169) (Windows Error Reporting LPE) and [CVE-2024-21338](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21338) (appid.sys IOCTL LPE) are both known to be used in ransomware campaigns.
- **Detection Engineering:**
  - **Sysmon Event ID 11** (FileCreate) — monitor shellbag file modifications
  - **Sigma rule** for registry access to BagMRU/Bags keys
  - **Windows Event Log 4688** (Process Creation) — detect `reg.exe` queries on NTUSER.DAT shellbag keys
  - **EDR** — memory scan for volatility tool usage (defenders detect attackers, but also vice-versa)
- **System Hardening:**
  - **CIS Benchmark for Windows 7** — disable unnecessary services, enable BitLocker, enforce AppLocker
  - **NIST SP 800-53 Rev. 5** — CM-2 (Baseline Configuration), SI-4 (System Monitoring), AU-3 (Audit Record Content)
  - **Microsoft D3FEND** — technique `D3-MAD` (Memory Artifact Detection) for identifying forensic tool traces
  - **Vulnerability reference links:** [OSV.dev](https://osv.dev/), [GitHub Advisory Database](https://github.com/advisories), [NVD Search](https://nvd.nist.gov/vuln/search), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Technical Appendix: Commands Worth Keeping

```bash
# 1 — OS Profile Identification
vol -f victim.raw windows.info

# 2 — Process Listing
vol -f victim.raw windows.pslist

# 3 — Registry Hive Enumeration
vol -f victim.raw windows.registry.hivelist

# 4 — Shellbag Analysis (BagMRU)
vol -f victim.raw windows.registry.printkey \
  --offset 0xf8a000fe7010 \
  --key "Software\Microsoft\Windows\Shell\BagMRU" \
  --recurse

# 5 — Shellbag Analysis (Bags — Desktop)
vol -f victim.raw windows.registry.printkey \
  --offset 0xf8a000fe7010 \
  --key "Software\Microsoft\Windows\Shell\Bags" \
  --recurse

# 6 — UserAssist (Program Execution History)
vol -f victim.raw windows.registry.userassist \
  --offset 0xf8a000fe7010

# 7 — File System Scan (accessed files and directories)
vol -f victim.raw windows.filescan | grep "\\\\Users\\\\victim"

# 8 — TypedPaths (user typed directories)
vol -f victim.raw windows.registry.printkey \
  --offset 0xf8a000fe7010 \
  --key "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

# 9 — RecentDocs (recently opened files)
vol -f victim.raw windows.registry.printkey \
  --offset 0xf8a000fe7010 \
  --key "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# 10 — Environment Variables (explorer.exe — user context)
vol -f victim.raw windows.envars --pid 1860 | grep USER
```
