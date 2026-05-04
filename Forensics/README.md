# Forensics Room — Memory Analysis (TryHackMe)

## Target
- File: `Task1/victim_1556932027367.zip` → `victim.raw` (MD5: `ba44c4b977d28132faeb5fb8b06debce`)
- Tool: volatility3 (vol)
- Platform: Windows 7 SP1 x64 (VirtualBox VM)

## Task 1 — OS, Process, Shellbags
| Q | Question | Answer | Method |
|---|----------|--------|--------|
| 1 | Operating System? | **Windows 7** | `windows.info` → NTBuildLab `7601.18409.amd64fre.win7sp1_gdr.` |
| 2 | PID of SearchIndexer? | **2180** | `windows.pslist` |
| 3 | Last directory accessed? | **deleted_files** | `windows.registry.printkey` → BagMRU/Bags shellbags |

## Task 2 — Network & Malicious Processes
| Q | Question | Answer | Method |
|---|----------|--------|--------|
| 1 | Suspicious open port? | **udp:5005** | `windows.netscan` → PID 2464 bound to UDP/5005 |
| 2 | Malicious process PIDs? | **1860;1820;2464** | `windows.malfind` → VadS + PAGE_EXECUTE_READWRITE |

## Task 3 — Indicators of Compromise (IOCs)
| Q | Question | Answer | Method |
|---|----------|--------|--------|
| 1 | Domain www.go****.ru | **www.goporn.ru** | `strings` + grep on raw dump |
| 2 | Domain www.i****.com | **www.ikaka.com** | `strings` + grep on raw dump |
| 3 | Domain www.ic******.com | **www.icsalabs.com** | `strings` + grep on raw dump |
| 4 | IP 202.***.233.*** | **202.107.233.211** | `strings` + grep on raw dump |
| 5 | IP ***.200.**.164 | **209.200.12.164** | `strings` + grep on raw dump |
| 6 | IP 209.190.***.*** | **209.190.122.186** | `strings` + grep on raw dump |
| 7 | Unique env var of PID 2464? | **OANOCACHE** | `windows.envars --pid 2464` |

## Vulnerability References
- **CISA KEV:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **NVD:** https://nvd.nist.gov/vuln/search
- **OSV.dev:** https://osv.dev/
- **GitHub Advisories:** https://github.com/advisories
