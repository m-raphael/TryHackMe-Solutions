# 🏆 Walkthrough: THM — Chrome

**Room:** https://tryhackme.com/room/chrome  
**Category:** Forensics  
**Status:** Complete

> A password manager is only as strong as the password that encrypts it.  
> You find that a malicious actor extracted something over the network, but what?

---

## Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | What is the first password that we find? | `bubbles` |
| 2 | What is the URL found in the first index? (defanged) | `hxxps[://]mysecuresite[.]thm/` |
| 3 | What is the password found in the first index? | `Sup3rPaS$w0rd1` |
| 4 | What is the URL found in the second index? (defanged) | `hxxps[://]worksite[.]thm/` |
| 5 | What is the password found in the second index? | `Sup3rSecuR3!` |

---

## Attack Chain

```
traffic.pcapng
  └─ SMB session (10.0.2.19 ↔ 10.0.2.36:445, 75MB)
       ├─ transfer.exe       (.NET binary, AES-256-CBC exfil tool)
       └─ encrypted_files    (encrypted Chrome AppData profile)

transfer.exe  ──monodis──►  AES key: PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1
                             AES IV:  lR3soZqkaWZ9ojTX

encrypted_files  ──AES-256-CBC──►  decrypted_files.zip
                                        └─ AppData/
                                             ├─ Local/Google/Chrome/User Data/
                                             │    ├─ Local State      (DPAPI-wrapped Chrome key)
                                             │    └─ Default/Login Data  (SQLite, 2 v10 entries)
                                             └─ Roaming/Microsoft/Protect/<SID>/
                                                  └─ 8c6b6187-...    (DPAPI master key)

NTLMv2 hash (pcap)  ──hashcat m5600 + rockyou──►  hacked  (SMB credential, not used for DPAPI)

DPAPI master key  ──PBKDF2-HMAC-SHA512 (8000 iter) + rockyou top-200──►  bubbles  (Windows password)
                  ──deriveKeysFromUser()──►  prekey  ──AES──►  master key bytes

Local State  ──DPAPI blob decrypt (master key)──►  Chrome AES-256-GCM key (32 bytes)

Login Data  ──AES-256-GCM (v10 nonce + ciphertext + tag)──►  plaintext passwords
```

---

## Key Technical Details

### AES Exfil (transfer.exe)
- .NET v4.7.2, decompiled with `monodis`
- Mode: CBC, key/IV hardcoded in IL bytecode

### NTLMv2 Crack
```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# result: hacked  (entry ~52,412 in rockyou)
```
This is the SMB MicrosoftAccount credential — **not** the local Windows account password.

### DPAPI Chain
```python
from impacket.dpapi import MasterKey, Credential
from impacket.crypto import deriveKeysFromUser

# Derive prekeys from Windows password
sid = "S-1-5-21-3854677062-280096443-3674533662-1001"
password = "bubbles"
mk = MasterKey(data=open("8c6b6187-...","rb").read())
keys = deriveKeysFromUser(sid, password)
for key in keys:
    if mk.decrypt(key):
        break
```

### Chrome v10 Password Format
```
v10 | 12-byte nonce | ciphertext | 16-byte GCM tag
```
Decrypted with AES-256-GCM using the key extracted from `Local State`.

---

## Vulnerability

**CWE-312 — Cleartext Storage of Sensitive Information**  
Chrome stores passwords encrypted with a key that is itself protected only by the Windows user account password (DPAPI). If an attacker can exfiltrate the Chrome profile (`Login Data` + `Local State`) alongside the DPAPI master key file, and knows (or can crack) the Windows account password, all stored credentials are fully recoverable offline — no interaction with the victim machine required after exfiltration.

**Related identifiers:**
- CWE-312: Cleartext Storage of Sensitive Information (post-decryption)
- CWE-522: Insufficiently Protected Credentials (key protection tied to OS user password strength)
- CWE-321: Use of Hard-coded Cryptographic Key (transfer.exe embedded AES key/IV)
- MITRE ATT&CK T1555.003: Credentials from Password Stores — Credentials from Web Browsers

---

## Lessons Learned

### 1. Credential hierarchy matters
Two separate passwords were in play: the SMB network credential (`hacked`) and the local Windows account password (`bubbles`). Conflating them blocked DPAPI decryption for most of the investigation. Always map what each credential is protecting before assuming re-use.

### 2. Hardcoded keys are trivially reversible
`transfer.exe` embedded the AES key and IV directly in IL bytecode. A single `monodis` pass exposed them. Any binary shipping a symmetric key in its own code offers no real confidentiality.

### 3. DPAPI security ceiling = Windows password strength
Chrome's encryption is only as strong as the local account password protecting the DPAPI master key. `bubbles` is a top-200 rockyou entry — the entire credential store fell in under a minute of manual testing once the correct target was identified.

### 4. NTLMv2 in plaintext network traffic is a gift to attackers
The NTLM challenge/response was visible in the pcap. SMB without signing or encryption over a monitored network leaks authentication material that can be cracked offline with no lockout risk.

### 5. Impacket CLI vs. API
The `impacket-dpapi` CLI tool had a bug (`options.password` vs `self.options.password`) that silently failed regardless of input. When a tool gives unexpected results, go one layer deeper and use the library API directly rather than chasing the wrong root cause.

### 6. Offline attacks need no time pressure
Once the Chrome profile and DPAPI key file were exfiltrated, the attacker had everything needed to recover credentials with zero network access. Detection/response after the exfil event is too late — the data is already gone.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `tshark` | PCAP analysis, SMB object export |
| `monodis` (mono-utils) | .NET IL disassembly |
| `openssl enc -aes-256-cbc` | Decrypt exfiltrated archive |
| `hashcat -m 5600` | NTLMv2 crack |
| `impacket` (Python) | DPAPI master key + blob decryption |
| `sqlite3` | Query Chrome Login Data |
| Python `cryptography` | AES-256-GCM final password decryption |
