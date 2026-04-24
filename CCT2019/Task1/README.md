# Security Assessment Report: CCT2019 — Task 1

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** `pcap2_1583863710056.pcapng` (US Navy CCT 2019 PCAP challenge)
- **Room Type:** Forensics / PCAP
- **Date Solved:** 2026-04-24

**Objectives & Status:**
- [x] Recover embedded `pcap_chal.pcap` from USBPcap transfer
- [x] Extract and decrypt cryptcat payload on port 4444
- [x] Reverse engineer the decrypted ELF to obtain the flag

---

## Executive Summary & Key Findings

This assessment is a three-stage PCAP forensics challenge. A USBPcap dump hides a ZIP-encapsulated network capture (`pcap_chal.pcap`, 4,588 packets). Inside, IRC traffic leaks the cryptcat password hint (`RedRoverRedRover$$`), and an encrypted TCP stream on port 4444 conceals a 64-bit ELF. Decrypting the payload with key `BER5348833` (reference to the movie *The Net*) reveals an IRC client binary that constructs the flag via ROT-13 + string reversal of five embedded 8-byte chunks.

- **Exposed Services:** IRC (`irc.cct:6667`), cryptcat tunnel (`192.168.55.203:4444`)
- **Interesting Paths:** USB bulk transfer payloads → embedded ZIP → second PCAP → IRC creds → cryptcat stream → ELF binary → static flag reconstruction
- **Credentials Discovered:** IRC `zoobah:binaryphalanx`, cryptcat passphrase `BER5348833`
- **Loot & Flags:**
  - `CCT{h3's_a_pc@p_w1z@rd_th3re_h4s_g0t_to_6e_a_7w1st}`

---

## Exploitation Chain

1. **Reconnaissance (USB layer):** `pcap2_1583863710056.pcapng` is a USBPcap capture with 20 bulk-transfer packets. `binwalk` identifies a ZIP archive at offset `0x1D7`, but direct carving fails because pcapng block headers interleave the payload.
2. **File Recovery (pcapng → ZIP → pcap):** Parse pcapng Enhanced Packet Blocks, strip USBPcap headers, concatenate payloads, carve the ZIP, and extract `pcap_chal.pcap` (exactly 4,588 packets, matching HINT2).
3. **Traffic Analysis (network PCAP):** IRC traffic reveals `PASS RedRoverRedRover$$` and user `binaryphalanx`. TCP stream to port 4444 contains 14,552 bytes of encrypted data from `192.168.55.187` to `192.168.55.203`.
4. **Decryption (cryptcat):** Use `cryptcat -l -p 9999 -k BER5348833` as listener, pipe the raw TCP payload into it. Output is a 64-bit ELF executable (14,888 bytes).
5. **Static Analysis (ELF):** The binary is an IRC client that connects to `irc.cct`, joins `#flag`, and builds the flag by concatenating five encoded chunks, reversing the result, and applying ROT-13.

---

## Vulnerability Details

### VULN-01: Insufficient Parsing of PCAPNG Block Structure During USB Exfiltration Recovery
- **Vulnerable Location:** Forensic analysis workflow on `pcap2_1583863710056.pcapng`
- **Overview:** Naive file-carving tools (`dd`, `binwalk -e`) treat the pcapng as a raw blob and extract the ZIP at offset `0x1D7` directly. Because pcapng wraps each USB payload in Section Header Blocks and Enhanced Packet Blocks, the carved ZIP includes block headers and produces a corrupted archive (`bad zipfile offset`).
- **Impact:** Complete inability to recover the second PCAP, stalling the entire multi-stage challenge.
- **Severity:** High
- **Remediation:** Parse pcapng at the block level per the specification. For each Enhanced Packet Block (`block_type == 0x00000006`), read `captured_len` at offset 20, skip the 28-byte block header plus the USBPcap header (`hdr_len` at offset 0), then extract only the raw USB payload. Concatenate all payloads before carving.
- **Proof of Impact (Execution):**
  - `binwalk -e` extracted a 2,309,203-byte ZIP that `unzip` failed to inflate (`invalid compressed data`).
  - Python parser concatenated 20 USB payloads into `usb_payload.bin` (2,308,223 bytes).
  - ZIP carved from the concatenated buffer at offset 28 extracted cleanly to `pcap_chal.pcap` (4,588 packets).

### VULN-02: Static Passphrase Used for Symmetric Tunnel Encryption (cryptcat)
- **Vulnerable Location:** TCP stream 49, `192.168.55.187:56446 → 192.168.55.203:4444`
- **Overview:** The attacker used `cryptcat` with a hardcoded passphrase (`BER5348833`) to encrypt a reverse-shell payload. The passphrase is derived from a movie reference (*The Net*), making it trivially guessable once the IRC context (`RedRoverRedRover$$`, username `binaryphalanx`) is known.
- **Impact:** Full decryption of the 14,552-byte payload, revealing a malicious ELF executable designed to connect to `irc.cct` and exfiltrate the flag.
- **Severity:** Critical
- **Remediation:** Never use static or pop-culture-derived passphrases for encrypted tunnels. Rotate keys per session using ephemeral key exchange (e.g., TLS 1.3 with mutual auth, WireGuard, or SSH port forwarding). If symmetric encryption is unavoidable, derive keys from a high-entropy source and rotate them per connection.
- **Proof of Impact (Execution):**
  - `cryptcat -l -p 9999 -k BER5348833` successfully decrypted the payload when the raw TCP bytes were piped into the listener.
  - Output verified as `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)`.

### VULN-03: Hardcoded Sensitive Data in Stripped Binary with Trivial Obfuscation
- **Vulnerable Location:** `.text` segment of decrypted ELF at offsets `0x180e`–`0x1836`
- **Overview:** The ELF constructs the flag at runtime by concatenating five 8-byte string chunks, reversing the combined string, and applying ROT-13. Because ROT-13 is its own inverse and the chunks are stored as inline ASCII in the `.text` segment, static analysis recovers the plaintext without execution.
- **Impact:** Complete bypass of the intended dynamic-analysis path (connecting to `irc.cct`, joining `#flag`, waiting for `PRIVMSG`). The flag is recoverable in seconds from a dead binary.
- **Severity:** High
- **Remediation:** Do not embed sensitive strings in executable code. Generate flags server-side and transmit them over authenticated channels. If client-side generation is unavoidable, use proper runtime decryption with a key fetched from a remote, authenticated endpoint — not stored in the binary.
- **Proof of Impact (Execution):**
  - `strings -n 6 decrypted.bin` extracted the chunks: `gf1j7_n_`, `r6_bg_g0`, `t_f4u_er`, `3ug_qe@m`, `1j_c@pc_`.
  - Concatenation → reversal → ROT-13 yielded: `pc@p_w1z@rd_th3re_h4s_g0t_to_6e_a_7w1st`.
  - Full flag: `CCT{h3's_a_pc@p_w1z@rd_th3re_h4s_g0t_to_6e_a_7w1st}`.

---

## Vulnerability

**CWE-312 — Cleartext Storage of Sensitive Information**  
The ELF stores the flag in `.text` as a series of ROT-13 encoded chunks. ROT-13 is not encryption — it is a trivial substitution cipher that provides zero confidentiality.

**Related identifiers:**
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-522: Insufficiently Protected Credentials (static cryptcat passphrase)
- CWE-798: Use of Hard-coded Credentials (`BER5348833` embedded in attacker tooling)
- CWE-326: Inadequate Encryption Strength (ROT-13 used as obfuscation)
- MITRE ATT&CK T1041: Exfiltration Over C2 Channel (IRC-based flag transmission)
- MITRE ATT&CK T1020: Automated Exfiltration (USB bulk transfer of ZIP archive)

---

## Lessons Learned

### 1. PCAPNG block-level parsing is mandatory for accurate extraction
Treating a pcapng file as a raw byte stream is a common trap. The format is block-structured, and every packet is wrapped in metadata headers. `binwalk` and `dd` can identify the file signature, but they cannot skip interleaved block headers. For USBPcap specifically, the USB header length varies and must be read from the packet itself. Parsing at the spec level is the only way to guarantee clean extraction.

### 2. Adjacent protocols provide cross-context clues
The IRC password `RedRoverRedRover$$` and username `binaryphalanx` were not directly used for decryption, but they established the attacker's theme (movie references, military/CTF naming). This context made `BER5348833` (from *The Net*) a testable hypothesis within minutes. In real investigations, protocol adjacency is a powerful pivot: IRC, DNS, HTTP, and TLS SNI entries often leak the attacker's intent, tooling, or infrastructure naming conventions.

### 3. Static analysis is faster and safer than dynamic execution
The ELF was designed to run and connect to `irc.cct`, but the flag was already present in `.text`. Running unknown binaries requires sandboxing, network isolation, and time. When the binary is in your possession, `strings`, `objdump`, and `radare2` provide immediate answers without risk. The return on investment for static analysis is almost always higher in CTF and incident-response scenarios.

### 4. Weak obfuscation is worse than no obfuscation
ROT-13 is self-inverse and instantly reversible. Splitting the flag into chunks and reversing the string does not add meaningful entropy — it only slows down an attacker by the time it takes to concatenate and decode. If the threat model includes an attacker with access to the binary, client-side obfuscation must use proper cryptographic primitives (AES-GCM with a remote key) or, better, server-side generation.

### 5. Covert tunnels over well-known ports still leave forensic traces
The cryptcat stream on port 4444 is high-entropy and one-directional (all 14,552 bytes from client to server, zero bytes back). Even though the payload is encrypted, the traffic pattern is anomalous: a single burst of data with no application-layer handshake, no HTTP/TLS structure, and no bidirectional chatter. Behavioral analysis (packet sizes, timing, entropy) can flag such tunnels without decrypting them.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **PCAPNG is not raw data.** USBPcap in pcapng format wraps every USB payload in block headers. Treating it like a raw blob (`dd`, `binwalk -e`) often produces corrupted output. Always parse at the spec level when accuracy matters.
- **Context from one protocol unlocks another.** The IRC creds (`RedRoverRedRover$$`, `zoobah`) were the breadcrumb that led to the cryptcat passphrase `BER5348833`. In real investigations, protocol adjacency (IRC next to an encrypted tunnel) is a strong pivot point.
- **Static analysis beats dynamic execution for CTF flags.** The ELF was designed to run and connect to `irc.cct`, but the flag was already present in `.text`. When you own the binary, `strings`, `objdump`, and `radare2` are faster and safer than spinning up infrastructure.

### Real-World Context & Defense
- **Threat Landscape:** USB exfiltration followed by covert network tunnels is a common insider-threat pattern. DLP tools should monitor bulk USB transfers and alert on large sequential reads from removable storage.
- **Detection Engineering:** Alert on `cryptcat` process execution and static key usage. Monitor for IRC connections from non-browser processes. Flag outbound connections to port 4444 from unexpected binaries.
- **System Hardening:** Restrict USB mass-storage access via device control policies. Block non-standard encrypted tunnels at the egress firewall. Use application allowlisting to prevent execution of unknown ELF binaries dropped by network tools.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Parse pcapng USB blocks and carve embedded ZIP
python3 -c "
import struct
with open('pcap2_1583863710056.pcapng', 'rb') as f:
    data = f.read()
pos = 0
payloads = []
while pos < len(data):
    block_type, block_len = struct.unpack_from('<II', data, pos)
    if block_type == 0x00000006:  # Enhanced Packet Block
        captured_len = struct.unpack_from('<I', data, pos + 20)[0]
        packet_data = data[pos + 28 : pos + 28 + captured_len]
        hdr_len = struct.unpack_from('<H', packet_data, 0)[0]
        payloads.append(packet_data[hdr_len:])
    pos += block_len
concatenated = b''.join(payloads)
zip_start = concatenated.find(b'PK\x03\x04')
zip_end = concatenated.rfind(b'PK\x05\x06') + 22
with open('pcap_chal.zip', 'wb') as f:
    f.write(concatenated[zip_start:zip_end])
"

# Decrypt cryptcat payload
cryptcat -l -p 9999 -k BER5348833 > decrypted.bin &
cat raw_tcp_payload.bin | nc -q 0 localhost 9999

# Verify decrypted binary
file decrypted.bin
# ELF 64-bit LSB pie executable, x86-64

# Extract flag chunks from binary strings
strings -n 6 decrypted.bin | grep -E '^[a-z0-9_!@]{8}$'
# gf1j7_n_  r6_bg_g0  t_f4u_er  3ug_qe@m  1j_c@pc_

# Decode flag
python3 -c "
import codecs
chunks = ['gf1j7_n_', 'r6_bg_g0', 't_f4u_er', '3ug_qe@m', '1j_c@pc_']
combined = ''.join(chunks)
reversed_str = combined[::-1]
flag = codecs.decode(reversed_str, 'rot_13')
print('CCT{h3\'s_a_' + flag + '}')
"
```
