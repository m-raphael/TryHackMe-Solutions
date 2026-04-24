# Security Assessment Report: CCT2019 — Task 3

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** `for1_8f90d68390b565c308871a52c6572de8_1583875226079.jpeg` (US Navy CCT 2019 steganography challenge)
- **Room Type:** Forensics / Steganography
- **Date Solved:** 2026-04-24

**Objectives & Status:**
- [x] Extract embedded files from JPEG (ZIP + steghide layers)
- [x] Decode Morse code from Exif metadata
- [x] Decrypt Enigma M4 cipher to obtain final flag

---

## Executive Summary & Key Findings

This assessment is a multi-layered steganography and cryptography challenge. A JPEG image found on an employee's desktop contains four sequential layers: an embedded password-protected ZIP, a `steghide` payload, a second encrypted archive, and finally an Enigma M4 cipher. Each layer's password is derived from the previous layer's output. The Exif metadata hides a Morse-encoded hint (`JUSTAWARMUPRIGHT?`), and a fake flag contains the passphrase for the `steghide` layer. The final Enigma decryption requires corrected ciphertext due to a known bug in the challenge.

- **Exposed Data:** Artist `Ed`, Morse hint `JUSTAWARMUPRIGHT?`, Matrix-themed passphrase `Z10N0101`
- **Interesting Paths:** Exif metadata → embedded ZIP (password `justawarmupright?`) → fakeflag.txt (`Z10N0101`) → steghide (`archive.zip`) → onion password → Enigma M4 decryption → `flag.zip`
- **Credentials Discovered:** `justawarmupright?`, `Z10N0101`, `0ni0n_0f_0bfu5c@ti0n`, `ctfforensicsisnotrealforensics`
- **Loot & Flags:**
  - `CCT{Well_that_wasn’t_such_a_chore_now_was_it?}`

---

## Exploitation Chain

1. **Reconnaissance (Exif):** `exiftool` reveals Artist `Ed`, Copyright `CCT 2019`, and a Description field containing Morse code: `.--- ..- ... - .- .-- .- .-. -- ..- .--. .-. .. --. .... - ..--..` → `JUSTAWARMUPRIGHT?`.
2. **File Carving (JPEG → ZIP):** `binwalk` identifies a password-protected ZIP appended after the JPEG EOI marker at offset `0x7212`. Password: `justawarmupright?`. Inside: `fakeflag.txt`.
3. **Fake Flag → Steghide:** `fakeflag.txt` contains a *Matrix* quote and password `Z10N0101`. `steghide extract` on the original JPEG with passphrase `Z10N0101` produces `archive.zip`.
4. **Archive Decryption:** `archive.zip` (password: `0ni0n_0f_0bfu5c@ti0n`) contains three files: `cipher.txt`, `config.txt`, and `flag.zip`.
5. **Enigma M4 Decryption:** The config specifies Enigma M4 ("Shark") with reflector `C-Thin`, rotors `Gamma VI VII VIII`, position `AMTU`, ring `RING`, and plugboard `AM BY CH DR EL FX GO IV JN KU PS QT WZ`. Due to a challenge bug, the original ciphertext (`FSXL PXTH EKYT DJXS PYMO JLAY VPRP VO`) must be replaced with `JHSL PGLW YSQO DQVL PFAO TPCY KPUD TF`. Decryption yields `ctfforensicsisnotrealforensics`.
6. **Flag Extraction:** `flag.zip` password: `ctfforensicsisnotrealforensics`. Inside: `flag.txt` with the final flag.

---

## Vulnerability Details

### VULN-01: Sensitive Data Hidden in JPEG Exif Metadata Without Encryption
- **Vulnerable Location:** `for1_8f90d68390b565c308871a52c6572de8_1583875226079.jpeg`, Exif APP1 segments at offsets `0x14` and `0x8E`
- **Overview:** The image's Exif metadata contains the Artist name (`Ed`), a Morse-encoded hint (`JUSTAWARMUPRIGHT?`), and a Copyright field (`CCT 2019`). All of these are stored in cleartext within standard Exif tags. No obfuscation, encryption, or steganographic technique is applied to the metadata itself.
- **Impact:** Anyone with `exiftool` or a simple hex editor can extract the first password (`justawarmupright?`) within seconds, bypassing the need for any image analysis.
- **Severity:** High
- **Remediation:** Do not embed sensitive hints or passwords in Exif metadata. Strip metadata entirely before publishing images (`exiftool -all= image.jpg`). If hints must be embedded, use encryption or store them server-side.
- **Proof of Impact (Execution):**
  - `exiftool for1_...jpeg` revealed the Morse-encoded Description in under a second.
  - Morse decoding produced `JUSTAWARMUPRIGHT?`.
  - Lowercasing (per HINT1) produced the correct ZIP password: `justawarmupright?`.

### VULN-02: Sequential Password Chaining with Embedded Passphrases
- **Vulnerable Location:** `fakeflag.txt` inside embedded ZIP, `archive.zip` contents
- **Overview:** The challenge relies on a linear chain of embedded passwords: Exif → ZIP password → fake flag text → steghide passphrase → archive password → Enigma plaintext → final ZIP password. Each password is stored in the output of the previous layer. If any layer is compromised, the entire chain collapses.
- **Impact:** An attacker who bypasses any single layer (e.g., by extracting the ZIP without knowing the Morse hint, or by brute-forcing `steghide`) gains access to all downstream passwords and the final flag.
- **Severity:** High
- **Remediation:** Layered challenges are fine for CTFs, but in production, each layer should require independent knowledge or credentials. Never derive layer N+1's password from layer N's output alone. Use independent secrets, MFA, or server-side validation.
- **Proof of Impact (Execution):**
  - Extracted `fakeflag.txt` → read `PW: Z10N0101`.
  - Used `Z10N0101` as `steghide` passphrase → extracted `archive.zip`.
  - Inside `archive.zip`: password `0ni0n_0f_0bfu5c@ti0n` was directly embedded in the challenge's context (HINT2).
  - Enigma decrypted plaintext `ctfforensicsisnotrealforensics` became the final `flag.zip` password.

### VULN-03: Challenge Bug — Incorrect Ciphertext Distributed to Players
- **Vulnerable Location:** `cipher.txt` inside `archive.zip`
- **Overview:** The original challenge shipped with an incorrect Enigma ciphertext (`FSXL PXTH EKYT DJXS PYMO JLAY VPRP VO`) that cannot be decrypted with the provided config. A correction was issued in the room notes: replace it with `JHSL PGLW YSQO DQVL PFAO TPCY KPUD TF`. This is a quality-control failure that breaks the challenge for players who do not check the errata.
- **Impact:** Players attempting to decrypt the original ciphertext will produce gibberish and waste time debugging their Enigma configuration. The bug effectively makes the challenge unsolvable without external hints.
- **Severity:** Medium (CTF-specific)
- **Remediation:** Before publishing a challenge, validate the entire chain end-to-end with the exact files distributed to players. Any correction should be applied to the challenge file itself, not just an errata note.
- **Proof of Impact (Execution):**
  - Original ciphertext `FSXL PXTH EKYT DJXS PYMO JLAY VPRP VO` decrypted to unreadable output with the given Enigma config.
  - After replacing with `JHSL PGLW YSQO DQVL PFAO TPCY KPUD TF` (per notes errata), decryption produced `ctfforensicsisnotrealforensics`.

---

## Vulnerability

**CWE-312 — Cleartext Storage of Sensitive Information**  
The JPEG's Exif metadata stores the Morse-encoded hint in cleartext. The embedded `fakeflag.txt` stores the next password (`Z10N0101`) in plaintext. Each layer's secret is trivially recoverable once the previous layer is unlocked.

**CWE-798 — Use of Hard-coded Credentials**  
All passwords (`justawarmupright?`, `Z10N0101`, `0ni0n_0f_0bfu5c@ti0n`, `ctfforensicsisnotrealforensics`) are hardcoded into the challenge artifacts. No user-specific or dynamic secrets are required.

**CWE-691 — Insufficient Control Flow Management**  
The challenge relies on a strictly linear, unbranching chain. There is no fallback or alternative path. A single broken link (the incorrect ciphertext) halts all progress.

**Related identifiers:**
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-798: Use of Hard-coded Credentials
- CWE-691: Insufficient Control Flow Management
- CWE-345: Insufficient Verification of Data Authenticity (erroneous ciphertext shipped)
- MITRE ATT&CK T1027.002: Obfuscated Files or Information — Steganography
- MITRE ATT&CK T1552.001: Credentials In Files

---

## Lessons Learned

### 1. Exif metadata is not private
Every JPEG carries a payload of metadata that survives resaving, resizing, and recompression. `exiftool`, `strings`, and even a hex editor can pull out Artist, Description, GPS, and Comment fields in seconds. If you are embedding secrets in images, strip or encrypt the metadata first.

### 2. Steghide is password-protectable, but passwords must be strong
The `steghide` layer used `Z10N0101` — a pop-culture reference with a predictable leet-speak pattern. A short wordlist of movie references and leet variants would crack this in minutes. Real steganography should use high-entropy passphrases (20+ characters, random) and independent of any previous layer.

### 3. Ciphertext correctness is a pre-flight requirement
The incorrect Enigma ciphertext (`FSXL PXTH EKYT DJXS PYMO JLAY VPRP VO`) wasted time because it looked like valid Enigma output but produced garbage when decrypted. Before shipping any crypto challenge, run the full encrypt→decrypt round-trip with the exact files players will download. Errata notes are a last resort, not a fix.

### 4. Layered security is only as strong as its weakest layer
Four layers of protection (Exif hint, embedded ZIP, steghide, Enigma) sound impressive, but each layer's key is stored in the previous layer's output. This is a "security through obscurity" chain. In real systems, each authentication factor should be independently derived, not chained.

### 5. Morse code is a hint, not a cipher
Encoding a password as Morse does not protect it — it merely changes the alphabet. Anyone who recognizes the pattern (dots, dashes, spaces) can decode it instantly. Treat Morse as a delivery mechanism for hints, not as confidentiality control.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Metadata is the first thing attackers check.** Before looking for steganography, LSB encoding, or appended files, always run `exiftool` and `strings`. In incident response, Exif metadata has been used to deanonymize sources, reveal camera models, and leak GPS coordinates.
- **Steghide passwords are crackable if short.** Unlike file encryption where brute-force is computationally expensive, `steghide` does not use key stretching (PBKDF2, Argon2). A short password can be brute-forced with `stegseek` or a custom wordlist in reasonable time.
- **Classical ciphers are puzzles, not protections.** Enigma, Vigenère, Caesar, and other historical ciphers are fun for CTFs but offer zero security against modern cryptanalysis. Enigma was broken in the 1940s with electromechanical devices; a Python script breaks it in milliseconds today.

### Real-World Context & Defense
- **Threat Landscape:** Steganography is used by APT groups to exfiltrate data via images posted on public forums, social media, or email attachments. The carrier image appears benign, but the hidden payload is only recoverable with the correct passphrase.
- **Detection Engineering:** Monitor for `steghide` or `stegseek` process execution. Alert on unusual Exif fields (Description, Comment, Artist) containing non-standard data. Flag images with appended ZIP/RAR signatures after the EOI marker (`FF D9`).
- **System Hardening:** Strip all metadata from images before publishing (`exiftool -all=`). Use DLP tools that scan image attachments for embedded archives or steganographic signatures. For sensitive data, use authenticated encryption (AES-GCM) over steganography.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Exif metadata extraction
exiftool for1_8f90d68390b565c308871a52c6572de8_1583875226079.jpeg
# Artist: Ed
# Copyright: CCT 2019
# Description: .--- ..- ... - .- .-- .- .-. -- ..- .--. .-. .. --. .... - ..--..

# Morse decode (Python)
python3 -c "
morse_map = {
    '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
    '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
    '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
    '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
    '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
    '--..':'Z', '..--..':'?'
}
morse = '.--- ..- ... - .- .-- .- .-. -- ..- .--. .-. .. --. .... - ..--..'
print(''.join(morse_map.get(c, c) for c in morse.split()))
# JUSTAWARMUPRIGHT?
"

# Embedded ZIP extraction
binwalk -e for1_8f90d68390b565c308871a52c6572de8_1583875226079.jpeg
# ZIP at offset 0x7212

# Brute-force ZIP with common password
python3 -c "
from zipfile import ZipFile
with ZipFile('7212.zip') as zf:
    zf.extractall(pwd=b'justawarmupright?')
"

# Steghide extraction
steghide extract -sf for1_8f90d68390b565c308871a52c6572de8_1583875226079.jpeg \
  -p Z10N0101 -xf archive.zip

# Extract archive.zip
python3 -c "
from zipfile import ZipFile
with ZipFile('archive.zip') as zf:
    zf.extractall(pwd=b'0ni0n_0f_0bfu5c@ti0n')
"

# Enigma M4 decryption with py-enigma
pip3 install --break-system-packages py-enigma
python3 -c "
from enigma.machine import EnigmaMachine
machine = EnigmaMachine.from_key_sheet(
    rotors='Gamma VI VII VIII',
    reflector='C-Thin',
    ring_settings=[17, 8, 13, 6],  # R=17, I=8, N=13, G=6
    plugboard_settings='AM BY CH DR EL FX GO IV JN KU PS QT WZ'
)
machine.set_display('AMTU')
cipher = 'JHSL PGLW YSQO DQVL PFAO TPCY KPUD TF'.replace(' ', '')
print(machine.process_text(cipher))
# ctfforensicsisnotrealforensics
"

# Final flag extraction
python3 -c "
from zipfile import ZipFile
with ZipFile('flag.zip') as zf:
    zf.extractall(pwd=b'ctfforensicsisnotrealforensics')
"
cat flag.txt
# CCT{Well_that_wasn’t_such_a_chore_now_was_it?}
```
