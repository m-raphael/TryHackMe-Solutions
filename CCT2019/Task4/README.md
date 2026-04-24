# Security Assessment Report: CCT2019 — Task 4

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** `crypto1_1583878372378.zip` (US Navy CCT 2019 cryptography challenge)
- **Room Type:** Cryptography
- **Date Solved:** 2026-04-24

**Objectives & Status:**
- [x] Decrypt crypto1a keyboard-layout substitution cipher (Dvorak)
- [x] Decrypt crypto1b rail-fence classical cipher (5 rails, bottom-up)
- [x] Decode crypto1c run-length-encoded binary payload

---

## Executive Summary & Key Findings

This assessment is a three-stage cryptography challenge that relies on weak obfuscation rather than encryption. Each stage uses a well-known classical cipher or encoding scheme: a Dvorak keyboard-layout substitution, a rail-fence transposition with only five rails, and a binary run-length encoding. Once identified, all three layers collapse instantly. The challenge passwords are derived from the cipher names themselves or from trivial pop-culture references (a 1973 animated film), making them guessable without solving the preceding stage.

- **Exposed Data:** Keyboard layout name `dvorak`, film reference `teerrrriiffiicccccc`
- **Interesting Paths:** Dvorak keyboard decode → `crypto1a.zip` password → rail-fence (5 rails, bottom-up) → `crypto1b.zip` password → RLE-to-binary decode → plaintext flag
- **Credentials Discovered:** `dvorakdvorakdvorak`, `teerrrriiffiicccccc`
- **Loot & Flags:**
  - `CCT{Actu411y_a_w@rmup}`
  - `CCT{th@t_w4s_th4_ea5y_bu770n!}`
  - `CCT{I_see_dead_ciphers_all_the_time}`

---

## Exploitation Chain

1. **Reconnaissance (Archive structure):** `crypto1_1583878372378.zip` extracts without a password to reveal `crypto1a.txt` (substitution ciphertext) and `crypto1a.zip` (password-protected).
2. **crypto1a — Keyboard Layout Substitution:** The ciphertext in `crypto1a.txt` is produced by typing QWERTY plaintext on a Dvorak keyboard. Using a Dvorak↔QWERTY converter reveals the hint: the key is the name of the layout, entered three times. Password: `dvorakdvorakdvorak`.
3. **crypto1b — Rail Fence Transposition:** The decrypted hint in `crypto1b.txt` explicitly references a "rail or five" and "bottom up." A rail-fence cipher with 5 rails, read from the bottom left, yields plaintext that references the goose spelling of "terrific" from *Charlotte's Web* (1973). Password: `teerrrriiffiicccccc`.
4. **crypto1c — Run-Length Encoding:** The final file is a string of digits representing alternating run-lengths of binary `0` and `1`, starting with `0`. Decoding to binary (`01011001...`) and converting 8-bit chunks to ASCII yields the congratulatory message and flag.

---

## Vulnerability Details

### VULN-01: Weak Obfuscation via Keyboard-Layout Substitution (Dvorak Cipher)
- **Vulnerable Location:** `crypto1a.txt`
- **Overview:** The first layer uses a keyboard-layout substitution (Dvorak → QWERTY) instead of a cryptographic cipher. This is trivially reversible once the attacker notices that common English digraphs and trigraphs map to adjacent keys on an alternative keyboard layout. No key, entropy, or computational effort is required beyond recognizing the scheme.
- **Impact:** Complete confidentiality bypass. An attacker who identifies the Dvorak mapping can recover the plaintext and the next password in seconds.
- **Severity:** High
- **Remediation:** Never rely on keyboard-layout shifts, Atbash, or other trivial substitutions for confidentiality. Use authenticated encryption (AES-GCM) with a high-entropy, independently derived key.
- **Proof of Impact (Execution):**
  - Passed `crypto1a.txt` through a Dvorak→QWERTY keyboard-change converter (dcode.fr).
  - Recovered plaintext revealing the password scheme: "the name of the 'layout' ... enter it thrice."
  - Unlocked `crypto1a.zip` with password `dvorakdvorakdvorak`.

### VULN-02: Classical Rail Fence Cipher with Predictable Parameters
- **Vulnerable Location:** `crypto1b.txt`
- **Overview:** The second layer uses a rail-fence transposition cipher with only five rails and a bottom-up read direction. The challenge text itself contains the parameters ("a rail or five" and "from the bottom up"). Rail-fence with ≤ 5 rails is brute-forceable by hand; automated tools recover the plaintext instantly.
- **Impact:** The plaintext leaks the next password (`teerrrriiffiicccccc`), which is in turn derived from a pop-culture reference rather than a strong secret.
- **Severity:** High
- **Remediation:** Rail-fence and other classical transposition ciphers are puzzles, not protections. Do not use them for data confidentiality. Replace with modern encryption.
- **Proof of Impact (Execution):**
  - Decoded `crypto1b.txt` with a rail-fence script set to 5 rails, read from bottom left.
  - Plaintext referenced *Charlotte's Web* (1973) goose spelling of "terrific."
  - Used `teerrrriiffiicccccc` to unlock `crypto1b.zip`.

### VULN-03: Encoding Misidentified as Encryption (RLE Cleartext Disclosure)
- **Vulnerable Location:** `crypto1c.txt`
- **Overview:** The final layer presents a run-length-encoded digit string and asks, "is it compression, encoding, or encryption?" In practice, it is encoding (RLE of binary runs), which provides zero confidentiality. An attacker who recognizes the alternating-count pattern can reconstruct the binary stream and ASCII text without any key.
- **Impact:** The flag and all preceding secrets are exposed to anyone who treats the digit string as RLE rather than encryption.
- **Severity:** Medium
- **Remediation:** Encoding (Base64, RLE, etc.) is not encryption. Never use encoding alone to protect sensitive data. Always encrypt before encoding if the payload must travel over an untrusted channel.
- **Proof of Impact (Execution):**
  - Treated the digit string as alternating counts of `0` and `1` starting with `0`.
  - Reconstructed the binary string and converted 8-bit chunks to ASCII.
  - Recovered flag `CCT{I_see_dead_ciphers_all_the_time}` in under a second.

---

## Vulnerability

**CWE-327 — Use of a Broken or Risky Cryptographic Algorithm**
Dvorak keyboard substitution and rail-fence transposition are classical ciphers that were broken decades ago. They offer no resistance to modern analysis.

**CWE-312 — Cleartext Storage of Sensitive Information**
The challenge passwords (`dvorakdvorakdvorak`, `teerrrriiffiicccccc`) are hardcoded into the challenge artifacts and trivially recoverable from the preceding layer's output.

**CWE-311 — Missing Encryption of Sensitive Data**
The `crypto1c` payload is encoded (RLE) but not encrypted. Encoding obfuscates structure but does not protect confidentiality.

**Related identifiers:**
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-311: Missing Encryption of Sensitive Data
- CWE-798: Use of Hard-coded Credentials
- CWE-691: Insufficient Control Flow Management
- MITRE ATT&CK T1552.001: Credentials In Files

---

## Lessons Learned

### 1. Classical ciphers are puzzles, not protections
Dvorak substitution and rail-fence transposition are fun brain teasers, but they are not encryption. If you need confidentiality, use AES-GCM or ChaCha20-Poly1305 with a high-entropy key.

### 2. Encoding is not encryption
Run-length encoding, Base64, and hex are transport-friendly formats, not confidentiality controls. An encoded payload can be decoded by anyone with the specification. Always encrypt first, then encode.

### 3. Passwords derived from pop-culture are predictable
The password `teerrrriiffiicccccc` is a reference to a 1973 animated film. Passwords based on movies, songs, or memes are vulnerable to wordlists and social media research.

### 4. Hints that reveal cipher names weaken the challenge
When the plaintext of one layer explicitly tells you the name of the next scheme ("the name of the 'layout'"), the challenge becomes a typing exercise rather than a test of cryptanalytic skill.

### 5. Pop-culture references make weak passwords
The password `teerrrriiffiicccccc` is a movie reference with predictable spelling variations. A custom wordlist of film quotes and leet-speak permutations would crack it in minutes. Passwords should be random, not memorable or thematic.

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Obfuscation ≠ Security.** Keyboard-layout tricks, symbol substitution, and classical transposition ciphers provide zero meaningful security. They delay an attacker by minutes, not years.
- **Encoding layers are transparent.** Any encoding scheme (RLE, Base64, URL encoding) is instantly reversible. Treat them as data-format concerns, not security controls.
- **Password hints leak entropy.** Embedding password generation rules inside ciphertext reduces the effective key space to the length of the hint phrase.

### Real-World Context & Defense
- **Threat Landscape:** Real attackers use statistical analysis and automated cipher-identification tools (e.g., `ciphey`, `dcode.fr`, CyberChef) to classify unknown ciphertext in seconds. A Dvorak substitution is identified as soon as the attacker sees key-adjacent digraph frequencies.
- **Detection Engineering:** Monitor for large volumes of digit-only or symbol-only data leaving the network; while not proof of exfiltration, it can indicate encoded payloads. Use DLP tools that attempt Base64, RLE, and common cipher decodes on outbound traffic.
- **System Hardening:** Replace any home-grown obfuscation with standard authenticated encryption. Use key-derivation functions (Argon2, PBKDF2) for password-based encryption. Derive passwords independently per layer, not sequentially from layer output.

---

## Technical Appendix: Commands Worth Keeping

```bash
# crypto1a — Dvorak keyboard decode
# Use dcode.fr Keyboard-Change-Cipher (QWERTY↔Dvorak)
# Or CyberChef "Dvorak" recipe
# Password: dvorakdvorakdvorak

python3 -c "
from zipfile import ZipFile
with ZipFile('crypto1a.zip') as zf:
    zf.extractall(pwd=b'dvorakdvorakdvorak')
"

# crypto1b — Rail fence decode (5 rails, bottom-up)
# Online tool: dcode.fr Rail Fence Cipher
# Or Python script with zigzag reconstruction
# Password: teerrrriiffiicccccc

python3 -c "
from zipfile import ZipFile
with ZipFile('crypto1b.zip') as zf:
    zf.extractall(pwd=b'teerrrriiffiicccccc')
"

# crypto1c — RLE to binary to ASCII
python3 -c "
data = '11122112141311112123131222211121621211124112213221112162112113114163113211421121132221622222411321311331611221121413111121231312222111216322121412123312222111122141624112123212416214122231631132114221112162321321242113531132142162321211424112123212322111121322231221111322216222232122141212112163113211422111216231224113221211211232216231224113113232121151124162312311111311416311321142211113212221112162411321222111216212111214132122211121623212114241121232123221111213222312211113222162411211422111124112214113316121421413132163131211211212321241642112141311112162222241132122211121624112231241121121121323221311416311321142141322122111216121212163131214121322213221111321311331615113114162411213242121632122411311322111211241631312211112123212416221321412132221112162411213222141621142211113212221112162112113222164211214131111132131622222123241122323113161421142111111341211212111151322122111122111111512213221111241122131151232121121135211422111132123221115124112123212311513113211422111111513113211211212111221111511'
counts = [int(c) for c in data]
binary = ''
current = '0'
for count in counts:
    binary += current * count
    current = '1' if current == '0' else '0'
text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
print(text)
# CCT{I_see_dead_ciphers_all_the_time}
"
```
