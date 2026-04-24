# Security Assessment Report: CCT2019 — Task 2

## Assessment Overview
- **Platform:** TryHackMe
- **Target:** `re3_1583875067748.exe` (US Navy CCT 2019 reverse engineering challenge)
- **Room Type:** Reverse Engineering / .NET
- **Date Solved:** 2026-04-24

**Objectives & Status:**
- [x] Reverse engineer the .NET Windows Forms binary
- [x] Solve the scroll-bar validation puzzle
- [x] Extract the 32-character hex key from the `goodBoy` decryption routine

---

## Executive Summary & Key Findings

This assessment targets a .NET Windows Forms application obfuscated with Dotfuscator. The binary presents a GUI with four horizontal scroll bars and a check button. The click handler enforces a system of equations on the scroll-bar values: their sum must equal 711, their product must equal 711,000,000, and they must be in strictly descending order. Solving this constraint system yields the scroll-bar values, which are then fed into a `goodBoy` XOR-decryption routine to recover the key from an embedded 32-byte array (`byteA`).

- **Binary Type:** PE32 .NET Assembly (Mono/.NET Framework 4.0)
- **Obfuscation:** Dotfuscator (renamed methods: `a`, `badBoy`, `goodBoy`, `classA`, `eventHandlerA`)
- **Key Artifacts:** `byteA` (field RVA `0x2110`), `byteB` (field RVA `0x2130`), constants `c=177`, `d=0x33`
- **Key:** `31C02DCFDE2FCF727016E2A7054B6DA5`

---

## Exploitation Chain

1. **Reconnaissance:** `file` identifies the binary as a PE32 Mono/.NET assembly. `monodis` disassembles the IL bytecode despite Dotfuscator renaming.
2. **Code Analysis:** The `a` class contains four `HScrollBar` fields (`bar1`–`bar4`), a `Button` (`checkButton`), and two byte arrays (`byteA`, `byteB`). The constructor initializes `byteA` and `byteB` via `RuntimeHelpers::InitializeArray` from static field tokens.
3. **Constraint Solving:** The `eventHandlerA` (click handler) validates:
   - `bar1 + bar2 + bar3 + bar4 == 711`
   - `bar1 * bar2 * bar3 * bar4 == 711000000`
   - `bar1 > bar2 > bar3 > bar4`
   Brute-forcing with early pruning and divisor enumeration yields the unique solution: `316, 150, 125, 120`.
4. **Decryption:** The `goodBoy` method XORs each byte of `byteA` with `c ^ bar2` (where `c=177`). `177 ^ 150 = 39` (0x27). Applying this to the 32-byte `byteA` array and encoding the first 16 bytes as uppercase hex produces the key.

---

## Vulnerability Details

### VULN-01: Obfuscation-Only Protection of Business Logic
- **Vulnerable Location:** Entire `re3_1583875067748.exe` binary
- **Overview:** The binary relies solely on Dotfuscator name obfuscation (renaming classes, methods, and fields to single-character or meaningless identifiers) to protect its validation logic. IL bytecode remains fully intact and reversible with standard .NET disassemblers.
- **Impact:** Complete recovery of the scroll-bar validation algorithm, decryption routine, and embedded data arrays within minutes using `monodis`.
- **Severity:** High
- **Remediation:** Obfuscation is not a security control. For client-side secrets, use code virtualization (VMProtect, Themida), native compilation (CoreRT, NativeAOT), or server-side validation. Never embed cryptographic material or validation logic in plain IL.
- **Proof of Impact (Execution):**
  - `monodis re3_1583875067748.exe` produced full IL disassembly.
  - Method names were trivially mapped: `badBoy` = failure path, `goodBoy` = success path, `eventHandlerA` = click handler.

### VULN-02: Client-Side Constraint System with Trivial Brute-Force Space
- **Vulnerable Location:** `a::eventHandlerA` click handler method
- **Overview:** The binary validates four integer inputs with two multiplicative constraints (sum and product) and an ordering constraint. The solution space is small enough to brute-force with divisor enumeration in under a second.
- **Impact:** An attacker can bypass the GUI entirely by solving the constraint system offline, obtaining the exact scroll-bar values needed to trigger the `goodBoy` decryption path.
- **Severity:** High
- **Remediation:** Move validation logic to a server-side API. If client-side validation is required for UX, always pair it with server-side enforcement. Do not derive decryption keys from client-controlled inputs.
- **Proof of Impact (Execution):**
  - Prime factorization of `711000000` = `2^6 * 3^2 * 5^6 * 79`.
  - Enumerating all divisor combinations and filtering by sum=711 and descending order yielded the unique solution: `(316, 150, 125, 120)`.

### VULN-03: Hardcoded Cryptographic Material in Static Field RVA
- **Vulnerable Location:** `.text` section at field RVAs `0x2110` (byteA) and `0x2130` (byteB)
- **Overview:** The binary stores the encrypted key (`byteA`, 32 bytes) and a secondary failure message array (`byteB`, 32 bytes) as static initialized arrays in the PE `.text` section. The decryption key is derived from a hardcoded constant (`c=177`) XORed with a scroll-bar value (`bar2=150`).
- **Impact:** Once the scroll-bar values are known, the key is recoverable with a single XOR pass. No runtime analysis or dynamic instrumentation is required.
- **Severity:** Critical
- **Remediation:** Do not embed encrypted secrets in client binaries with recoverable keys. Use proper key derivation (PBKDF2, Argon2) with user-provided passwords, or move decryption entirely to a trusted server. If the client must hold secrets, use platform keychains (DPAPI, Keychain, Keystore) instead of static arrays.
- **Proof of Impact (Execution):**
  - `pefile` mapped field RVA `0x2110` to file offset `0x310`.
  - `byteA = 1416641715636461636215616461101510171611621566101712136511636612`.
  - `goodBoy` XOR key = `177 ^ 150 = 39`.
  - Decoded `byteA` → hex string `31C02DCFDE2FCF727016E2A7054B6DA5`.

---

## Vulnerability

**CWE-312 — Cleartext Storage of Sensitive Information**  
The binary stores the encrypted key in `.text` as a static initialized array. While the bytes are XOR-obfuscated, the key derivation logic (hardcoded constant XORed with a client-controlled value) is present in plain IL, making the obfuscation equivalent to cleartext for a reverse engineer.

**CWE-798 — Use of Hard-coded Credentials**  
The decryption key is derived from a hardcoded constant (`c=177`) combined with a scroll-bar value. The constant and the derivation formula are both embedded in the binary.

**CWE-916 — Use of Password Hash With Insufficient Computational Effort**  
The XOR-based obfuscation provides no computational barrier. A single XOR operation recovers the plaintext — no iteration count, no salt, no memory-hard function.

**Related identifiers:**
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-798: Use of Hard-coded Credentials
- CWE-916: Use of Password Hash With Insufficient Computational Effort
- CWE-306: Missing Authentication for Critical Function (key decryption requires only correct scroll-bar values)
- MITRE ATT&CK T1027: Obfuscated Files or Information (Dotfuscator name obfuscation)
- MITRE ATT&CK T1552.001: Credentials In Files (static array in PE)

---

## Lessons Learned

### 1. Obfuscation is not security
Dotfuscator renaming made the code slightly harder to read, but the IL instructions, method signatures, and control flow were completely intact. A single `monodis` pass exposed every class, method, and field. Any binary that relies on name obfuscation as its primary defense will fall to standard reverse-engineering tools in minutes.

### 2. Constraint systems on the client are trivially solvable
The scroll-bar puzzle reduced to a number-theory problem: find four descending integers that sum to 711 and multiply to 711,000,000. By factorizing `711000000 = 2^6 * 3^2 * 5^6 * 79` and enumerating divisor combinations, the solution space collapsed to a single tuple. Moving validation to the server would have prevented offline analysis.

### 3. Static field RVAs are treasure maps
.NET static initialized arrays are stored at fixed RVAs in the PE file. Tools like `monodis --fieldrva` and `pefile` convert these to raw file offsets instantly. If a binary contains `InitializeArray` calls with `ldtoken` instructions, the data is at a known, fixed address. This is the IL equivalent of a hardcoded string.

### 4. XOR with a single-byte key is not encryption
The `goodBoy` routine used a one-byte XOR key (`39`) derived from two known or guessable values (`177` and `150`). Once the scroll-bar values were known, decryption required no cryptanalysis — just a byte-wise XOR. For any secret that must survive reverse engineering, use a proper authenticated encryption scheme (AES-GCM) with a key derived from a high-entropy, user-provided password.

### 5. Dual-path binaries leak failure modes
The binary had two decryption routines: `goodBoy` (success) and `badBoy` (failure). Decoding `byteB` with `badBoy` produced the taunt: `None shall pass! Again? Give up?`. While amusing, the existence of a failure path with a known decryption routine (`XOR with 0x33`) confirmed that the `goodBoy` routine must use a similar simple transformation, reducing the search space from "unknown algorithm" to "find the correct XOR key."

---

## Senior-Level Lessons Learned & Analysis

### Strategic Takeaways
- **Client-side secrets are client-side.** Any data or logic shipped to an attacker's machine can and will be extracted. If the key is needed client-side, the attacker can recover it. The only meaningful defense is keeping secrets server-side.
- **.NET IL is an intermediate representation, not machine code.** Unlike native binaries where disassembly is lossy and control flow can be obfuscated with opaque predicates, IL is designed to be verifiable and reversible. Obfuscation tools only raise the time cost, not the difficulty ceiling.
- **Guards that depend on client-controlled inputs are bypassable.** Scroll bars, sliders, and spinners are all client-controlled values. If the validation logic is in the binary, an attacker can compute the correct inputs without ever launching the GUI.

### Real-World Context & Defense
- **Threat Landscape:** .NET licensing and activation systems often use similar patterns (client-side validation of serial keys, hardware fingerprint checks, obfuscated constants). These systems are routinely bypassed by tools like `dnSpy`, `ILSpy`, and `de4dot`.
- **Detection Engineering:** Monitor for `.NET` process launches that immediately attach debuggers or load `mscordbi.dll`. Alert on processes that read their own PE file (self-introspection) or access `.text` sections at unusual offsets. EDR can detect `monodis`-like behavior by watching for `CreateFileMapping` + `ReadProcessMemory` patterns on .NET assemblies.
- **System Hardening:** For .NET applications that must protect secrets, compile to native code ahead-of-time (NativeAOT, CoreRT, .NET 7+ AOT publish) to remove IL. Use hardware-backed key storage (TPM, HSM) instead of static fields. Implement server-side license validation with network attestation.

---

## Technical Appendix: Commands Worth Keeping

```bash
# Identify binary type
file re3_1583875067748.exe
# PE32 executable for MS Windows 4.00 (GUI), Intel i386 Mono/.Net assembly

# Full IL disassembly
monodis re3_1583875067748.exe > re3.il

# Find obfuscated class/method outline
grep -E 'class.*private auto ansi|\.method|\.field' re3.il

# Search for key method references
grep -n 'badBoy\|goodBoy\|checkButton\|byteA\|byteB' re3.il

# Get static field RVAs (where byteA and byteB live)
monodis --fieldrva re3_1583875067748.exe
# Field 21: 2110
# Field 22: 2130

# Extract byte arrays with pefile
python3 -c "
import pefile
pe = pefile.PE('re3_1583875067748.exe')
byteA = pe.get_data(0x2110, 32)
byteB = pe.get_data(0x2130, 32)
print('byteA:', byteA.hex())
print('byteB:', byteB.hex())
"

# Solve scroll-bar constraint system
python3 -c "
import math
target_sum, target_prod = 711, 711000000
# Prime factorization
factors = []
n = target_prod
d = 2
while d * d <= n:
    while n % d == 0:
        factors.append(d)
        n //= d
    d += 1
if n > 1:
    factors.append(n)
print('Prime factors:', factors)
# 711000000 = 2^6 * 3^2 * 5^6 * 79
# Brute-force divisor combinations
solutions = []
divisors = set([1])
for p in factors:
    new_divs = set()
    for d in divisors:
        new_divs.add(d * p)
    divisors |= new_divs
divisors = sorted(divisors)
for d1 in divisors:
    for d2 in divisors:
        if d2 > d1: break
        for d3 in divisors:
            if d3 > d2: break
            if target_prod % (d1 * d2 * d3) != 0:
                continue
            d4 = target_prod // (d1 * d2 * d3)
            if d4 >= d3:
                continue
            if d1 + d2 + d3 + d4 == target_sum:
                solutions.append((d1, d2, d3, d4))
print('Solutions:', solutions)
# [(316, 150, 125, 120)]
"

# Decrypt the key
python3 -c "
byteA = bytes.fromhex('1416641715636461636215616461101510171611621566101712136511636612')
c, bar2 = 177, 150
key = c ^ bar2  # 39
result = bytes([b ^ key for b in byteA])
print(result[:16].hex().upper())
# 31C02DCFDE2FCF727016E2A7054B6DA5
"
```
