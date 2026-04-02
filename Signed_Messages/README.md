# 🏆 Walkthrough: Signed Messages

## Room info
- Platform: TryHackMe
- Target: 10.49.159.15
- Date solved: 2026-04-01
- Objectives: flag

## Summary
The app claimed RSA-2048 security but used deterministic key generation seeded from the username. A leaked `/debug` endpoint exposed the seed pattern, allowing full reconstruction of admin's private key. Signing admin's message with RSA-PSS yielded the flag.

## Task answers
### Task 1
- Question: What is the flag?
- Answer: THM{PR3D1CT4BL3_S33D5_BR34K_H34RT5}

## Enumeration
### Nmap
```bash
nmap -sV -sC -T4 -p- --open 10.49.159.15
```

Key findings:
- Port 22: OpenSSH 8.9p1
- Port 5000: Werkzeug/2.0.2 (Python/3.10.12) — "LoveNote - Secure Valentine's Day Messaging"

### Service analysis
Flask app on port 5000. Claims RSA-2048 digital signatures on all messages. Admin user has one public message. Routes: `/`, `/messages`, `/verify`, `/register`, `/compose`, `/profile/<user>`, `/debug`.

### Web enumeration
- `/debug` — exposed internal key generation logs (critical leak)
- `/profile/admin` — admin's public key (505-bit, not 2048-bit)
- `/verify` — accepts `username + message + signature(hex)`, returns flag on valid admin signature

## Initial foothold

### Discovery
1. Registered account → received Flask session cookie
2. Fetched `/profile/admin` public key → `openssl rsa -pubin -text` revealed **505-bit key**, not 2048-bit
3. Fetched `/debug` → exposed deterministic seed pattern:

```
Seed pattern: {username}_lovenote_2026_valentine
p = nextprime(SHA256(seed))
q = nextprime(SHA256(seed + b"pki"))
```

### Exploitation
```python
import hashlib
from sympy import nextprime
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import binascii

# Reconstruct admin private key
seed = b"admin_lovenote_2026_valentine"
p = int(nextprime(int.from_bytes(hashlib.sha256(seed).digest(), 'big')))
q = int(nextprime(int.from_bytes(hashlib.sha256(seed + b"pki").digest(), 'big')))
n = p * q  # matches admin's public key modulus
e = 65537
d = pow(e, -1, (p-1)*(q-1))

pub = RSAPublicNumbers(e, n)
priv = RSAPrivateNumbers(p, q, d, rsa_crt_dmp1(d, p), rsa_crt_dmq1(d, q), rsa_crt_iqmp(p, q), pub)
admin_key = priv.private_key(default_backend())

# Sign admin's message with PSS
msg = b"Welcome to LoveNote! Send encrypted love messages this Valentine's Day. Your communications are secured with industry-standard RSA-2048 digital signatures."
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
sig = admin_key.sign(msg, pss, hashes.SHA256())

# POST to /verify: username=admin, message=<msg>, signature=<hex>
print(binascii.hexlify(sig).decode())
```

Result:
- `n == known_admin_n` → True
- `/verify` response: **Signature Valid** → flag revealed

## Flags
- Flag: `THM{PR3D1CT4BL3_S33D5_BR34K_H34RT5}`

## Lessons learned
- **CWE-338 — Use of Cryptographically Weak PRNG**: Seeding RSA key generation from a predictable, username-derived string allows any attacker to reproduce any user's private key.
- **CWE-215 — Debug info in production**: The `/debug` endpoint explicitly leaked the seed formula. Never expose key generation internals.
- **Algorithm mismatch**: The app advertised RSA-2048 but generated ~505-bit keys. Always verify key sizes; small keys are factorable even without the seed leak.
