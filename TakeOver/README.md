# TakeOver — Subdomain Takeover via SSL Certificate SAN Leak

**Objective:** Find the subdomain vulnerability that blackhat hackers could exploit to takeover futurevera.thm.

---

## Phase 1: Reconnaissance & Subdomain Enumeration

### Step 1: Add Target to /etc/hosts

    echo "10.49.175.242 futurevera.thm" | sudo tee -a /etc/hosts

### Step 2: HTTP Subdomain Bruteforce

Using `ffuf` with Host header fuzzing against the target IP to discover virtual hosts:

    ffuf -u http://10.49.175.242 -H "Host: FUZZ.futurevera.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 1

**Result:** Found `portal.futurevera.thm` (Status 200, 69 bytes).

Checking it:

    curl -sk http://10.49.175.242 -H "Host: portal.futurevera.thm"

**Response:** `portal.futurevera.thm is only availiable via internal VPN` — a dead end for now.

---

## Phase 2: SSL Certificate SAN Inspection

The room description mentions they're "rebuilding support", hinting at a `support` subdomain. SSL/TLS certificates often leak internal subdomains via **Subject Alternative Names (SANs)** that aren't discoverable by wordlist bruteforce.

### Step 3: Inspect SSL Certs via SNI

Using `openssl s_client` with different `-servername` values to trigger Server Name Indication and retrieve different certificates:

    echo | openssl s_client -connect 10.49.175.242:443 -servername support.futurevera.thm 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|DNS:"

**Result:**
```
Subject: C=US, ST=Oregon, L=Portland, O=Futurevera, OU=Thm, CN=support.futurevera.thm
DNS:secrethelpdesk934752.support.futurevera.thm
```

The `support.futurevera.thm` certificate leaks a hidden subdomain: **`secrethelpdesk934752.support.futurevera.thm`**.

---

## Phase 3: Exploiting the Subdomain Takeover

### Step 4: Probe the Hidden Subdomain

    curl -sk http://10.49.175.242 -H "Host: secrethelpdesk934752.support.futurevera.thm" -v 2>&1 | grep Location

**Result:**
```
< HTTP/1.1 302 Found
< Location: http://flag{beea0d6edfcee06a59b83fb50ae81b2f}.s3-website-us-west-3.amazonaws.com/
```

The subdomain returns a **302 redirect** to a non-existent AWS S3 bucket. The flag is embedded directly in the redirect URL — this is a classic **dangling CNAME / subdomain takeover** scenario. An attacker could register the S3 bucket and serve arbitrary content on `secrethelpdesk934752.support.futurevera.thm`.

### Step 5: Claim the Flag

**Flag:** `flag{beea0d6edfcee06a59b83fb50ae81b2f}`
