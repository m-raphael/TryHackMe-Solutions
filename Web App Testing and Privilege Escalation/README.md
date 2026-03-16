# TryHackMe: Web App Testing and Privilege Escalation

This repository contains my walkthrough and methodology for completing the "Web App Testing and Privilege Escalation" task.

## 📝 Challenge Overview
* **Target IP:** `10.48.142.208`
* **Objective:** Enumerate services, brute-force credentials, and escalate privileges to access restricted user files.

---

## 🎯 Quick Answers Summary

| Question | Answer |
| :--- | :--- |
| **Find the services exposed by the machine** | Port 22 (SSH), 80 (HTTP), 139, 445, 8009, 8080 |
| **What is the name of the hidden directory on the web server?** | `development` |
| **What is the username?** | `jan` |
| **What is the password?** | `armando` |
| **What service do you use to access the server?** | `SSH` |
| **What is the name of the other user you found?** | `kay` |
| **What can you do with this information?** | Exploit their files to escalate privileges (steal SSH key) |
| **What is the final password you obtain?** | `heresareallystrongpasswordthatfollowsthepasswordpolicy$$` |

---

## 🕵️ Detailed Walkthrough

### Phase 1: Reconnaissance & Enumeration

**1. Port Scanning**
I started by scanning the target machine with Nmap to identify open ports and running services.

`nmap 10.48.142.208`

*Result:* Found ports 22 (SSH), 80 (HTTP), 139, 445, 8009, and 8080 open. 

**2. Directory Brute-Forcing**
Knowing a web server was running on port 80, I used Gobuster with a common wordlist to find hidden directories.

`gobuster dir -u http://10.48.142.208 -w /usr/share/wordlists/dirb/common.txt`

*Result:* Discovered a `301` redirect to the `/development/` directory.

---

### Phase 2: Exploitation & Initial Access

**1. Finding Credentials**
Browsing to `http://10.48.142.208/development/` revealed notes left by the developers. The notes exposed two usernames: **jan** and **kay**, and hinted at a weak password policy.

**2. SSH Brute-Forcing**
Armed with the username `jan`, I used Hydra and the `rockyou.txt` wordlist to brute-force the SSH service.

`hydra -l jan -P /usr/share/wordlists/rockyou.txt ssh://10.48.142.208`

*Result:* Hydra successfully cracked the password, revealing it to be: `armando`.

---

### Phase 3: Privilege Escalation

**1. Internal Enumeration**
I logged into the server via SSH as `jan`.

`ssh jan@10.48.142.208`

Once inside, I checked the `/home` directory and discovered another user named **kay**. 

**2. Identifying the Attack Vector**
I inspected Kay's home directory for accessible files:

`ls -la /home/kay`

I found a restricted backup file (`pass.bak`) that I couldn't read, but I noticed the `.ssh` directory was readable by my user. Inside, I found Kay's private SSH key (`id_rsa`). I copied this key to my local attacking machine and saved it as `id_rsa2`.

**3. Cracking the SSH Key**
The private key was encrypted with a passphrase. I used `ssh2john` to convert the key into a crackable hash format, and then used John the Ripper to crack it.

`/usr/share/john/ssh2john.py id_rsa2 > kay_hash.txt`
`john --wordlist=/usr/share/wordlists/rockyou.txt kay_hash.txt`

*Result:* John cracked the passphrase, revealing it to be: `beeswax`.

**4. Securing the Final Password**
With the cracked passphrase, I corrected the permissions on the stolen SSH key and logged in as Kay.

`chmod 600 id_rsa2`
`ssh -i id_rsa2 kay@10.48.142.208`
*(Entered `beeswax` when prompted for the passphrase).*

Once logged in as Kay, I finally had the proper permissions to read the restricted backup file I found earlier.

`cat /home/kay/pass.bak`

*Result:* The file contained the final flag/password: `heresareallystrongpasswordthatfollowsthepasswordpolicy$$`

---

## 🛠️ Tools Utilized
* **Nmap:** Port scanning and service discovery.
* **Gobuster:** Web directory brute-forcing.
* **Hydra:** Online service password brute-forcing.
* **John the Ripper / ssh2john:** Offline hash extraction and password cracking.