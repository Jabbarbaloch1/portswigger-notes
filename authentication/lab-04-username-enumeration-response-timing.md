# 📝 PortSwigger Lab: Username Enumeration via Response Timing

- **Vulnerability Class:** Authentication / Information Disclosure
- **Severity:** Medium / High
- **Key Mechanics:** Response Timing Side-Channel + IP Spoofing (`X-Forwarded-For`)
- **Difficulty:** Practitioner

## 🎯 Objective

1. Bypass IP-based rate limiting on the `/login` endpoint.
2. Identify a valid username by exploiting differences in server-side password hashing execution time.
3. Brute-force the password for the identified account and log in.

## 🔬 Vulnerability Analysis & Methodology

### 1. The Timing Side-Channel Concept

When a user submits login credentials:

- **If the username is invalid:** The application rejects the request immediately without running the heavy password-hashing algorithm (e.g., `bcrypt`, `pbkdf2`). Response time is fast (~50–100ms).
- **If the username is valid:** The application looks up the user, retrieves their password hash, and executes the hash function against the supplied password. Response time is noticeably slower (~500ms+).

> **Amplification Trick:** Using an excessively long password (e.g., 100+ characters) forces the server to spend significantly more CPU cycles processing it *only if* the account exists, amplifying the timing discrepancy.
> 

### 2. Bypassing Rate-Limiting

The application blocks client requests after multiple failed attempts. However, it relies on client-controlled HTTP headers to determine the source IP. By rotating the `X-Forwarded-For` header value with each request, we simulate requests coming from distinct IP addresses, completely bypassing lockouts.

## 🛠️ Step-by-Step Exploitation Guide

### Step 1: Confirm the Timing Difference

1. Capture a `POST /login` request in Burp Suite and send it to **Repeater**.
2. Add the header: `X-Forwarded-For: 123`
3. Test two scenarios using a **100-character password**:
    - `username=invalid_user_999` + `password=AAAA...` $\rightarrow$ Fast response time (~100ms)
    - `username=wiener` (known valid) + `password=AAAA...` $\rightarrow$ Slow response time (~800ms–1500ms)

### Step 2: Enumerate Valid Username (Burp Intruder)

1. Send the request to **Intruder** and select **Pitchfork** attack type.
2. Mark payload positions:HTTP
    
    ```
    POST /login HTTP/1.1
    Host:YOUR-LAB-ID.web-security-academy.net
    X-Forwarded-For:§1§
    ...
    
    username=§invaliduser§&password=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ```
    
3. **Payload 1 (`X-Forwarded-For`):**
    - Type: **Numbers** (From `1` to `150`, Step `1`)
4. **Payload 2 (`username`):**
    - Type: **Simple List** (Paste candidate usernames list)
5. **Intruder Settings:** Enable **"Response received"** column in attack settings.
6. **Execution:** Sort results by **Response received** descending. The username causing the longest processing delay is the valid account.

### Step 3: Brute-Force Password

1. Set the attack type in Intruder to **Pitchfork**.
2. Hardcode the discovered valid username and set positions on `X-Forwarded-For` and `password`:HTTP
    
    ```
    POST /login HTTP/1.1
    Host:YOUR-LAB-ID.web-security-academy.net
    X-Forwarded-For:§151§
    ...
    
    username=DISCOVERED_USER&password=§password_payload§
    ```
    
3. **Payload 1 (`X-Forwarded-For`):** Numbers (`151` to `300`).
4. **Payload 2 (`password`):** Simple List (Paste candidate passwords list).
5. **Execution:** Look for a **302 Found** HTTP redirect response or a differing response length indicating successful authentication.

## 🛡️ Remediation

1. **Constant-Time Responses:** Always run password hashing algorithms (e.g., using dummy hashes for non-existent users) so response execution time remains identical regardless of whether the username exists.
2. **Generic Error Messages:** Always return "Invalid username or password" for failed login attempts.
3. **Robust Rate Limiting:** Enforce rate limits based on authenticated session context or secure gateway IP tracking rather than trusting header values like `X-Forwarded-For`.