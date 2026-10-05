# 📝 Lab Breakdown: JWT Authentication Bypass via Weak Signing Key

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability Class:** Inadequate Encryption Strength / Weak Cryptographic Key (CWE-326 / CWE-321)
- **Difficulty:** Practitioner
- **Key Mechanics:** Offline dictionary attack against symmetric HMAC-SHA256 (HS256) signatures.

## 📐 Vulnerability Architecture & Logic Flow

```python
                     [ Phase 1: Offline Key Extraction ]
                               │
            1. Attacker intercepts legitimate JWT from their own session
               (e.g., eyJhbGciOiJIUzI1Ni...wiener...signature)
                               │
                               ▼
            ┌───────────────────────────────────────┐
            │   Offline Brute-Force (Hashcat)       │
            │   Tests thousands of keys per second  │
            │   against the token's signature.      │
            └──────────────────┬────────────────────┘
                               │
                               ▼
                   [ Secret Key Recovered: "secret1" ]

──────────────────────────────────────────────────────────────────────────

                     [ Phase 2: Forgery & Exploitation ]
                               │
            2. Attacker modifies payload: {"sub": "administrator"}
                               │
                               ▼
            ┌───────────────────────────────────────┐
            │   Local JWT Generator                 │
            │   Signs modified token using "secret1"│
            └──────────────────┬────────────────────┘
                               │
                               ▼
            3. Attacker sends forged token to Target Application
                  GET /admin (Cookie: session=eyJhbG...admin...)
                               │
                               ▼
            ┌───────────────────────────────────────┐
            │   JWT Handler Middleware              │
            │   Verifies signature using "secret1"  │
            │   ✅ Validation Passes!               │
            └───────────────────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

When a JWT uses a symmetric signing algorithm like **HS256 (HMAC-SHA256)**, the backend application uses the *exact same secret key* to both generate the signature when logging a user in, and verify the signature when authenticating their subsequent requests.

Because the JWT header and payload are simply Base64-encoded (not encrypted), anyone who possesses the token can see the exact plaintext data that was signed. This allows an attacker to perform an **offline brute-force attack**.

The attacker takes a massive list of common passwords/secrets, hashes the header and payload with each candidate secret, and checks if the resulting signature matches the signature on the captured JWT. Because this attack happens entirely offline on the attacker's own hardware, rate-limiting or account lockouts on the web server offer zero protection.

Once the secret is found, the cryptographic trust model is completely broken. The attacker can forge valid tokens for any user, including administrators.

#### Vulnerable Backend Implementation Example:

Python

```python
import jwt

# 🚨 VULNERABILITY: Hardcoded, low-entropy secret key
# Easily guessable via dictionary attack
SECRET_KEY = "secret123"

def generate_session(username):
    payload = {"sub": username}
    # Signs the token using the weak secret
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_session(token):
    try:
        # If an attacker cracked "secret123", they can forge tokens that pass this check
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.InvalidSignatureError:
        return None
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Capture & Crack the Token Offline

1. Log into the application using `wiener:peter`.
2. Inspect the HTTP requests in **Burp Suite** and extract your JWT from the `session` cookie.
3. Save the entire JWT string (Header.Payload.Signature) to a local text file named `jwt.txt`.
4. Obtain a JWT secrets wordlist (PortSwigger provides one, or use lists from SecLists like `jwt.secrets.list`).
5. Use **Hashcat** to crack the signature offline. The module for JWT is `16500`:Bash
    
    ```
    hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list
    ```
    
6. Hashcat will output the cracked secret. (e.g., `secret1`).

### Phase 2: Forge an Admin Token

1. Open the **JWT Editor** extension in Burp Suite (or use `jwt.io`).
2. Paste your original token.
3. In the payload section, change the `"sub"` claim from `"wiener"` to `"administrator"`.
4. Navigate to the signature/keys section of your tool. Input the cracked symmetric key (`secret1`).
5. Re-sign the token. The tool will generate a new valid Base64 URL-encoded signature.

### Phase 3: Execute Attack & Gain Access

1. Send a request to `/admin` in Burp Repeater.
2. Replace your original `session` cookie with the newly forged, signed JWT.
3. The server successfully validates the signature using its internal weak key, trusts the `"sub": "administrator"` claim, and grants access to the admin panel.
4. Send a follow-up request to `/admin/delete?username=carlos` using the same forged token to complete the lab.

## 📋 Personal Bug Hunting Checklist: JWT Secrets

- **Identify HS256 Tokens:** Check the JWT header for `"alg": "HS256"`. If it uses `RS256` (asymmetric RSA keys), offline brute-forcing the private key is computationally infeasible.
- **Run Standard Wordlists:** Always run captured HS256 tokens through a quick Hashcat check using a robust JWT secret wordlist. Many developers use defaults like `secret`, `changeme`, `123456`, or their company name.
- **Open Source Recon:** If the target application is open-source or you found a GitHub repository during recon, search the codebase for hardcoded `JWT_SECRET` variables in `.env.example` or configuration files.

## 🛡️ Remediation Strategy

Symmetric JWT secrets must possess high cryptographic entropy to mathematically eliminate the possibility of offline brute-forcing. Keys should be randomly generated, heavily guarded, and ideally rotated periodically.

Python

```python
import jwt
import os
import binascii

# ✅ REMEDIATION: Generate a 256-bit (32 byte) cryptographically secure random key
# This cannot be brute-forced using dictionary attacks
# In production, this is generated once and stored in secure environment variables
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", binascii.hexlify(os.urandom(32)).decode())

def generate_session(username):
    payload = {"sub": username}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")
```