# 📝 Lab Breakdown: JWT Authentication Bypass via JWK Header Injection

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability Class:** Improper Verification of Cryptographic Signature / Insecure Trust of Client Input (CWE-347 / CWE-345)
- **Difficulty:** Practitioner
- **Key Mechanics:** Exploiting the `jwk` (JSON Web Key) header parameter to force the backend to verify a token using an attacker-controlled public key.

## 📐 Vulnerability Architecture & Logic Flow

```python
                     [ Phase 1: Attacker Key Generation ]
                               │
            1. Attacker generates a new RSA Key Pair
               (Private Key + Public Key)
                               │
                               ▼
                     [ Phase 2: Token Forgery ]
                               │
            2. Modifies Payload: {"sub": "administrator"}
            3. Injects Public Key into Header:
               {"alg": "RS256", "jwk": { "kty": "RSA", "n": "...", "e": "AQAB" }}
            4. Signs token using the Malicious Private Key
                               │
                               ▼
                     [ Phase 3: Exploitation ]
               GET /admin (Cookie: session=eyJhbG...admin...)
                               │
                               ▼
            ┌───────────────────────────────────────┐
            │   JWT Handler Middleware              │
            │   1. Reads the "jwk" parameter from   │
            │      the untrusted client header.     │
            │   2. 🚨 Trusts it implicitly!         │
            │   3. Verifies signature using the     │
            │      attacker's Public Key.           │
            │   ✅ Validation Passes!               │
            └───────────────────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

In modern, distributed architectures (like microservices or SSO environments), multiple servers often need to verify JWTs. Instead of sharing a single secret key, they use asymmetric encryption (like **RS256**). The server signing the token uses a **Private Key**, and anyone verifying it uses a **Public Key**.

To make it easy for receiving servers to know *which* public key to use, the JWT specification (RFC 7515) allows embedding the public key directly inside the JWT header using the `jwk` (JSON Web Key) parameter.

**The Fatal Flaw:**
If a backend application parses the JWT header, extracts the `jwk` object, and immediately uses it to verify the signature **without checking if that public key comes from a trusted source (like an internal whitelist)**, the cryptographic chain of trust is broken.

An attacker can generate their own RSA key pair, embed their *own* public key in the `jwk` header, sign the token with their *own* private key, and the server will successfully verify the signature against the attacker's public key. The server essentially asks the attacker, *"Is this your signature?"* and the attacker's key replies, *"Yes, it is."*

#### Vulnerable Backend Implementation Example:

Python

```python
import jwt

# 🚨 VULNERABILITY: Blindly trusting client-supplied cryptographic material
def verify_session(token):
    try:
        # Extracts the unverified header from the incoming token
        unverified_header = jwt.get_unverified_header(token)

        # Pulls the embedded public key directly from the attacker's input
        client_supplied_jwk = unverified_header.get('jwk')

        # Reconstructs the public key to use for verification
        public_key = jwk_to_pem(client_supplied_jwk)

        # The server verifies the token using the attacker's public key!
        payload = jwt.decode(token, key=public_key, algorithms=["RS256"])
        return payload

    except Exception:
        return None
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Generate Malicious RSA Keys

1. Log into the application using `wiener:peter`.
2. Intercept a request in **Burp Suite** and send it to **Repeater**.
3. Go to the **JWT Editor Keys** tab in Burp Suite (requires the JWT Editor extension).
4. Click **New RSA Key**.
5. Click **Generate** to create a fresh RSA key pair, then click **OK** to save it. (This key pair belongs exclusively to you).

### Phase 2: Forge and Sign the Token

1. In Burp Repeater, switch to the **JSON Web Token** tab for your intercepted request.
2. In the **Payload** section, change the `"sub"` claim from `"wiener"` to `"administrator"`.
3. At the bottom of the JWT Editor, click **Attack**, then select **Embedded JWK**.
4. A prompt will appear asking you to select a key. Choose the RSA key you just generated in Phase 1 and click **OK**.
*(Under the hood, Burp automatically inserts your public key into the `jwk` header parameter and signs the token with your matching private key).*

### Phase 3: Execute the Attack

1. Send the modified request to the server (e.g., `GET /admin`).
2. The server will parse your injected `jwk` header, use your public key to verify your signature, and grant you access to the admin panel.
3. Update the request path to `GET /admin/delete?username=carlos`, ensure your forged JWT is in the cookie, and send it to solve the lab.

## 📋 Personal Bug Hunting Checklist: JWT Header Injections

When you see `"alg": "RS256"`, immediately test the header parameters for trust issues:

- **`jwk` Injection:** Can you embed a full JSON Web Key in the header and sign the token with your own private key?
- **`jku` (JWK Set URL) Injection:** Does the header accept a `jku` parameter? Point it to your own Exploit Server hosting a malicious JWKS JSON file (`[https://attacker.com/keys.json](https://attacker.com/keys.json)`).
- **`kid` (Key ID) Directory Traversal:** If the server uses the `kid` parameter to locate a local key file (e.g., `"kid": "key1"`), can you use path traversal (`"kid": "../../../dev/null"`) to force the server to use an empty or predictable file as the public key?

## 🛡️ Remediation Strategy

Never implicitly trust cryptographic parameters provided in an unverified JWT header.

If the application must support multiple keys, it should use the `kid` (Key ID) parameter to look up the correct public key from a strictly controlled, server-side whitelist or a trusted internal keystore.

Python

```python
import jwt

# ✅ REMEDIATION: A strict, server-side mapping of trusted Public Keys
TRUSTED_KEYS = {
    "key-id-001": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEF...\n-----END PUBLIC KEY-----",
    "key-id-002": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEF...\n-----END PUBLIC KEY-----"
}

def verify_session(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        # Rejects the token if the key ID is not in the hardcoded trusted list
        if kid not in TRUSTED_KEYS:
            raise Exception("Untrusted Key ID")

        public_key = TRUSTED_KEYS[kid]

        # Verifies the token using ONLY the trusted, server-stored public key
        # The 'jwk' header is completely ignored if present
        payload = jwt.decode(token, key=public_key, algorithms=["RS256"])
        return payload

    except Exception:
        return None
```