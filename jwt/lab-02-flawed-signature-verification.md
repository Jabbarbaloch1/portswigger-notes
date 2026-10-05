# 📝 Lab Breakdown: JWT Authentication Bypass via Flawed Signature Verification (Unsigned JWTs)

- **Target:** PortSwigger Web Security Academy (Apprentice)
- **Vulnerability Class:** Improper Verification of Cryptographic Signature / Unsigned JWT Acceptance (CWE-347)
- **Difficulty:** Apprentice
- **Key Mechanics:** Acceptance of the `"none"` Algorithm / Missing Signature Enforcement

## 📐 Vulnerability Architecture & Logic Flow

```
                     [ Client / Browser Request ]
                 GET /admin (Cookie: session=eyJhbG...)
                               │
                               ▼
                  ┌───────────────────────────┐
                  │   JWT Handler Middleware  │
                  └─────────────┬─────────────┘
                                │
             ( Decodes Header: "alg": "none" )
                                │
                                ▼
            ┌───────────────────────────────────────┐
            │ 🚨 Cryptographic Verification Skipped │
            └──────────────────┬────────────────────┘
                               │
            ┌──────────────────┴────────────────────┐
            │ Reads Claims directly:                │
            │ "sub": "administrator"                │
            └──────────────────┬────────────────────┘
                               │
                               ▼
            ┌───────────────────────────────────────┐
            │ Grants Administrator Session Access   │
            └───────────────────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

The JSON Web Signature (JWS) specification (RFC 7515) defines an algorithm parameter value of `"none"`. It was originally intended for unassigned or integrity-protected environments where signature verification is handled out-of-band.

When JWT parsing libraries or custom backend middleware accept tokens with `"alg": "none"` without explicit restrictions, the backend parser strips or ignores the signature portion entirely (the third segment after the second dot `.`).

If the application trusts the claims in the payload segment whenever `"alg": "none"` is specified, an attacker can modify identity attributes (such as changing `"sub": "wiener"` to `"sub": "administrator"`) and strip the signature component, gaining unauthorized elevated privileges.

#### Vulnerable Backend Implementation Example:

Python

```python
import jwt

# Vulnerable JWT Verification Middleware
def authenticate_request(token):
    try:
        # 🚨 VULNERABILITY: Inspecting unverified header and accepting 'none'
        header = jwt.get_unverified_header(token)

        if header.get('alg', '').lower() == 'none':
            # Unsafely decodes without requiring a secret signature check
            payload = jwt.decode(token, options={"verify_signature": False})
        else:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        username = payload.get("sub")
        if username == "administrator":
            return grant_admin_access()
        return grant_user_access(username)

    except Exception as e:
        return "Authentication Failed", 401
```

## 📋 Personal Bug Hunting Checklist: JWT Signature Weaknesses

- **Algorithm Switching:** Test if JWT handlers accept `"alg": "none"`, `"alg": "NONE"`, or `"alg": "nOnE"`.
- **Signature Stripping:** Verify whether removing the signature bytes entirely (leaving `header.payload.`) is processed by the server without throwing an error.
- **Algorithm Confusion (RS256 to HS256):** Check if asymmetric public keys can be used as symmetric secrets when algorithm header declarations are changed from `RS256` to `HS256`.
- **Weak Key Entropy:** Conduct offline brute-force verification against secret keys using dictionary lists to identify predictable signing passwords.

## 🛡️ Remediation Strategy

Enforce strict algorithm whitelisting and reject any token declaring the `"none"` algorithm or lacking a valid signature:

Python

```python
import jwt
import os

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

def authenticate_request(auth_header):
    token = auth_header.split(" ")[1]

    try:
        # ✅ Explicitly require HMAC-SHA256 and mandate signature verification
        # The 'none' algorithm is strictly rejected by specifying allowed algorithms
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"verify_signature": True}
        )

        username = payload.get("sub")
        if username == "administrator":
            return grant_admin_access()

        return grant_user_access(username)

    except jwt.InvalidAlgorithmError:
        return jsonify({"error": "Unsupported or forbidden algorithm"}), 401
    except jwt.InvalidSignatureError:
        return jsonify({"error": "Invalid signature"}), 401
    except jwt.DecodeError:
        return jsonify({"error": "Malformed token"}), 400
```