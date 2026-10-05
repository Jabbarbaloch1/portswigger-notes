# 📝 Lab Breakdown: JWT Authentication Bypass via Unverified Signature

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability class:** Improper Verification of Cryptographic Signature (CWE-347)
- **Key mechanics:** Flawed token parsing (payload trusted without signature validation)

---

## Vulnerability architecture (logic flow)

```
[ Client / Browser Request ]
GET /admin (Header: Bearer eyJhbG...)
        |
        v
+---------------------------+
| JWT handler middleware    |
+-------------+-------------+
              |
   (Decodes header/payload)
              |
              v
+---------------------------+
| 🚨 Signature verification |
|     step is skipped       |
+-------------+-------------+
              |
   (Reads claims directly)
              |
              v
+---------------------------+
| Grants administrator      |
| access based on "sub"     |
+---------------------------+
```

---

## Root cause (ask *why*)

A JWT has three Base64URL-encoded parts separated by a dot (`.`):

1. **Header** — token type + signing algorithm (e.g. `{ "alg": "HS256", "typ": "JWT" }`)
2. **Payload** — user claims (e.g. `{ "sub": "carlos", "admin": false }`)
3. **Signature** — cryptographic proof the header+payload were signed with a server-side key

This class of bug happens when backend code **decodes and trusts the payload without verifying the signature**. If signature verification is skipped (or misconfigured), an attacker can change claims (for example, `"sub": "administrator"`) and the server will accept them.

### Vulnerable backend example (Python)

```python
import jwt

# Vulnerable JWT verification middleware
def authenticate_request(auth_header: str):
    token = auth_header.split(" ", 1)[1]

    # 🚨 VULNERABILITY: signature verification disabled
    payload = jwt.decode(token, options={"verify_signature": False})

    username = payload.get("sub")
    if username == "administrator":
        return grant_admin_access()

    return grant_user_access(username)
```

---

## Diagnostic checks

- **Signature enforcement:** verify *every* incoming token before using claims.
- **Algorithm pinning:** allow only expected algorithms (don’t trust `alg` from the header).
- **Secret/key strength:** use high-entropy symmetric keys (or prefer asymmetric keys where appropriate).

---

## Remediation strategy

Verify the signature using a **server-managed secret** and **explicit algorithm allowlist**.

```python
import os
import jwt

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

def authenticate_request(auth_header: str):
    token = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"verify_signature": True},
        )

        username = payload.get("sub")
        if username == "administrator":
            return grant_admin_access()

        return grant_user_access(username)

    except jwt.InvalidSignatureError:
        return jsonify({"error": "Invalid token signature"}), 401
    except jwt.DecodeError:
        return jsonify({"error": "Malformed token"}), 400
```