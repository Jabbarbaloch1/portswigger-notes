# 📝 Lab Breakdown: JWT Authentication Bypass via Algorithm Confusion

- **Target:** PortSwigger Web Security Academy (Expert)
- **Vulnerability Class:** Cryptographic Algorithm Confusion (CWE-327 / CWE-347)
- **Difficulty:** Expert
- **Key Mechanics:** Tricking a backend server into verifying an asymmetric RS256 signature using a symmetric HS256 verification algorithm, utilizing the server's own Public Key as the symmetric password.

## 📐 Vulnerability Architecture & Logic Flow

```
                     [ Phase 1: Public Key Extraction ]
                               │
            1. Attacker requests the server's Public Key
               (e.g., GET /jwks.json or /api/public_key)
                               │
                               ▼
                     [ Phase 2: Token Forgery ]
                               │
            2. Attacker modifies Header: {"alg": "HS256"}  <-- Algorithm switch!
            3. Attacker modifies Payload: {"sub": "administrator"}
            4. 🚨 Attacker signs the token using the SERVER'S PUBLIC KEY
               as if it were a symmetric HMAC secret password.
                               │
                               ▼
                     [ Phase 3: Exploitation ]
               GET /admin (Cookie: session=eyJhbG...)
                               │
                               ▼
            ┌───────────────────────────────────────────────┐
            │   JWT Handler Middleware                      │
            │   1. Reads "alg": "HS256" from the header.    │
            │   2. Retrieves its own Public Key from memory │
            │      (intending to use it for RS256).         │
            │   3. Passes the Public Key into the           │
            │      verification function.                   │
            │   4. 🚨 Because the header says HS256, the    │
            │      library treats the Public Key as a       │
            │      symmetric password.                      │
            │   ✅ Validation Passes!                       │
            └───────────────────────────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

This is one of the most famous architectural flaws in early JWT libraries.

In a secure **Asymmetric (RS256)** setup:

- The server **signs** the token using its tightly guarded **Private Key**.
- The server **verifies** the token using its openly shared **Public Key**.

In a **Symmetric (HS256)** setup:

- The server **signs and verifies** using the same **Secret Password**.

**The Flaw:**
Many generic JWT libraries use a single `verify(token, verification_key)` function. Developers are supposed to hardcode the expected algorithm, but often they let the library dynamically determine the algorithm by reading the `"alg"` parameter directly from the untrusted client's JWT header.

If an attacker changes the header to `"alg": "HS256"`, the JWT library switches to symmetric mode. The backend still passes its **Public Key** into the `verification_key` variable. However, because the library is now in symmetric mode, it doesn't use the Public Key for complex asymmetric math. Instead, it treats the literal string/bytes of the Public Key as a simple symmetric password.

Because the attacker already possesses the server's Public Key (since it is public by design), the attacker can use that exact same Public Key as the symmetric password to sign their forged token.

#### Vulnerable Backend Implementation Example:

JavaScript

```jsx
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Server loads its public key from the filesystem
const publicKey = fs.readFileSync('public_key.pem');

// 🚨 VULNERABILITY: The verify function dynamically accepts whatever algorithm
// is in the token header because 'algorithms' is not explicitly restricted.
function verifySession(token){
    try {
        // If the token header says "alg": "HS256", jsonwebtoken treats
        // the 'publicKey' variable as a symmetric HMAC secret!
        const payload = jwt.verify(token, publicKey);
        return payload;
    } catch (err) {
        return null;
    }
}
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Obtain the Server's Public Key

1. Log into the application using `wiener:peter`.
2. Map the application in Burp Suite and look for standard endpoints that expose public keys (e.g., `/jwks.json`, `/.well-known/jwks.json`, or embedded in HTML source code).
3. In this lab, it's often found at a dedicated endpoint. Copy the JSON Web Key (JWK) object.

### Phase 2: Convert and Prepare the Key

1. Go to the **JWT Editor Keys** tab in Burp Suite.
2. Click **New RSA Key**.
3. Paste the server's JWK into the JWK format box and click **OK**. (You now have the server's public key saved as an RSA key).
4. Right-click this newly saved RSA key and select **Copy Public Key as PEM**.
5. Now, click **New Symmetric Key**.
6. In the dialog box, click **Generate** to create a blank template.
7. Replace the `"k"` value (the key material) with the Base64-encoded version of the PEM key you just copied. *(Note: The JWT Editor extension usually has a "PEM to Base64" conversion button built into this dialog to do this automatically).*
8. Ensure `"alg"` is set to `"HS256"` and click **OK**. You now have a symmetric key that uses the server's public key as its password.

### Phase 3: Forge and Sign the Token

1. Intercept a legitimate request to `/my-account` and send it to **Repeater**.
2. Switch to the **JSON Web Token** tab.
3. Change the `"alg"` in the Header from `"RS256"` to `"HS256"`.
4. Change the `"sub"` claim in the Payload from `"wiener"` to `"administrator"`.
5. Click **Sign** at the bottom.
6. Select the **Symmetric Key** you created in Phase 2.
7. Send the request to `GET /admin` to verify access, then change the path to `GET /admin/delete?username=carlos` to solve the lab.

## 📋 Personal Bug Hunting Checklist: Algorithm Confusion

- **Identify RS256 Tokens:** If you see `"alg": "RS256"`, immediately hunt for the server's public key. Check `/jwks.json`, OpenID configuration endpoints, or mobile application binaries.
- **Test the Downgrade:** Change `"RS256"` to `"HS256"` and sign the token using the extracted public key as an HMAC secret.
- **Format Variations:** Backend parsers read keys differently. You may need to test signing your HS256 token with the public key in different formats:
    - Strict PEM format (with `\n` newlines and `----BEGIN PUBLIC KEY-----` headers).
    - Single-line string format.
    - Extracted modulus (`n`) values.

## 🛡️ Remediation Strategy

Never allow the JWT library to implicitly trust the `"alg"` header from the client. The backend code must explicitly define and enforce the expected algorithm when calling the verify function.

JavaScript

```jsx
const jwt = require('jsonwebtoken');
const fs = require('fs');

const publicKey = fs.readFileSync('public_key.pem');

function verifySession(token){
    try {
        // ✅ REMEDIATION: Hardcode the allowed algorithm.
        // If an attacker sends an HS256 token, it will be instantly rejected
        // because it is not in the allowed algorithms array.
        const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return payload;
    } catch (err) {
        return null;
    }
}
```