# 📝 Lab Breakdown: JWT Authentication Bypass via kid Header Path Traversal

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability Class:** Local File Inclusion (LFI) / Path Traversal / Cryptographic Bypass (CWE-22 / CWE-347)
- **Difficulty:** Practitioner
- **Key Mechanics:** Exploiting the `kid` (Key ID) header parameter to force the server to read an empty file (`/dev/null`), which is then used as a known symmetric secret key to verify the token.

## 📐 Vulnerability Architecture & Logic Flow

```
                     [ Phase 1: Header Injection ]
                               │
            1. Attacker modifies JWT Header:
               {"alg": "HS256", "kid": "../../../../../../../dev/null"}
            2. Attacker modifies Payload: {"sub": "administrator"}
            3. Attacker signs token using an EMPTY STRING ("") as the key.
                               │
                               ▼
                     [ Phase 2: Server-Side Execution ]
               GET /admin (Cookie: session=eyJhbG...admin...)
                               │
                               ▼
            ┌───────────────────────────────────────────────┐
            │   JWT Handler Middleware                      │
            │   1. Parses the "kid" parameter.              │
            │   2. 🚨 Concatenates it into a file path:     │
            │      /var/app/keys/../../../../../../../dev/null
            │   3. Reads the file from the OS.              │
            │      (/dev/null returns an empty byte array)  │
            │   4. Uses the empty byte array to verify the  │
            │      HS256 signature.                         │
            │   ✅ Validation Passes!                       │
            └───────────────────────────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

When applications support key rotation, they use the `kid` (Key ID) parameter in the JWT header to determine which key from their internal storage should be used to verify the signature.

Some backend architectures store these keys as physical files on the server. If the application directly uses the client-supplied `kid` parameter to construct the file path without sanitizing path traversal sequences (`../`), an attacker can point the application to any file on the operating system.

### The Cryptographic Exploit Chain

This attack requires chaining a Path Traversal with an **Algorithm Confusion** trick:

1. **The Traversal:** Linux distributions contain a special device file at `/dev/null`. Reading from this file always returns an empty string/byte array.
2. **The Algorithm Switch:** The application normally uses asymmetric encryption (`RS256`), meaning it reads a public key from the filesystem. The attacker changes the header to `"alg": "HS256"`. This forces the backend to treat whatever file it reads as a *symmetric* password.
3. **The Bypass:** By combining the two, the backend reads `/dev/null` and effectively sets `SECRET_KEY = ""`. The attacker then signs their forged token using an empty string, and the server's math checks out perfectly.

#### Vulnerable Node.js Implementation Example:

JavaScript

```
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// 🚨 VULNERABILITY: Unsanitized file system read based on user input
function verifySession(token){
    try {
        const unverifiedHeader = jwt.decode(token, { complete: true }).header;
        const kid = unverifiedHeader.kid;

        // Constructs a vulnerable path: /app/keys/../../../../../../../dev/null
        const keyPath = path.join(__dirname, 'keys', kid);

        // Reads an empty string from /dev/null
        const secretKey = fs.readFileSync(keyPath);

        // Verifies the HS256 token using the empty string
        const payload = jwt.verify(token, secretKey, { algorithms: ['RS256', 'HS256'] });
        return payload;

    } catch (err) {
        return null;
    }
}
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Set Up the Empty Symmetric Key

1. In **Burp Suite**, navigate to the **JWT Editor Keys** tab.
2. Click **New Symmetric Key**.
3. In the dialog, click **Generate** to create a template in JSON format.
4. Replace the generated `k` value (the actual key material) with an empty string: `"k": ""`
5. Change the `"alg"` parameter to `"HS256"` and click **OK** to save the key.

### Phase 2: Forge the Traversal Token

1. Intercept a legitimate request using your `wiener` session and send it to **Repeater**.
2. Go to the **JSON Web Token** tab in Repeater.
3. Modify the Header to force symmetric encryption and traverse to the null device:JSON
    
    ```
    {
        "kid": "../../../../../../../dev/null",
        "alg": "HS256"
    }
    ```
    
4. Modify the Payload to elevate your privileges:JSON
    
    ```
    {
        "sub": "administrator"
    }
    ```
    
5. Click **Sign** at the bottom.
6. Select your newly created empty symmetric key.
7. **Crucial:** Uncheck the *"Update 'kid' parameter"* box before signing so Burp doesn't overwrite your traversal payload.

### Phase 3: Execute the Attack

1. Change the HTTP request path to `GET /admin/delete?username=carlos`.
2. Ensure your forged JWT is in the `session` cookie.
3. Send the request. The server reads `/dev/null`, treats the empty string as the HMAC secret, successfully validates your empty-string signature, and processes the deletion.

## 📋 Bug Hunting Checklist & Remediation

**Bug Hunting Triggers:**

- **`kid` Parameter:** Whenever you see `"kid"`, inject path traversal sequences.
- **Linux Targets:** Test `"kid": "../../../../../../../dev/null"`.
- **Windows Targets:** Test `"kid": "../../../../../../../windows/win.ini"`. While `win.ini` isn't empty, if you can guess its exact Base64-encoded string equivalent, you can use it as the symmetric signing key.
- **Predictable Files:** If `/dev/null` is blocked, try targeting predictable, static application files (like an empty `.keep` file or a static CSS file) that you can also read from the outside to use as your signing secret.

**Remediation Strategy:**
Never pass untrusted user input directly into file system APIs. Map Key IDs to their respective files or values using a strict, hardcoded dictionary.

JavaScript

```
// ✅ REMEDIATION: Strict whitelisting of Key IDs
const TRUSTED_KEYS = {
    "key-id-001": fs.readFileSync('/app/keys/public-key-001.pem'),
    "key-id-002": fs.readFileSync('/app/keys/public-key-002.pem')
};

function verifySession(token){
    const header = jwt.decode(token, { complete: true }).header;

    // Validates against the server-side map; rejects arbitrary paths
    if (!TRUSTED_KEYS[header.kid]) {
        throw new Error("Untrusted Key ID");
    }

    return jwt.verify(token, TRUSTED_KEYS[header.kid], { algorithms: ['RS256'] });
}
```