📝 Conceptual Notes: JWT Algorithm Confusion 
## 1. What is Algorithm Confusion in Simple Terms?

- **RS256 (Asymmetric Encryption):** Uses two keys. The server keeps a **Private Key** secret to sign tokens, and shares a **Public Key** so others can verify them.
- **HS256 (Symmetric Encryption):** Uses one single **Secret Password** to both sign and verify tokens.
- **The Core Flaw:** The server reads the algorithm name directly from the client's token header. If the header is changed from `RS256` to `HS256`, the server switches to symmetric mode and accidentally uses its **Public Key as the Secret Password**.

## 2. What Happens When the Public Key Is Not Published?

- In standard setups, public keys are shared publicly (for example, at `/.well-known/jwks.json`).
- If an application does not publish its public key, the key can still theoretically be calculated offline by analyzing two or more valid tokens signed by the same private key using standard RSA mathematical properties.
- Once the public key is mathematically calculated, the algorithm confusion vulnerability allows that key to be used to verify forged tokens.

## 3. Root Cause (Why It Happens)

- **Trusting Unvalidated Headers:** The backend reads the `"alg"` parameter directly from incoming user tokens without checking if it is allowed.
- **Dynamic Library Modes:** The server's JWT library dynamically switches cryptographic modes based on client input instead of enforcing a fixed algorithm.

## 4. How to Fix It (Defense Strategy)

- **Hardcode Allowed Algorithms:** Always specify allowed algorithms explicitly in backend verification calls so unexpected algorithms are rejected automatically.
- **Separate Key Types:** Never allow asymmetric public keys to be passed into symmetric HMAC verification logic.

JavaScript

```
// SECURE VERIFICATION EXAMPLE
// Strictly enforce RS256; reject any incoming token claiming HS256 or none
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```