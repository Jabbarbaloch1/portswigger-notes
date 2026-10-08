# 🔑 JWT (JSON Web Tokens)

Notes and lab write-ups for PortSwigger's **JWT attacks** topic.
A JWT carries claims (user, role) plus a signature. If the server verifies the signature badly, an attacker can forge a token and act as any user.

<<<<<<< HEAD
![Labs](https://img.shields.io/badge/labs%20solved-7-brightgreen)
=======
![Labs](https://img.shields.io/badge/labs%20solved-8-brightgreen)
>>>>>>> 1cde4da (docs(jwt): fix README formatting and add lab 08)
![Topic](https://img.shields.io/badge/topic-jwt-blue)
![Level](https://img.shields.io/badge/level-apprentice%20to%20expert-orange)

## Contents

- [JWT structure](#jwt-structure)
- [Attack types](#attack-types)
- [Lab index](#lab-index)
- [Testing checklist](#testing-checklist)
- [Common mitigations](#common-mitigations)
- [Tools](#tools)

## JWT structure

```
header.payload.signature

header    {"alg":"HS256","typ":"JWT"}     how the token is signed
payload   {"sub":"wiener","role":"user"}  the claims
signature HMAC/RSA over header + payload  proves nothing was changed
```

Each part is Base64URL-encoded. Decoding is easy; the security comes only from the signature check.

## Attack types

| Category | What goes wrong | Labs |
|---|---|---|
| No signature check | Server accepts any signature | 01 |
| Weak verification | `alg: none` accepted | 02 |
| Weak secret | Signing key can be brute-forced | 03 |
| Header injection | Attacker controls `jwk`, `jku` or `kid` | 04, 05, 06 |
<<<<<<< HEAD
| Algorithm confusion | RS256 token verified as HS256 using the public key | 07 |
=======
| Algorithm confusion | RS256 token verified as HS256 using the public key | 07, 08 |
>>>>>>> 1cde4da (docs(jwt): fix README formatting and add lab 08)

## Lab index

| # | Lab | Level | Key idea | Tool |
|---|---|---|---|---|
| 01 | [Unverified signature](lab-01-unverified-signature.md) | Apprentice | Edit the payload; signature is never checked | Burp Repeater |
| 02 | [Flawed signature verification](lab-02-flawed-signature-verification.md) | Apprentice | Set `alg` to `none` | Burp Repeater |
| 03 | [Weak signing key](lab-03-weak-signing-key.md) | Practitioner | Crack the secret, then re-sign | hashcat, JWT Editor |
| 04 | [JWK header injection](lab-04-jwk-header-injection.md) | Practitioner | Embed your own public key in the header | JWT Editor |
| 05 | [JKU header injection](lab-05-jku-header-injection.md) | Practitioner | Point `jku` to your hosted key set | JWT Editor, exploit server |
| 06 | [kid header path traversal](lab-06-kid-header-path-traversal.md) | Practitioner | Make `kid` load a known file as the key | JWT Editor |
| 07 | [Algorithm confusion](lab-07-algorithm-confusion.md) | Expert | Sign with the public key as an HMAC secret | JWT Editor |
<<<<<<< HEAD
=======
| 08 | [Algorithm confusion, no exposed key](lab-08-algorithm-confusion-no-exposed-key.md) | Expert | Derive the public key from two tokens, then sign as HMAC | JWT Editor, sig2n |
>>>>>>> 1cde4da (docs(jwt): fix README formatting and add lab 08)

## Testing checklist

- [ ] Decode the token and note `alg`, `kid`, `jku`, `jwk` and the claims
- [ ] Change a claim with no re-sign: is the signature checked at all?
- [ ] Try `alg: none` (and case variants)
- [ ] Try cracking the secret with a common wordlist
- [ ] Test header injection: `jwk`, `jku`, `kid`
- [ ] Try swapping RS256 for HS256 using the public key
<<<<<<< HEAD
=======
- [ ] If no public key is exposed, derive it from two tokens
>>>>>>> 1cde4da (docs(jwt): fix README formatting and add lab 08)
- [ ] Check `exp`, `iss` and `aud` are enforced

## Common mitigations

- Always verify the signature server-side and reject `alg: none`
- Allow-list algorithms; never trust the `alg` header
- Use long, random secrets or proper asymmetric keys
- Allow-list `jku` hosts and ignore `jwk` from the token
- Validate and sanitize `kid`; never use it as a file path
- Set short expiry and validate `exp`, `iss`, `aud`

## Tools

Burp Suite, JWT Editor extension, hashcat, jwt.io (decoding only; never paste real tokens)

---
<<<<<<< HEAD
*Educational notes. All testing was done only on PortSwigger's official labs.*
=======
*Educational notes. All testing was done only on PortSwigger's official labs.*
>>>>>>> 1cde4da (docs(jwt): fix README formatting and add lab 08)
