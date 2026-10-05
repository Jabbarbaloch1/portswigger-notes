\# 🔑 JWT (JSON Web Tokens)



Notes and lab write-ups for PortSwigger's \*\*JWT attacks\*\* topic.

A JWT carries claims (user, role) and a signature. If the server verifies the signature badly, an attacker can forge a token and become any user.



!\[Labs](https://img.shields.io/badge/labs%20solved-7-brightgreen)

!\[Topic](https://img.shields.io/badge/topic-jwt-blue)



\## Contents



\- \[Attack types](#attack-types)

\- \[Lab index](#lab-index)

\- \[Common mitigations](#common-mitigations)

\- \[Tools](#tools)



\## Attack types



| Category | What goes wrong | Labs |

|---|---|---|

| No signature check | Server accepts any signature | 01 |

| Weak verification | `alg: none` accepted | 02 |

| Weak secret | Signing key can be cracked | 03 |

| Header injection | Attacker controls `jwk`, `jku` or `kid` | 04, 05, 06 |

| Algorithm confusion | RS256 token verified as HS256 with the public key | 07 |



\## Lab index



| # | Lab | Level | Technique |

|---|---|---|---|

| 01 | \[Unverified signature](lab-01-unverified-signature.md) | Apprentice | Edit the payload, signature is ignored |

| 02 | \[Flawed signature verification](lab-02-flawed-signature-verification.md) | Apprentice | Set `alg` to `none` |

| 03 | \[Weak signing key](lab-03-weak-signing-key.md) | Practitioner | Crack the secret, re-sign |

| 04 | \[JWK header injection](lab-04-jwk-header-injection.md) | Practitioner | Embed your own public key |

| 05 | \[JKU header injection](lab-05-jku-header-injection.md) | Practitioner | Point `jku` to your key set |

| 06 | \[kid header path traversal](lab-06-kid-header-path-traversal.md) | Practitioner | Traverse to a known file as the key |

| 07 | \[Algorithm confusion](lab-07-algorithm-confusion.md) | Expert | Sign with the public key as an HMAC secret |



\## Common mitigations



\- Always verify the signature server-side and reject `alg: none`

\- Allow-list algorithms; never trust the `alg` header

\- Use long, random secrets or proper asymmetric keys

\- Allow-list `jku` hosts and ignore `jwk` from the token

\- Validate and sanitize `kid`; never use it as a file path

\- Set short expiry and validate `exp`, `iss`, `aud`



\## Tools



Burp Suite, JWT Editor extension, hashcat, jwt.io (for decoding only, never paste real tokens)



\---

\*Educational notes. All testing was done only on PortSwigger's official labs.\*

