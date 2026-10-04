# 🔐 Authentication

Notes and lab write-ups for PortSwigger's **Authentication** topic.
Authentication flaws let an attacker log in as someone else, usually by guessing credentials, bypassing a step in the login flow, or abusing recovery features.

![Labs](https://img.shields.io/badge/labs%20solved-12-brightgreen)
![Topic](https://img.shields.io/badge/topic-authentication-blue)

## Contents

- [Attack types](#attack-types)
- [Lab index](#lab-index)
- [Common mitigations](#common-mitigations)
- [Tools](#tools)
- [Extras](#extras)

## Attack types

| Category | What goes wrong | Labs |
|---|---|---|
| Username enumeration | Response text, length, status or timing reveals valid users | 01, 04, 05, 07 |
| Brute force | Weak or missing rate limiting and lockouts | 06, 09, 11, 12 |
| 2FA bypass | Second step can be skipped or the code guessed | 02, 08 |
| Password reset flaws | Broken logic or poisoned reset links | 03, 10 |
| Weak session persistence | Predictable "stay logged in" cookie | 09 |

## Lab index

| # | Lab | Level | Technique |
|---|---|---|---|
| 01 | [Username enumeration via different responses](lab-01-username-enumeration-different-responses.md) | Apprentice | Compare error messages |
| 02 | [2FA simple bypass](lab-02-2fa-simple-bypass.md) | Apprentice | Skip the 2FA page |
| 03 | [Password reset broken logic](lab-03-password-reset-broken-logic.md) | Apprentice | Tamper with reset token and username |
| 04 | [Username enumeration via response timing](lab-04-username-enumeration-response-timing.md) | Practitioner | Timing difference, spoofed IP header |
| 05 | [Username enumeration via subtly different responses](lab-05-username-enumeration-subtly-different-responses.md) | Practitioner | Grep for tiny text differences |
| 06 | [Broken brute-force protection, IP block](lab-06-broken-brute-force-ip-block.md) | Practitioner | Reset the counter with a valid login |
| 07 | [Username enumeration via account lock](lab-07-username-enumeration-account-lock.md) | Practitioner | Lockout message leaks valid users |
| 08 | [2FA broken logic](lab-08-2fa-broken-logic.md) | Practitioner | Swap the `verify` cookie, brute-force the code |
| 09 | [Brute-forcing a stay-logged-in cookie](lab-09-brute-force-stay-logged-in-cookie.md) | Practitioner | Reverse the cookie format |
| 10 | [Password reset poisoning via middleware](lab-10-password-reset-poisoning-middleware.md) | Practitioner | `X-Forwarded-Host` injection |
| 11 | [Password brute-force via password change](lab-11-password-brute-force-password-change.md) | Practitioner | Error differences on the change form |
| 12 | [Broken brute-force protection, multiple credentials per request](lab-12-broken-brute-force-multiple-credentials.md) | Expert | JSON array of passwords in one request |

## Common mitigations

- Return one generic login error and keep response size and timing consistent
- Rate-limit per account **and** per IP; don't trust client-supplied IP headers
- Bind 2FA to the session, verify it server-side, and limit code attempts
- Use long, random, single-use, expiring reset tokens; build reset links from a fixed server-side host
- Never build "remember me" cookies from guessable values

## Tools

Burp Suite (Repeater, Intruder, Turbo Intruder), ffuf, browser dev tools

## Extras

- [Payloads and wordlists notes](payloads/)

---
*Educational notes. All testing was done only on PortSwigger's official labs.*
