\# Authentication



Flaws in how an app checks who you are: login, password reset, 2FA, "stay logged in" cookies, and brute-force protection.



\## Attack types



| Type | Idea |

|---|---|

| Username enumeration | Different response, length or timing reveals valid users |

| Brute force | Guess passwords, bypass rate limits and lockouts |

| 2FA bypass | Skip the second step or brute-force the code |

| Password reset flaws | Weak logic, poisoned links, leaked tokens |

| Stay-logged-in cookie | Predictable or crackable cookie |



\## Labs



| # | Lab | Level | Status |

|---|---|---|---|

| 01 | \[Username enumeration via different responses](lab-01-username-enumeration-different-responses.md) | Apprentice | ✅ |

| 02 | \[2FA simple bypass](lab-02-2fa-simple-bypass.md) | Apprentice | ✅ |

| 03 | \[Password reset broken logic](lab-03-password-reset-broken-logic.md) | Apprentice | ✅ |

| 04 | \[Username enumeration via response timing](lab-04-username-enumeration-response-timing.md) | Practitioner | ✅ |

| 05 | \[Username enumeration via subtly different responses](lab-05-username-enumeration-subtly-different-responses.md) | Practitioner | ✅ |

| 06 | \[Broken brute-force protection, IP block](lab-06-broken-brute-force-ip-block.md) | Practitioner | ✅ |

| 07 | \[Username enumeration via account lock](lab-07-username-enumeration-account-lock.md) | Practitioner | ✅ |

| 08 | \[2FA broken logic](lab-08-2fa-broken-logic.md) | Practitioner | ✅ |

| 09 | \[Brute-forcing a stay-logged-in cookie](lab-09-brute-force-stay-logged-in-cookie.md) | Practitioner | ✅ |

| 10 | \[Password reset poisoning via middleware](lab-10-password-reset-poisoning-middleware.md) | Practitioner | ✅ |

| 11 | \[Password brute-force via password change](lab-11-password-brute-force-password-change.md) | Practitioner | ✅ |

| 12 | \[Broken brute-force protection, multiple credentials per request](lab-12-broken-brute-force-multiple-credentials.md) | Expert | ✅ |



\## Extras



\- \[Payloads](payloads/)

