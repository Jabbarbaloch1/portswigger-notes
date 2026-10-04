# 📝 Lab Breakdown: Username Enumeration via Account Lock

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability class:** Observable discrepancy / information disclosure (CWE-203)
- **Difficulty:** Practitioner
- **Key mechanics:** Response variance caused by account lockout logic

## Vulnerability architecture (high level)

```
                     [ Attacker Requests ]
             POST /login (Username, Wrong Password x5)
                               │
                               ▼
                 ┌───────────────────────────┐
                 │    Authentication Engine   │
                 └─────────────┬─────────────┘
                               │
            ┌──────────────────┴──────────────────┐
     [ Valid Username ]                     [ Invalid Username ]
            │                                      │
            ▼                                      ▼
┌─────────────────────────┐            ┌─────────────────────────┐
│ Increment lock counter  │            │ No database row exists  │
└───────────┬─────────────┘            └───────────┬─────────────┘
            │                                      │
 ┌──────────┴──────────┐                           │
 │ Hits lock threshold? │                           │
 └──────────┬──────────┘                           │
     ┌──────┴──────┐                               │
   [ YES ]      [ NO ]                             │
     │            │                                │
     ▼            ▼                                ▼
┌──────────┐  ┌──────────┐                   ┌──────────┐
│  200 OK  │  │  200 OK  │                   │  200 OK  │
│ "Account │  │ "Invalid │                   │ "Invalid │
│ locked"  │  │ creds"   │                   │ creds"   │
└──────────┘  └──────────┘                   └──────────┘
```

## Root cause analysis

Account lockout is often implemented *only after* confirming that the username exists. This creates a measurable discrepancy:

- **Invalid username:** no user record → lock counter is not incremented → generic error
- **Valid username:** user record exists → failed-attempt counter increases → lockout path eventually returns a distinct response (message, status code, length, timing, etc.)

### Vulnerable pseudocode (illustrative)

```python
def login(username, password):
    user = db.query("SELECT * FROM users WHERE username = ?", username)

    if not user:
        # Invalid users never update a counter
        return "Invalid username or password"

    if user.failed_attempts >= 5:
        # Discrepancy leaks that the username is valid
        return "Account is locked due to too many failed attempts."

    if not check_password(user, password):
        user.failed_attempts += 1
        db.save(user)
        return "Invalid username or password"

    return "Login successful"
```

## Exploitation walkthrough

### Phase 1 — Enumerate valid usernames

1. Intercept a failed login request in **Burp Suite** and send it to **Intruder**.
2. Configure Intruder to submit **5 invalid passwords per candidate username** (to intentionally hit the lockout threshold).
    - **Payload 1 (usernames):** candidate usernames
    - **Payload 2 (passwords):** `wrong1` → `wrong5` (or any five distinct invalid values)
3. Start the attack.
4. Identify the username(s) that behave differently:
    - Search for the string `locked`, or
    - Sort by **response length**, **status code**, or other observable differences.

Expected outcome:

- Invalid usernames keep returning the generic response.
- A valid username eventually triggers an “account locked” response (or another distinct signal).

### Phase 2 — Brute-force the password (without re-locking)

1. **Wait for lockout reset** (e.g., ~1 minute in this lab) if required.
2. Switch to a single-username attack using the discovered valid username.
3. Load the candidate password list.
4. To avoid re-locking during brute force:
    - In Intruder **Resource Pool**, set **Maximum concurrent requests** to `1`.
    - Add a small **delay** between requests if the application has aggressive thresholds.
5. Identify the successful password by a clear success indicator:
    - `302 Found` redirect, or
    - a post-login page (`200 OK` with different content), session cookie changes, etc.

## Practical checklist (authentication enumeration)

- **Error message differences:** small text changes across failure states
- **HTTP status codes:** e.g., `200` vs `403` vs `429`
- **Response timing:** valid users may take longer (hashing) than invalid users
- **Headers/cookies:** additional cookies or headers only when the username exists

## Remediation

Goal: ensure authentication failures are indistinguishable and that rate limiting occurs *before* account-specific logic.

Key controls:

- Return a **single generic error** for all auth failures (invalid user, invalid password, locked account).
- Apply **rate limiting** at the IP/network level and at the account level.
- Mitigate timing leakage by performing a **dummy hash** when the user does not exist.

### Remediated pseudocode (illustrative)

```python
# Remediated implementation

def login(username, password):
    user = db.query("SELECT * FROM users WHERE username = ?", username)

    # Use a dummy user/hash to equalize timing when the username is unknown
    password_valid = check_password(user if user else DUMMY_USER, password)

    if user and not password_valid:
        user.failed_attempts += 1
        db.save(user)

    # Generic failure regardless of user existence or lock state
    if not user or not password_valid or (user and user.failed_attempts >= 5):
        return "Invalid username or password"

    return "Login successful"
```