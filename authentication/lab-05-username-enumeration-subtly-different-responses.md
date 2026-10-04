# 📝 PortSwigger Lab: Username Enumeration via Subtly Different Responses

<aside>
🎯

A PortSwigger Web Security Academy lab on username enumeration caused by subtly different authentication responses.

</aside>

## Overview

| Field | Details |
| --- | --- |
| **Vulnerability class** | Authentication / Information Disclosure |
| **Severity** | Medium |
| **Key mechanic** | Typographical and string-formatting discrepancies in generic error messages |
| **Difficulty** | Practitioner |

## Vulnerability Architecture & Logic Flow

```
                     ┌────────────────────────┐
                     │ Attacker POST /login   │
                     └───────────┬────────────┘
                                 │
                                 ▼
                     ┌────────────────────────┐
                     │  Check user existence  │
                     └───────────┬────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
                 ▼                               ▼
          [ User exists ]                [ User does not exist ]
                 │                               │
                 ▼                               ▼
     ┌───────────────────────┐       ┌───────────────────────┐
     │ Verify password hash  │       │ Return error message  │
     └───────────┬───────────┘       │ "Invalid username or  │
                 │                   │  password."           │
        ┌────────┴────────┐          └───────────────────────┘
        │                 │             Ends with full stop (.)
        ▼                 ▼
   [ Valid ]        [ Invalid ]
        │                 │
        ▼                 ▼
 ┌─────────────┐   ┌───────────────────────┐
 │ 302 Redirect│   │ Return error message  │
 │ (logged in) │   │ "Invalid username or  │
 └─────────────┘   │  password"            │
                   └───────────────────────┘
                     Missing full stop (.)
                              │
                              ▼
                       🚨 Enumeration vector
```

## Root Cause Analysis: Ask “Why?”

Developers often try to prevent username enumeration by returning a generic error instead of specific messages such as `User not found` or `Incorrect password`.

The flaw appears when these generic strings are hardcoded in separate code paths or modules rather than imported from one shared configuration. A one-character difference—such as a missing period—is enough to reveal whether an account exists.

### Vulnerable backend implementation

```python
# auth_controller.py

def login(request):
    user = db.find_user_by_username(request.username)

    # Branch 1: user does not exist
    if not user:
        # Developer A included a period.
        return render_error("Invalid username or password.")

    # Branch 2: user exists, but the password is wrong
    if not check_password(request.password, user.password_hash):
        # Developer B forgot the period.
        return render_error("Invalid username or password")

    return create_session(user)
```

Because the two branches return slightly different strings, an attacker can distinguish existing accounts from nonexistent ones.

## Exploitation Walkthrough

### Phase 1 — Identify a valid username

1. **Intercept the request:** Capture a login request in **Burp Suite** and send it to **Intruder** with `Ctrl + I`.
2. **Configure positions:** Select **Sniper** as the attack type and wrap only the `username` value:

```
POST /login HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
...

username=§candidate_user§&password=invalid_password_123
```

1. **Load payloads:** In the **Payloads** tab, paste the **Candidate usernames** wordlist.
2. **Configure response matching:** Open **Settings** or **Options → Grep - Match**. Clear the default matches and add:
    
    `Invalid username or password.`
    
    Include the period.
    
3. **Run and filter:** Start the attack, then sort by **Grep - Match** or **Length**.
4. **Interpret the result:** Invalid usernames should match the version with the period. The valid username should return no match—or show a one-byte response-size difference—because its error message lacks the trailing period.

### Phase 2 — Brute-force the password

1. **Move the payload marker:** Hardcode the discovered username and place the marker on the password:

```
username=DISCOVERED_VALID_USER&password=§candidate_password§
```

1. **Load passwords:** Paste the **Candidate passwords** wordlist into the **Payloads** tab.
2. **Run the attack:** Start the Intruder attack.
3. **Identify success:** Look for the request returning **HTTP 302 Found** instead of **200 OK**.
4. **Complete the lab:** Use the discovered credentials to log in through the browser.

## Personal Bug-Hunting Checklist

When testing login, registration, or password-reset forms on authorized targets, compare responses for subtle differences.

- **Punctuation:** `Invalid credentials.` vs `Invalid credentials`
- **Capitalization:** `Invalid Username or Password` vs `Invalid username or password`
- **Whitespace:** Trailing spaces or duplicated spaces in an error message
- **HTML structure:** `<span class="err">` vs `<p class="error-msg">`
- **HTTP status:** `200 OK` vs `401 Unauthorized` or `403 Forbidden`
- **Response headers:** A `Set-Cookie` header returned for an existing username even when authentication fails
- **Response length:** A consistent one-byte or small-length discrepancy between failure paths
- **Timing:** Noticeably different processing times when account lookup and password verification take different code paths

> Test only systems you own or are explicitly authorized to assess.
> 

## Remediation Strategy

Centralize authentication error handling and use one shared constant across every failure path. Also perform password-hash verification against a dummy hash when the user does not exist, so the two paths have similar execution timing.

```python
# constants.py
GENERIC_AUTH_ERROR = "Invalid username or password."

# auth_controller.py
from constants import GENERIC_AUTH_ERROR

def login(request):
    user = db.find_user_by_username(request.username)

    # Run the password check on every path to reduce timing differences.
    password_hash = user.password_hash if user else DUMMY_HASH
    is_valid = check_password(request.password, password_hash)

    if not user or not is_valid:
        # Use exactly the same response for every authentication failure.
        return render_error(GENERIC_AUTH_ERROR)

    return create_session(user)
```

### Defensive checklist

- Return identical error text, markup, status codes, and headers for all authentication failures.
- Centralize generic authentication messages as shared constants.
- Verify a password hash against a dummy hash when the username is unknown.
- Keep response timing and response size as consistent as practical.
- Rate-limit login attempts and monitor suspicious enumeration patterns.
- Consider MFA and account-protection controls for higher-risk applications.