# 📝 Lab Breakdown: 2FA Broken Logic

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability class:** Broken Authentication / Improper State Management (CWE-306 / CWE-287)
- **Difficulty:** Practitioner
- **Key mechanic:** Client-controlled session identifier (`verify` cookie) during 2FA verification

## Overview

The 2FA verification step trusts a user identifier supplied by the client (the `verify` cookie). By swapping this cookie to another username, an attacker can brute-force that user’s 4-digit code and obtain a valid session—without knowing the password.

## Vulnerability architecture (logic flow)

```
[ Attacker request ]
POST /login2  (Step 2: 2FA)
Cookie: verify=carlos   ← swapped cookie
Body: mfa-code=1234
        │
        ▼
┌───────────────────────────┐
│   2FA verification engine  │
└─────────────┬─────────────┘
              │
        reads "verify" cookie
              │
              ▼
┌──────────────────────────────┐
│ Target user = "carlos"        │
│ Fetch carlos.mfa_code from DB │
└───────────────┬──────────────┘
                │
        ┌───────┴────────┐
        │                │
      matches           fails
        │                │
        ▼                ▼
┌───────────────────────┐  ┌────────────────────────┐
│ 302 → /my-account      │  │ 200 "Invalid 2FA"       │
│ set session for carlos │  │ attacker keeps trying   │
└───────────────────────┘  └────────────────────────┘
```

## Root cause (why it exists)

Multi-factor authentication requires the server to maintain a **trusted, server-side state** that Step 1 (password verification) completed for a specific user before Step 2 is evaluated.

In this lab, the backend does not bind Step 2 to a server-side session created during Step 1. Instead, it determines the “current user” for Step 2 from an untrusted client cookie (`verify=wiener`). Because `/login2` accepts arbitrary values in that cookie, an attacker can target any user.

### Vulnerable backend example (pseudo-Python)

```python
@app.route('/login2', methods=['POST'])
def verify_2fa():
    # VULNERABILITY: user context is read directly from an untrusted cookie
    target_user = request.cookies.get('verify')
    submitted_code = request.form.get('mfa-code')

    # Fetches 2FA code for whatever username is provided
    real_code = db.query(
        "SELECT mfa_code FROM users WHERE username = ?",
        target_user,
    )

    if submitted_code == real_code:
        # Issues a full session token for the target user without password proof
        session_token = create_session(target_user)
        response = redirect('/my-account')
        response.set_cookie('session', session_token)
        return response

    return "Invalid verification code", 200
```

## Exploitation walkthrough

### 1) Confirm the Step 1 → Step 2 state mechanism

1. Log in as `wiener:peter`.
2. Observe Step 1 sets `Set-Cookie: verify=wiener`.
3. You’re redirected to `/login2`.
4. Observe the `POST /login2` request:

```
POST /login2 HTTP/2
Host: target.web-security-academy.net
Cookie: verify=wiener

mfa-code=1234
```

### 2) Target Carlos by swapping the cookie

1. Send `GET /login2` and change the cookie to `verify=carlos`.
2. The server renders the 2FA page for Carlos (and typically triggers code generation/delivery for that user).

### 3) Brute-force the 4-digit code

1. Send the request to Burp Intruder / Turbo Intruder.
2. Keep the cookie fixed as `verify=carlos`.
3. Put the payload position on `mfa-code`:

```
POST /login2 HTTP/2
Host: target.web-security-academy.net
Cookie: verify=carlos

mfa-code=§0000§
```

1. Payload settings:
    - Type: Numbers
    - Range: `0000` → `9999`
    - Digits: 4
2. Success signal: a `302 Found` redirect instead of `200 OK`.
3. Open the successful response in the browser and navigate to `/my-account` to confirm access.

## Quick checklist: common 2FA/MFA weaknesses

- **Parameter/cookie swapping:** Try changing identifiers used by Step 2 (`verify`, `user`, `username`, `user_id`).
- **Missing rate limiting:** Confirm lockouts / throttling after repeated failures (4 digits = 10,000 tries).
- **Step bypass:** Attempt direct access to authenticated pages right after Step 1.
- **Reused/predictable codes:** Check if codes repeat across attempts or follow a pattern.
- **Code leakage:** Look for codes or secrets exposed in responses, headers, cookies, or APIs.

## Remediation

Bind Step 2 to a **server-side, temporary authentication state** generated only after successful password verification in Step 1. Store that state server-side, use a short expiry, and enforce rate limiting before code checks.

```python
@app.route('/login', methods=['POST'])
def step1_login():
    user = authenticate_password(request.form['username'], request.form['password'])
    if user:
        # Generate a cryptographically secure temporary token (store server-side)
        temp_2fa_session = generate_secure_token()
        redis.setex(f"2fa_session:{temp_2fa_session}", 300, user.username)  # 5 min

        response = redirect('/login2')
        response.set_cookie('2fa_auth_state', temp_2fa_session, httponly=True, secure=True)
        return response

@app.route('/login2', methods=['POST'])
def verify_2fa():
    temp_token = request.cookies.get('2fa_auth_state')
    target_user = redis.get(f"2fa_session:{temp_token}")

    if not target_user:
        return redirect('/login')

    if is_rate_limited(target_user):
        return "Too many failed attempts", 429

    if check_mfa_code(target_user, request.form['mfa-code']):
        return issue_full_session(target_user)

    return "Invalid verification code", 200
```