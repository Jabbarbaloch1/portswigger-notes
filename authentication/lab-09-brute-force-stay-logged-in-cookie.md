# 📝 Lab Breakdown: Brute-forcing a Stay-Logged-In Cookie

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability class:** Broken session management / weak cookie cryptography (CWE-312 / CWE-384)
- **Difficulty:** Practitioner
- **Key mechanics:** Deterministic persistent cookie: `base64(username:md5(password))`

## 📐 Vulnerability architecture & logic flow

```
                               [ Attacker request ]
                         GET /my-account?id=carlos
            Cookie: stay-logged-in=Y2FybG9zOjVkNDE3MzAz...
                                       │
                                       ▼
                         ┌───────────────────────────┐
                         │   Cookie parsing engine   │
                         └─────────────┬─────────────┘
                                       │
                               (Base64 decode)
                                       │
                                       ▼
                     "carlos:5d41402abc4b2a76b9719d911017c592"
                                       │
                     ┌─────────────────┴─────────────────┐
                     │ Split by ":"                      │
                     │ Username = "carlos"               │
                     │ Password hash = "5d41402abc..."   │
                     └─────────────────┬─────────────────┘
                                       │
                         ┌─────────────┴─────────────┐
                    [ Matches? ]                 [ Fails? ]
                         │                           │
                         ▼                           ▼
            ┌─────────────────────────┐  ┌──────────────────────────────┐
            │ 200 OK "My Account"     │  │ Redirect / unauthenticated   │
            │ Authenticated as Carlos │  │ (e.g., to /login)            │
            └─────────────────────────┘  └──────────────────────────────┘
```

## 🔬 Root cause ("ask why")

Developers sometimes try to implement “remember me” in a **stateless** way (no server-side token store). They encode identity + a password-derived verifier directly into a client-side cookie.

If the verifier is a **deterministic, unsalted hash** such as `MD5(password)`, the cookie becomes **static and forgeable**. An attacker who knows (or can guess) a username can brute-force password candidates **offline** and generate valid cookies without triggering login-rate limits or lockouts.

### Vulnerable backend pattern (illustrative)

```python
@app.route('/my-account', methods=['GET'])
def check_remember_me():
    remember_cookie = request.cookies.get('stay-logged-in')

    if remember_cookie:
        # Vulnerable: deterministic structure derived from user-controlled cookie
        decoded = base64.b64decode(remember_cookie).decode('utf-8')  # "username:md5_hash"
        username, submitted_hash = decoded.split(':')

        user = db.query("SELECT password_hash FROM users WHERE username = ?", username)

        # Vulnerable: compares client-provided MD5(password) directly
        if user and user.password_hash == submitted_hash:
            session['user'] = username
            return render_template('account.html', user=username)

    return redirect('/login')
```

## 🛠️ Step-by-step exploitation walkthrough

### Phase 1: confirm cookie structure

1. Log in with `wiener:peter` and check **Stay logged in**.
2. Inspect the response header setting the cookie:
    
    ```
    Set-Cookie: stay-logged-in=d2llbmVyOjUxZmRjODAwOTAxYjI5NmQyMWU2ZDcxN2U0NjM4OWQy;
    ```
    
3. Base64-decode the cookie in Burp Decoder / Inspector.
    - **Decoded:** `wiener:51fdc800901b296d21e6d717e46389d2`
4. Identify the 32-character digest:
    - `MD5("peter")` = `51fdc800901b296d21e6d717e46389d2`
5. **Conclusion:** cookie rule is `Base64(username:MD5(password))`.

### Phase 2: configure Burp Intruder payload processing

Goal: generate `Base64("carlos:" + MD5(password_candidate))`.

1. Intercept a request to `/my-account?id=carlos` (or `/my-account`).
2. Send the request to **Intruder**.
3. Set the payload position on the `stay-logged-in` cookie value:
    
    ```
    GET /my-account?id=carlos HTTP/2
    Host: target.web-security-academy.net
    Cookie: stay-logged-in=§d2llbmVyOjUx...§
    ```
    
4. In **Payloads**:
    - **Payload type:** Simple list
    - Load the candidate password list from the lab
5. Under **Payload Processing**, add these rules **in order**:
    1. **Hash:** MD5
    2. **Add prefix:** `carlos:`
    3. **Encode:** Base64
6. Disable **Payload encoding** (so Burp doesn’t URL-encode Base64 padding like `=`).

### Phase 3: execute and validate

1. Launch the Intruder attack.
2. Sort by **Status** and/or **Response length**.
3. The correct candidate returns a `200` with Carlos’s account page (often recognizable by a **Log out** button).
4. Copy the successful Base64 payload into your browser cookie store for `stay-logged-in`, refresh, and access Carlos’s account.

## ✅ Personal checklist: persistent-session flaws

- **Decode static cookies:** test session or remember-me tokens for Base64/Hex/URL encoding.
- **Recognize common hash lengths:** 32 (MD5), 40 (SHA1), 64 (SHA-256).
- **Test invalidation:** does a remember-me token remain valid after password change?
- **Look for low entropy:** tokens derived from username/timestamps are often predictable.

## 🛡️ Remediation strategy

Use the **Selector / Verifier** pattern (OWASP Persistent Authentication). Never put password hashes (or password-derived verifiers) in cookies.

### Safer implementation pattern (illustrative)

```python
import secrets, hashlib

@app.route('/login', methods=['POST'])
def login():
    if validate_credentials(request.form['username'], request.form['password']):
        if request.form.get('remember_me'):
            # Generate two separate cryptographically secure random tokens
            selector = secrets.token_hex(16)   # Lookup key
            verifier = secrets.token_hex(32)   # Secret validator

            # Save selector and SHA256(verifier) in database
            verifier_hash = hashlib.sha256(verifier.encode()).hexdigest()
            db.execute(
                "INSERT INTO remember_tokens (selector, verifier_hash, user_id, expires) VALUES (?, ?, ?, ?)",
                (selector, verifier_hash, user.id, time.time() + 2592000)
            )

            # Send raw selector:verifier token to client
            cookie_value = f"{selector}:{verifier}"
            response.set_cookie('stay-logged-in', cookie_value, httponly=True, secure=True)
            return response
```