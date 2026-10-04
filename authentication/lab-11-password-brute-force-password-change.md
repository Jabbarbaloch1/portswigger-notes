# 📝 Lab Breakdown: Password Brute-force via Password Change

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability Class:** Authentication Logic Flaw / Business Logic Discrepancy (CWE-203 / CWE-307)
- **Difficulty:** Practitioner
- **Key Mechanics:** Response Variance via Password Mismatch Trick (`new-password-1 != new-password-2`) to bypass lockout and identify valid credentials non-destructively.

## 📐 Vulnerability Architecture & Logic Flow

```
                         [ Attacker Request ]
             POST /my-account/change-password
             username=carlos
             current-password=§candidate_password§
             new-password-1=pass1
             new-password-2=pass2 (mismatched!)
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │      Password Change Controller      │
            └──────────────────┬───────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
    [ Current Password WRONG ]           [ Current Password CORRECT ]
            │                                      │
            ▼                                      ▼
┌───────────────────────────┐          ┌───────────────────────────┐
│ Check New Password Match  │          │ Check New Password Match  │
└───────────┬───────────────┘          └───────────┬───────────────┘
            │                                      │
            ▼                                      ▼
┌───────────────────────────┐          ┌───────────────────────────┐
│ Returns:                  │          │ Returns:                  │
│ "Current password is      │          │ "New passwords do not     │
│  incorrect"               │          │  match"                   │
└───────────────────────────┘          └───────────────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

Security teams frequently enforce strict rate-limiting and account lockout mechanisms on main login portals (`/login`). However, secondary authentication endpoints—such as `/my-account/change-password`—are often overlooked during security audits.

Furthermore, developers often sequence input validation checks in a way that leaks execution paths:

1. **Validation Order:** The backend first checks if `current-password` matches the stored hash in the database.
2. **Second Check:** If the current password is valid, it checks whether `new-password-1 == new-password-2`.
3. **The Oracle:** By intentionally supplying non-matching new passwords (`123` vs `abc`), an attacker prevents the database from actually updating Carlos's password. Instead, if the candidate `current-password` is correct, the application throws a validation error: `"New passwords do not match"`.

#### Vulnerable Backend Implementation Example:

Python

```
@app.route('/my-account/change-password', methods=['POST'])
def change_password():
    username = request.form.get('username')
    current_pass = request.form.get('current-password')
    new_pass1 = request.form.get('new-password-1')
    new_pass2 = request.form.get('new-password-2')

    user = db.query("SELECT * FROM users WHERE username = ?", username)

    # 🚨 VULNERABILITY 1: Checking current password without rate limiting/lockout
    if not check_password_hash(user.password_hash, current_pass):
        return "Current password is incorrect", 400

    # 🚨 VULNERABILITY 2: Secondary validation leak reveals current_pass was correct!
    if new_pass1 != new_pass2:
        return "New passwords do not match", 400

    # Update password in DB
    user.password_hash = hash_password(new_pass1)
    db.save(user)
    return "Password changed successfully", 200
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Analyze Endpoint Response Variance

1. Log in with `wiener:peter`.
2. Inspect the password change request in **Burp Suite**:HTTP
    
    ```
    POST /my-account/change-password HTTP/2
    Host:target.web-security-academy.net
    Content-Type:application/x-www-form-urlencoded
    
    username=wiener&current-password=peter&new-password-1=123&new-password-2=abc
    ```
    
3. Test two scenarios:
    - **Wrong current password + Mismatched new passwords:** Returns `"Current password is incorrect"`.
    - **Correct current password + Mismatched new passwords:** Returns `"New passwords do not match"`.

### Phase 2: Configure Burp Intruder

1. Intercept a password change request and send it to **Burp Intruder**.
2. Set the target parameter to `carlos` and add the payload position on `current-password`: HTTP
    
    ```
    POST /my-account/change-password HTTP/2
    Host:target.web-security-academy.net
    Content-Type:application/x-www-form-urlencoded
    
    username=carlos&current-password=§wrong-pass§&new-password-1=123&new-password-2=abc
    ```
    
3. Load the candidate password list into the **Payloads** tab.
4. Under **Settings** $\rightarrow$ **Grep - Match**, add a rule to search for the string: `New passwords do not match`.

### Phase 3: Execute & Authenticate

1. Launch the Intruder attack.
2. Sort the attack results by the `New passwords do not match` grep column.
3. Identify the candidate password that returned a `200 OK` (or `400 Bad Request`) containing `"New passwords do not match"`.
4. Log out of `wiener` and log into Carlos's account directly on the `/login` page using the discovered password.

## 📋 Personal Bug Hunting Checklist: Secondary Auth Flaws

- **Hidden Target Parameters:** Check if `/change-password`, `/update-email`, or `/reset-2fa` endpoints contain a `username` or `user_id` parameter that can be altered to target another user.
- **Rate-Limit Coverage:** Test whether account lockout rules apply consistently across all password-handling endpoints (`/login`, `/change-password`, `/forgot-password`).
- **Validation Order Logic:** Input mismatched verification values (e.g., non-matching passwords, mismatched new email confirmation fields) to test if the server evaluates credentials before field matching.
- **CSRF on Password Change:** Ensure password change forms validate anti-CSRF tokens to prevent forced credential updates via cross-site requests.

## 🛡️ Remediation Strategy

Implement consistent rate-limiting across all authentication endpoints, and validate structural input requirements before evaluating sensitive database credentials:

Python

```
@app.route('/my-account/change-password', methods=['POST'])
def change_password():
    # 1. Enforce rate limiting globally per user/IP
    if is_rate_limited(request.remote_addr):
        return "Too many requests", 429

    new_pass1 = request.form.get('new-password-1')
    new_pass2 = request.form.get('new-password-2')

    # 2. Validate structural constraints FIRST
    if new_pass1 != new_pass2:
        return "New passwords do not match", 400

    # 3. Check current password last and return generic errors
    user = get_authenticated_user(session)
    if not check_password_hash(user.password_hash, request.form.get('current-password')):
        return "Invalid current password", 400

    user.password_hash = hash_password(new_pass1)
    db.save(user)
    return "Password updated successfully", 200
```