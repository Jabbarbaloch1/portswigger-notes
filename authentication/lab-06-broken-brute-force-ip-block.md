# 📝 PortSwigger Lab: Broken Brute-Force Protection, IP Block

<aside>
🧭

A practitioner-focused walkthrough of PortSwigger's lab on bypassing IP-based brute-force protection by interleaving failed login attempts with valid logins.

</aside>

## At a glance

| Item | Details |
| --- | --- |
| **Vulnerability class** | Authentication / Broken rate limiting |
| **Severity** | High |
| **Core weakness** | A successful login resets a shared IP failure counter |
| **Exploit technique** | Interleave victim guesses with valid credentials |
| **Difficulty** | Practitioner |
| **Primary tool** | Burp Suite Intruder |

## Vulnerability architecture

### Standard attack — blocked

```
Request 1: carlos:pass1  ❌  Failed attempts = 1
Request 2: carlos:pass2  ❌  Failed attempts = 2
Request 3: carlos:pass3  🛑  IP blocked
```

### Interleaved attack — bypassed

```
Request 1: carlos:pass1  ❌  Failed attempts = 1
Request 2: wiener:peter   ✅  Failed attempts = 0  ← Counter reset
Request 3: carlos:pass2  ❌  Failed attempts = 1
Request 4: wiener:peter   ✅  Failed attempts = 0  ← Counter reset
...
```

The bypass works because the application tracks failures by **IP address**, but resets that counter after **any** successful authentication—not only after a successful login for the targeted account.

## Root cause

The intended control is usually described as “block an IP after three consecutive failures.” The implementation flaw is the scope of the state:

- The failure counter is keyed only by `client_ip`.
- Any valid login from that IP resets the counter.
- The valid login does not need to belong to the account being attacked.
- An attacker can therefore keep the counter below the blocking threshold indefinitely.

### Vulnerable implementation

```python
# Flawed rate-limiting middleware

def authenticate(request):
    client_ip = get_client_ip(request)

    # Block the IP after three failures.
    if failed_attempts.get(client_ip, 0) >= 3:
        return render_error(
            "Too many failed attempts. IP blocked.",
            status=429,
        )

    user = db.find_user(request.username)

    if user and check_password(request.password, user.password_hash):
        # Flaw: resets the shared IP counter for every valid account.
        failed_attempts[client_ip] = 0
        return create_session(user)

    failed_attempts[client_ip] = failed_attempts.get(client_ip, 0) + 1
    return render_error("Invalid credentials.", status=200)
```

## Exploitation walkthrough

### 1. Confirm the counter behavior

1. Intercept a login request in **Burp Suite** and send it to **Repeater**.
2. Submit two incorrect passwords for `carlos`.
3. Submit a third incorrect password and confirm that the IP is blocked.
4. Log in successfully with your own valid account, `wiener:peter`.
5. Submit another failed attempt for `carlos` and confirm that the block has been cleared.

> **Observation:** the successful `wiener` login resets the counter used to protect `carlos`.
> 

### 2. Build interleaved payloads

Use two equally sized lists. Each failed `carlos` attempt must be followed by a valid `wiener` login.

**Payload set 1 — usernames**

```
carlos
wiener
carlos
wiener
carlos
wiener
```

**Payload set 2 — passwords**

```
candidate_password_1
peter
candidate_password_2
peter
candidate_password_3
peter
```

The payloads must remain aligned so that every victim-password guess is immediately followed by `wiener:peter`.

### 3. Configure Burp Intruder

1. Send the `POST /login` request to **Burp Intruder** with `Ctrl + I`.
2. Select **Pitchfork** as the attack type.
3. Mark the username and password values as payload positions:

```
POST /login HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=§carlos§&password=§candidate_password_1§
```

1. Open the **Payloads** tab.
2. Configure **Payload set 1** with the interleaved usernames.
3. Configure **Payload set 2** with the interleaved passwords.
4. Use a **single-threaded Resource Pool** so requests execute sequentially.

### 4. Identify the valid password

1. Start the attack.
2. Filter by **status code** or **response length**.
3. Find a request where `username=carlos` returns an HTTP `302` redirect instead of the normal `200` response or `429` block.
4. Log in as `carlos` with the discovered password to complete the lab.

## Testing checklist

Use this checklist when assessing brute-force and lockout logic on authorized targets.

- [ ]  **Interleaved valid logins:** place valid credentials between failed guesses and observe whether the counter resets.
- [ ]  **Per-user vs. per-IP isolation:** test whether password spraying bypasses account-level lockouts.
- [ ]  **Trusted proxy handling:** verify whether IP-derived controls rely on correctly validated proxy headers.
- [ ]  **Account canonicalization:** test case, whitespace, email-format, and normalization differences.
- [ ]  **Duplicate parameters:** assess how repeated parameters such as `username=carlos&username=wiener` are parsed.
- [ ]  **Endpoint consistency:** compare controls across `/login`, `/api/v1/login`, and `/oauth/token`.
- [ ]  **Threshold and window behavior:** document the failure threshold, reset conditions, and expiration period.

> Only perform these checks against systems where you have explicit authorization.
> 

## Remediation strategy

A robust design should combine multiple controls rather than relying on a single IP counter:

1. Track failures across multiple dimensions, such as `(IP, username)` and account-wide signals.
2. Reset only the counter associated with the account and key that actually authenticated.
3. Apply an expiration window to counters.
4. Use progressive delays or temporary challenges instead of permanent IP blocks.
5. Monitor distributed attempts and password spraying across many IP addresses.
6. Avoid trusting client-controlled forwarding headers without a validated proxy chain.

### Safer implementation pattern

```python
# Safer rate-limiting pattern

def authenticate(request):
    client_ip = get_client_ip(request)
    username = normalize_username(request.username)
    rate_key = f"fails:{client_ip}:{username}"

    if redis.get(rate_key) and int(redis.get(rate_key)) >= 5:
        return render_error(
            "Too many failed attempts. Try again later.",
            status=429,
        )

    user = db.find_user(username)

    if user and check_password(request.password, user.password_hash):
        # Reset only the relevant IP-and-username key.
        redis.delete(rate_key)
        return create_session(user)

    # Keep the counter within a bounded time window.
    redis.incr(rate_key)
    redis.expire(rate_key, 900)
    return render_error("Invalid credentials.", status=200)
```

## Key takeaway

The vulnerability is not simply “weak rate limiting.” It is a **state-scoping error**: a global IP-based failure counter is reset by an unrelated successful login. Authentication controls should be scoped to the identity and risk signal they are intended to protect, with consistent enforcement across all login endpoints.