# 📝 Lab Breakdown: Broken Brute-Force Protection, Multiple Credentials per Request

- **Target:** PortSwigger Web Security Academy (Expert)
- **Vulnerability Class:** Rate Limiting / Authentication Logic Flaw (CWE-307)
- **Difficulty:** Expert
- **Key Mechanics:** Request-based rate limiting bypass via JSON array parameter batching (`"password": ["pass1", "pass2", ...]`)

## 📐 Vulnerability Architecture & Logic Flow

```
                      [ Attacker Request ]
                        POST /login
              {"username": "carlos", "password": ["p1", "p2", ..., "p100"]}
                                │
                                ▼
                  ┌───────────────────────────┐
                  │   Rate Limiter Middleware │
                  └─────────────┬─────────────┘
                                │
         ( Increments Request Counter by 1 ONLY )
                                │
                                ▼
                  ┌───────────────────────────┐
                  │    Authentication Engine   │
                  └─────────────┬─────────────┘
                                │
        ( Loops through array of 100 passwords in memory )
                                │
          ┌─────────────────────┴─────────────────────┐
     [ Match Found? ]                            [ No Match ]
          │                                           │
          ▼                                           ▼
┌───────────────────────────┐               ┌───────────────────┐
│ 302 Redirect / Set Cookie │               │ 200 OK            │
│ Session authenticated!    │               │ "Invalid creds"   │
└───────────────────────────┘               └───────────────────┘
```

## 🔬 Deep Dive: "Ask WHY" & Root Cause Analysis

### Why does this vulnerability exist?

Rate-limiting mechanisms (such as IP-based throttling or account lockout counters) are often placed in middleware layers, upstream from the actual application logic. These rate limiters inspect high-level HTTP metrics—counting the **number of HTTP requests** hitting the `/login` endpoint over a given timeframe.

However, modern JSON-based authentication APIs may be designed or configured in a way that accepts flexible data structures. If the backend parser or login handler processes an array of values for the password parameter, it evaluates multiple password attempts sequentially **within a single HTTP transaction**.

Because the middleware rate-limiter only saw **one incoming HTTP request**, it increments the counter by 1, completely missing the fact that 100 or 1,000 credential verification attempts occurred behind the scenes.

#### Vulnerable Backend Implementation Example:

Python

```
# Vulnerable JSON Authentication Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    passwords = data.get('password') # Can be a string OR a list!

    user = db.query("SELECT * FROM users WHERE username = ?", username)
    if not user:
        return jsonify({"message": "Invalid credentials"}), 200

    # 🚨 VULNERABILITY: If 'passwords' is an array, it checks all candidates in 1 request!
    if isinstance(passwords, list):
        for candidate in passwords:
            if check_password_hash(user.password_hash, candidate):
                session_token = create_session(user.username)
                res = jsonify({"message": "success"})
                res.set_cookie('session', session_token)
                return res
    else:
        if check_password_hash(user.password_hash, passwords):
            session_token = create_session(user.username)
            res = jsonify({"message": "success"})
            res.set_cookie('session', session_token)
            return res

    return jsonify({"message": "Invalid credentials"}), 200
```

## 🛠️ Step-by-Step Exploitation Walkthrough

### Phase 1: Analyze the Login Request Structure

1. Intercept a normal login request in **Burp Suite**.
2. Notice that the endpoint accepts JSON data:HTTP
    
    ```
    POST /login HTTP/2
    Host:target.web-security-academy.net
    Content-Type:application/json
    
    {"username": "wiener", "password": "peter"}
    ```
    
3. Test how the backend handles an array value for the `password` key:JSON
    
    ```
    {"username": "wiener", "password": ["wrong_pass", "peter"]}
    ```
    
4. If the server evaluates the array and successfully returns a `302 Found` or sets a session cookie, the endpoint is vulnerable to batch credential submission.

### Phase 2: Construct the Multi-Credential Payload

1. Extract the full candidate password list provided in the lab.
2. Format the password list into a valid JSON array string:
`["candidate1", "candidate2", "candidate3", ...]`
3. In **Burp Repeater**, target `carlos` and replace the single password string with the full JSON array:HTTP
    
    ```
    POST /login HTTP/2
    Host:target.web-security-academy.net
    This vulnerability stems from a fundamental mismatch between how brute-force rate limiters count activity (per HTTP request) and how backend authentication code processes input data structures (per element within a payload).
    ```
    

### Flaw Mechanics

When an authentication endpoint accepts JSON-formatted data, weak input parsing might allow fields to accept multiple types, such as either a single string or an array of strings.

If the security mechanism only increments its failure counter once per incoming HTTP request, submitting multiple candidate passwords inside a JSON array in a single request bypasses the rate limit completely:

- **Standard Request (1 Attempt = 1 Request Count):**JSON
    
    ```
    {
      "username": "carlos",
      "password": "password123"
    }
    ```
    
- **Batched Request (N Attempts = 1 Request Count):**JSON
    
    ```
    {
      "username": "carlos",
      "password": [
        "123456",
        "password",
        "carlos123",
        "admin",
        "letmein"
      ]
    }
    ```
    

If the backend logic iterates through the array and attempts to match each entry against the account's password hash, all candidates are evaluated in a single round trip. The rate limiter registers only a single request, allowing hundreds or thousands of password attempts to bypass threshold protections.

### Key Behavioral Indicators

- **Success State:** If any password within the array matches the user's actual password, the backend returns an HTTP redirect (e.g., `302 Found`) or issues a valid authentication cookie/token in the response header.
- **Failure State:** If none of the passwords match, the response returns the standard error message (e.g., `"Invalid username or password"`) with an HTTP `200 OK` or `401 Unauthorized` status.

### Remediation Strategies

To defend against batch-based brute-force attacks:

1. **Strict Type and Schema Validation:** Reject any authentication payload that does not strictly adhere to expected data types. If `"password"` must be a string, validate the JSON schema on receipt and reject arrays or unexpected data structures with an HTTP `400 Bad Request`.
2. **Track Attempts, Not Requests:** Ensure rate-limiting and logging logic record individual authentication evaluations rather than relying solely on HTTP request counts.
3. **Enforce Account-Level Controls:** Implement lockouts, progressive delays, or CAPTCHA challenges tied directly to the target account name, regardless of source IP or request structure.