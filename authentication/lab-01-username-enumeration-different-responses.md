# 📝 Lab Overview: Username Enumeration via Different Responses

- **Difficulty:** Apprentice
- **Main Concept:** Finding a valid username by looking for small differences in the website’s login responses, then cracking its password.

## 1. What is Username Enumeration?

Username enumeration occurs when a website reveals whether a specific username exists in the database. Instead of returning a generic error, the server gives **different responses** for valid vs. invalid usernames.

## 2. Key Vulnerabilities in This Lab

- **Information Disclosure:** The server returns slightly different error messages or HTTP status codes depending on whether the username is correct.
    - *Example (Invalid user):* "Invalid username"
    - *Example (Valid user, wrong password):* "Incorrect password"
- **Missing Rate Limiting:** The application allows multiple login attempts without blocking or delaying requests, enabling brute-force attacks.

## 3. High-Level Attack Steps

1. **Enumerate the Username:** Send login requests using the *Candidate Usernames* list while keeping the password constant.
2. **Analyze Responses:** Look for an anomaly in the server's response (e.g., a different error message, response length, or status code) to confirm the valid username.
3. **Brute-Force the Password:** Fix the valid username and run a brute-force attack using the *Candidate Passwords* list.
4. **Access the Account:** Log in with the discovered credentials to solve the lab.

## 4. How to Prevent This Vulnerable Design

- **Generic Error Messages:** Always return the same neutral message for any failed login attempt (e.g., *"Invalid username or password"*).
- **Account Lockout / Rate Limiting:** Restrict the number of failed login attempts from a single IP or account to block automated brute-forcing.