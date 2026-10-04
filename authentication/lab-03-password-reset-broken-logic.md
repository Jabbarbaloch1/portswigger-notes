# 📝 Lab Overview: Password Reset Broken Logic

- **Difficulty:** Apprentice
- **Main Concept:** Exploiting a broken password reset feature where the server trusts user-controllable input (the username parameter) instead of validating it against a secure session token.

## 1. What is Broken Password Reset Logic?

This issue occurs when a password reset mechanism relies on data sent from the client (like a hidden input field or POST parameter) to decide *whose* password to update, rather than verifying that the request belongs to the user who requested the reset token.

## 2. Key Vulnerability: Over-Reliance on Client Input

- **Flawed State Tracking:** The server issues a reset token or session, but when the final password update form is submitted, it reads the target account name directly from a POST request parameter (e.g., `username=carlos`).
- **Missing Server-Side Check:** The backend fails to cross-check whether the reset token or logged-in session actually matches the username specified in the request body.

## 3. Attack Workflow

```
[ Attacker ]                                                 [ Target Server ]
     |                                                               |
     |  1. Request password reset for "wiener"                       |
     |-------------------------------------------------------------->|
     |                                                               |
     |  2. Receive valid reset link/email for "wiener"               |
     |<--------------------------------------------------------------|
     |                                                               |
     |  3. Submit new password form & Intercept Request              |
     |-------------------------------------------------------------->|
     |     POST /forgot-password?temp-forgot-password-token=xyz      |
     |     Body: username=wiener&temp-forgot-password-token=xyz...   |
     |                                                               |
     |  4. Modify HTTP Request Parameter                             |
     |     Change "username=wiener"  -->  "username=carlos"          |
     |-------------------------------------------------------------->|
     |                                                               |
     |  5. Server accepts modified parameter and updates password    |
     |<--------------------------------------------------------------|
     |     "Password for Carlos successfully updated!"               |
```

## 4. How to Secure Password Reset Logic

- **Tie Tokens to Accounts on the Server:** Store reset tokens in a secure server database alongside the associated account ID. When processing a reset, look up the account using only the token.
- **Remove User-Controlled Parameters:** Do not include editable username or user ID fields in the final password reset submission body.