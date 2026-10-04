# 📝 Lab Overview: 2FA Simple Bypass

- **Difficulty:** Apprentice
- **Main Concept:** Bypassing two-factor authentication (2FA) by directly navigating to the target URL after completing the first authentication step.

## 1. What is a 2FA Simple Bypass?

A 2FA simple bypass happens when an application assumes a user has completed the second authentication factor just because they landed on a specific page.

If the backend fails to verify whether the current session actually passed the 2FA check before serving protected pages, an attacker can skip the prompt entirely by entering the destination URL manually.

## 2. Key Vulnerability: Broken Access Control & Missing Session Verification

- **Flawed Workflow:** The backend tracks login states incorrectly (e.g., logging in with a valid password creates a fully authenticated session immediately instead of a temporary "pending 2FA" state).
- **Missing Page Protection:** Internal endpoints like `/my-account` fail to check if the user completed the 2FA step before serving the page.

## 3. Attack Workflow

1. **Step 1 Authentication:** Log in with valid primary credentials (`wiener:peter`).
2. **2FA Prompt:** The application redirects to `/login2` asking for a verification code.
3. **Direct Navigation:** Change the URL directly from `/login2` to the account page endpoint (e.g., `/my-account?id=carlos` or `/my-account`).
4. **Bypass Confirmed:** The application loads Carlos's account page because the server only checked if a valid session existed, not if 2FA was solved.

## 4. How to Secure This Workflow

- **Enforce Strict Multi-Stage State Management:** Keep the user in a restricted, temporary session state (e.g., `2FA_PENDING`) until the correct 2FA code is supplied.
- **Centralized Authorization Checks:** Protect every sensitive endpoint so it verifies both `authenticated == true` AND `2fa_completed == true` before rendering data.