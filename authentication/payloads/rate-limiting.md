# RATE LIMITING

## 1) IP Spoofing Headers

Try each one individually in Burp Repeater, change the value each request:

- `X-Forwarded-For: 1.2.3.4`
- `X-Forwarded-For: 127.0.0.1`
- `X-Originating-IP: 127.0.0.1`
- `X-Remote-IP: 127.0.0.1`
- `X-Remote-Addr: 127.0.0.1`
- `X-Client-IP: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `True-Client-IP: 127.0.0.1`
- `Forwarded: for=127.0.0.1;by=127.0.0.1`
- `CF-Connecting-IP: 127.0.0.1` (if Cloudflare in front)

### How to test it fast

Send request in Repeater → right-click → "Send to Intruder" → set payload position on the IP value → payload list = incrementing IPs (or a list of known bypass IPs) → check if lockout counter resets.

## 2) Header Duplication / Order Tricks

- Send `X-Forwarded-For` header twice with different values
- Add a trailing space or different casing: `X-Forwarded-For :`
- Add extra whitespace: `X-Forwarded-For: 1.1.1.1`

## 3) Session/Fingerprint Reset

- Remove or randomize `User-Agent`
- Rotate `Cookie` / session token per request (if rate limit is session-scoped, not IP-scoped)
- Change `Referer` header

---

### What to Try — Sequence (for your "Broken Brute-Force Protection" notes)

| Step | Action | What you're testing |
| --- | --- | --- |
| 1 | Fire 10-15 requests with no changes | Confirm lockout triggers, note threshold |
| 2 | Repeat same requests, add `X-Forwarded-For` incrementing each time | IP-based counter reset |
| 3 | Same but rotate session cookie each request | Session-based vs IP-based limit |
| 4 | Race condition: send burst via Intruder "Null payloads" + Turbo Intruder for true parallel requests | Check if limit is checked before or after the attempt is processed |
| 5 | Try correct password on final attempt (e.g., 3 wrong + 1 correct in same burst) | Logic flaw where limit resets on last request instead of counting all |
| 6 | Change `Content-Length`/param casing (`username` vs `Username`) | See if lockout key is case-sensitive per param |