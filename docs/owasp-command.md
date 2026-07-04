# OWASP Command Reference

The `owasp` command group lets you run **exactly one OWASP module in isolation** against a target. It is the right tool for focused red-team work on a single vulnerability class. For a full orchestrated run across all modules (or a subset), use [`scan`](scan-guide.md).

## Table of Contents

- [Overview](#overview)
- [Listing Modules](#listing-modules)
- [Running a Module](#running-a-module)
- [Shared Transversal Options](#shared-transversal-options)
- [BOLA Module Options (API1)](#bola-module-options-api1)
- [Auth Module Options (API2)](#auth-module-options-api2)
- [Module Reference](#module-reference)
- [Examples](#examples)

## Overview

```
apileaks owasp                        # list every registered module
apileaks owasp <key> --target URL     # run exactly one module in isolation
```

Each subcommand is named character-for-character by the module's engine registration key. Unknown subcommand names are rejected natively by Click with a non-zero exit before any request is issued.

`dir` and `par` are intentionally not registered here — they are separate top-level commands.

## Listing Modules

Running `owasp` with no subcommand prints one line per registered module:

```bash
python apileaks.py owasp
```

Output format: `<key>\t<owasp_category>\t<summary>`

```
bola	API1	Broken Object Level Authorization (BOLA) detection
auth	API2	Broken Authentication detection
property	API3	Broken Object Property Level Authorization detection
resource	API4	Unrestricted Resource Consumption detection
function_auth	API5	Broken Function Level Authorization detection
business_flow	API6	Unrestricted Access to Sensitive Business Flows detection
ssrf	API7	Server-Side Request Forgery (SSRF) detection
security_misconfig	API8	Security Misconfiguration detection
inventory	API9	Improper Inventory Management detection
unsafe_consumption	API10	Unsafe Consumption of APIs detection
```

## Running a Module

```bash
python apileaks.py owasp <key> --target URL [OPTIONS]
```

`--target` is required. The module runs only the specified OWASP module against the target — no other modules execute.

## Shared Transversal Options

Every `owasp <key>` subcommand accepts these options:

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--target`, `-t` | Target URL (required) | — | `--target https://api.example.com` |
| `--output`, `-o` | Report filename prefix | Auto-generated | `--output bola-run` |
| `--log-level` | Logging level | `WARNING` | `--log-level DEBUG` |
| `--log-file` | Log file path | Console only | `--log-file run.log` |
| `--json-logs` | Output logs in JSON format | off | `--json-logs` |
| `--rate-limit` | Requests per second | `10` | `--rate-limit 3` |
| `--timeout` | Per-request timeout in seconds (must be `> 0`) | `10` | `--timeout 30` |
| `--retries` | Retry count per failed request (must be `>= 0`) | `2` | `--retries 3` |
| `--concurrency` | Max in-flight requests (must be `>= 1`) | `50` | `--concurrency 25` |
| `--jwt` | JWT bearer token | — | `--jwt eyJ0eXAi...` |
| `--auth-context` | Authenticated identity `user:token[:privilege]`. Repeatable | — | `--auth-context alice:eyJ...:1` |
| `--proxy` | Intercepting proxy URL | — | `--proxy http://127.0.0.1:8080` |
| `--proxy-verify-ssl` | Keep TLS verification with proxy | off | `--proxy-verify-ssl` |
| `--ci-mode` | CI mode (deterministic exit codes) | off | `--ci-mode` |
| `--fail-on` | Severity gate threshold | `high` | `--fail-on critical` |
| `--sarif` | Generate SARIF 2.1.0 report | off | `--sarif` |
| `--safe-mode` | Skip state-changing probes | off | `--safe-mode` |
| `--baseline` | Baseline report path | — | `--baseline prev.json` |
| `--user-agent-random` | Random User-Agent rotation | off | `--user-agent-random` |
| `--user-agent-custom` | Fixed custom User-Agent | — | `--user-agent-custom "MyBot/1.0"` |
| `--user-agent-file` | User-Agent rotation from file | — | `--user-agent-file agents.txt` |
| `--depth` | Max recursion depth (0 = no recursion) | `3` | `--depth 2` |
| `--recursive` / `--no-recursive` | Enable/disable recursive discovery | enabled | `--no-recursive` |
| `--max-requests` | Request budget for discovery | unbounded | `--max-requests 2000` |
| `--extensions`, `-x` | Extensions appended to wordlist entries | — | `-x json,php` |
| `--recursion-status` | Restrict recursion by status class | — | `--recursion-status 2xx` |
| `--recursion-type` | Restrict recursion by endpoint type | — | `--recursion-type admin` |

User-Agent options are mutually exclusive. `--jwt` and `--basic-auth` are mutually exclusive.

## BOLA Module Options (API1)

The `bola` subcommand accepts the transversal options above plus these module-specific options:

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--allow-write-bola` | Authorize the BOLA module to issue state-changing (destructive) probes | off | `--allow-write-bola` |
| `--bola-destructive-methods` | HTTP methods treated as destructive when `--allow-write-bola` is set (comma-separated, uppercased) | `PATCH,PUT` | `--bola-destructive-methods PATCH,PUT,DELETE` |
| `--bola-composite` | Enable the composite-key BOLA probe | off | `--bola-composite` |
| `--bola-id-leakage` | Enable the object-identifier leakage probe | off | `--bola-id-leakage` |
| `--bola-verb-tampering` | Enable the HTTP verb-tampering technique | off | `--bola-verb-tampering` |
| `--bola-parameter-pollution` | Enable the HTTP parameter-pollution technique | off | `--bola-parameter-pollution` |
| `--bola-dry-run` | Plan destructive probes without issuing them | off | `--bola-dry-run` |

Without `--allow-write-bola`, the BOLA module runs read-only probes only. Destructive options (`--bola-destructive-methods`) are ignored without it.

## Auth Module Options (API2)

The `auth` subcommand accepts the transversal options above plus these module-specific options:

### JWT Module Tests (key material)

| Option | Description | Example |
|--------|-------------|---------|
| `--public-key` | RSA public key (PEM/DER file path or inline PEM) for the algorithm-confusion test | `--public-key idp_pub.pem` |
| `--jwks-url` | JWKS endpoint URL to fetch public key material | `--jwks-url https://idp.example.com/.well-known/jwks.json` |
| `--signing-secret` | Known HMAC secret for the expired-token-acceptance test | `--signing-secret mysecret` |

### Advanced Auth Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--allow-aggressive-auth` | Enable high-volume/concurrency probes (anti-automation burst, token-revocation race) | off | `--allow-aggressive-auth` |
| `--auth-rate-limit-attempts` | Login attempts for the rate-limit probe (requires `--allow-aggressive-auth`) | `10` | `--auth-rate-limit-attempts 15` |
| `--auth-revocation-race-requests` | Concurrent requests for the revocation-race probe (requires `--allow-aggressive-auth`) | `8` | `--auth-revocation-race-requests 10` |
| `--auth-benign-username` | Benign account username for the anti-automation probe | — | `--auth-benign-username testuser` |
| `--mfa-provisional-token` | Provisional token before the MFA step (requires `--mfa-protected-endpoint`) | — | `--mfa-provisional-token tok_abc` |
| `--mfa-protected-endpoint` | Endpoint targeted by the MFA-bypass probe (requires `--mfa-provisional-token`) | — | `--mfa-protected-endpoint https://api.example.com/dashboard` |
| `--oauth-authorize-url` | OAuth authorization endpoint URL | — | `--oauth-authorize-url https://auth.example.com/authorize` |
| `--oauth-attacker-redirect` | Attacker-controlled Redirect_URI | — | `--oauth-attacker-redirect https://attacker.example.com/cb` |
| `--oauth-foreign-aud-token` | Token issued for a different application (audience-confusion probe) | — | `--oauth-foreign-aud-token eyJ0eXAi...` |
| `--reset-token-sample` | Observed password-reset token to analyze for predictability. Repeatable | — | `--reset-token-sample tok1 --reset-token-sample tok2` |
| `--reset-token-known-input` | Known input for hash-of-known-input classification. Repeatable | — | `--reset-token-known-input user@example.com` |

When none of the aggressive or input-driven options are supplied, those probes are skipped. The auth module's safe defaults never issue destructive, high-volume, or account-dependent probes without explicit opt-in.

## Module Reference

### API1 — `bola` (Broken Object Level Authorization)

Detects unauthorized access to objects belonging to other users: sequential/GUID ID enumeration, horizontal privilege escalation, anonymous object access, cross-user object leakage.

```bash
python apileaks.py owasp bola --target https://api.example.com
```

For the full `bola` guide, see [BOLA Testing (API1)](owasp/bola-testing.md).

### API2 — `auth` (Broken Authentication)

Detects weak JWT algorithms (alg:none, algorithm confusion), expired tokens accepted by the server, weak HMAC secrets, missing authentication on protected endpoints, MFA bypass, OAuth flow abuse, and predictable password-reset tokens.

```bash
python apileaks.py owasp auth --target https://api.example.com
```

> For manual JWT attacks and utilities, use the `jwt` command group (`apileaks jwt --help`).

### API3 — `property` (Broken Object Property Level Authorization)

Detects exposure of sensitive fields (passwords, API keys, SSNs), mass assignment vulnerabilities, undocumented fields in responses, and modifiable read-only properties.

```bash
python apileaks.py owasp property --target https://api.example.com
```

For the full `property` guide, see [Property Level Auth (API3)](owasp/property-level-auth.md).

### API4 — `resource` (Unrestricted Resource Consumption)

Detects missing rate limiting, acceptance of oversized payloads, deeply nested JSON, ReDoS-susceptible patterns, and complex query processing without resource guards.

```bash
python apileaks.py owasp resource --target https://api.example.com
```

### API5 — `function_auth` (Broken Function Level Authorization)

Detects unauthorized access to administrative functions, HTTP method bypass, parameter/header bypass, and vertical privilege escalation.

```bash
python apileaks.py owasp function_auth --target https://api.example.com
```

### API6 — `business_flow` (Unrestricted Access to Sensitive Business Flows)

Detects business logic bypass and workflow manipulation that allow excessive or unauthorized use of sensitive operations.

```bash
python apileaks.py owasp business_flow --target https://api.example.com
```

### API7 — `ssrf` (Server-Side Request Forgery)

Detects SSRF vectors: internal network access, cloud metadata endpoint access (`169.254.169.254`), and file-protocol abuse.

```bash
python apileaks.py owasp ssrf --target https://api.example.com
```

### API8 — `security_misconfig` (Security Misconfiguration)

Detects misconfigured CORS policies, missing or weak security headers, and insecure framework defaults.

```bash
python apileaks.py owasp security_misconfig --target https://api.example.com
```

### API9 — `inventory` (Improper Inventory Management)

Detects deprecated/undocumented API versions, shadow endpoints not referenced in official specs, and documentation gaps.

```bash
python apileaks.py owasp inventory --target https://api.example.com
```

### API10 — `unsafe_consumption` (Unsafe Consumption of APIs)

Detects vulnerabilities in how the API consumes third-party services: insufficient data validation from external sources and insecure trust boundaries.

```bash
python apileaks.py owasp unsafe_consumption --target https://api.example.com
```

## Examples

### Basic isolated module runs

```bash
# List all modules
python apileaks.py owasp

# Run BOLA (API1)
python apileaks.py owasp bola --target https://api.example.com

# Run Auth (API2) with a JWT
python apileaks.py owasp auth \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Run SSRF (API7)
python apileaks.py owasp ssrf --target https://api.example.com

# Run Security Misconfiguration (API8)
python apileaks.py owasp security_misconfig --target https://api.example.com

# Run Resource Consumption (API4)
python apileaks.py owasp resource --target https://api.example.com --rate-limit 5
```

### BOLA with advanced probes

```bash
# Read-only BOLA with multi-user contexts
python apileaks.py owasp bola \
  --target https://api.example.com \
  --auth-context alice:eyJ...:1 \
  --auth-context bob:eyJ...:1

# BOLA with composite key and verb-tampering (read-only)
python apileaks.py owasp bola \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --bola-composite \
  --bola-verb-tampering \
  --bola-id-leakage

# BOLA with destructive probes (dry-run first)
python apileaks.py owasp bola \
  --target https://api.example.com \
  --allow-write-bola \
  --bola-destructive-methods PATCH,PUT,DELETE \
  --bola-dry-run

# BOLA full destructive run (after reviewing dry-run output)
python apileaks.py owasp bola \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --allow-write-bola \
  --bola-destructive-methods PATCH,PUT,DELETE \
  --bola-composite \
  --bola-parameter-pollution
```

### Auth with key material

```bash
# Algorithm-confusion test with a PEM public key file
python apileaks.py owasp auth \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --public-key ./idp_public.pem

# Auth with JWKS endpoint
python apileaks.py owasp auth \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --jwks-url https://idp.example.com/.well-known/jwks.json

# Expired-token acceptance test
python apileaks.py owasp auth \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --signing-secret 'hs256secret'

# MFA bypass probe
python apileaks.py owasp auth \
  --target https://api.example.com \
  --mfa-provisional-token tok_provisional_abc123 \
  --mfa-protected-endpoint https://api.example.com/dashboard

# OAuth abuse
python apileaks.py owasp auth \
  --target https://api.example.com \
  --oauth-authorize-url https://auth.example.com/authorize \
  --oauth-attacker-redirect https://attacker.example.com/cb \
  --oauth-foreign-aud-token eyJ0eXAiOiJKV1Q...

# Reset token predictability analysis
python apileaks.py owasp auth \
  --target https://api.example.com \
  --reset-token-sample tok_abc123 \
  --reset-token-sample tok_def456 \
  --reset-token-known-input "user@example.com"

# Aggressive probes (anti-automation burst + revocation race)
python apileaks.py owasp auth \
  --target https://api.example.com \
  --allow-aggressive-auth \
  --auth-benign-username testuser \
  --auth-rate-limit-attempts 15 \
  --auth-revocation-race-requests 10
```

### Combining options

```bash
# Full auth module coverage
python apileaks.py owasp auth \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --public-key ./idp_pub.pem \
  --signing-secret 'fallback_secret' \
  --rate-limit 3 \
  --timeout 20 \
  --safe-mode \
  --output auth-audit

# Module run through a proxy
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --proxy http://127.0.0.1:8080 \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# CI-gated isolated module run
python apileaks.py owasp bola \
  --target https://api.example.com \
  --jwt "${JWT_TOKEN}" \
  --ci-mode \
  --fail-on high \
  --no-banner
```

---

See also: [Scan Guide](scan-guide.md) · [OWASP Coverage](owasp/README.md) · [BOLA Testing](owasp/bola-testing.md) · [JWT Attacks](jwt-attacks.md) · [CLI Reference](cli-reference.md)
