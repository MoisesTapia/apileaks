# OWASP Command Reference

The `owasp` command group lets you run **exactly one OWASP module in isolation** against a target. It is the right tool for focused red-team work on a single vulnerability class. For a full orchestrated run across all modules (or a subset), use [`scan`](scan-guide.md).

## Table of Contents

- [Overview](#overview)
- [Listing Modules](#listing-modules)
- [Running a Module](#running-a-module)
- [Shared Transversal Options](#shared-transversal-options)
- [BOLA Module Options (API1)](#bola-module-options-api1)
- [Auth Module Options (API2)](#auth-module-options-api2)
- [Property Level Auth Module Options (API3)](#property-level-auth-module-options-api3)
- [Resource Consumption Module Options (API4)](#resource-consumption-module-options-api4)
- [Function Level Auth Module Options (API5)](#function-level-auth-module-options-api5)
- [Business Flow Module Options (API6)](#business-flow-module-options-api6)
- [SSRF Module Options (API7)](#ssrf-module-options-api7)
- [Security Misconfiguration Module Options (API8)](#security-misconfiguration-module-options-api8)
- [Inventory Management Module Options (API9)](#inventory-management-module-options-api9)
- [Unsafe Consumption Module Options (API10)](#unsafe-consumption-module-options-api10)
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

## Function Level Auth Module Options (API5)

The `function_auth` subcommand accepts the transversal options above plus these module-specific options. For the full guide, see [Function Level Authorization Testing (API5)](owasp/function-level-auth.md).

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--bfla-admin-endpoints PATH` | URL path prefix identifying an admin endpoint (repeatable). Replaces the built-in list when any value is supplied. | `/admin`, `/api/admin`, `/management`, `/dashboard` | `--bfla-admin-endpoints /backstage` |
| `--bfla-dangerous-methods METHODS` | Comma-separated HTTP methods for L2a verb-tampering probes | `DELETE,PUT,PATCH` | `--bfla-dangerous-methods DELETE,PUT,PATCH,POST` |
| `--bfla-role-fields FIELD` | JSON body field name for L3 mass-assignment injection (repeatable). Replaces built-in list when any value supplied. | `role`, `is_admin`, `admin`, … | `--bfla-role-fields account_type` |
| `--bfla-role-values VALUE` | Role value to inject in L3 probes (repeatable). Replaces built-in list when any value supplied. | `admin`, `administrator`, `root`, … | `--bfla-role-values superuser` |
| `--bfla-api-versions VERSIONS` | Comma-separated API version strings for L4 version-downgrade probes | `v0,v1,v2,v3,v4` | `--bfla-api-versions v1,v2,v3` |
| `--bfla-output-file PATH` | JSON file where the full BFLA probe matrix is persisted | — | `--bfla-output-file /tmp/bfla.json` |
| `--allow-destructive-bfla` | Allow state-changing (DELETE/PUT) replay probes against admin endpoints | off | `--allow-destructive-bfla` |

The grey-box approach requires at least two `--auth-context` values at different privilege levels: one at 100 (admin) for the mapping phase and one at a lower level (e.g. 1) for replay. If only one context is supplied, only anonymous replay runs.

## Business Flow Module Options (API6)

The `business_flow` subcommand accepts the transversal options above plus these module-specific options. For the full guide, see [Business Flows Testing (API6)](owasp/business-flows.md).

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--flow-patterns PATTERN` | URL substring identifying a sensitive flow endpoint (repeatable). Replaces the built-in list when any value is supplied. | `/checkout`, `/purchase`, `/transfer`, etc. | `--flow-patterns /buy` |
| `--flow-repetitions N` | Number of times to repeat each sensitive-flow request | `50` | `--flow-repetitions 100` |
| `--flow-check-quota` / `--no-flow-check-quota` | Enable or disable the quota / resource-decrement detector | enabled | `--no-flow-check-quota` |
| `--flow-quota-fields FIELD` | JSON response field to watch for quota decrement (repeatable). Replaces the built-in list when any value is supplied. | `stock`, `remaining`, `seats`, etc. | `--flow-quota-fields ticketsLeft` |
| `--flow-delay-ms MS` | Delay in milliseconds between repeated flow requests | `0` | `--flow-delay-ms 1100` |

Multi-step flow sequences (Detector 3) are configured in YAML only — the CLI does not accept inline step definitions.

## SSRF Module Options (API7)

The `ssrf` subcommand accepts the transversal options above plus these module-specific options. For the full SSRF guide, see [SSRF Testing (API7)](owasp/ssrf-testing.md).

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--openapi` | OpenAPI/Swagger spec that seeds the scan with known endpoints (repeatable) | — | `--openapi /tmp/spec.json` |
| `--postman` | Postman collection as endpoint seed source (repeatable) | — | `--postman /tmp/collection.json` |
| `--ssrf-callback-url` | OOB listener URL for blind SSRF detection | — | `--ssrf-callback-url https://xyz.interact.sh` |
| `--ssrf-internal-targets` | Additional internal host/IP to probe (repeatable) | — | `--ssrf-internal-targets 10.0.0.1` |
| `--ssrf-schemes` | Additional URL scheme to test (repeatable) | — | `--ssrf-schemes gopher://` |
| `--ssrf-scan-ports` | Comma-separated ports for internal port scanning (requires `--allow-aggressive-ssrf`) | — | `--ssrf-scan-ports 22,80,443,8080` |
| `--ssrf-body-injection` | Enable SSRF payload injection into JSON body fields on POST/PUT/PATCH | off | `--ssrf-body-injection` |
| `--ssrf-body-methods` | HTTP methods for body injection probes, overriding discovery (implies `--ssrf-body-injection`) | — | `--ssrf-body-methods POST,PUT,PATCH` |
| `--ssrf-body-field` | Explicit JSON body field to always probe (repeatable, additive) | — | `--ssrf-body-field imageUrl` |
| `--burp-xml` | Path to a Burp Suite Proxy History XML export (Full Replay Mode) | — | `--burp-xml ~/burp.xml` |
| `--har` | Path to a HAR JSON file (Burp, Caido, Chrome DevTools, Firefox) (Full Replay Mode) | — | `--har ~/traffic.har` |
| `--allow-aggressive-ssrf` | Enable port scanning and redirect-chain probes | off | `--allow-aggressive-ssrf` |
| `--ssrf-require-signature` | Only emit a finding when a known internal-target signature is matched in the response body | off | `--ssrf-require-signature` |
| `--ssrf-match-status` | Comma-separated HTTP status codes that count as a success hit | — | `--ssrf-match-status 200,301` |

## Unsafe Consumption Module Options (API10)

The `unsafe_consumption` subcommand accepts the transversal options above plus these module-specific options. For the full guide, see [Unsafe Consumption Testing (API10)](owasp/unsafe-consumption.md).

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--unsafe-upstream-indicators` | Keyword used to identify upstream-sourced endpoints (repeatable). Replaces the built-in list when any value is supplied. | `proxy, upstream, external, aggregate` | `--unsafe-upstream-indicators fetch` |
| `--unsafe-payloads` | Malformed payload to inject into upstream-sourced endpoints (repeatable). Replaces the built-in list when any value is supplied. | XSS, SQLi, prototype-pollution, null-byte | `--unsafe-payloads "<script>"` |
| `--unsafe-check-redirects` / `--no-unsafe-check-redirects` | Enable or disable the blind-redirect-following detector | enabled | `--no-unsafe-check-redirects` |
| `--unsafe-redirect-url` | URL injected as the redirect probe target. Use an OOB listener in production. | `http://169.254.169.254/latest/meta-data/` | `--unsafe-redirect-url https://xyz.interact.sh` |
| `--unsafe-check-cleartext` / `--no-unsafe-check-cleartext` | Enable or disable the cleartext-upstream-channel detector | enabled | `--no-unsafe-check-cleartext` |

When none of the `--unsafe-upstream-indicators` values are supplied, the module uses its built-in list (`proxy`, `upstream`, `external`, `aggregate`). When at least one value is supplied, the built-in list is replaced entirely — include every keyword you need. The same replacement behavior applies to `--unsafe-payloads`.

## Property Level Auth Module Options (API3)

The `property` subcommand accepts the transversal options above plus these module-specific options. For the full guide, see [Property Level Authorization Testing (API3)](owasp/property-level-auth.md).

| Option | Description | Default |
|--------|-------------|---------|
| `--property-sensitive-fields FIELD` | Field name considered sensitive in API responses (repeatable). Replaces the built-in list when any value is supplied. | `password`, `api_key`, `secret`, `token`, `ssn`, `credit_card` |
| `--property-mass-assignment-fields FIELD` | Dangerous field name for mass-assignment probes (repeatable). Replaces the built-in list when any value is supplied. | `is_admin`, `role`, `permissions`, `user_id` |

## Resource Consumption Module Options (API4)

The `resource` subcommand accepts the transversal options above plus these module-specific options. For the full guide, see [Resource Consumption Testing (API4)](owasp/resource-consumption.md).

| Option | Description | Default |
|--------|-------------|---------|
| `--resource-burst-size N` | Concurrent requests in the rate-limit burst test | `100` |
| `--resource-payload-sizes BYTES` | Comma-separated payload sizes in bytes for the large-payload test | `1048576,10485760` |
| `--resource-json-depth N` | JSON nesting depth for the deep-nesting probe | `1000` |

## Security Misconfiguration Module Options (API8)

The `security_misconfig` subcommand accepts the transversal options above plus this option. For the full guide, see [Security Misconfiguration Testing (API8)](owasp/security-misconfiguration.md).

| Option | Description | Default |
|--------|-------------|---------|
| `--misconfig-required-headers HEADER` | HTTP response header that must be present (repeatable). Replaces the built-in list when any value is supplied. | `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` |

## Inventory Management Module Options (API9)

The `inventory` subcommand accepts the transversal options above plus this option. For the full guide, see [Inventory Management Testing (API9)](owasp/inventory-management.md).

| Option | Description | Default |
|--------|-------------|---------|
| `--inventory-detect-deprecated` / `--no-inventory-detect-deprecated` | Enable or disable detection of deprecated API versions | enabled |

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

Detects mass assignment, sensitive field exposure (passwords, API keys, SSNs), read-only property modification, and undocumented field discovery across auth contexts. Configurable sensitive-field and mass-assignment-field lists.

```bash
python apileaks.py owasp property \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1
```

For the full guide, see [Property Level Authorization Testing (API3)](owasp/property-level-auth.md).

### API4 — `resource` (Unrestricted Resource Consumption)

Detects rate-limit absence (burst test), oversized payload acceptance, deeply nested JSON, ReDoS-susceptible patterns, and complex queries. Configurable burst size, payload sizes, and nesting depth.

```bash
python apileaks.py owasp resource --target https://api.example.com
```

For the full guide, see [Resource Consumption Testing (API4)](owasp/resource-consumption.md).

### API5 — `function_auth` (Broken Function Level Authorization)

Detects unauthorized access to administrative functions via four attack levels: multi-token matrix replay (L1), HTTP verb tampering and method-override header bypass (L2), mass-assignment role injection in registration flows (L3), and API version downgrade to unpatched older versions (L4).

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1
```

For the full `function_auth` guide, see [Function Level Authorization Testing (API5)](owasp/function-level-auth.md).

### API6 — `business_flow` (Unrestricted Access to Sensitive Business Flows)

Detects missing rate limiting on sensitive flows (checkout, purchase, transfer, booking, referral…), inventory/quota not enforced server-side, and multi-step business transactions that can be repeated end-to-end without any control.

```bash
python apileaks.py owasp business_flow --target https://api.example.com
```

For the full guide, see [Business Flows Testing (API6)](owasp/business-flows.md).

### API7 — `ssrf` (Server-Side Request Forgery)

Detects SSRF vectors: internal network access, cloud metadata endpoint access (`169.254.169.254`), and file-protocol abuse.

```bash
python apileaks.py owasp ssrf --target https://api.example.com
```

### API8 — `security_misconfig` (Security Misconfiguration)

Detects permissive CORS policies (wildcard origins, credentials+wildcard) and missing required security headers. Read-only probes — inherently Safe Mode compatible. Configurable required-header list.

```bash
python apileaks.py owasp security_misconfig --target https://api.example.com
```

For the full guide, see [Security Misconfiguration Testing (API8)](owasp/security-misconfiguration.md).

### API9 — `inventory` (Improper Inventory Management)

Detects deprecated, undocumented (dev/beta), and non-current API versions accessible in production. Configurable deprecated-detection toggle.

```bash
python apileaks.py owasp inventory --target https://api.example.com
```

For the full guide, see [Inventory Management Testing (API9)](owasp/inventory-management.md).

### API10 — `unsafe_consumption` (Unsafe Consumption of APIs)

Detects vulnerabilities in how the API consumes third-party services: unvalidated data reflection, blind redirect following, and cleartext upstream channels.

```bash
python apileaks.py owasp unsafe_consumption --target https://api.example.com
```

For the full `unsafe_consumption` guide, see [Unsafe Consumption Testing (API10)](owasp/unsafe-consumption.md).

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

### Function Level Auth / BFLA (API5)

```bash
# Two-token grey-box scan — all four attack levels
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1

# Explicit admin endpoints + verb tampering with POST included
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-admin-endpoints /api/v3/admin \
  --bfla-admin-endpoints /management/users \
  --bfla-dangerous-methods DELETE,PUT,PATCH,POST

# Custom role fields and values for a specific application
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context user:USER_TOKEN:1 \
  --bfla-role-fields account_type \
  --bfla-role-fields tier \
  --bfla-role-values enterprise \
  --bfla-role-values superuser

# Persist probe matrix for downstream chained attacks
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-output-file /tmp/bfla-matrix.json

# Version downgrade with explicit version list
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-api-versions v1,v2,v3,v4,v5

# Destructive replay opt-in
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --allow-destructive-bfla

# Safe mode — GET-only probes
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --safe-mode

# CI-gated run
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:${ADMIN_TOKEN}:100 \
  --auth-context user:${USER_TOKEN}:1 \
  --ci-mode \
  --fail-on critical \
  --no-banner
```

### Business Flows (API6)

```bash
# Basic scan — all three detectors with built-in defaults
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom patterns for a ticketing platform
python apileaks.py owasp business_flow \
  --target https://tickets.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --flow-patterns /buy-ticket \
  --flow-patterns /reserve-seat \
  --flow-patterns /apply-promo

# High-repetition run for more conclusive evidence
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --flow-repetitions 200

# Custom quota fields for a fintech API
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-quota-fields balance \
  --flow-quota-fields creditsRemaining \
  --flow-quota-fields transactionLimit

# Detect time-window controls with delay between requests
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-repetitions 10 \
  --flow-delay-ms 1100

# Rate-limit check only — skip quota decrement detector
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --no-flow-check-quota

# Safe mode — GET endpoints only
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --safe-mode

# CI-gated run
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "${JWT_TOKEN}" \
  --ci-mode \
  --fail-on high \
  --no-banner
```

### Unsafe Consumption (API10)

```bash
# Basic scan — all three detectors with built-in defaults
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom upstream indicators matching your target's naming conventions
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --unsafe-upstream-indicators fetch \
  --unsafe-upstream-indicators webhook \
  --unsafe-upstream-indicators "third-party" \
  --unsafe-upstream-indicators import

# Custom injection payloads for a known template-injection surface
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-upstream-indicators proxy \
  --unsafe-payloads "{{7*7}}" \
  --unsafe-payloads "{{config.items()}}" \
  --unsafe-payloads "<%= 7*7 %>"

# Blind redirect with OOB listener (production-grade)
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --unsafe-check-redirects \
  --unsafe-redirect-url "https://xyz.interact.sh"

# Reflection + cleartext only (skip redirect probe)
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --no-unsafe-check-redirects

# Safe mode — query params only, no state-changing probes
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --safe-mode

# Full red-team run: custom indicators + payloads + OOB redirect + cleartext
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --unsafe-upstream-indicators proxy \
  --unsafe-upstream-indicators aggregate \
  --unsafe-upstream-indicators fetch \
  --unsafe-payloads "<script>alert(1)</script>" \
  --unsafe-payloads "' OR 1=1--" \
  --unsafe-payloads '{"__proto__":{"polluted":true}}' \
  --unsafe-check-redirects \
  --unsafe-redirect-url "https://xyz.interact.sh" \
  --unsafe-check-cleartext \
  --rate-limit 5 \
  --output api10-report

# CI-gated run — fail pipeline on HIGH or above
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "${JWT_TOKEN}" \
  --ci-mode \
  --fail-on high \
  --no-banner
```

---

See also: [Scan Guide](scan-guide.md) · [OWASP Coverage](owasp/README.md) · [BOLA Testing](owasp/bola-testing.md) · [SSRF Testing](owasp/ssrf-testing.md) · [Unsafe Consumption Testing](owasp/unsafe-consumption.md) · [JWT Attacks](jwt-attacks.md) · [CLI Reference](cli-reference.md)
