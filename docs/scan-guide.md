# Scan Guide — Orchestrated OWASP Assessment

`scan` is APILeak's primary command. It runs endpoint discovery and then executes all ten registered OWASP API Security Top 10 modules by default, aggregating every finding through the unified reporting pipeline and driving the CI/CD severity gate.

Use [`owasp <key>`](owasp-command.md) to run a single module in isolation.

## Table of Contents

- [Overview](#overview)
- [Syntax](#syntax)
- [Required Options](#required-options)
- [Configuration](#configuration)
- [Module Selection](#module-selection)
- [Discovery Control](#discovery-control)
- [Advanced Discovery Features](#advanced-discovery-features)
- [Authentication Options](#authentication-options)
- [BOLA Module Options](#bola-module-options)
- [Auth Module Options](#auth-module-options)
- [Spec-Driven Testing](#spec-driven-testing)
- [Multi-User Testing](#multi-user-testing)
- [CI/CD Integration](#cicd-integration)
- [General Options](#general-options)
- [Basic Examples](#basic-examples)
- [Intermediate Examples](#intermediate-examples)
- [Advanced Examples](#advanced-examples)
- [Exit Codes](#exit-codes)

## Overview

A plain `scan` invocation:

1. Runs endpoint discovery against the target (same engine as `dir`)
2. Executes all ten registered OWASP modules by default
3. Aggregates all findings into one report
4. Evaluates the CI/CD severity gate (when `--ci-mode` is set)

`full` and `main` are deprecated hidden aliases of `scan`. They still work but emit a one-line deprecation notice to stderr. Migrate scripts to `scan`.

## Syntax

```bash
python apileaks.py scan [OPTIONS]
```

## Required Options

`--target` is required unless you pass `--config` with a config file that contains the target URL.

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan | `--target https://api.example.com` |

## Configuration

| Option | Description | Example |
|--------|-------------|---------|
| `--config`, `-c` | YAML or JSON config file path (optional; overrides built-in defaults for any key it sets) | `--config config/api.yaml` |

When `--config` is supplied and also `--target`, the CLI target wins over the config's `base_url`.

## Module Selection

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--modules` | Comma-separated list of OWASP module keys to run | All ten modules | `--modules bola,auth,property` |

The `APILEAK_MODULES` environment variable is the fallback when `--modules` is not supplied. If neither is set, all ten modules run.

**Available module keys** (in OWASP category order):

| Key | OWASP | Summary |
|-----|-------|---------|
| `bola` | API1 | Broken Object Level Authorization (BOLA) detection |
| `auth` | API2 | Broken Authentication detection |
| `property` | API3 | Broken Object Property Level Authorization detection |
| `resource` | API4 | Unrestricted Resource Consumption detection |
| `function_auth` | API5 | Broken Function Level Authorization detection |
| `business_flow` | API6 | Unrestricted Access to Sensitive Business Flows detection |
| `ssrf` | API7 | Server-Side Request Forgery (SSRF) detection |
| `security_misconfig` | API8 | Security Misconfiguration detection |
| `inventory` | API9 | Improper Inventory Management detection |
| `unsafe_consumption` | API10 | Unsafe Consumption of APIs detection |

An unrecognized key aborts with a descriptive error before any module runs.

## Discovery Control

These options tune the endpoint discovery phase that runs before the OWASP modules.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--depth` | Max recursion depth (`0` = depth-0 pass only, no recursion) | `3` (or `APILEAK_MAX_DEPTH` env var) | `--depth 5` |
| `--recursive` / `--no-recursive` | Enable or disable recursive discovery | enabled | `--no-recursive` |
| `--max-requests` | Global request budget for discovery | unbounded | `--max-requests 5000` |
| `--concurrency` | Max concurrent in-flight requests | `50` | `--concurrency 100` |
| `--timeout` | Per-request timeout in seconds (must be `> 0`) | `10` | `--timeout 30` |
| `--retries` | Automatic retries per failed request (must be `>= 0`) | `2` | `--retries 5` |
| `--extensions`, `-x` | File extensions appended to each wordlist entry (comma-separated, repeatable) | — | `-x json,php` |
| `--recursion-status` | Restrict recursion to endpoints in these status classes (comma-separated: `2xx,3xx`) | — | `--recursion-status 2xx,3xx` |
| `--recursion-type` | Restrict recursion to endpoints of these types (comma-separated: `admin,api_version`) | — | `--recursion-type admin` |

**Depth precedence:** explicit `--depth` > `APILEAK_MAX_DEPTH` env var > built-in default of `3`.

## `--fuzz-versions` vs the `inventory` module — when to use each

Both options use the same `VersionFuzzer` internally, but they do different things:

| | `--fuzz-versions` | `inventory` module (API9) |
|---|---|---|
| **Phase** | `advanced_discovery` (before OWASP modules) | `owasp_testing` |
| **Input** | Target URL directly | Endpoints already discovered by the discovery phase |
| **Output** | One `API_VERSION_FOUND` finding per accessible version, severity `INFO` | `DEPRECATED_API_VERSION`, `UNDOCUMENTED_API_VERSION`, `NON_CURRENT_API_VERSION`, severity `LOW` with semantic analysis |
| **Detects deprecated/shadow versions** | ❌ Only reports that a version exists | ✅ Reads `Deprecation:`/`Sunset:` headers, `410` status, body indicators |
| **Determines current version** | ❌ | ✅ Compares versions and flags non-current ones |

**⚠️ Double execution:** if you use `--fuzz-versions` and the `inventory` module is active (the default in `scan`), the `VersionFuzzer` runs **twice** against the same host — first in `advanced_discovery`, then in `owasp_testing`. The outputs are different but the HTTP requests are identical. To avoid duplicate requests, use one or the other:
- `inventory` only (default in `scan`): full API9 analysis, no extra requests
- `--fuzz-versions` without `inventory`: fast reconnaissance with INFO severity, no semantic classification — exclude `inventory` with `--modules bola,auth,...`

See the [full dir vs scan vs inventory analysis](dir-vs-scan-vs-inventory.md).

## Advanced Discovery Features

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Detect the backend framework (FastAPI, Django, Flask, Express, etc.) during discovery | off | `--detect-framework` |
| `--fuzz-versions`, `--fv` | Enumerate API versions (`/v1`, `/v2`, `/api/v1`, etc.) during discovery | off | `--fuzz-versions` |
| `--framework-confidence` | Minimum confidence for framework detection (0.0–1.0) | `0.6` | `--framework-confidence 0.8` |
| `--version-patterns` | Custom version patterns for fuzzing (comma-separated) | Built-in patterns | `--version-patterns /v1,/v2,/api/v1` |
| `--enable-advanced` | Enable all advanced features in one flag (framework detection, version fuzzing, subdomain discovery, CORS analysis) | off | `--enable-advanced` |
| `--enable-payload-encoding` | Enable advanced payload encoding and obfuscation techniques | off | `--enable-payload-encoding` |
| `--enable-waf-evasion` | Enable WAF detection and evasion techniques | off | `--enable-waf-evasion` |
| `--enable-subdomain-discovery` | Enable subdomain discovery and testing | off | `--enable-subdomain-discovery` |
| `--enable-cors-analysis` | Enable CORS policy analysis and security headers testing | off | `--enable-cors-analysis` |

`--enable-advanced` is equivalent to enabling `--detect-framework`, `--fuzz-versions`, `--enable-payload-encoding`, `--enable-waf-evasion`, `--enable-subdomain-discovery`, and `--enable-cors-analysis` at once.

## Authentication Options

| Option | Description | Example |
|--------|-------------|---------|
| `--jwt` | JWT bearer token applied to every request | `--jwt eyJ0eXAiOiJKV1Q...` |
| `--auth-context` | Authenticated identity as `user:token[:privilege]`. Repeatable — pass once per user for multi-user authorization tests | `--auth-context alice:eyJ...:1 --auth-context bob:eyJ...:2` |
| `--proxy` | Route all traffic through an intercepting proxy (HTTP or SOCKS5). TLS verification is auto-disabled while proxying | `--proxy http://127.0.0.1:8080` |
| `--proxy-verify-ssl` | Keep TLS verification enabled when using `--proxy` (use after installing the proxy CA) | `--proxy-verify-ssl` |

`--jwt` and `--basic-auth` are mutually exclusive. `--auth-context` extends the authentication context list instead of replacing `--jwt`.

## BOLA Module Options

These options are specific to the `bola` module and only take effect when `bola` is in the selected module set.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--allow-write-bola` | Authorize the BOLA module to issue state-changing (destructive) probes | off | `--allow-write-bola` |
| `--bola-destructive-methods` | HTTP methods treated as destructive when `--allow-write-bola` is set | `PATCH,PUT` | `--bola-destructive-methods PATCH,PUT,DELETE` |
| `--bola-composite` | Enable the composite-key BOLA probe | off | `--bola-composite` |
| `--bola-id-leakage` | Enable the object-identifier leakage BOLA probe | off | `--bola-id-leakage` |
| `--bola-verb-tampering` | Enable the HTTP verb-tampering BOLA technique | off | `--bola-verb-tampering` |
| `--bola-parameter-pollution` | Enable the HTTP parameter-pollution BOLA technique | off | `--bola-parameter-pollution` |
| `--bola-dry-run` | Plan destructive BOLA probes without issuing them | off | `--bola-dry-run` |

By default (without `--allow-write-bola`) the BOLA module only issues safe-method (read-only) probes.

## Auth Module Options

These options are specific to the `auth` module. They only take effect when `auth` is in the selected module set.

### JWT Module Tests (cryptographic key material)

| Option | Description | Example |
|--------|-------------|---------|
| `--public-key` | RSA public key material (PEM/DER file path or inline PEM) for the algorithm-confusion test | `--public-key server_pub.pem` |
| `--jwks-url` | JWKS endpoint URL to fetch public key material when `--public-key` is not supplied | `--jwks-url https://idp.example.com/.well-known/jwks.json` |
| `--signing-secret` | Known HMAC signing secret for the expired-token-acceptance test | `--signing-secret 's3cr3t'` |

### Advanced Auth Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--allow-aggressive-auth` | Authorize high-volume/concurrency probes (anti-automation burst, token-revocation race) | off | `--allow-aggressive-auth` |
| `--auth-rate-limit-attempts` | Login attempts for the anti-automation probe (requires `--allow-aggressive-auth`) | `10` | `--auth-rate-limit-attempts 20` |
| `--auth-revocation-race-requests` | Concurrent requests for the token-revocation race probe (requires `--allow-aggressive-auth`) | `8` | `--auth-revocation-race-requests 12` |
| `--auth-benign-username` | Benign account username for the anti-automation probe | — | `--auth-benign-username testuser` |
| `--mfa-provisional-token` | Provisional token issued before the MFA step (requires `--mfa-protected-endpoint`) | — | `--mfa-provisional-token tok_abc123` |
| `--mfa-protected-endpoint` | Endpoint targeted by the MFA-bypass probe (requires `--mfa-provisional-token`) | — | `--mfa-protected-endpoint https://api.example.com/dashboard` |
| `--oauth-authorize-url` | OAuth authorization endpoint URL for OAuth-flow abuse probes | — | `--oauth-authorize-url https://auth.example.com/authorize` |
| `--oauth-attacker-redirect` | Attacker-controlled Redirect_URI for the redirect-URI manipulation probe | — | `--oauth-attacker-redirect https://attacker.example.com/cb` |
| `--oauth-foreign-aud-token` | Token issued for a different application (audience-confusion probe) | — | `--oauth-foreign-aud-token eyJ0eXAi...` |
| `--reset-token-sample` | Observed password-reset token to analyze for predictability. Repeatable | — | `--reset-token-sample tok1 --reset-token-sample tok2` |
| `--reset-token-known-input` | Known input (e.g. account email) for hash-of-known-input classification. Repeatable | — | `--reset-token-known-input user@example.com` |

## Spec-Driven Testing

Supply OpenAPI/Swagger or Postman specs so the OWASP modules test declared operations in addition to discovered endpoints.

| Option | Description | Example |
|--------|-------------|---------|
| `--openapi` | OpenAPI/Swagger document (JSON or YAML). Repeatable | `--openapi api.yaml` |
| `--postman` | Postman collection (JSON). Repeatable | `--postman collection.json` |

A spec source that cannot be read or parsed aborts before any request is issued.

## Multi-User Testing

| Option | Description | Example |
|--------|-------------|---------|
| `--actor-profile` | Actor profile source (JSON or YAML) supplying per-identity typed query/body values keyed by context name and endpoint | `--actor-profile profiles/actors.yaml` |
| `--unauthorized-assertions` | Unauthorized endpoint assertion source (JSON or YAML) mapping each context name to endpoint pattern regexes that should be forbidden for that identity | `--unauthorized-assertions assertions.yaml` |

A missing, unreadable, or unparseable `--actor-profile` or `--unauthorized-assertions` source aborts before any request is issued.

## CI/CD Integration

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--ci-mode` | Enable CI mode: deterministic exit codes, artifact generation, disables interactive prompts | off | `--ci-mode` |
| `--fail-on` | Severity threshold for the CI gate: fail on findings at or above this level | `high` | `--fail-on critical` |
| `--sarif` | Generate a SARIF 2.1.0 report alongside the standard report | off | `--sarif` |
| `--safe-mode` | Non-destructive scan: skip state-changing probes (POST/PUT/PATCH/DELETE) | off | `--safe-mode` |
| `--baseline` | Path to a baseline JSON report; only findings absent from the baseline drive the gate | — | `--baseline reports/prev.json` |

**Default gate.** Without `--fail-on`, `scan` fails on `high` or `critical` findings. Use `--fail-on critical` to restore the old behavior.

**Available severity levels:** `critical`, `high`, `medium`, `low`

## General Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--output`, `-o` | Report filename prefix (saved to `reports/`) | Auto-generated | `--output my-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level INFO` |
| `--log-file` | Log file path | Console only | `--log-file scan.log` |
| `--json-logs` | Output logs in JSON format | off | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 5` |
| `--status-code` | Show only HTTP requests with specific status codes | All codes | `--status-code 200,401` |
| `--user-agent-random` | Random User-Agent per request (WAF evasion) | off | `--user-agent-random` |
| `--user-agent-custom` | Fixed custom User-Agent string | — | `--user-agent-custom "MyScanner/1.0"` |
| `--user-agent-file` | User-Agent rotation from file (one per line) | — | `--user-agent-file agents.txt` |
| `--no-banner` | Suppress banner output | off | `--no-banner` |

User-Agent options are mutually exclusive. Passing more than one aborts with an error before any request.

## Basic Examples

**1. Full scan — all modules**

```bash
python apileaks.py scan --target https://api.example.com
```

**2. Authenticated scan**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**3. Restrict to specific modules**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,auth,property
```

**4. From a config file**

```bash
python apileaks.py scan \
  --config config/production.yaml \
  --target https://api.example.com
```

**5. Adjust rate limit**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --rate-limit 3
```

## Intermediate Examples

**1. Framework detection and version fuzzing**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.8
```

**2. Recursion control**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --depth 5 \
  --max-requests 5000 \
  --concurrency 100
```

**3. Resilience tuning**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --timeout 30 \
  --retries 5 \
  -x json,php
```

**4. WAF evasion**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --user-agent-random \
  --rate-limit 2
```

**5. Route through a proxy**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,auth,ssrf \
  --proxy http://127.0.0.1:8080
```

**6. Structured logging to file**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --log-level INFO \
  --log-file scan.log \
  --json-logs
```

**7. Multi-user BOLA testing**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola \
  --auth-context alice:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig:1 \
  --auth-context bob:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.sig:1
```

**8. Spec-driven scan with OpenAPI**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --openapi openapi.yaml \
  --modules bola,auth,property
```

## Advanced Examples

**1. Enable all advanced discovery features**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --enable-advanced \
  --user-agent-random \
  --output advanced-scan
```

**2. Non-destructive scan (safe mode)**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --safe-mode \
  --modules bola,auth,security_misconfig
```

**3. CI/CD gate with SARIF output**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --ci-mode \
  --fail-on high \
  --sarif \
  --no-banner
```

**4. Baseline-gated CI/CD (only new findings fail the pipeline)**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --ci-mode \
  --fail-on medium \
  --baseline reports/previous-scan.json
```

**5. Full CI/CD: non-destructive + baseline + SARIF**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --ci-mode \
  --fail-on high \
  --safe-mode \
  --sarif \
  --baseline reports/baseline.json \
  --no-banner
```

**6. Auth module with real key material**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules auth \
  --public-key ./idp_public.pem \
  --signing-secret 's3cr3t'
```

**7. Auth module with JWKS endpoint**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules auth \
  --jwks-url https://idp.example.com/.well-known/jwks.json
```

**8. BOLA with destructive probes enabled**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola \
  --allow-write-bola \
  --bola-destructive-methods PATCH,PUT,DELETE \
  --bola-composite \
  --bola-verb-tampering \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**9. Deep discovery + full orchestrated scan**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --depth 5 \
  --max-requests 8000 \
  --concurrency 100 \
  -x json,php \
  --timeout 30 \
  --retries 5 \
  --output deep-scan
```

**10. MFA bypass and OAuth abuse testing**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules auth \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --mfa-provisional-token tok_provisional_abc123 \
  --mfa-protected-endpoint https://api.example.com/dashboard \
  --oauth-authorize-url https://auth.example.com/authorize \
  --oauth-attacker-redirect https://attacker.example.com/cb
```

**11. Multi-user with actor profiles and unauthorized assertions**

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,function_auth \
  --auth-context alice:eyJ...:1 \
  --auth-context admin:eyJ...:3 \
  --actor-profile profiles/actors.yaml \
  --unauthorized-assertions assertions/forbidden.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | High severity findings found (default gate: `high`) |
| `2` | Critical findings found |

These exit codes are deterministic and documented for CI/CD consumption. The gate is only evaluated when `--ci-mode` is set; outside CI mode the exit code is always `0` on a clean run.

---

See also: [OWASP Command Reference](owasp-command.md) · [OWASP Modules Guide](owasp-modules-guide.md) · [CLI Reference](cli-reference.md) · [CI/CD Integration](ci-cd-integration.md)
