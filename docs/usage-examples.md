# 🎯 Usage Examples

This guide provides comprehensive examples for using APILeak across different scenarios, from basic scans to advanced security testing workflows.

## Quick Start Commands

APILeak supports multiple scan modes for different use cases. Each mode is optimized for specific types of API security testing.

## Directory/Endpoint Fuzzing

Directory fuzzing helps discover hidden endpoints, administrative interfaces, and forgotten API paths.

### Basic Directory Fuzzing
```bash
# Simple directory fuzzing
python apileaks.py dir --target https://api.example.com

# With custom wordlist
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt
```

### Advanced Directory Fuzzing
```bash
# With WAF evasion and status filtering
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --status-code 200-299,401,403

# With custom user agent and multiple methods
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-custom "Mozilla/5.0 (Custom Security Scanner)" \
  --methods GET,POST,PUT,DELETE \
  --rate-limit 15

# With user agent rotation and error focus
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 500-599 \
  --output error_focused_scan

# With framework detection
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --detect-framework \
  --fuzz-versions \
  --user-agent-random \
  --output comprehensive_discovery
```

### Recursive Discovery Control

These flags keep recursive discovery agile: go shallow and fast for a quick sweep, or deep and thorough for full coverage. Discovery is always bounded by the request budget (`--max-requests`) and catch-all detection, so deep scans stay safe. The effective depth follows the precedence CLI `--depth` > `APILEAK_MAX_DEPTH` env var > default `3`.

```bash
# Shallow + fast: a quick, single-level sweep (no recursion)
python apileaks.py dir \
  --target https://api.example.com \
  --depth 1

# Disable recursion entirely (depth-0 pass only)
python apileaks.py dir \
  --target https://api.example.com \
  --no-recursive

# Deep + thorough: recurse further with a request budget as a safety net
python apileaks.py dir \
  --target https://api.example.com \
  --depth 6 \
  --max-requests 5000

# Tune concurrency for faster discovery (default is 50 in-flight requests)
python apileaks.py dir \
  --target https://api.example.com \
  --concurrency 100 \
  --max-requests 8000

# Let the APILEAK_MAX_DEPTH env var drive depth (CLI --depth would override it)
APILEAK_MAX_DEPTH=4 python apileaks.py dir \
  --target https://api.example.com
```

### Discovery Triage Workflow

The triage workflow layers status-code grouping/filtering, session persistence, a human-readable export, a `rich` results table, and an opt-in interactive follow-up on top of discovery. It activates automatically when any triage flag is present.

```bash
# Group/filter by status class and save a structured session (source of truth)
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 2xx \
  --save-session session.json

# Save a session AND write a human-readable Markdown export
python apileaks.py dir \
  --target https://api.example.com \
  --save-session session.json \
  --export md \
  --export-file discovery.md

# Plain-text export instead of Markdown
python apileaks.py dir \
  --target https://api.example.com \
  --export txt \
  --export-file discovery.txt

# Reload a prior session (no re-discovery) and re-render the triage table
python apileaks.py dir \
  --target https://api.example.com \
  --load-session session.json

# Reload a session and filter to server errors
python apileaks.py dir \
  --target https://api.example.com \
  --load-session session.json \
  --status-code 5xx

# Interactive triage: pick one endpoint for a targeted follow-up scan (opt-in)
python apileaks.py dir \
  --target https://api.example.com \
  --load-session session.json \
  --interactive

# CI-safe: --ci-mode disables the interactive prompt so it never blocks a pipeline
python apileaks.py dir \
  --target https://api.example.com \
  --interactive \
  --ci-mode \
  --save-session session.json \
  --export md \
  --export-file discovery.md

# Full triage workflow in a single run
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --rate-limit 10 \
  --detect-framework \
  --status-code 2xx \
  --save-session session.json \
  --export md \
  --export-file discovery.md \
  --interactive
```

**Status-code filter forms** (triage mode): a status class token (`2xx`, `3xx`, `4xx`, `5xx`), explicit codes (`200,401,403`), or a range (`400-403`). Class tokens are single-valued; explicit codes are validated to the `100-599` range.

### Rate Limiting and User-Agent with Discovery and Triage

`--rate-limit` and the User-Agent options pace and identify every discovery request `dir` issues, and they combine cleanly with the discovery-control and triage flags. The targeted follow-up scan launched from interactive triage inherits the same settings, so request pacing and identification stay consistent from discovery through any follow-up.

```bash
# Random User-Agent + gentle rate limit, bounded recursive discovery,
# filter to successful endpoints, and save a session
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 5 \
  --user-agent-random \
  --depth 4 \
  --max-requests 5000 \
  --status-code 2xx \
  --save-session session.json

# Single custom User-Agent + rate limit, with interactive triage —
# the follow-up scan inherits both the rate limit and the custom UA
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 8 \
  --user-agent-custom "MyScanner/1.0" \
  --status-code 2xx \
  --save-session session.json \
  --interactive

# Rotating User-Agents from a file + rate limit, deep discovery with a budget,
# then open interactive triage (the follow-up reuses the same UA file rotation)
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 10 \
  --user-agent-file wordlists/user_agents.txt \
  --depth 5 \
  --max-requests 8000 \
  --save-session session.json \
  --interactive
```

**Notes on rate limiting and User-Agent:** the three User-Agent options are mutually exclusive, `--user-agent-file` rotates one UA per line (blank/`#` lines skipped), reloaded sessions (`--load-session`) issue no requests, and the targeted follow-up scan inherits the originating `--rate-limit` and User-Agent option. See the [CLI Reference](cli-reference.md#rate-limiting-and-user-agent-in-discovery-and-triage) for the full semantics.

### Discovery Robustness: Seeds, Matchers, Secrets, and Machine Output

These flags harden and broaden discovery and compose freely with the discovery-control (`--depth`, `--max-requests`, `--concurrency`) and triage (`--status-code`, `--save-session`, `--export`, `--interactive`, `--ci-mode`) flags. See the [CLI Reference](cli-reference.md#discovery-robustness-options) for full semantics. The shared `-x`/`--extensions`, `--timeout`, and `--retries` options also work with `scan`.

```bash
# Seed from a spec + multiple wordlists (merged & de-duplicated) and expand
# with extensions, then filter to successful endpoints and save a session
python apileaks.py dir \
  --target https://api.example.com \
  --openapi specs/openapi.yaml \
  --wordlist wordlists/endpoints.txt \
  --wordlist wordlists/admin_endpoints.txt \
  --extensions json,php \
  --status-code 2xx \
  --save-session session.json

# Read wordlist entries from stdin (`-`) and append extensions
cat wordlists/endpoints.txt | python apileaks.py dir \
  --target https://api.example.com \
  --wordlist - \
  -x .json -x .php \
  --depth 2

# Attach request context (headers, cookie, basic auth) to every request
python apileaks.py dir \
  --target https://api.example.com \
  -H "X-API-Key: key123" \
  -H "X-Tenant: acme" \
  --cookie "session=abc123" \
  --basic-auth admin:secret \
  --status-code 2xx \
  --save-session session.json

# Response matchers + filters to cut soft-404 noise (kept results must be
# larger than 100 bytes and not match "Not Found"); combine with --status-code
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 200,403 \
  --match-size ">100" \
  --filter-regex "Not Found" \
  --filter-words "<5"

# Enumerate allowed methods and probe for GraphQL introspection, bounded by a
# request budget and concurrency limit
python apileaks.py dir \
  --target https://api.example.com \
  --enumerate-methods \
  --graphql \
  --max-requests 5000 \
  --concurrency 100

# Per-request resilience against a slow / rate-limiting target
python apileaks.py dir \
  --target https://api.example.com \
  --timeout 30 \
  --retries 5 \
  --rate-limit 5

# Transport / TLS: mutual TLS, custom CA, DNS override, cross-domain redirects
python apileaks.py dir \
  --target https://api.example.com \
  --client-cert client.pem \
  --ca-bundle ca.pem \
  --resolve api.example.com:127.0.0.1 \
  --allow-cross-domain-redirects

# Route discovery through a SOCKS5 proxy with auth (requires httpx[socks])
python apileaks.py dir \
  --target https://api.example.com \
  --proxy socks5://user:pass@127.0.0.1:1080

# Secret detection (redacted) with custom patterns, plus machine-readable output
python apileaks.py dir \
  --target https://api.example.com \
  --detect-secrets \
  --secret-patterns config/secret_patterns.json \
  --status-code 2xx \
  --output-format jsonl \
  --output-file reports/discovery.jsonl

# Everything together: spec + multi-wordlist seeds, extensions, request context,
# matchers/filters, method+GraphQL probes, secret detection, machine output,
# and a saved session — CI-safe
python apileaks.py dir \
  --target https://api.example.com \
  --openapi specs/openapi.yaml \
  --wordlist wordlists/endpoints.txt \
  --wordlist - \
  --extensions json,php \
  -H "X-API-Key: key123" \
  --cookie "session=abc123" \
  --match-size ">100" \
  --filter-regex "Not Found" \
  --enumerate-methods \
  --graphql \
  --timeout 20 \
  --retries 3 \
  --detect-secrets \
  --status-code 2xx \
  --save-session session.json \
  --output-format csv \
  --output-file reports/discovery.csv \
  --ci-mode

# scan reusing the shared robustness flags (extensions, timeout, retries)
python apileaks.py scan \
  --target https://api.example.com \
  --extensions json,php \
  --timeout 20 \
  --retries 3 \
  --depth 2 \
  --modules bola,auth
```

### Discovery Scope, Integration, and Resilience

These flags scope what discovery persists, narrow recursion, confirm flaky hits, feed discovered endpoints straight into an OWASP scan, and checkpoint/resume long runs. They compose with the discovery-control, robustness, and triage flags above. See the [CLI Reference](cli-reference.md#path-and-status-scope-storage-time-selection) for full semantics.

```bash
# Storage-time path scope: persist only /api/* endpoints, drop static assets.
# Exclude takes precedence over include.
python apileaks.py dir \
  --target https://api.example.com \
  --include-path "^/api/" \
  --exclude-path "\.(png|jpg|css|js)$" \
  --save-session session.json

# Storage-time status scope: persist only 2xx, drop 404s. Distinct from the
# display-only --status-code: dropped records never reach the session or output.
python apileaks.py dir \
  --target https://api.example.com \
  --include-status 2xx \
  --exclude-status 404 \
  --output-format jsonl \
  --output-file reports/discovery.jsonl

# Combine storage-time scope with display-only matchers/filters: scope decides
# what is stored, matchers/filters decide what is shown from the stored set
python apileaks.py dir \
  --target https://api.example.com \
  --include-path "^/api/" \
  --include-status 2xx \
  --match-size ">100" \
  --filter-regex "Not Found" \
  --save-session session.json

# Recursion scope: only descend into 2xx/3xx admin and api_version endpoints.
# Only narrows the default VALID/AUTH_REQUIRED recursion; never relaxes it.
python apileaks.py dir \
  --target https://api.example.com \
  --depth 4 \
  --max-requests 5000 \
  --recursion-status 2xx,3xx \
  --recursion-type admin,api_version

# Recursion scope also works on the scan command
python apileaks.py scan \
  --target https://api.example.com \
  --depth 3 \
  --recursion-type admin,api_version \
  --modules bola,auth

# Hit confirmation: re-request each interesting candidate 3 times and record it
# only when the responses are consistent (reduces false positives)
python apileaks.py dir \
  --target https://api.example.com \
  --confirm-hits 3 \
  --rate-limit 5 \
  --status-code 2xx

# Batch scan scope (non-interactive): discover, then run an OWASP scan over all
# VALID discovered endpoints. CI-safe — the interactive prompt never runs.
python apileaks.py dir \
  --target https://api.example.com \
  --scan-scope valid \
  --ci-mode

# Batch scan scope by status class, with request context inherited by the scan
python apileaks.py dir \
  --target https://api.example.com \
  -H "X-API-Key: key123" \
  --rate-limit 8 \
  --scan-scope 2xx

# Interactive multi-select: enter "1,3,5" or "2-4" at the prompt to batch-scan
# those records; a single index keeps the single-endpoint follow-up
python apileaks.py dir \
  --target https://api.example.com \
  --interactive

# Checkpoint a long run so it can be resumed after an interruption (atomic writes)
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/big.txt \
  --max-requests 50000 \
  --checkpoint reports/scan.ckpt

# Resume from the checkpoint and keep checkpointing the resumed run. Already
# tested candidates are not re-requested; results merge with no duplicates.
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/big.txt \
  --resume reports/scan.ckpt \
  --checkpoint reports/scan.ckpt

# Everything together: storage-time scope + recursion scope + hit confirmation,
# checkpointed, then batch-scan the VALID endpoints — CI-safe
python apileaks.py dir \
  --target https://api.example.com \
  --include-path "^/api/" \
  --exclude-path "\.(png|jpg|css|js)$" \
  --include-status 2xx \
  --recursion-status 2xx,3xx \
  --recursion-type admin,api_version \
  --confirm-hits 2 \
  --max-requests 20000 \
  --checkpoint reports/scan.ckpt \
  --scan-scope valid \
  --ci-mode
```

### Positional Fuzz Markers

Positional fuzzing places a literal keyword (`FUZZ` by default) inside the target URL and sweeps each marked position with wordlist values, instead of appending entries to a base path. Every literal occurrence of the keyword becomes a marker; in marker mode the repeatable `--wordlist` values are the per-marker wordlists, associated in left-to-right marker order. These runs compose with the same discovery-control and triage flags (`--max-requests`, `--rate-limit`, matchers, `--confirm-hits`, `--status-code`). See the [CLI Reference](cli-reference.md#positional-fuzz-markers---fuzz-keyword---fuzz-mode) for full semantics.

```bash
# Single-marker version sweep: fuzz just the API version segment. The one
# wordlist is the marker's wordlist; bounded by a rate limit and request budget.
python apileaks.py dir \
  --target "https://api.example.com/FUZZ/users" \
  --wordlist wordlists/versions.txt \
  --rate-limit 10 \
  --max-requests 2000 \
  --status-code 2xx

# Two markers, clusterbomb (default): every version × every filename. The first
# --wordlist pairs with the first marker (version), the second with the filename.
# Confirm interesting hits to cut false positives.
python apileaks.py dir \
  --target "https://api.example.com/FUZZ/FUZZ" \
  --wordlist wordlists/versions.txt \
  --wordlist wordlists/filenames.txt \
  --confirm-hits 2 \
  --match-size ">100" \
  --filter-regex "Not Found" \
  --max-requests 5000

# Two markers, pitchfork: pair the i-th version with the i-th filename in
# lockstep (stops at the shortest list) instead of exploding into all combos.
python apileaks.py dir \
  --target "https://api.example.com/FUZZ/FUZZ" \
  --fuzz-mode pitchfork \
  --wordlist wordlists/versions.txt \
  --wordlist wordlists/filenames.txt \
  --rate-limit 8 \
  --status-code 2xx,403

# Custom keyword to avoid colliding with legitimate URL text (here "FUZZ" could
# appear literally, so a distinct marker token is used instead)
python apileaks.py dir \
  --target "https://api.example.com/__M__/report.__M__" \
  --fuzz-keyword __M__ \
  --wordlist wordlists/versions.txt \
  --wordlist wordlists/extensions.txt \
  --confirm-hits 3 \
  --max-requests 4000
```

## Parameter Fuzzing

Parameter fuzzing identifies hidden parameters, injection points, and input validation issues.

### Basic Parameter Fuzzing
```bash
# Simple parameter fuzzing
python apileaks.py par --target https://api.example.com

# With custom wordlist
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt
```

### Advanced Parameter Fuzzing
```bash
# With authentication and WAF evasion
python apileaks.py par \
  --target https://api.example.com/users \
  --wordlist wordlists/parameters.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --rate-limit 10 \
  --methods GET,POST

# With custom user agent and response filtering
python apileaks.py par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "APILeak Security Scanner v2.0" \
  --status-code 200-299,400-499 \
  --output parameter_discovery

# Focus on injection detection
python apileaks.py par \
  --target https://api.example.com/search \
  --wordlist wordlists/injection_params.txt \
  --status-code 500-599 \
  --user-agent-random \
  --output injection_testing

# With framework detection
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --detect-framework \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output framework_aware_param_scan
```

## Security Scan (`scan`)

The `scan` command is APILeak's primary orchestrator: it combines endpoint discovery, parameter fuzzing, and OWASP security testing for comprehensive coverage, running **all** registered OWASP modules by default (restrict with `--modules a,b`). To run a single module in isolation, use `owasp <key>` (see [OWASP Security Testing](#owasp-security-testing) below).

> **Deprecation.** `full` and `main` are deprecated, hidden aliases of `scan`. They still forward to `scan` (with a one-line stderr notice) — migrate scripts to `scan`. A single-module alias call like `full --modules bola` becomes `apileaks owasp bola`.

### Basic Scan
```bash
# Simple scan (runs discovery + all OWASP modules by default)
python apileaks.py scan --target https://api.example.com

# With configuration file
python apileaks.py scan \
  --config config/api_config.yaml \
  --target https://api.example.com
```

### Advanced Full Scan
```bash
# With WAF evasion and OWASP modules
python apileaks.py scan \
  --target https://api.example.com \
  --user-agent-file wordlists/user_agents.txt \
  --modules bola,auth,property \
  --rate-limit 5 \
  --output comprehensive_security_scan

# With custom user agent and status filtering
python apileaks.py scan \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --user-agent-custom "Enterprise Security Scanner" \
  --status-code 200,401,403,500 \
  --output enterprise_scan

# With framework and version detection (all modules run by default)
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.8 \
  --user-agent-random \
  --output advanced_discovery_scan
```

### Recursive Discovery Control (Scan)

The same discovery-control flags work with `scan`, so you can tune how aggressively the scan discovers endpoints before running OWASP tests. They keep recursion agile — shallow/fast vs deep/thorough — and stay bounded by the request budget and catch-all detection. Depth precedence is CLI `--depth` > `APILEAK_MAX_DEPTH` env var > default `3`.

```bash
# Shallow + fast discovery ahead of the OWASP modules
python apileaks.py scan \
  --target https://api.example.com \
  --depth 1 \
  --modules bola,auth

# Deep + thorough discovery with a request budget as a safety net
python apileaks.py scan \
  --target https://api.example.com \
  --depth 6 \
  --max-requests 5000 \
  --concurrency 100

# Skip recursive discovery entirely (depth-0 pass only)
python apileaks.py scan \
  --target https://api.example.com \
  --no-recursive
```

## Advanced Discovery Features

### Framework Detection Only
```bash
# Detect API framework
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --framework-confidence 0.8 \
  --output framework_detection

# Framework detection with confidence threshold
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --framework-confidence 0.9 \
  --user-agent-random
```

### Version Fuzzing Only
```bash
# Discover API versions
python apileaks.py scan \
  --target https://api.example.com \
  --fuzz-versions \
  --version-patterns "/v1,/v2,/api/v1,/api/v2" \
  --output version_discovery

# Version fuzzing with custom patterns
python apileaks.py scan \
  --target https://api.example.com \
  --fuzz-versions \
  --version-patterns "/version1,/version2,/rest/v1,/rest/v2" \
  --user-agent-random
```

### Combined Advanced Discovery
```bash
# Framework detection and version fuzzing
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.7 \
  --user-agent-random \
  --output combined_discovery

# With directory fuzzing integration
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --detect-framework \
  --fuzz-versions \
  --user-agent-random \
  --output integrated_discovery

# Short flags for convenience
python apileaks.py scan \
  --target https://api.example.com \
  --df \
  --fv \
  --framework-confidence 0.9 \
  --user-agent-random
```

## Authentication Testing

### JWT Token Testing
```bash
# Basic JWT authentication
python apileaks.py scan \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules auth,bola \
  --output jwt_security_test

# JWT with parameter fuzzing
python apileaks.py par \
  --target https://api.example.com/protected \
  --wordlist wordlists/parameters.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output jwt_param_test

# JWT with directory fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/admin_endpoints.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --status-code 200,401,403 \
  --output jwt_endpoint_test
```

### API Key Testing
```bash
# API key in header
python apileaks.py scan \
  --target https://api.example.com \
  --header "X-API-Key: your-api-key" \
  --modules auth,bola \
  --output api_key_test

# API key in query parameter
python apileaks.py par \
  --target "https://api.example.com?api_key=your-key" \
  --wordlist wordlists/parameters.txt \
  --output api_key_param_test
```

## OWASP Security Testing

`scan` runs every OWASP API Security Top 10 module by default. To list the modules or run one in isolation, use the `owasp` command group:

```bash
# List every module (key, OWASP category, one-line summary)
python apileaks.py owasp

# Run exactly one module against a target
python apileaks.py owasp <key> --target https://api.example.com
```

### Specific OWASP Modules

To focus on a single vulnerability class, run the module in isolation with `owasp <key>`:

```bash
# BOLA (Broken Object Level Authorization) testing — single module in isolation
python apileaks.py owasp bola \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output bola_security_test

# Authentication testing — single module in isolation
python apileaks.py owasp auth \
  --target https://api.example.com \
  --user-agent-random \
  --output auth_security_test

# Property-level authorization testing — single module in isolation
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output property_auth_test

# Multiple OWASP modules — aggregate a subset through scan
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,auth,property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output comprehensive_owasp_test
```

### All Available OWASP Modules
```bash
# Run all implemented OWASP modules (scan runs every module by default,
# so no --modules flag is needed)
python apileaks.py scan \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --rate-limit 8 \
  --output complete_owasp_assessment
```

## Status Code Filtering Examples

### Success Response Focus
```bash
# Only show successful responses
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --status-code 200-299 \
  --user-agent-random \
  --output success_endpoints

# Focus on specific success codes
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --status-code 200,201,202 \
  --output successful_parameters
```

### Error Analysis
```bash
# Server error analysis
python apileaks.py par \
  --target https://api.example.com/search \
  --wordlist wordlists/injection_params.txt \
  --status-code 500-599 \
  --output server_errors

# Client error analysis
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --status-code 400-499 \
  --output client_errors
```

### Authentication Focus
```bash
# Authentication-related responses
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/admin_endpoints.txt \
  --status-code 401,403 \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output auth_responses

# Mixed authentication and success responses
python apileaks.py scan \
  --target https://api.example.com \
  --status-code 200,401,403 \
  --modules bola,auth \
  --output auth_focused_scan
```

## Performance Optimization

### High-Speed Scanning
```bash
# Fast directory fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --rate-limit 50 \
  --status-code 200-299 \
  --user-agent-random

# Fast parameter discovery
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --rate-limit 30 \
  --methods GET,POST \
  --status-code 200,500-599
```

### Conservative Scanning
```bash
# Slow and careful scanning
python apileaks.py scan \
  --target https://api.example.com \
  --rate-limit 2 \
  --user-agent-random \
  --modules bola,auth \
  --output careful_scan

# Respectful parameter testing
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --rate-limit 5 \
  --user-agent-custom "Authorized Security Test" \
  --output respectful_param_test
```

## Legacy Usage (Still Supported)

### Traditional Configuration-Based Usage
```bash
# Traditional usage with config file
python apileaks.py scan \
  --config config/api_config.yaml \
  --target https://api.example.com

# With custom configuration
python apileaks.py scan \
  --config config/comprehensive_config.yaml \
  --target https://api.example.com \
  --output legacy_scan
```

## Command Options Reference

The full, authoritative list of options for every command — `dir`, `par`, `scan`, `owasp`, and `jwt` — lives in the [CLI Reference](cli-reference.md). For the `dir` command specifically:

- [`dir` options overview](cli-reference.md#directory-fuzzing-dir)
- [Discovery Control](cli-reference.md#discovery-control-options) · [Robustness](cli-reference.md#discovery-robustness-options) · [Triage](cli-reference.md#discovery-triage-options) · [Batch Scan Scope](cli-reference.md#discovery-to-scan-integration-batch-scan-scope)

You can also run `python apileaks.py dir --help` for the inline option list.

## Real-World Scenarios

### E-commerce API Testing
```bash
# Comprehensive e-commerce API security assessment
python apileaks.py scan \
  --target https://api.ecommerce.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules bola,auth,property \
  --user-agent-random \
  --status-code 200,401,403,500 \
  --detect-framework \
  --output ecommerce_security_assessment
```

### Banking API Security Test
```bash
# Conservative banking API testing
python apileaks.py scan \
  --target https://api.bank.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules bola,auth,property \
  --user-agent-custom "Authorized Security Assessment" \
  --rate-limit 2 \
  --status-code 200,401,403 \
  --output banking_security_test
```

### Mobile App API Testing
```bash
# Mobile app backend API testing
python apileaks.py scan \
  --target https://mobile-api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules bola,auth,property \
  --user-agent-file mobile_user_agents.txt \
  --detect-framework \
  --fuzz-versions \
  --output mobile_api_security_test
```

### Microservices Testing
```bash
# Individual microservice testing
python apileaks.py scan \
  --target https://user-service.example.com \
  --modules bola,auth \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output user_service_test

python apileaks.py scan \
  --target https://payment-service.example.com \
  --modules bola,auth,property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output payment_service_test
```

## Troubleshooting Common Issues

### Rate Limiting Issues
```bash
# If you encounter rate limiting (429 responses)
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 1 \
  --user-agent-random \
  --wordlist wordlists/endpoints.txt
```

### WAF Blocking
```bash
# If WAF is blocking requests
python apileaks.py par \
  --target https://api.example.com \
  --user-agent-file realistic_agents.txt \
  --rate-limit 3 \
  --wordlist wordlists/parameters.txt
```

### Large Response Handling
```bash
# For APIs with large responses
python apileaks.py scan \
  --target https://api.example.com \
  --status-code 200-299 \
  --rate-limit 5 \
  --modules bola,auth
```

---

For more specific use cases and advanced configurations, see the [Configuration Guide](configuration.md) and [CI/CD Integration](ci-cd-integration.md) documentation.