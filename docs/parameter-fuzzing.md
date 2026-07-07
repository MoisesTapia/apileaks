# Parameter Fuzzing Guide

Parameter fuzzing discovers hidden, undocumented, or debug parameters accepted by an API endpoint. APILeak's `par` command injects candidate parameter names from a wordlist and compares responses against a baseline to detect parameters that alter application behavior — even when status codes remain unchanged.

## 📋 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Basic Examples](#basic-examples)
- [Intermediate Examples](#intermediate-examples)
- [Advanced Examples](#advanced-examples)
- [Detection Signals](#detection-signals)
- [Configuration Reference](#configuration-reference)
- [Results Interpretation](#results-interpretation)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

### 🎯 Main Objectives

- **Hidden Parameter Discovery**: Find parameters not documented in API specs
- **Injection Point Identification**: Detect where user input influences application logic
- **Reflection Detection**: Identify parameters whose values are echoed in responses
- **Structural Change Detection**: Discover parameters that introduce new JSON fields

### 🔍 Detection Capabilities

| Signal | Description |
|--------|-------------|
| Status code change | Response code differs from baseline |
| Body size change | Response body length diverges significantly |
| Response time change | Measurably slower or faster response |
| Content-type change | Different response content type |
| Reflection | Injected sentinel value echoed in body or headers |
| New JSON fields | Response JSON contains keys absent from baseline |

### ⚡ Key Features

- Unique per-candidate sentinel values (≥16 alphanumeric chars) for precise reflection detection
- Optional hit confirmation to reduce false positives
- Request budget to bound scan cost
- Method-based injection point selection (query vs body)
- Repeatable wordlists with merge and deduplication
- Full request-context support (headers, cookies, auth)
- Response matchers/filters for finding selection
- Machine-readable output (CSV, JSONL)

## How It Works

```
┌─────────────────────────────────────────────────────┐
│                  par workflow                         │
├─────────────────────────────────────────────────────┤
│ 1. Capture baseline response (no injected params)   │
│ 2. For each candidate parameter from wordlist:      │
│    a. Generate unique sentinel value                 │
│    b. Inject into query string or request body       │
│    c. Compare response against baseline             │
│    d. Check: status, size, time, type, reflection,  │
│       new JSON fields                               │
│    e. If difference detected → candidate finding    │
│ 3. (Optional) Confirm hits with N retests           │
│ 4. Apply matchers/filters to findings               │
│ 5. Report results                                   │
└─────────────────────────────────────────────────────┘
```

The injection point is determined by `--methods`:
- **GET, DELETE** → inject into query string (`?param=sentinel`)
- **POST, PUT, PATCH** → inject into request body (JSON, form-encoded, or XML)

### `par` vs `dir`: parameter name discovery vs positional value fuzzing

These two commands solve different problems:

| | `par` (parameter fuzzing) | `dir` (directory/endpoint fuzzing) |
|---|---|---|
| **Primary goal** | Discover **unknown parameter names** | Discover hidden **paths/endpoints** |
| **Default target URL** | Plain base URL: `https://api.example.com/api/v1/users` | Plain base URL or marker URL: `https://api.example.com/FUZZ` |
| **What the wordlist supplies** | Candidate parameter **names** (each injected as `?name=<sentinel>` or in the request body) | Candidate **path segments** appended to the base URL, or **values** at each marker position |
| **Marker mode** | ✅ Supported — `--fuzz-keyword` (default `FUZZ`), `--fuzz-mode` (clusterbomb/pitchfork). In marker mode, markers in the URL are swept with wordlist values rather than parameter names being probed | ✅ Full support — same `--fuzz-keyword` / `--fuzz-mode` options |
| **Baseline comparison** | ✅ Compares each response against a no-parameter baseline to detect behavioral changes | ❌ No baseline comparison — discovery relies on status codes and response classification |
| **Detection signals** | Reflection, new JSON fields, status/size/time/content-type changes | Status code, response size, endpoint classification |

**In marker mode**, `par` sweeps the marker positions in the URL with candidate values from `--wordlist` — this is the same positional-fuzzing behavior as `dir`. **In name-discovery mode** (no markers in the URL), `par` injects each wordlist entry as a parameter name and compares responses against a no-parameter baseline.

> If you want to fuzz **values** at a specific URL position without baseline comparison and using directory-discovery classification, use `dir` marker mode:
>
> ```bash
> # Sweep a known parameter VALUE with dir marker mode
> python apileaks.py dir --target "https://api.example.com/api/v1/?id=FUZZ" --wordlist ids.txt
> ```
>
> See [Positional Fuzz Markers](usage-examples.md#positional-fuzz-markers) for the full `dir` marker workflow.

## Basic Examples

Simple parameter fuzzing with minimal configuration.

```bash
# Discover hidden parameters on an endpoint using the default wordlist
python apileaks.py par --target https://api.example.com/users/123

# Use a custom wordlist
python apileaks.py par \
  --target https://api.example.com/api/v1/products \
  --wordlist wordlists/parameters.txt

# Fuzz with authentication (JWT)
python apileaks.py par \
  --target https://api.example.com/api/v1/account \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Fuzz only POST body parameters
python apileaks.py par \
  --target https://api.example.com/api/v1/orders \
  --methods POST

# Limit request volume
python apileaks.py par \
  --target https://api.example.com/search \
  --max-requests 500
```

## Intermediate Examples

Adding authentication, resilience, confirmation, and targeted detection.

### Request Context

```bash
# Custom headers and cookie for an authenticated session
python apileaks.py par \
  --target https://api.example.com/api/v1/profile \
  -H "X-API-Key: sk_live_abc123" \
  -H "X-Tenant-ID: acme" \
  --cookie "session=eyJpZCI6MTIzfQ=="

# Basic auth with a gentle rate limit
python apileaks.py par \
  --target https://internal-api.example.com/admin/config \
  --basic-auth admin:s3cr3t \
  --rate-limit 5

# JWT auth with custom headers
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Request-ID: pentest-2024"
```

### Hit Confirmation (False Positive Reduction)

```bash
# Confirm each candidate finding with 3 retests — only report stable hits
python apileaks.py par \
  --target https://api.example.com/api/v1/search \
  --confirm-hits 3

# Confirmation with a request budget so the total scan stays bounded
python apileaks.py par \
  --target https://api.example.com/api/v1/search \
  --confirm-hits 2 \
  --max-requests 1000
```

### Method and Injection Point Control

```bash
# Fuzz only query parameters (GET and DELETE methods)
python apileaks.py par \
  --target https://api.example.com/api/v1/items \
  --methods GET,DELETE

# Fuzz only body parameters (POST and PUT methods)
python apileaks.py par \
  --target https://api.example.com/api/v1/orders \
  --methods POST,PUT

# Fuzz both query and body injection points
python apileaks.py par \
  --target https://api.example.com/api/v1/resources \
  --methods GET,POST,PUT,PATCH
```

### Multiple Wordlists

```bash
# Merge two wordlists (duplicates removed automatically)
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --wordlist wordlists/parameters.txt \
  --wordlist wordlists/debug_params.txt

# Read candidates from stdin (pipe from another tool)
cat custom_params.txt | python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --wordlist -

# Combine stdin with a file-based wordlist
cat discovered_params.txt | python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --wordlist - \
  --wordlist wordlists/parameters.txt
```

### Resilience and Concurrency

```bash
# Slow target: increase timeout and add retries
python apileaks.py par \
  --target https://slow-api.example.com/endpoint \
  --timeout 30 \
  --retries 3

# High concurrency for fast targets
python apileaks.py par \
  --target https://fast-api.example.com/search \
  --concurrency 50 \
  --max-requests 5000

# Conservative pacing against rate-limited APIs
python apileaks.py par \
  --target https://api.example.com/api/v1/data \
  --rate-limit 3 \
  --timeout 15 \
  --retries 2
```

## Advanced Examples

Combining multiple capabilities for thorough and targeted parameter discovery.

### Full-Featured Authenticated Scan

```bash
# Comprehensive parameter discovery with all options
python apileaks.py par \
  --target https://api.example.com/api/v1/users/me \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Correlation-ID: pentest-run-001" \
  --wordlist wordlists/parameters.txt \
  --wordlist wordlists/admin_params.txt \
  --methods GET,POST \
  --confirm-hits 3 \
  --max-requests 2000 \
  --rate-limit 10 \
  --timeout 20 \
  --retries 2 \
  --concurrency 25 \
  --output-format jsonl \
  --output-file reports/par_findings.jsonl
```

### Response Matchers and Filters

```bash
# Only report findings with responses larger than 200 bytes
python apileaks.py par \
  --target https://api.example.com/api/v1/search \
  --match-size ">200"

# Exclude false positives matching "not found" text
python apileaks.py par \
  --target https://api.example.com/api/v1/items \
  --filter-regex "not found|error"

# Combine matchers and filters: keep large responses, exclude error patterns
python apileaks.py par \
  --target https://api.example.com/api/v1/data \
  --match-size ">100" \
  --match-words ">10" \
  --filter-regex "404|invalid" \
  --filter-size "<50"

# Time-based detection: find parameters that make the app noticeably slower
python apileaks.py par \
  --target https://api.example.com/api/v1/query \
  --match-time ">2.0"
```

### TLS and Transport

```bash
# Mutual TLS (client certificate) against an internal API
python apileaks.py par \
  --target https://internal-api.example.com/admin \
  --client-cert certs/client.pem \
  --ca-bundle certs/internal-ca.pem \
  --basic-auth admin:pass

# DNS resolution override (test against a staging backend)
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --resolve api.example.com:10.0.1.50

# Route through an intercepting proxy (Burp/Caido)
python apileaks.py par \
  --target https://api.example.com/api/v1/orders \
  --proxy http://127.0.0.1:8080 \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Machine-Readable Output

```bash
# JSONL output for pipeline consumption
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --output-format jsonl \
  --output-file reports/parameters.jsonl

# CSV output for spreadsheet analysis
python apileaks.py par \
  --target https://api.example.com/api/v1/products \
  --output-format csv \
  --output-file reports/parameters.csv

# JSONL with full detection context
python apileaks.py par \
  --target https://api.example.com/api/v1/search \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --confirm-hits 2 \
  --output-format jsonl \
  --output-file reports/confirmed_params.jsonl
```

### Marker Mode (positional value fuzzing)

When the target URL contains the `--fuzz-keyword` token, `par` switches to Marker_Mode and sweeps each marked position with values from `--wordlist` (instead of probing candidate parameter names).

```bash
# Single marker: sweep a path segment with version values
python apileaks.py par \
  --target "https://api.example.com/FUZZ/users" \
  --wordlist versions.txt

# Two markers, cartesian product (clusterbomb — every combination)
python apileaks.py par \
  --target "https://api.example.com/FUZZ/users/FUZZ" \
  --fuzz-mode clusterbomb \
  --wordlist versions.txt \
  --wordlist user_ids.txt

# Two markers paired position-by-position (pitchfork)
python apileaks.py par \
  --target "https://api.example.com/__MARKER__/items/__MARKER__" \
  --fuzz-keyword __MARKER__ \
  --fuzz-mode pitchfork \
  --wordlist prefixes.txt \
  --wordlist suffixes.txt
```

**Per-marker wordlist association.** In Marker_Mode the repeatable `--wordlist` values are associated with markers left-to-right (first `--wordlist` → first marker). If fewer wordlists than markers are supplied, the last wordlist fills the remaining markers. More wordlists than markers is rejected with an error.

**Validation.** These configurations are rejected before any request:
- Empty or whitespace-only `--fuzz-keyword`
- `--fuzz-keyword` or `--fuzz-mode` supplied explicitly but the URL contains no occurrence of the keyword
- More `--wordlist` sources than markers
- `--fuzz-mode pitchfork` with an empty associated wordlist

### WAF Evasion

```bash
# Random user agent rotation with conservative pacing
python apileaks.py par \
  --target https://protected-api.example.com/endpoint \
  --user-agent-random \
  --rate-limit 3 \
  --timeout 20

# Custom user agent string
python apileaks.py par \
  --target https://api.example.com/api/v1/data \
  --user-agent-custom "Mozilla/5.0 (compatible; Googlebot/2.1)"

# User agent rotation from file
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --user-agent-file wordlists/user_agents.txt \
  --rate-limit 5
```

### CI/CD Pipeline Integration

```bash
# CI-safe parameter scan: bounded budget, machine output, no interactive prompts
python apileaks.py par \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --wordlist wordlists/parameters.txt \
  --methods GET,POST \
  --confirm-hits 2 \
  --max-requests 1000 \
  --timeout 15 \
  --retries 2 \
  --match-size ">100" \
  --filter-regex "Not Found" \
  --output-format jsonl \
  --output-file reports/par_ci.jsonl \
  --no-banner

# Quick smoke test in a pipeline (small budget, fast)
python apileaks.py par \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --max-requests 200 \
  --output-format csv \
  --output-file reports/par_smoke.csv \
  --no-banner
```

### Real-World Scenarios

```bash
# E-commerce: find debug/admin parameters on the checkout endpoint
python apileaks.py par \
  --target https://shop.example.com/api/checkout \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Cart-ID: test-cart-001" \
  --wordlist wordlists/parameters.txt \
  --wordlist wordlists/ecommerce_params.txt \
  --methods POST \
  --confirm-hits 3 \
  --max-requests 1500 \
  --rate-limit 8 \
  --output-format jsonl \
  --output-file reports/checkout_params.jsonl

# Banking API: conservative testing with mutual TLS
python apileaks.py par \
  --target https://api.bank.example.com/v1/accounts/me \
  --client-cert certs/pentest-client.pem \
  --ca-bundle certs/bank-ca.pem \
  --basic-auth auditor:securepass \
  --wordlist wordlists/parameters.txt \
  --confirm-hits 3 \
  --max-requests 500 \
  --rate-limit 2 \
  --timeout 30 \
  --output-format jsonl \
  --output-file reports/bank_params.jsonl

# GraphQL endpoint: find hidden query parameters alongside the standard body
python apileaks.py par \
  --target https://api.example.com/graphql \
  --methods GET,POST \
  --wordlist wordlists/graphql_params.txt \
  --wordlist wordlists/parameters.txt \
  -H "Content-Type: application/json" \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --match-size ">500" \
  --confirm-hits 2

# Microservices: scan multiple internal services behind mTLS
for svc in users orders inventory; do
  python apileaks.py par \
    --target "https://${svc}-service.internal.example.com/api/v1" \
    --client-cert certs/scanner.pem \
    --ca-bundle certs/internal-ca.pem \
    --wordlist wordlists/parameters.txt \
    --max-requests 800 \
    --rate-limit 10 \
    --output-format jsonl \
    --output-file "reports/par_${svc}.jsonl" \
    --no-banner
done
```

## Detection Signals

Each reported finding includes the detection signal(s) that triggered it:

### Reflection

A unique sentinel value injected as the parameter value was echoed back in the response body or headers. This strongly indicates the parameter is processed by the application.

**Finding fields:**
- `detection_signal: "reflection"`
- `reflection_location: "body"` or `"header"`

### New JSON Fields

The test response contained top-level JSON keys that were absent from the baseline response. This indicates the parameter unlocks additional data in the response.

**Finding fields:**
- `detection_signal: "new_json_field"`
- `new_json_fields: ["field1", "field2"]`

### Status / Size / Time / Content-Type

Classic difference signals: the response status code, body size, response time, or content type diverged from the baseline.

**Finding fields:**
- `detection_signal: "status_code"` / `"body_size"` / `"response_time"` / `"content_type"`

### Multiple Signals

A single finding can carry multiple detection signals when several indicators fire simultaneously.

**Finding fields:**
- `detection_signals: ["reflection:body", "new_json_field"]`

## Configuration Reference

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target`, `-t` | Target URL (required) | — |
| `--wordlist`, `-w` | Wordlist file (repeatable, merged/deduped) | `wordlists/parameters.txt` |
| `--fuzz-keyword` | Literal token marking positions to fuzz in the URL. When present, activates Marker_Mode | `FUZZ` |
| `--fuzz-mode` | Combination strategy for multiple markers: `clusterbomb` (cartesian product) or `pitchfork` (index-wise zip) | `clusterbomb` |
| `--methods` | HTTP methods to test (comma-separated) | `GET,POST` |
| `--confirm-hits` | Retest count for hit confirmation (≥1) | Off |
| `--max-requests` | Request budget (≥1) | Unbounded |
| `--rate-limit` | Requests per second | `10` |
| `--timeout` | Per-request timeout in seconds (>0) | Config default |
| `--retries` | Retry count for failed requests (≥0) | Config default |
| `--concurrency` | Max in-flight requests (≥1) | Config default |
| `-H`, `--header` | Custom header (repeatable, `Name: Value`) | — |
| `--cookie` | Cookie value | — |
| `--basic-auth` | Basic auth (`user:pass`) | — |
| `--jwt` | JWT bearer token | — |
| `--client-cert` | Client TLS certificate path | — |
| `--ca-bundle` | Custom CA bundle path | — |
| `--resolve` | DNS override (`host:ip`) | — |
| `--match-size` | Keep findings by size (e.g., `>100`) | — |
| `--match-words` | Keep findings by word count | — |
| `--match-lines` | Keep findings by line count | — |
| `--match-regex` | Keep findings matching regex | — |
| `--match-time` | Keep findings by response time | — |
| `--filter-size` | Exclude findings by size | — |
| `--filter-words` | Exclude findings by word count | — |
| `--filter-lines` | Exclude findings by line count | — |
| `--filter-regex` | Exclude findings matching regex | — |
| `--filter-time` | Exclude findings by response time | — |
| `--output-format` | Machine output format (`csv`, `jsonl`) | — |
| `--output-file` | Machine output file path | — |
| `--output`, `-o` | Report filename prefix | Auto |
| `--proxy` | HTTP/SOCKS proxy URL | — |
| `--user-agent-random` | Random UA rotation | Off |
| `--user-agent-custom` | Fixed custom UA string | — |
| `--user-agent-file` | UA rotation from file | — |
| `--detect-framework` | Enable framework detection | Off |
| `--status-code` | Display filter by status code | All |
| `--no-banner` | Suppress startup banner | Off |

### YAML Configuration

Parameter fuzzing can also be driven via a YAML config file:

```yaml
target:
  base_url: "https://api.example.com/api/v1/users"
  timeout: 20

fuzzing:
  parameters:
    enabled: true
    methods: ["GET", "POST"]
    confirm_hits: 2
    max_requests: 1000
    query_wordlist: "wordlists/parameters.txt"
    body_wordlist: "wordlists/body_params.txt"
    boundary_testing: true
  endpoints:
    enabled: false
  concurrency: 25
  retries: 2

authentication:
  contexts:
    - name: "tester"
      type: "bearer"
      token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

rate_limiting:
  requests_per_second: 10
```

## Results Interpretation

### Understanding Findings

Each finding represents a candidate parameter that produced a detectable response difference:

| Field | Meaning |
|-------|---------|
| `parameter` | The candidate parameter name |
| `detection_signal` | Primary signal that triggered the finding |
| `detection_signals` | All signals that fired (may be multiple) |
| `reflection_location` | Where the sentinel was reflected (`body`/`header`) |
| `new_json_fields` | List of new JSON keys that appeared |
| `confirmation_status` | `confirmed` / `excluded_failed_retest` / null |
| `status_code` | Response status code from the test request |
| `response_size` | Response body size |
| `response_time` | Response time in seconds |

### Prioritizing Results

1. **High confidence** — Reflection findings with hit confirmation: the sentinel value was echoed and the behavior reproduced across retests.
2. **Medium confidence** — New JSON field findings: the parameter unlocks additional response data, suggesting it is processed server-side.
3. **Lower confidence** — Status code or body size changes without confirmation: may indicate a real parameter but can also be transient noise (use `--confirm-hits` to filter).

### SSRF-Candidate Escalation

When `par` discovers a query parameter whose name contains a URL-carrying keyword — `url`, `uri`, `host`, `endpoint`, `target`, `webhook`, `callback`, `redirect`, `src`, `feed`, `imageUrl`, etc. — the finding is automatically escalated:

| Without keyword match | With keyword match (`url`, `callback`, `webhook`, …) |
|----------------------|------------------------------------------------------|
| Severity: **INFO** | Severity: **MEDIUM** |
| OWASP: — | OWASP: **API7** (SSRF) |
| Generic recommendation | Recommendation includes SSRF test payload |

This means `par` acts as a **first-phase SSRF reconnaissance step**: it discovers which URL-accepting parameters exist, and marks them for follow-up with `owasp ssrf`.

**Example finding evidence for an escalated parameter:**
```
Query parameter 'url' discovered - response differs from baseline.
Parameter name suggests a URL-carrying field — potential SSRF attack surface.
Test manually with internal target payloads (e.g. ?url=http://127.0.0.1/).
```

**Recommended follow-up workflow:**
```bash
# Step 1: discover URL-accepting parameters
python apileaks.py par \
  --target https://api.example.com/v1/proxy \
  --methods GET

# Step 2: exploit confirmed URL params with SSRF probes
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --openapi /tmp/spec.json \
  --ssrf-internal-targets 169.254.169.254 \
  --ssrf-body-methods POST
```

### Example JSONL Output

```json
{"parameter":"debug","detection_signal":"reflection","detection_signals":["reflection:body"],"reflection_location":"body","confirmation_status":"confirmed","status_code":200,"response_size":1842}
{"parameter":"admin","detection_signal":"new_json_field","detection_signals":["new_json_field"],"new_json_fields":["is_admin","permissions"],"confirmation_status":"confirmed","status_code":200,"response_size":2105}
{"parameter":"verbose","detection_signal":"body_size","detection_signals":["body_size"],"confirmation_status":null,"status_code":200,"response_size":4521}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Parameter Fuzzing
on: [pull_request]

jobs:
  par-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt

      - name: Parameter fuzzing
        env:
          API_ENDPOINT: ${{ secrets.STAGING_API_URL }}
          JWT_TOKEN: ${{ secrets.STAGING_JWT }}
        run: |
          python apileaks.py par \
            --target "${API_ENDPOINT}/api/v1/users" \
            --jwt "${JWT_TOKEN}" \
            --methods GET,POST \
            --confirm-hits 2 \
            --max-requests 1000 \
            --rate-limit 10 \
            --match-size ">100" \
            --filter-regex "Not Found" \
            --output-format jsonl \
            --output-file reports/par_findings.jsonl \
            --no-banner

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: par-findings
          path: reports/par_findings.jsonl
```

### GitLab CI

```yaml
par-scan:
  stage: security
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python apileaks.py par
        --target "${API_ENDPOINT}/api/v1/users"
        --jwt "${JWT_TOKEN}"
        --confirm-hits 2
        --max-requests 1000
        --output-format jsonl
        --output-file reports/par_findings.jsonl
        --no-banner
  artifacts:
    paths:
      - reports/
  only:
    - merge_requests
```

## Troubleshooting

### Common Issues

#### No parameters tested (parameters_tested = 0)

This means the fuzzing engine was unable to reach the target or build the fuzzer.

```bash
# Verify target is reachable
curl -s -o /dev/null -w "%{http_code}" https://api.example.com/endpoint

# Try with increased timeout
python apileaks.py par \
  --target https://api.example.com/endpoint \
  --timeout 30 \
  --retries 3
```

#### Too many false positives

Unstable responses cause noise. Enable hit confirmation:

```bash
python apileaks.py par \
  --target https://api.example.com/unstable-endpoint \
  --confirm-hits 3 \
  --filter-size "<50"
```

#### Budget exhausted before completing

Increase the budget or reduce the wordlist:

```bash
# Larger budget
python apileaks.py par \
  --target https://api.example.com/endpoint \
  --max-requests 5000

# Or use a smaller, targeted wordlist
python apileaks.py par \
  --target https://api.example.com/endpoint \
  --wordlist wordlists/top_100_params.txt
```

#### Validation errors before any request

The CLI validates all options before issuing requests. Common causes:

| Error | Fix |
|-------|-----|
| `--methods` empty or unsupported | Provide at least one of: GET, POST, PUT, PATCH, DELETE |
| `--basic-auth` format | Use `user:pass` format (colon required) |
| `--basic-auth` + `--jwt` | These are mutually exclusive; choose one |
| `--header` missing colon | Format must be `Name: Value` |
| `--client-cert` / `--ca-bundle` unreadable | Verify file path and permissions |
| `--resolve` malformed | Format must be `host:ip` |
| `--max-requests` < 1 | Must be a positive integer |
| `--confirm-hits` < 1 | Must be a positive integer |
| Invalid matcher/filter expression | Check regex syntax or numeric bounds |

#### WAF blocking requests

```bash
# Conservative approach: slow rate, legitimate user agent
python apileaks.py par \
  --target https://protected-api.example.com/endpoint \
  --user-agent-custom "Mozilla/5.0 (compatible; Googlebot/2.1)" \
  --rate-limit 2 \
  --timeout 20
```

---

For the full CLI reference, see the [CLI Reference](cli-reference.md#parameter-fuzzing-par). For directory fuzzing, see [Usage Examples](usage-examples.md#directory-fuzzing).
