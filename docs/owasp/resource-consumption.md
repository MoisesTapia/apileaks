# Resource Consumption Testing (API4)

The Resource Consumption Testing Module detects **OWASP API4 - Unrestricted Resource Consumption** vulnerabilities: cases where an API accepts requests without enforcing limits on the number of requests (rate limiting), the size of payloads, the depth of nested structures, or the complexity of queries — allowing denial-of-service attacks or infrastructure cost exhaustion.

The module runs in isolation as `apileaks owasp resource --target URL` or as part of an orchestrated `scan` run.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Detector 1 — Rate Limiting Absence](#detector-1--rate-limiting-absence)
- [Detector 2 — Large Payload Acceptance](#detector-2--large-payload-acceptance)
- [Detector 3 — Deep JSON Nesting](#detector-3--deep-json-nesting)
- [Detector 4 — ReDoS Patterns](#detector-4--redos-patterns)
- [Detector 5 — Complex Queries](#detector-5--complex-queries)
- [Command Reference](#command-reference)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Remediation](#remediation)

---

## 🎯 Overview

Unlike most OWASP API Security categories, API4 is about resource exhaustion rather than unauthorized access. The attacker doesn't need special privileges — they just need to make requests that consume disproportionate resources: hundreds of requests per second, a 100MB payload, a JSON object nested 10,000 levels deep, or a regex that takes minutes to evaluate.

**Five detectors, all enabled by default:**

| Detector | Finding | Severity |
|----------|---------|----------|
| N rapid requests with no throttle | `MISSING_RATE_LIMITING` | MEDIUM |
| Large payload (1MB / 10MB) accepted | `LARGE_PAYLOAD_ACCEPTED` | MEDIUM |
| Deeply nested JSON accepted | `MISSING_RATE_LIMITING` | MEDIUM |
| ReDoS-susceptible regex patterns accepted | `MISSING_RATE_LIMITING` | MEDIUM |
| Complex query strings accepted without guard | `MISSING_RATE_LIMITING` | MEDIUM |

---

## 🚀 Quick Start

```bash
# All five detectors with built-in defaults
python apileaks.py owasp resource --target https://api.example.com

# With authentication
python apileaks.py owasp resource \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Higher burst to confirm rate limiting is absent
python apileaks.py owasp resource \
  --target https://api.example.com \
  --resource-burst-size 200

# Custom payload sizes (500KB and 5MB)
python apileaks.py owasp resource \
  --target https://api.example.com \
  --resource-payload-sizes 524288,5242880

# Deep nesting probe with custom depth
python apileaks.py owasp resource \
  --target https://api.example.com \
  --resource-json-depth 2000

# Run alongside other modules
python apileaks.py scan \
  --target https://api.example.com \
  --modules resource,business_flow,auth
```

---

## Detector 1 — Rate Limiting Absence

**Finding:** `MISSING_RATE_LIMITING` · **Severity:** MEDIUM · **OWASP:** API4

Issues `burst_size` (default 100) concurrent requests to each discovered endpoint. If the API accepts all of them without returning HTTP 429 or anti-automation headers, no rate limiting is in place.

```bash
# Default burst of 100
python apileaks.py owasp resource --target https://api.example.com

# Stronger confirmation
python apileaks.py owasp resource \
  --target https://api.example.com \
  --resource-burst-size 200
```

---

## Detector 2 — Large Payload Acceptance

**Finding:** `LARGE_PAYLOAD_ACCEPTED` · **Severity:** MEDIUM · **OWASP:** API4

Sends POST requests with payloads of increasing size (default: 1MB and 10MB) to every POST/PUT/PATCH endpoint. A 2xx response to a multi-megabyte payload indicates no input size validation.

```bash
# Default sizes (1MB, 10MB)
python apileaks.py owasp resource --target https://api.example.com

# Custom sizes in bytes
python apileaks.py owasp resource \
  --target https://api.example.com \
  --resource-payload-sizes 524288,5242880,52428800
```

---

## Detector 3 — Deep JSON Nesting

**Finding:** `MISSING_RATE_LIMITING` · **Severity:** MEDIUM · **OWASP:** API4

Sends a POST request with a JSON object nested `json_depth_limit` (default 1000) levels deep. If the server processes it without a 400 or timeout, it has no recursion guard — making it susceptible to stack-overflow or excessive memory allocation.

```bash
python apileaks.py owasp resource \
  --target https://api.example.com \
  --resource-json-depth 2000
```

---

## Detector 4 — ReDoS Patterns

**Finding:** `MISSING_RATE_LIMITING` · **Severity:** MEDIUM · **OWASP:** API4

Injects catastrophic backtracking regex patterns (e.g. `(a+)+$`, `([a-zA-Z]+)*$`) into query parameters. A response time significantly higher than the baseline indicates the server evaluates user-supplied patterns without a timeout guard — a ReDoS vulnerability.

---

## Detector 5 — Complex Queries

**Finding:** `MISSING_RATE_LIMITING` · **Severity:** MEDIUM · **OWASP:** API4

Sends complex SQL-like query strings and deeply chained filter expressions into query parameters. A 2xx response with high latency indicates the backend forwards or evaluates these without query complexity limits.

---

## 📖 Command Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--resource-burst-size N` | Concurrent requests in the rate-limit burst test | `100` |
| `--resource-payload-sizes BYTES` | Comma-separated payload sizes in bytes for the large-payload test | `1048576,10485760` |
| `--resource-json-depth N` | JSON nesting depth for the deep-nesting probe | `1000` |

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["resource"]

  resource_testing:
    enabled: true
    burst_size: 100
    large_payload_sizes:
      - 1048576    # 1 MB
      - 10485760   # 10 MB
    json_depth_limit: 1000
```

---

## 📊 Finding Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `MISSING_RATE_LIMITING` | MEDIUM | Endpoint accepted N rapid requests with no throttle |
| `LARGE_PAYLOAD_ACCEPTED` | MEDIUM | Endpoint accepted a multi-megabyte payload without rejection |

---

## 🛡️ Remediation

- **Rate limiting:** Enforce per-user, per-IP, and global request-rate limits at the API gateway and application layer. Return `429 Too Many Requests` with `Retry-After`.
- **Payload size limits:** Reject requests larger than the expected maximum at the reverse proxy / framework level. Never rely solely on application-level checks.
- **JSON depth limits:** Configure your JSON parser with a maximum depth (most parsers support this). Return `400 Bad Request` for over-deep structures.
- **ReDoS mitigation:** Never evaluate user-supplied regular expressions without a timeout. Use a safe regex library or validate patterns against an allowlist.
- **Query complexity limits:** Implement GraphQL query depth / complexity limits or equivalent for REST query parameters.

---

See also: [OWASP Coverage](README.md) · [Business Flows (API6)](business-flows.md) · [OWASP Command Reference](../owasp-command.md)
