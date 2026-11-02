# Security Misconfiguration Testing (API8)

The Security Misconfiguration Module detects **OWASP API8 - Security Misconfiguration** vulnerabilities: permissive CORS policies and missing security response headers. It reuses the existing `CORSAnalyzer` and `SecurityHeadersAnalyzer` components via composition and only issues read-only (GET/OPTIONS) requests — making it inherently Safe Mode compatible.

The module runs in isolation as `apileaks owasp security_misconfig --target URL` or as part of an orchestrated `scan` run.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Detector 1 — Permissive CORS Policy](#detector-1--permissive-cors-policy)
- [Detector 2 — Missing Security Headers](#detector-2--missing-security-headers)
- [Command Reference](#command-reference)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Remediation](#remediation)

---

## 🎯 Overview

Security misconfiguration in APIs is pervasive and often an oversight rather than a deliberate choice: a wildcard CORS policy left over from development, a missing `Strict-Transport-Security` header, or `X-Content-Type-Options` never configured. These gaps are easy to discover and provide attackers with cross-origin data access, clickjacking vectors, or MIME-sniffing attack paths.

**Two detectors, both read-only:**

| Detector | Finding | Severity |
|----------|---------|----------|
| Wildcard or over-permissive CORS | `CORS_MISCONFIGURATION` | HIGH |
| Missing required security headers | `MISSING_SECURITY_HEADERS` | MEDIUM |

---

## 🚀 Quick Start

```bash
# Both detectors with built-in defaults
python apileaks.py owasp security_misconfig --target https://api.example.com

# With authentication (headers are added to all probes)
python apileaks.py owasp security_misconfig \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Check only specific headers
python apileaks.py owasp security_misconfig \
  --target https://api.example.com \
  --misconfig-required-headers Strict-Transport-Security \
  --misconfig-required-headers Content-Security-Policy \
  --misconfig-required-headers X-Content-Type-Options

# Run alongside other modules
python apileaks.py scan \
  --target https://api.example.com \
  --modules security_misconfig,inventory,auth
```

---

## Detector 1 — Permissive CORS Policy

**Finding:** `CORS_MISCONFIGURATION` · **Severity:** HIGH (CRITICAL for credentials + wildcard) · **OWASP:** API8

Sends OPTIONS preflight requests with crafted `Origin` headers to probe the API's CORS policy. A finding is emitted when:

- The response allows `Origin: *` (wildcard origin)
- The response allows credentials (`Access-Control-Allow-Credentials: true`) alongside a wildcard or overly permissive origin
- The response allows dangerous methods (DELETE, PUT on wildcard origins)
- The overall CORS security risk is rated MEDIUM or above

The module delegates all CORS analysis to the existing `CORSAnalyzer` component.

---

## Detector 2 — Missing Security Headers

**Finding:** `MISSING_SECURITY_HEADERS` · **Severity:** MEDIUM · **OWASP:** API8

Issues a GET request to each endpoint and checks the response headers against the configured `required_headers` list.

**Built-in required headers:**

| Header | Purpose |
|--------|---------|
| `Strict-Transport-Security` | Enforces HTTPS |
| `X-Content-Type-Options` | Prevents MIME sniffing |
| `X-Frame-Options` | Prevents clickjacking |
| `Content-Security-Policy` | Restricts resource loading |

```bash
# Check only specific headers (replaces built-in list)
python apileaks.py owasp security_misconfig \
  --target https://api.example.com \
  --misconfig-required-headers Strict-Transport-Security \
  --misconfig-required-headers X-Content-Type-Options \
  --misconfig-required-headers Permissions-Policy
```

---

## 📖 Command Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--misconfig-required-headers HEADER` | HTTP response header that must be present (repeatable). Replaces the built-in list when any value is supplied. | `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` |

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["security_misconfig"]

  security_misconfig_testing:
    enabled: true
    required_headers:
      - "Strict-Transport-Security"
      - "X-Content-Type-Options"
      - "X-Frame-Options"
      - "Content-Security-Policy"
```

---

## 📊 Finding Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `CORS_MISCONFIGURATION` | HIGH | Wildcard origin, credentials+wildcard, or dangerous methods allowed |
| `MISSING_SECURITY_HEADERS` | MEDIUM | One or more required security headers absent from the response |

---

## 🛡️ Remediation

### CORS misconfiguration

- **Never use `*` for authenticated endpoints.** If you need cross-origin access, enumerate the specific allowed origins explicitly.
- **Never combine `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *`.** Browsers block this combination, but some backends will still reflect it.
- **Allowlist your origins:** Maintain an explicit list of trusted domains and reject any `Origin` not in it.
- **Restrict allowed methods:** Only allow the HTTP methods the API actually uses cross-origin.

### Missing security headers

- `Strict-Transport-Security`: `max-age=31536000; includeSubDomains`
- `X-Content-Type-Options`: `nosniff`
- `X-Frame-Options`: `DENY` or `SAMEORIGIN`
- `Content-Security-Policy`: At minimum `default-src 'self'`
- Apply these at the reverse proxy / CDN layer so they are consistent across all endpoints.

---

See also: [OWASP Coverage](README.md) · [OWASP Command Reference](../owasp-command.md) · [Scan Guide](../scan-guide.md)
