# 🚀 APILeak - Quick Reference

## Basic Commands

`scan` is the primary command: it runs discovery + **all** OWASP modules by default and drives the CI gate. To run a single module in isolation, use `owasp <key>` (see below).

```bash
# Scan (runs discovery + all OWASP modules by default)
python apileaks.py scan --target https://api.example.com

# Specific modules (two or more keys, aggregated in one report)
python apileaks.py scan --target https://api.example.com --modules bola,auth,resource

# A single module in isolation
python apileaks.py owasp bola --target https://api.example.com

# With JWT authentication
python apileaks.py scan --target https://api.example.com --jwt YOUR_JWT_TOKEN

# With custom rate limiting
python apileaks.py scan --target https://api.example.com --rate-limit 5
```

> **Deprecation.** `full` and `main` are deprecated, hidden aliases of `scan`. They still forward to `scan` (with a one-line stderr notice) — migrate scripts to `scan`. A single-module alias call like `full --modules bola` becomes `apileaks owasp bola`.

## Endpoint Discovery (`dir`)

```bash
# Basic directory/endpoint fuzzing
python apileaks.py dir --target https://api.example.com

# Custom wordlist + gentle rate limit
python apileaks.py dir --target https://api.example.com \
  --wordlist wordlists/endpoints.txt --rate-limit 5

# Triage: filter by status class, save a session, export Markdown
python apileaks.py dir --target https://api.example.com \
  --status-code 2xx --save-session session.json --export md --export-file results.md

# Reload a saved session and triage interactively (opt-in prompt)
python apileaks.py dir --target https://api.example.com \
  --load-session session.json --interactive
```

Full `dir` option list: [CLI Reference](cli-reference.md#directory-fuzzing-dir).

## Available Modules

Run all of these at once with `scan`, or one in isolation with `owasp <key>`.

| Key | OWASP | Description |
|-----|-------|-------------|
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

```bash
# List modules (key, OWASP category, summary)
python apileaks.py owasp

# Run a single module in isolation
python apileaks.py owasp ssrf --target https://api.example.com
```

## Examples by API Type

### E-commerce API
```bash
python apileaks.py scan --target https://api.shop.com \
  --modules bola,auth,property \
  --jwt eyJ0eXAi... \
  --rate-limit 5
```

### Banking API
```bash
python apileaks.py scan --target https://api.bank.com \
  --modules bola,auth,function_auth \
  --jwt eyJ0eXAi... \
  --rate-limit 1
```

### Social Media API
```bash
python apileaks.py scan --target https://api.social.com \
  --modules bola,property,resource \
  --jwt eyJ0eXAi... \
  --rate-limit 10
```

## Quick YAML Configuration

```yaml
# config/quick_config.yaml
target:
  base_url: "https://api.example.com"

owasp_testing:
  enabled_modules: ["bola", "auth", "property", "resource"]

authentication:
  contexts:
    - name: "user"
      type: "bearer"
      token: "YOUR_JWT_TOKEN"
      privilege_level: 1

rate_limiting:
  requests_per_second: 10
```

```bash
python apileaks.py scan --config config/quick_config.yaml
```

## Environment Variables

```bash
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,resource"
export APILEAK_JWT_TOKEN="eyJ0eXAi..."
export APILEAK_RATE_LIMIT="5"

python apileaks.py scan
```

## Result Interpretation

### Exit Codes
- `0` - No critical/high vulnerabilities
- `1` - High vulnerabilities found
- `2` - Critical vulnerabilities found

### Severity Levels
- **CRITICAL** - Immediate fix required
- **HIGH** - Fix within 24-48h
- **MEDIUM** - Fix within 1-2 weeks
- **LOW** - Next development cycle

## Quick Troubleshooting

### Server Rate Limiting
```bash
python apileaks.py scan --target URL --rate-limit 1
```

### Timeouts
```bash
python apileaks.py scan --target URL --log-level DEBUG
```

### JWT Issues
```bash
python apileaks.py jwt decode YOUR_JWT_TOKEN
```

## CI/CD Integration

The severity gate default is now `high` (was `critical`). The example below pins `--fail-on critical` to keep the exit-code-2 check; drop it to use the `high` default.

```bash
#!/bin/bash
python apileaks.py scan \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --modules bola,auth,property \
  --rate-limit 3 \
  --ci-mode \
  --fail-on critical

if [ $? -eq 2 ]; then
    echo "❌ Critical vulnerabilities found!"
    exit 1
fi
```

---

For complete documentation, see: [CLI Reference](cli-reference.md)