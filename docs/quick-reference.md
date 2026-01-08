# 🚀 APILeak - Quick Reference

## Basic Commands

```bash
# Full scan (all modules)
python apileaks.py full --target https://api.example.com

# Specific modules
python apileaks.py full --target https://api.example.com --modules bola,auth,resource

# With JWT authentication
python apileaks.py full --target https://api.example.com --jwt YOUR_JWT_TOKEN

# With custom rate limiting
python apileaks.py full --target https://api.example.com --rate-limit 5
```

## Available Modules

| Code | Module | OWASP | Description |
|------|--------|-------|-------------|
| `bola` | BOLA Testing | API1 | Broken Object Level Authorization |
| `auth` | Authentication | API2 | Broken Authentication (JWT) |
| `property` | Property Level Auth | API3 | Broken Object Property Level Authorization |
| `resource` | Resource Consumption | API4 | Unrestricted Resource Consumption |
| `function_auth` | Function Level Auth | API5 | Broken Function Level Authorization |
| `ssrf` | SSRF Testing | API10 | Server Side Request Forgery |

## Examples by API Type

### E-commerce API
```bash
python apileaks.py full --target https://api.shop.com \
  --modules bola,auth,property \
  --jwt eyJ0eXAi... \
  --rate-limit 5
```

### Banking API
```bash
python apileaks.py full --target https://api.bank.com \
  --modules bola,auth,function_auth \
  --jwt eyJ0eXAi... \
  --rate-limit 1
```

### Social Media API
```bash
python apileaks.py full --target https://api.social.com \
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
python apileaks.py full --config config/quick_config.yaml
```

## Environment Variables

```bash
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,resource"
export APILEAK_JWT_TOKEN="eyJ0eXAi..."
export APILEAK_RATE_LIMIT="5"

python apileaks.py full
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
python apileaks.py full --target URL --rate-limit 1
```

### Timeouts
```bash
python apileaks.py full --target URL --log-level DEBUG
```

### JWT Issues
```bash
python apileaks.py jwt decode YOUR_JWT_TOKEN
```

## CI/CD Integration

```bash
#!/bin/bash
python apileaks.py full \
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