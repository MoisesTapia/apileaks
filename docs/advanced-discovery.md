# Advanced Discovery Module

The **Advanced Discovery** module of APILeak provides advanced attack surface mapping capabilities that go beyond traditional fuzzing. This module includes subdomain discovery, CORS policy analysis, and security header verification.

## 📋 Table of Contents

- [Overview](#overview)
- [Components](#components)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [Practical Examples](#practical-examples)
- [Results Interpretation](#results-interpretation)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

Advanced Discovery extends APILeak's capabilities to provide complete attack surface mapping, including:

### 🎯 **Main Objectives**
- **Complete Mapping**: Discover all infrastructure related to the API
- **Security Analysis**: Evaluate security configurations at infrastructure level
- **Risk Detection**: Identify dangerous configurations in CORS and headers
- **Attack Surface**: Provide a complete view of entry points

### 🔍 **Capabilities**
- Automatic subdomain discovery
- Comprehensive CORS policy analysis
- Critical security header verification
- Insecure configuration detection
- Finding generation with appropriate severity

## Components

### 1. 🌐 **Subdomain Discovery**

Discovers subdomains related to the target domain.

**Features:**
- Tests common subdomains (api, dev, staging, test, qa, admin, etc.)
- DNS verification and HTTP accessibility
- Detection of sensitive subdomains (dev, staging, admin)
- Concurrent processing with rate limiting

**Tested Subdomain Patterns:**
```
api, www, dev, staging, test, qa, uat, prod, production,
admin, management, dashboard, portal, app, mobile,
v1, v2, v3, beta, alpha, demo, sandbox, internal
```

### 2. 🔒 **CORS Analyzer**

Analyzes CORS policies to detect insecure configurations.

**Tests Performed:**
- Wildcard origins (`*`)
- Suspicious origins (`evil.com`, `attacker.com`)
- Dangerous methods (DELETE, PUT, PATCH)
- Credentials with wildcard (CRITICAL)
- Permissive configurations

**Test Origins:**
```
https://evil.com
https://attacker.com
http://localhost:3000
https://example.com
null
*
```

### 3. 🛡️ **Security Headers Analyzer**

Verifies the presence and configuration of critical security headers.

**Analyzed Headers:**
- `X-Frame-Options` - Clickjacking protection
- `Content-Security-Policy` - Content security policy
- `Strict-Transport-Security` - HSTS for forced HTTPS
- `X-Content-Type-Options` - MIME sniffing prevention
- `Referrer-Policy` - Referrer information control
- `Permissions-Policy` - Browser permissions control
- `X-XSS-Protection` - XSS protection (legacy)
- `Cache-Control` - Cache control
- `X-Permitted-Cross-Domain-Policies` - Cross-domain policies

## Configuration

### Basic Configuration

```yaml
# Minimal configuration
advanced_discovery:
  enabled: true
  subdomain_discovery: true
  cors_analysis: true
  security_headers: true
```

### Full Configuration

```yaml
advanced_discovery:
  enabled: true
  
  # Subdomain discovery configuration
  subdomain_discovery: true
  subdomain_wordlist:
    - "api"
    - "www"
    - "dev"
    - "staging"
    - "test"
    - "qa"
    - "uat"
    - "prod"
    - "production"
    - "admin"
    - "management"
    - "dashboard"
    - "portal"
    - "app"
    - "mobile"
    - "v1"
    - "v2"
    - "v3"
    - "beta"
    - "alpha"
    - "demo"
    - "sandbox"
    - "internal"
  
  # CORS analysis configuration
  cors_analysis: true
  cors_test_origins:
    - "https://evil.com"
    - "https://attacker.com"
    - "http://localhost:3000"
    - "https://example.com"
    - "null"
    - "*"
  
  # Security headers configuration
  security_headers: true
  
  # Performance configuration
  max_concurrent: 10
  timeout: 10.0
```

### Advanced Discovery Only Configuration

```yaml
# To run only Advanced Discovery without traditional fuzzing
target:
  base_url: "https://api.example.com"

advanced_discovery:
  enabled: true
  subdomain_discovery: true
  cors_analysis: true
  security_headers: true

# Disable other modules
fuzzing:
  endpoints:
    enabled: false
  parameters:
    enabled: false
  headers:
    enabled: false

owasp_testing:
  enabled_modules: []
```

## CLI Usage

### 1. **Basic Execution**

```bash
# Full scan with Advanced Discovery enabled
python apileaks.py full --target https://api.example.com
```

### 2. **With Configuration File**

```bash
# Use custom configuration
python apileaks.py full --config config/advanced_discovery.yaml
```

### 3. **With Additional Parameters**

```bash
# With rate limiting and authentication
python apileaks.py full \
  --target https://api.example.com \
  --rate-limit 5 \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --output advanced_scan
```

### 4. **With WAF Evasion**

```bash
# With random User-Agent to evade WAF
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --rate-limit 3
```

### 5. **With Detailed Logging**

```bash
# With logging for debugging
python apileaks.py full \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file advanced_discovery.log
```

## Practical Examples

### Example 1: Corporate API Scan

```bash
# Configuration for a corporate API with multiple subdomains
python apileaks.py full \
  --config config/corporate_api.yaml \
  --target https://api.company.com \
  --rate-limit 5 \
  --output corporate_scan_$(date +%Y%m%d)
```

**Configuration file (`config/corporate_api.yaml`):**
```yaml
target:
  base_url: "https://api.company.com"
  timeout: 15

advanced_discovery:
  enabled: true
  subdomain_discovery: true
  subdomain_wordlist:
    - "api"
    - "api-dev"
    - "api-staging"
    - "api-prod"
    - "dev"
    - "staging"
    - "test"
    - "qa"
    - "admin"
    - "management"
    - "internal"
  cors_analysis: true
  security_headers: true
  max_concurrent: 5
  timeout: 15.0

rate_limiting:
  requests_per_second: 5
  burst_size: 10
  adaptive: true
```

### Example 2: Quick Security Analysis

```bash
# Security analysis only, without fuzzing
python apileaks.py full \
  --config config/security_only.yaml \
  --target https://api.example.com
```

**Configuration file (`config/security_only.yaml`):**
```yaml
target:
  base_url: "https://api.example.com"

advanced_discovery:
  enabled: true
  subdomain_discovery: false  # Disable for a quick scan
  cors_analysis: true
  security_headers: true
  max_concurrent: 10
  timeout: 5.0

fuzzing:
  endpoints:
    enabled: false
  parameters:
    enabled: false
  headers:
    enabled: false

owasp_testing:
  enabled_modules: []
```

### Example 3: Complete Infrastructure Discovery

```bash
# Exhaustive discovery with a custom wordlist
python apileaks.py full \
  --config config/infrastructure_discovery.yaml \
  --target https://example.com \
  --rate-limit 3 \
  --output infrastructure_scan
```

## Results Interpretation

### Console Output

```
🎯 Target: https://api.example.com
⚡ Rate Limit: 10 req/sec

2026-01-07 [info] Phase 1: Starting subdomain discovery
2026-01-07 [info] Generated subdomain candidates count=23 domain=example.com
2026-01-07 [info] Accessible subdomain found subdomain=api.example.com status_code=200
2026-01-07 [info] Accessible subdomain found subdomain=dev.example.com status_code=200

2026-01-07 [info] Phase 3: Starting CORS analysis
2026-01-07 [info] CORS analysis completed endpoints_analyzed=3

2026-01-07 [info] Phase 4: Starting security headers analysis
2026-01-07 [info] Security headers analysis completed endpoints_analyzed=3

==================================================
APILeak Scan Completed Successfully
==================================================
Target: https://api.example.com
Discovered Subdomains: 2
Total Findings: 15
Critical: 0
High: 3
Medium: 8
Low: 4
Info: 0
```

### Finding Types

#### 🔴 **CRITICAL**
- `CORS_WILDCARD_WITH_CREDENTIALS`: CORS with wildcard (*) and credentials enabled

#### 🟠 **HIGH**
- `CORS_WILDCARD_ORIGIN`: CORS with wildcard origin
- `CORS_SUSPICIOUS_ORIGINS`: Suspicious origins allowed
- `MISSING_SECURITY_HEADERS`: Multiple critical headers missing

#### 🟡 **MEDIUM**
- `SENSITIVE_SUBDOMAIN_EXPOSURE`: Sensitive subdomains exposed (dev, staging)
- `CORS_DANGEROUS_METHODS`: Dangerous methods allowed via CORS
- `INSECURE_SECURITY_HEADERS`: Headers with insecure configuration
- `LOW_SECURITY_HEADERS_SCORE`: Low security headers score

#### 🔵 **INFO**
- `SUBDOMAIN_DISCOVERY`: Discovered subdomains

### HTML Report

The HTML report includes:
- **Dashboard**: Overview with metrics
- **Discovered Subdomains**: Complete list with status
- **CORS Analysis**: Results per endpoint
- **Security Headers**: Score and recommendations
- **Detailed Findings**: With evidence and recommendations

### JSON Report

```json
{
  "scan_id": "12345678-1234-1234-1234-123456789012",
  "target": "https://api.example.com",
  "advanced_results": {
    "target_domain": "example.com",
    "discovered_subdomains": ["api.example.com", "www.example.com"],
    "total_findings": 15,
    "high_risk_findings": 3
  },
  "findings": [
    {
      "category": "CORS_WILDCARD_ORIGIN",
      "severity": "HIGH",
      "endpoint": "https://api.example.com",
      "evidence": "CORS policy allows wildcard origin (*)",
      "recommendation": "Specify explicit allowed origins"
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: APILeak Advanced Discovery
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      
      - name: Install APILeak
        run: |
          pip install -r requirements.txt
      
      - name: Run Advanced Discovery
        run: |
          python apileaks.py full \
            --config config/ci_advanced_discovery.yaml \
            --target ${{ secrets.API_TARGET }} \
            --output ci_scan_${{ github.run_number }} \
            --log-level WARNING \
            --json-logs
      
      - name: Upload Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

### GitLab CI

```yaml
stages:
  - security-scan

advanced-discovery:
  stage: security-scan
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - |
      python apileaks.py full \
        --config config/ci_advanced_discovery.yaml \
        --target $API_TARGET \
        --output ci_scan_$CI_PIPELINE_ID \
        --rate-limit 5 \
        --log-level WARNING
  artifacts:
    reports:
      junit: reports/ci_scan_$CI_PIPELINE_ID.xml
    paths:
      - reports/
  only:
    - main
    - develop
```

### Environment Variables

```bash
# Configuration via environment variables
export APILEAK_TARGET="https://api.example.com"
export APILEAK_RATE_LIMIT="5"
export APILEAK_OUTPUT_DIR="reports"
export APILEAK_TIMEOUT="15"

# Run with variables
python apileaks.py full --config config/advanced_discovery.yaml
```

## Troubleshooting

### Common Problems

#### 1. **DNS Resolution Failed**
```
Error: DNS resolution failed for subdomain
```
**Solution:**
- Check network connectivity
- Use `dns_resolution: false` in the configuration to skip DNS verification
- Verify that the target domain is valid

#### 2. **Rate Limiting Detected**
```
Warning: Rate limit detected, backing off
```
**Solution:**
- Reduce `requests_per_second` in the configuration
- Increase `timeout` for requests
- Enable `adaptive: true` in rate limiting

#### 3. **Timeouts in CORS Analysis**
```
Error: CORS test failed - timeout
```
**Solution:**
- Increase `timeout` in the CORS configuration
- Reduce `max_concurrent` for less concurrency
- Verify that the endpoint responds to OPTIONS requests

#### 4. **No Subdomains Found**
```
Info: No accessible subdomains found
```
**Possible Causes:**
- Domain has no public subdomains
- Wordlist too limited
- Server's rate limiting too aggressive

**Solution:**
- Expand `subdomain_wordlist`
- Manually verify some subdomains
- Adjust rate limiting

### Debug Configuration

```yaml
# Configuration for debugging
advanced_discovery:
  enabled: true
  subdomain_discovery: true
  cors_analysis: true
  security_headers: true
  max_concurrent: 1  # Reduce concurrency
  timeout: 30.0      # Increase timeout

rate_limiting:
  requests_per_second: 1  # Very slow for debugging
  burst_size: 1
```

```bash
# Run with full debug
python apileaks.py full \
  --config config/debug_advanced_discovery.yaml \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log
```

### Useful Logs

```bash
# Filter Advanced Discovery logs
grep "advanced_discovery" debug.log

# Show errors only
grep "ERROR" debug.log | grep "advanced_discovery"

# Show final statistics
grep "statistics" debug.log
```

## Best Practices

### 1. **Responsible Rate Limiting**
- Use `requests_per_second: 5-10` for public APIs
- Enable `adaptive: true` for automatic adjustment
- Respect `Retry-After` headers

### 2. **Timeout Configuration**
- `timeout: 10-15` seconds for most cases
- Increase for slow or high-latency APIs
- Consider the server's geographic location

### 3. **Custom Wordlists**
- Adapt `subdomain_wordlist` to the organization
- Include company-specific patterns
- Consider naming conventions

### 4. **Operational Security**
- Do not run against production APIs without authorization
- Use conservative rate limiting
- Monitor the target server's logs

### 5. **Results Interpretation**
- Prioritize CRITICAL and HIGH findings
- Manually verify sensitive subdomain findings
- Correlate with other security findings

---

## 📚 Additional References

- [General Configuration](configuration.md)
- [WAF Evasion](waf-evasion.md)
- [OWASP API Security Top 10](owasp/README.md)
- [CLI Reference](cli-reference.md)

---

**Need help?** Check our [troubleshooting guide](advanced/troubleshooting.md) or open an issue on GitHub.