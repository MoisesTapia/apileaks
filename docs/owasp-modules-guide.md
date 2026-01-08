# 🛡️ Complete OWASP Modules Guide - APILeak

This guide covers all OWASP modules implemented in APILeak, from basic concepts to advanced usage examples.

## 📋 Table of Contents

1. [Introduction to OWASP Modules](#introduction)
2. [Available Modules](#available-modules)
3. [Basic Usage](#basic-usage)
4. [Advanced Configuration](#advanced-configuration)
5. [Practical Examples](#practical-examples)
6. [Results Interpretation](#results-interpretation)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 Introduction

APILeak implements specialized modules for each category of the **OWASP API Security Top 10 2023**. Each module is designed to detect specific vulnerabilities through advanced automated testing techniques.

### Why use OWASP modules?

- **Complete Coverage**: Each module covers a specific OWASP Top 10 category
- **Specialized Testing**: Specific techniques for each type of vulnerability
- **Automation**: Automatic detection without manual intervention
- **Detailed Reports**: Clear evidence and remediation recommendations

---

## 🧩 Available Modules

| Module | OWASP Category | Description | Priority |
|--------|----------------|-------------|----------|
| `bola` | **API1** - Broken Object Level Authorization | Detects unauthorized object access | **P0** |
| `auth` | **API2** - Broken Authentication | Identifies JWT authentication flaws | **P0** |
| `property` | **API3** - Broken Object Property Level Authorization | Detects excessive data exposure | **P0** |
| `resource` | **API4** - Unrestricted Resource Consumption | Identifies missing rate limiting and DoS | **P1** |
| `function_auth` | **API5** - Broken Function Level Authorization | Detects privilege escalation | **P0** |

### Implementation Status

✅ **Fully Implemented**: `bola`, `auth`, `property`, `resource`, `function_auth`  
🚧 **In Development**: `ssrf` (API7), `business_flows` (API6)  
📋 **Planned**: `security_misconfig` (API8), `inventory_mgmt` (API9), `unsafe_consumption` (API10)

---

## 🚀 Basic Usage

### Basic Command

```bash
# Run ALL OWASP modules
python apileaks.py full --target https://api.example.com

# Run specific modules
python apileaks.py full --target https://api.example.com --modules bola,auth,resource
```

### Default Modules

By default, APILeak runs these modules in `full` mode:
```bash
bola,auth,property,resource,function_auth
```

### Module Syntax

```bash
--modules <module1>,<module2>,<module3>
```

**Available modules:**
- `bola` - BOLA Testing
- `auth` - Authentication Testing  
- `property` - Property Level Authorization
- `resource` - Resource Consumption
- `function_auth` - Function Level Authorization

---

## ⚙️ Advanced Configuration

### YAML Configuration File

```yaml
# config/owasp_config.yaml
target:
  base_url: "https://api.example.com"
  timeout: 30

owasp_testing:
  enabled_modules: ["bola", "auth", "property", "resource", "function_auth"]
  
  # Module-specific configuration
  bola_testing:
    enabled: true
    id_patterns: ["sequential", "guid", "uuid"]
    test_contexts: ["anonymous", "user", "admin"]
  
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: "wordlists/jwt_secrets.txt"
    test_logout_invalidation: true
  
  property_testing:
    enabled: true
    sensitive_fields: ["password", "api_key", "secret", "ssn"]
    mass_assignment_fields: ["is_admin", "role", "permissions"]
  
  resource_testing:
    enabled: true
    burst_size: 100
    large_payload_sizes: [1048576, 10485760]  # 1MB, 10MB
    json_depth_limit: 1000
  
  function_auth_testing:
    enabled: true
    admin_endpoints: ["/admin", "/api/admin", "/management"]
    dangerous_methods: ["DELETE", "PUT", "PATCH"]

# Authentication for testing
authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 1
    - name: "admin"
      type: "bearer"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 3

rate_limiting:
  requests_per_second: 10
  adaptive: true
  respect_retry_after: true
```

### Environment Variables

```bash
# Basic configuration
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,resource"
export APILEAK_RATE_LIMIT="5"
export APILEAK_JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Run with environment variables
python apileaks.py full
```

---

## 📚 Practical Examples

### 1. 🔐 BOLA Testing (API1)

**What does it detect?**
- Unauthorized access to other users' objects
- Sequential ID enumeration
- Horizontal privilege escalation

```bash
# Basic BOLA test
python apileaks.py full --target https://api.example.com --modules bola

# BOLA with multiple authentication contexts
python apileaks.py full --target https://api.example.com --modules bola \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# BOLA with low rate limiting for sensitive APIs
python apileaks.py full --target https://api.example.com --modules bola \
  --rate-limit 2
```

**Example of detected vulnerability:**
```
🚨 CRITICAL: BOLA_ANONYMOUS_ACCESS
Endpoint: https://api.example.com/users/123
Evidence: Object 123 accessible without authentication. Status: 200, Size: 245 bytes
Recommendation: Implement proper authentication checks for object access.
```

### 2. 🔑 Authentication Testing (API2)

**What does it detect?**
- Weak JWT algorithms (none, algorithm confusion)
- Tokens that don't expire properly
- Weak JWT secrets
- Endpoints accessible without authentication

```bash
# Complete authentication test
python apileaks.py full --target https://api.example.com --modules auth

# Test with specific JWT token
python apileaks.py full --target https://api.example.com --modules auth \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Test with custom JWT secrets wordlist
python apileaks.py full --config config/auth_config.yaml --target https://api.example.com
```

**Example configuration for auth testing:**
```yaml
owasp_testing:
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: "wordlists/custom_jwt_secrets.txt"
    test_logout_invalidation: true
```

### 3. 📊 Property Level Authorization (API3)

**What does it detect?**
- Exposure of sensitive fields (passwords, API keys)
- Mass assignment vulnerabilities
- Undocumented fields in responses
- Modifiable read-only properties

```bash
# Property level authorization test
python apileaks.py full --target https://api.example.com --modules property

# With custom sensitive fields
python apileaks.py full --config config/property_config.yaml --target https://api.example.com
```

**Custom configuration:**
```yaml
owasp_testing:
  property_testing:
    enabled: true
    sensitive_fields: 
      - "password"
      - "api_key" 
      - "secret"
      - "ssn"
      - "credit_card"
      - "bank_account"
    mass_assignment_fields:
      - "is_admin"
      - "role"
      - "permissions"
      - "user_id"
      - "account_type"
```

### 4. ⚡ Resource Consumption (API4)

**What does it detect?**
- Missing rate limiting
- Large payload acceptance
- Deeply nested JSON
- ReDoS vulnerabilities
- Complex query processing

```bash
# Basic resource consumption test
python apileaks.py full --target https://api.example.com --modules resource

# Test with custom burst
python apileaks.py full --target https://api.example.com --modules resource \
  --rate-limit 20

# Test with advanced configuration
python apileaks.py full --config config/resource_config.yaml --target https://api.example.com
```

**Advanced configuration:**
```yaml
owasp_testing:
  resource_testing:
    enabled: true
    burst_size: 150                    # Requests for rate limiting test
    large_payload_sizes: [1048576, 10485760, 104857600]  # 1MB, 10MB, 100MB
    json_depth_limit: 1500             # JSON depth
```

### 5. 🛡️ Function Level Authorization (API5)

**What does it detect?**
- Unauthorized access to administrative functions
- HTTP method bypass
- Parameter and header bypass
- Vertical privilege escalation

```bash
# Function level authorization test
python apileaks.py full --target https://api.example.com --modules function_auth

# With custom administrative endpoints
python apileaks.py full --config config/function_auth_config.yaml --target https://api.example.com
```

**Custom configuration:**
```yaml
owasp_testing:
  function_auth_testing:
    enabled: true
    admin_endpoints: 
      - "/admin"
      - "/api/admin" 
      - "/management"
      - "/dashboard"
      - "/api/v1/admin"
    dangerous_methods: ["DELETE", "PUT", "PATCH", "POST"]
```

---

## 🎯 Real-World Use Case Examples

### Case 1: E-commerce API

```bash
# Complete testing for e-commerce API
python apileaks.py full --target https://api.shop.example.com \
  --modules bola,auth,property,resource \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --rate-limit 5 \
  --output ecommerce_security_test
```

### Case 2: Banking API (High Security)

```bash
# Testing with very low rate limiting for critical APIs
python apileaks.py full --target https://api.bank.example.com \
  --modules bola,auth,property,function_auth \
  --rate-limit 1 \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --log-level INFO \
  --output banking_security_audit
```

### Case 3: Social Media API

```bash
# Testing focused on BOLA and property level auth
python apileaks.py full --target https://api.social.example.com \
  --modules bola,property,resource \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --rate-limit 10 \
  --output social_media_test
```

### Case 4: CI/CD Testing

```bash
#!/bin/bash
# ci_security_test.sh

export APILEAK_TARGET="https://staging-api.example.com"
export APILEAK_MODULES="bola,auth,property"
export APILEAK_JWT_TOKEN="${CI_JWT_TOKEN}"
export APILEAK_RATE_LIMIT="3"
export APILEAK_OUTPUT_DIR="security_reports"

python apileaks.py full --log-level ERROR

# Check for critical vulnerabilities
if [ $? -eq 2 ]; then
    echo "❌ Critical vulnerabilities found! Failing CI/CD pipeline."
    exit 1
elif [ $? -eq 1 ]; then
    echo "⚠️ High severity vulnerabilities found. Review required."
    exit 0
else
    echo "✅ No critical vulnerabilities found."
    exit 0
fi
```

---

## 📊 Results Interpretation

### Severity Levels

| Severity | Description | Required Action |
|----------|-------------|-----------------|
| **CRITICAL** | Vulnerabilities allowing immediate unauthorized access | Immediate fix |
| **HIGH** | Significant vulnerabilities requiring urgent attention | Fix within 24-48h |
| **MEDIUM** | Moderate vulnerabilities that should be fixed | Fix within 1-2 weeks |
| **LOW** | Minor security issues | Fix in next cycle |
| **INFO** | Information about configuration or discovered endpoints | Optional review |

### Finding Categories by Module

#### BOLA Module (API1)
- `BOLA_ANONYMOUS_ACCESS` (CRITICAL)
- `BOLA_HORIZONTAL_ESCALATION` (CRITICAL)
- `BOLA_ID_ENUMERATION` (HIGH)
- `BOLA_OBJECT_ACCESS` (HIGH)

#### Auth Module (API2)
- `AUTH_BYPASS` (CRITICAL)
- `WEAK_JWT_ALGORITHM` (HIGH)
- `TOKEN_NOT_EXPIRED` (HIGH)
- `WEAK_JWT_SECRET` (HIGH)

#### Property Module (API3)
- `SENSITIVE_DATA_EXPOSURE` (CRITICAL)
- `MASS_ASSIGNMENT` (HIGH)
- `UNDOCUMENTED_FIELD` (MEDIUM)
- `READONLY_PROPERTY_MODIFIED` (HIGH)

#### Resource Module (API4)
- `MISSING_RATE_LIMITING` (MEDIUM)
- `LARGE_PAYLOAD_ACCEPTED` (MEDIUM/HIGH)
- `REDOS_VULNERABILITY` (HIGH)
- `COMPLEX_QUERY_PROCESSED` (MEDIUM/HIGH)

#### Function Auth Module (API5)
- `ADMIN_ACCESS_ANONYMOUS` (CRITICAL)
- `FUNCTION_LEVEL_BYPASS` (HIGH)
- `HTTP_METHOD_BYPASS` (HIGH)
- `PARAMETER_BYPASS` (MEDIUM)

### Example Report

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "https://api.example.com",
  "timestamp": "2024-01-08T10:30:00Z",
  "summary": {
    "total_findings": 15,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 2,
    "info": 1
  },
  "owasp_coverage": {
    "tested_categories": 5,
    "total_categories": 10,
    "coverage_percentage": 50.0
  },
  "findings": [
    {
      "id": "finding-001",
      "category": "BOLA_ANONYMOUS_ACCESS",
      "owasp_category": "API1",
      "severity": "CRITICAL",
      "endpoint": "https://api.example.com/users/123",
      "method": "GET",
      "evidence": "Object 123 accessible without authentication. Status: 200, Size: 245 bytes",
      "recommendation": "Implement proper authentication checks for object access."
    }
  ]
}
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Server Rate Limiting
```
Error: Too many requests (429)
```
**Solution:**
```bash
# Reduce rate limit
python apileaks.py full --target https://api.example.com --rate-limit 1

# Use adaptive mode (default)
python apileaks.py full --target https://api.example.com --modules bola
```

#### 2. Connection Timeouts
```
Error: Connection timeout
```
**Solution:**
```yaml
target:
  timeout: 60  # Increase timeout to 60 seconds
```

#### 3. Invalid JWT Token
```
Warning: JWT token validation failed
```
**Solution:**
```bash
# Verify JWT token
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Generate new token
python apileaks.py jwt encode '{"sub":"user123","role":"user"}' --secret mysecret
```

#### 4. Wordlists Not Found
```
Error: Wordlist file not found
```
**Solution:**
```bash
# Verify wordlists exist
ls -la wordlists/

# Use custom wordlists
python apileaks.py full --config config/custom_wordlists.yaml --target https://api.example.com
```

### Debug Logs

```bash
# Enable detailed logging
python apileaks.py full --target https://api.example.com \
  --modules bola \
  --log-level DEBUG \
  --log-file debug.log
```

### Network Configuration

```yaml
# For APIs behind proxies or with custom SSL
target:
  verify_ssl: false  # Only for testing, not in production
  timeout: 30
  
rate_limiting:
  adaptive: true
  respect_retry_after: true
```

---

## 📈 Best Practices

### 1. **Module Selection**
- **Public APIs**: Use all modules (`bola,auth,property,resource,function_auth`)
- **Internal APIs**: Focus on `bola,property,function_auth`
- **High Traffic APIs**: Use `resource,auth` with low rate limiting

### 2. **Rate Limiting**
- **Production APIs**: `--rate-limit 1-5`
- **Staging APIs**: `--rate-limit 5-10`
- **Development APIs**: `--rate-limit 10-20`

### 3. **Authentication**
- Use multiple authentication contexts when possible
- Include tokens with different privilege levels
- Test with both valid and invalid tokens

### 4. **CI/CD Integration**
```bash
# Script for CI/CD
python apileaks.py full \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --modules bola,auth,property \
  --rate-limit 3 \
  --output "security-scan-${BUILD_NUMBER}" \
  --log-level ERROR

# Check exit codes
# 0 = No critical/high findings
# 1 = High severity findings found  
# 2 = Critical findings found (fail pipeline)
```

### 5. **Reporting**
- Use descriptive names for outputs
- Generate multiple formats (JSON for automation, HTML for humans)
- Archive reports with timestamps

---

## 🚀 Next Steps

### Modules in Development
- **SSRF Testing** (API7) - Server Side Request Forgery
- **Business Flows** (API6) - Unrestricted Access to Sensitive Business Flows
- **Security Misconfiguration** (API8)

### Future Features
- **Machine Learning**: Intelligent pattern detection
- **Custom Rules**: Industry-specific custom rules
- **Integration APIs**: APIs for SIEM/SOAR integration
- **Real-time Monitoring**: Continuous API monitoring

---

## 📞 Support

### Additional Documentation
- **[Quick Reference](quick-reference.md)** - Basic commands and examples
- **[CI/CD Integration](ci-cd-integration.md)** - Configuration for automated pipelines
- **[Troubleshooting Guide](troubleshooting-guide.md)** - Common problem solutions
- **[Example Configurations](../config/examples/README.md)** - Ready-to-use examples

### Available Example Configurations
- **[BOLA Testing](../config/examples/bola_testing_config.yaml)** - API1: Broken Object Level Authorization
- **[Auth Testing](../config/examples/auth_testing_config.yaml)** - API2: Broken Authentication
- **[Property Testing](../config/examples/property_testing_config.yaml)** - API3: Broken Object Property Level Authorization
- **[Resource Testing](../config/resource_testing_example.yaml)** - API4: Unrestricted Resource Consumption
- **[Function Auth Testing](../config/examples/function_auth_testing_config.yaml)** - API5: Broken Function Level Authorization

### Report Issues
- **Troubleshooting:** First check the [Troubleshooting Guide](troubleshooting-guide.md)
- **GitHub Issues:** [APILeak Issues](https://github.com/your-org/apileak/issues)
- **Documentation:** [APILeak Docs](https://docs.apileak.com)

---

*This documentation covers APILeak version 0.1.0. For updates, check the [CHANGELOG](../CHANGELOG.md).*