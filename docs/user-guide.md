# APILeak User Guide

Complete guide for using APILeak to perform comprehensive API security testing with OWASP API Security Top 10 2023 coverage.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [OWASP Module Testing](#owasp-module-testing)
- [Configuration Management](#configuration-management)
- [WAF Evasion Techniques](#waf-evasion-techniques)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Network access to target API
- Valid authentication tokens (if testing authenticated endpoints)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/apileak.git
cd apileak

# Set up development environment
make setup-dev

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Verify installation
python apileaks.py --help
```

### Quick Start

```bash
# Basic endpoint discovery
python apileaks.py dir --target https://api.example.com

# Parameter fuzzing
python apileaks.py par --target https://api.example.com

# Full security scan with OWASP modules
python apileaks.py full --target https://api.example.com --modules bola,auth,property
```

## Basic Usage

### Command Structure

APILeak supports three main scanning modes:

1. **Directory Fuzzing (`dir`)** - Discover hidden endpoints
2. **Parameter Fuzzing (`par`)** - Find hidden parameters
3. **Full Scan (`full`)** - Comprehensive security testing

### Directory Fuzzing

Discover hidden API endpoints and administrative interfaces:

```bash
# Basic directory fuzzing
python apileaks.py dir --target https://api.example.com

# With custom wordlist
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt

# With WAF evasion
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --rate-limit 5

# Focus on specific status codes
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 200,401,403 \
  --output endpoint_discovery
```

### Parameter Fuzzing

Identify hidden parameters and input validation issues:

```bash
# Basic parameter fuzzing
python apileaks.py par --target https://api.example.com

# With authentication
python apileaks.py par \
  --target https://api.example.com/users \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test specific HTTP methods
python apileaks.py par \
  --target https://api.example.com \
  --methods GET,POST,PUT \
  --wordlist wordlists/parameters.txt
```

### Full Security Scan

Comprehensive security testing with OWASP modules:

```bash
# Basic full scan
python apileaks.py full --target https://api.example.com

# With specific OWASP modules
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# With configuration file
python apileaks.py full \
  --config config/examples/rest_api_config.yaml \
  --target https://api.example.com
```

## Advanced Features

### Framework Detection

Automatically detect API frameworks and adapt testing strategies:

```bash
# Enable framework detection
python apileaks.py full \
  --target https://api.example.com \
  --detect-framework \
  --framework-confidence 0.8

# Short flag version
python apileaks.py full \
  --target https://api.example.com \
  --df \
  --framework-confidence 0.9
```

**Supported Frameworks:**
- FastAPI
- Express.js
- Django REST Framework
- Flask
- Spring Boot
- ASP.NET Core
- Laravel
- Ruby on Rails

### API Version Discovery

Discover and test multiple API versions:

```bash
# Enable version fuzzing
python apileaks.py full \
  --target https://api.example.com \
  --fuzz-versions \
  --version-patterns "/v1,/v2,/api/v1,/api/v2"

# Short flag version
python apileaks.py full \
  --target https://api.example.com \
  --fv

# Combined framework and version detection
python apileaks.py full \
  --target https://api.example.com \
  --df --fv \
  --output comprehensive_discovery
```

### Status Code Filtering

Focus testing on specific response codes:

```bash
# Success responses only
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 200-299

# Authentication-related responses
python apileaks.py par \
  --target https://api.example.com \
  --status-code 401,403

# Error analysis
python apileaks.py full \
  --target https://api.example.com \
  --status-code 500-599 \
  --modules bola,auth
```

## OWASP Module Testing

APILeak provides specialized modules for each OWASP API Security Top 10 category:

### API1 - Broken Object Level Authorization (BOLA)

Test for unauthorized access to objects:

```bash
# BOLA testing only
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# With multiple authentication contexts
python apileaks.py full \
  --config config/examples/bola_testing_config.yaml \
  --target https://api.example.com
```

**What BOLA Testing Covers:**
- Sequential ID enumeration
- GUID/UUID enumeration
- Cross-user object access
- Privilege escalation detection
- Anonymous access testing

### API2 - Broken Authentication

Test authentication mechanisms and JWT security:

```bash
# Authentication testing
python apileaks.py full \
  --target https://api.example.com \
  --modules auth \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# JWT-specific testing
python apileaks.py full \
  --config config/examples/auth_testing_config.yaml \
  --target https://api.example.com
```

**What Authentication Testing Covers:**
- JWT algorithm confusion (RS256/HS256)
- Weak JWT secrets
- Token expiration validation
- Logout token invalidation
- Algorithm downgrade attacks

### API3 - Broken Object Property Level Authorization

Test for excessive data exposure and mass assignment:

```bash
# Property-level authorization testing
python apileaks.py full \
  --target https://api.example.com \
  --modules property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Comprehensive property testing
python apileaks.py full \
  --config config/examples/property_testing_config.yaml \
  --target https://api.example.com
```

**What Property Testing Covers:**
- Sensitive data exposure detection
- Mass assignment vulnerabilities
- Read-only field modification
- Undocumented field discovery
- PII leakage detection

### API4 - Unrestricted Resource Consumption

Test for DoS vulnerabilities and rate limiting:

```bash
# Resource consumption testing
python apileaks.py full \
  --target https://api.example.com \
  --modules resource \
  --rate-limit 20  # Higher rate for resource testing

# Comprehensive resource testing
python apileaks.py full \
  --config config/examples/resource_testing_example.yaml \
  --target https://api.example.com
```

**What Resource Testing Covers:**
- Rate limiting detection
- Large payload handling
- JSON depth bomb testing
- Array size limits
- ReDoS pattern detection

### API5 - Broken Function Level Authorization

Test for privilege escalation and admin access:

```bash
# Function-level authorization testing
python apileaks.py full \
  --target https://api.example.com \
  --modules function_auth \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Admin endpoint testing
python apileaks.py full \
  --config config/examples/function_auth_testing_config.yaml \
  --target https://api.example.com
```

**What Function Auth Testing Covers:**
- Admin endpoint discovery
- HTTP method bypass testing
- Parameter-based privilege escalation
- Header-based bypass detection
- Anonymous admin access

### Multiple Module Testing

Run multiple OWASP modules together:

```bash
# Core P0 modules
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property,function_auth \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# All available modules
python apileaks.py full \
  --target https://api.example.com \
  --modules all \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Configuration Management

### Configuration File Structure

APILeak uses YAML configuration files for complex testing scenarios:

```yaml
# Basic configuration structure
target:
  base_url: "https://api.example.com"
  timeout: 15
  verify_ssl: true

authentication:
  contexts:
    - name: "user"
      type: "bearer"
      token: "your-jwt-token"
      privilege_level: 1

owasp_testing:
  enabled_modules: ["bola", "auth", "property"]

rate_limiting:
  requests_per_second: 10
  adaptive: true

reporting:
  formats: ["json", "html"]
  output_dir: "reports"
```

### Using Configuration Files

```bash
# Use configuration file
python apileaks.py full \
  --config config/examples/rest_api_config.yaml \
  --target https://api.example.com

# Override configuration with CLI arguments
python apileaks.py full \
  --config config/examples/rest_api_config.yaml \
  --target https://api.example.com \
  --rate-limit 5 \
  --modules bola,auth
```

### Environment Variables

Override configuration with environment variables:

```bash
# Set environment variables
export APILEAK_TARGET_URL="https://api.example.com"
export APILEAK_AUTH_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
export APILEAK_RATE_LIMIT="5"

# Run with environment variables
python apileaks.py full --config config/examples/ci_cd_config.yaml
```

## WAF Evasion Techniques

APILeak provides multiple strategies for bypassing Web Application Firewalls:

### User Agent Rotation

```bash
# Random user agent from built-in list
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random

# Custom user agent
python apileaks.py par \
  --target https://api.example.com \
  --user-agent-custom "Mozilla/5.0 (compatible; Googlebot/2.1)"

# User agent rotation from file
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-file wordlists/user_agents.txt \
  --modules bola,auth
```

### Rate Limiting for WAF Bypass

```bash
# Conservative rate limiting
python apileaks.py full \
  --target https://api.example.com \
  --rate-limit 1 \
  --user-agent-random \
  --modules bola,auth

# Adaptive rate limiting
python apileaks.py full \
  --config config/examples/waf_protected_api_config.yaml \
  --target https://api.example.com
```

### Configuration-Based WAF Evasion

```yaml
# WAF evasion in configuration
fuzzing:
  headers:
    user_agent_rotation: true
    user_agent_list:
      - "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
      - "curl/8.4.0"
      - "Postman/10.20.0"

rate_limiting:
  requests_per_second: 1
  jitter: true
  jitter_factor: 0.3
```

## CI/CD Integration

### Basic CI/CD Usage

```bash
# CI/CD friendly command
python apileaks.py full \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --modules bola,auth,property \
  --output ci_security_scan \
  --no-banner

# With exit code handling
python apileaks.py full \
  --config config/examples/ci_cd_config.yaml \
  --target "${API_ENDPOINT}" || exit 1
```

### GitHub Actions Example

```yaml
name: API Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run APILeak Security Scan
        env:
          API_ENDPOINT: ${{ secrets.API_ENDPOINT }}
          JWT_TOKEN: ${{ secrets.JWT_TOKEN }}
        run: |
          python apileaks.py full \
            --target "${API_ENDPOINT}" \
            --jwt "${JWT_TOKEN}" \
            --modules bola,auth,property \
            --output github_actions_scan \
            --no-banner
      
      - name: Upload Security Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: reports/
```

### GitLab CI Example

```yaml
stages:
  - security

api_security_scan:
  stage: security
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python apileaks.py full
        --target "${API_ENDPOINT}"
        --jwt "${JWT_TOKEN}"
        --modules bola,auth,property
        --output gitlab_ci_scan
        --no-banner
  artifacts:
    reports:
      junit: reports/*.xml
    paths:
      - reports/
  variables:
    API_ENDPOINT: "https://api.staging.example.com"
  only:
    - merge_requests
    - main
```

## Troubleshooting

### Common Issues and Solutions

#### Rate Limiting (429 Responses)

```bash
# Reduce request rate
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 1 \
  --user-agent-random

# Use adaptive rate limiting
python apileaks.py full \
  --target https://api.example.com \
  --rate-limit 5 \
  --modules bola \
  --config config/examples/waf_protected_api_config.yaml
```

#### WAF Blocking Requests

```bash
# Use legitimate user agents
python apileaks.py par \
  --target https://api.example.com \
  --user-agent-custom "Mozilla/5.0 (compatible; Googlebot/2.1)"

# Conservative testing
python apileaks.py full \
  --target https://api.example.com \
  --rate-limit 2 \
  --user-agent-file wordlists/legitimate_agents.txt \
  --modules bola
```

#### SSL Certificate Issues

```bash
# Disable SSL verification (not recommended for production)
python apileaks.py full \
  --target https://api.example.com \
  --no-verify-ssl

# Or in configuration:
target:
  verify_ssl: false
```

#### Authentication Issues

```bash
# Test with different authentication methods
python apileaks.py full \
  --target https://api.example.com \
  --header "X-API-Key: your-api-key"

# Use configuration file for complex auth
python apileaks.py full \
  --config config/examples/auth_testing_config.yaml \
  --target https://api.example.com
```

### Debug Mode

```bash
# Enable debug logging
python apileaks.py full \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log

# JSON structured logging
python apileaks.py full \
  --target https://api.example.com \
  --json-logs \
  --log-file structured.log
```

## Best Practices

### Security Testing Guidelines

1. **Start Conservative**
   ```bash
   # Begin with low rate limits
   python apileaks.py dir --target https://api.example.com --rate-limit 2
   ```

2. **Use Legitimate User Agents**
   ```bash
   # Avoid suspicious user agents
   python apileaks.py full --target https://api.example.com --user-agent-random
   ```

3. **Test with Proper Authorization**
   ```bash
   # Always use valid tokens when available
   python apileaks.py full \
     --target https://api.example.com \
     --jwt "valid-jwt-token" \
     --modules bola,auth
   ```

### Performance Optimization

1. **Use Status Code Filtering**
   ```bash
   # Focus on relevant responses
   python apileaks.py dir \
     --target https://api.example.com \
     --status-code 200,401,403
   ```

2. **Optimize Wordlists**
   ```bash
   # Use targeted wordlists
   python apileaks.py par \
     --target https://api.example.com \
     --wordlist wordlists/api_parameters.txt
   ```

3. **Configure Appropriate Timeouts**
   ```yaml
   target:
     timeout: 30  # Adjust based on API response times
   ```

### Reporting Best Practices

1. **Use Multiple Formats**
   ```bash
   python apileaks.py full \
     --target https://api.example.com \
     --output comprehensive_scan
   # Generates: .json, .html, .xml, .txt
   ```

2. **Structured Output for Automation**
   ```bash
   python apileaks.py full \
     --target https://api.example.com \
     --json-logs \
     --output automation_scan
   ```

3. **Include Context in Filenames**
   ```bash
   python apileaks.py full \
     --target https://api.example.com \
     --output "production_api_$(date +%Y%m%d)"
   ```

### Ethical Testing Guidelines

1. **Obtain Proper Authorization**
   - Always get written permission before testing
   - Respect scope limitations
   - Follow responsible disclosure practices

2. **Respect Rate Limits**
   - Start with conservative settings
   - Monitor for 429 responses
   - Use adaptive rate limiting

3. **Avoid Destructive Testing**
   - Don't test DELETE operations on production data
   - Avoid large payload testing on production systems
   - Use test environments when possible

4. **Document Your Testing**
   - Keep detailed logs of testing activities
   - Document any issues discovered
   - Provide clear remediation guidance

---

For more detailed information, see:
- [Configuration Guide](configuration.md)
- [OWASP Modules Guide](owasp-modules-guide.md)
- [CI/CD Integration Guide](ci-cd-integration.md)
- [Troubleshooting Guide](troubleshooting-guide.md)