# 📖 APILeak CLI Reference

Complete command-line interface reference for APILeak v0.1.0 - Enterprise API security testing tool.

## Table of Contents

- [Global Options](#global-options)
- [Commands Overview](#commands-overview)
- [Directory Fuzzing (`dir`)](#directory-fuzzing-dir)
- [Parameter Fuzzing (`par`)](#parameter-fuzzing-par)
- [Full Security Scan (`full`)](#full-security-scan-full)
- [JWT Utilities](#jwt-utilities)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

## Global Options

These options are available for all commands:

| Option | Description | Default |
|--------|-------------|---------|
| `--no-banner` | Suppress banner output | `false` |
| `--help` | Show help message and exit | - |

## Commands Overview

APILeak provides the following main commands:

| Command | Purpose | Use Case |
|---------|---------|----------|
| `dir` | Directory/endpoint fuzzing | Discover hidden endpoints and directories |
| `par` | Parameter fuzzing | Find hidden parameters in API endpoints |
| `full` | Full comprehensive scan | Complete OWASP API Security Top 10 testing |
| `jwt` | JWT security utilities | JWT token manipulation and security testing |

### Help System

APILeak provides comprehensive help at multiple levels:

```bash
# Main help - shows all commands and global options
python apileaks.py --help

# Command-specific help - shows all options for a specific command
python apileaks.py full --help
python apileaks.py dir --help
python apileaks.py par --help

# JWT utilities help
python apileaks.py jwt --help
python apileaks.py jwt decode --help
python apileaks.py jwt encode --help
```

## Directory Fuzzing (`dir`)

Discover hidden API endpoints and administrative interfaces.

### Syntax

```bash
python apileaks.py dir [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan | `--target https://api.example.com` |

### Optional Parameters

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--wordlist`, `-w` | Wordlist file for directory fuzzing | `wordlists/endpoints.txt` | `--wordlist custom_endpoints.txt` |
| `--output`, `-o` | Output filename for reports | Auto-generated | `--output my-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level DEBUG` |
| `--log-file` | Log file path | Console only | `--log-file scan.log` |
| `--json-logs` | Output logs in JSON format | `false` | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 5` |
| `--methods` | HTTP methods to test | `GET,POST,PUT,DELETE,PATCH` | `--methods GET,POST` |
| `--jwt` | JWT token for authentication | - | `--jwt eyJ0eXAi...` |
| `--response` | Filter by response codes | All codes | `--response 200,301,404` |
| `--status-code` | Show only specific status codes | All codes | `--status-code 200-300` |

### User Agent Options (Mutually Exclusive)

| Option | Description | Example |
|--------|-------------|---------|
| `--user-agent-random` | Use random User-Agent headers | `--user-agent-random` |
| `--user-agent-custom` | Custom User-Agent string | `--user-agent-custom "MyScanner/1.0"` |
| `--user-agent-file` | File with User-Agent strings | `--user-agent-file agents.txt` |

### Advanced Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Enable framework detection | `false` | `--detect-framework` |
| `--fuzz-versions`, `--fv` | Enable API version fuzzing | `false` | `--fuzz-versions` |

### Examples

```bash
# Basic directory fuzzing
python apileaks.py dir --target https://api.example.com

# With custom wordlist and rate limiting
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist custom_endpoints.txt \
  --rate-limit 5

# With WAF evasion and framework detection
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --detect-framework \
  --fuzz-versions

# Focus on successful responses
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 200-299,401,403 \
  --output successful-endpoints
```

## Parameter Fuzzing (`par`)

Identify hidden parameters and input validation issues.

### Syntax

```bash
python apileaks.py par [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan | `--target https://api.example.com/users` |

### Optional Parameters

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--wordlist`, `-w` | Wordlist file for parameter fuzzing | `wordlists/parameters.txt` | `--wordlist custom_params.txt` |
| `--output`, `-o` | Output filename for reports | Auto-generated | `--output param-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level INFO` |
| `--log-file` | Log file path | Console only | `--log-file param.log` |
| `--json-logs` | Output logs in JSON format | `false` | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 3` |
| `--methods` | HTTP methods to test | `GET,POST` | `--methods GET,POST,PUT` |
| `--jwt` | JWT token for authentication | - | `--jwt eyJ0eXAi...` |
| `--response` | Filter by response codes | All codes | `--response 200,400,422` |
| `--status-code` | Show only specific status codes | All codes | `--status-code 200,500-599` |

### User Agent Options (Mutually Exclusive)

Same as directory fuzzing - see above.

### Advanced Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Enable framework detection | `false` | `--detect-framework` |

### Examples

```bash
# Basic parameter fuzzing
python apileaks.py par --target https://api.example.com/users/123

# With authentication and custom wordlist
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --wordlist custom_parameters.txt

# Focus on error responses
python apileaks.py par \
  --target https://api.example.com/search \
  --status-code 400,422,500-599 \
  --output error-parameters
```

## Full Security Scan (`full`)

Comprehensive OWASP API Security Top 10 testing with advanced features.

### Syntax

```bash
python apileaks.py full [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan (required if no config) | `--target https://api.example.com` |

### Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `--config`, `-c` | Configuration file path (YAML/JSON) | `--config config/api.yaml` |

### Basic Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--output`, `-o` | Output filename for reports | Auto-generated | `--output comprehensive-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level INFO` |
| `--log-file` | Log file path | Console only | `--log-file full-scan.log` |
| `--json-logs` | Output logs in JSON format | `false` | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 15` |
| `--jwt` | JWT token for authentication | - | `--jwt eyJ0eXAi...` |
| `--status-code` | Show only specific status codes | All codes | `--status-code 200,401,403` |

### OWASP Module Selection

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--modules` | Comma-separated OWASP modules | All modules | `--modules bola,auth,property` |

Available modules:
- `bola` - BOLA (Broken Object Level Authorization) testing
- `auth` - Authentication testing (JWT vulnerabilities)
- `property` - Property Level Authorization testing
- `function_auth` - Function Level Authorization testing
- `resource` - Resource Consumption testing
- `ssrf` - Server-Side Request Forgery testing

### User Agent Options (Mutually Exclusive)

Same as directory fuzzing - see above.

### Advanced Discovery Features

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Enable framework detection | `false` | `--detect-framework` |
| `--fuzz-versions`, `--fv` | Enable API version fuzzing | `false` | `--fuzz-versions` |
| `--framework-confidence` | Framework detection confidence | `0.6` | `--framework-confidence 0.8` |
| `--version-patterns` | Custom version patterns | Default patterns | `--version-patterns /v1,/v2,/api/v1` |
| `--enable-advanced` | Enable all advanced features | `false` | `--enable-advanced` |
| `--enable-payload-encoding` | Enable payload encoding/obfuscation | `false` | `--enable-payload-encoding` |
| `--enable-waf-evasion` | Enable WAF detection and evasion | `false` | `--enable-waf-evasion` |
| `--enable-subdomain-discovery` | Enable subdomain discovery | `false` | `--enable-subdomain-discovery` |
| `--enable-cors-analysis` | Enable CORS analysis | `false` | `--enable-cors-analysis` |

### CI/CD Integration

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--ci-mode` | Enable CI/CD mode | `false` | `--ci-mode` |
| `--fail-on` | Fail on severity level | `critical` | `--fail-on high` |

Available severity levels: `critical`, `high`, `medium`, `low`

### Examples

```bash
# Basic full scan
python apileaks.py full --target https://api.example.com

# With specific OWASP modules
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Advanced scan with all features
python apileaks.py full \
  --target https://api.example.com \
  --enable-advanced \
  --user-agent-random \
  --output advanced-security-scan

# CI/CD integration
python apileaks.py full \
  --target https://api.example.com \
  --ci-mode \
  --fail-on high \
  --modules bola,auth,function_auth

# Using configuration file
python apileaks.py full \
  --config config/production_api.yaml \
  --target https://api.example.com
```

## JWT Utilities

APILeak includes comprehensive JWT security testing utilities organized as a command group.

### JWT Command Group

All JWT utilities are accessed through the `jwt` command group:

```bash
python apileaks.py jwt [SUBCOMMAND] [OPTIONS]
```

#### Available Subcommands

| Subcommand | Purpose | Description |
|------------|---------|-------------|
| `decode` | Token Analysis | Decode and analyze JWT tokens |
| `encode` | Token Generation | Create JWT tokens for testing |
| `test-alg-none` | Algorithm Confusion | Test alg:none vulnerability |
| `test-null-signature` | Null Signature | Test null signature bypass |
| `brute-secret` | Secret Brute-force | Crack weak HMAC secrets |
| `test-kid-injection` | Key ID Injection | Test kid parameter injection |
| `test-jwks-spoof` | JWKS Spoofing | Test JWKS URL spoofing |
| `test-inline-jwks` | Inline JWKS | Test inline JWKS injection |

### JWT Decode (`jwt decode`)

Decode and analyze JWT tokens with security insights.

#### Syntax

```bash
python apileaks.py jwt decode TOKEN
```

#### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `TOKEN` | JWT token to decode | `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...` |

#### Example

```bash
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### JWT Encode (`jwt encode`)

Create JWT tokens for testing purposes.

#### Syntax

```bash
python apileaks.py jwt encode PAYLOAD [OPTIONS]
```

#### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `PAYLOAD` | JWT payload as JSON string | `'{"sub":"user123","role":"admin"}'` |

#### Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--header` | JWT header as JSON string | `{"alg":"HS256","typ":"JWT"}` | `--header '{"alg":"HS512","typ":"JWT"}'` |
| `--secret` | Secret key for signing | `secret` | `--secret mysecretkey` |

#### Examples

```bash
# Basic JWT encoding
python apileaks.py jwt encode '{"sub":"user123","role":"user"}'

# With custom secret
python apileaks.py jwt encode \
  '{"sub":"admin","role":"admin","exp":1735689600}' \
  --secret mysecretkey

# With custom header
python apileaks.py jwt encode \
  '{"sub":"user123"}' \
  --header '{"alg":"HS512","typ":"JWT"}' \
  --secret strongsecret
```

### JWT Security Testing

APILeak provides advanced JWT security testing capabilities to identify common vulnerabilities.

#### Algorithm Confusion Attack (`jwt test-alg-none`)

Test if the server accepts unsigned tokens with `alg:none`.

```bash
python apileaks.py jwt test-alg-none TOKEN [--payload CUSTOM_PAYLOAD]
```

**Example:**
```bash
python apileaks.py jwt test-alg-none eyJ0eXAiOiJKV1Q...
python apileaks.py jwt test-alg-none TOKEN --payload '{"sub":"admin","role":"admin"}'
```

#### Null Signature Testing (`jwt test-null-signature`)

Test various null signature bypass techniques.

```bash
python apileaks.py jwt test-null-signature TOKEN [--payload CUSTOM_PAYLOAD]
```

#### HMAC Secret Brute-force (`jwt brute-secret`)

Attempt to crack weak HMAC secrets using wordlists.

```bash
python apileaks.py jwt brute-secret TOKEN [OPTIONS]
```

**Options:**
- `--wordlist`, `-w`: Wordlist file (default: `wordlists/jwt_secrets.txt`)
- `--max-attempts`: Maximum attempts (default: `1000`)

**Example:**
```bash
python apileaks.py jwt brute-secret TOKEN --wordlist custom_secrets.txt
```

#### Key ID Injection (`jwt test-kid-injection`)

Test kid parameter injection vulnerabilities.

```bash
python apileaks.py jwt test-kid-injection TOKEN [--kid-payload PAYLOAD]
```

**Example:**
```bash
python apileaks.py jwt test-kid-injection TOKEN --kid-payload "../../etc/passwd"
```

#### JWKS Spoofing (`jwt test-jwks-spoof`)

Test JWKS URL spoofing vulnerabilities.

```bash
python apileaks.py jwt test-jwks-spoof TOKEN [--jwks-url URL]
```

**Example:**
```bash
python apileaks.py jwt test-jwks-spoof TOKEN --jwks-url http://attacker.com/jwks.json
```

#### Inline JWKS Injection (`jwt test-inline-jwks`)

Test inline JWKS injection vulnerabilities.

```bash
python apileaks.py jwt test-inline-jwks TOKEN
```

### JWT Security Testing Workflow

For comprehensive JWT security testing, use this workflow:

```bash
# 1. Decode and analyze the token
python apileaks.py jwt decode $TOKEN

# 2. Test algorithm confusion
python apileaks.py jwt test-alg-none $TOKEN

# 3. Test null signature bypass
python apileaks.py jwt test-null-signature $TOKEN

# 4. Attempt secret brute-force
python apileaks.py jwt brute-secret $TOKEN

# 5. Test kid injection
python apileaks.py jwt test-kid-injection $TOKEN

# 6. Test JWKS spoofing
python apileaks.py jwt test-jwks-spoof $TOKEN

# 7. Test inline JWKS
python apileaks.py jwt test-inline-jwks $TOKEN
```

## Environment Variables

APILeak supports configuration through environment variables:

| Variable | Description | Default | CLI Equivalent |
|----------|-------------|---------|----------------|
| `APILEAK_TARGET` | Target URL | - | `--target` |
| `APILEAK_LOG_LEVEL` | Logging level | `INFO` | `--log-level` |
| `APILEAK_RATE_LIMIT` | Requests per second | `10` | `--rate-limit` |
| `APILEAK_MODULES` | OWASP modules | All modules | `--modules` |
| `APILEAK_JWT_TOKEN` | JWT token | - | `--jwt` |
| `APILEAK_USER_AGENT` | Custom User-Agent | Default | `--user-agent-custom` |
| `APILEAK_TIMEOUT` | Request timeout | `10` | - |
| `APILEAK_MAX_DEPTH` | Max recursion depth | `3` | - |
| `APILEAK_VERIFY_SSL` | Verify SSL certificates | `true` | - |
| `APILEAK_OUTPUT_DIR` | Output directory | `reports` | - |

### Example Usage

```bash
# Set environment variables
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,property"
export APILEAK_JWT_TOKEN="eyJ0eXAiOiJKV1Q..."
export APILEAK_RATE_LIMIT="5"

# Run scan with environment variables
python apileaks.py full
```

## Exit Codes

APILeak uses specific exit codes to indicate scan results:

| Exit Code | Meaning | Description |
|-----------|---------|-------------|
| `0` | Success | No critical or high severity findings |
| `1` | High Severity | High severity vulnerabilities found |
| `2` | Critical Severity | Critical vulnerabilities found |
| `3` | Scan Error | Scan failed due to technical issues (CI mode only) |

### CI/CD Integration

In CI/CD mode (`--ci-mode`), exit codes are determined by the `--fail-on` setting:

```bash
# Fail only on critical findings
python apileaks.py full --target URL --ci-mode --fail-on critical

# Fail on high or critical findings
python apileaks.py full --target URL --ci-mode --fail-on high

# Fail on medium, high, or critical findings
python apileaks.py full --target URL --ci-mode --fail-on medium
```

## Examples

### Basic Usage Examples

```bash
# Quick endpoint discovery
python apileaks.py dir --target https://api.example.com

# Parameter fuzzing with authentication
python apileaks.py par \
  --target https://api.example.com/users/123 \
  --jwt "eyJ0eXAiOiJKV1Q..."

# Full security scan
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property
```

### Advanced Usage Examples

```bash
# WAF evasion with random user agents
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --enable-waf-evasion \
  --rate-limit 3

# Framework detection and version fuzzing
python apileaks.py full \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.8

# Comprehensive scan with all advanced features
python apileaks.py full \
  --target https://api.example.com \
  --enable-advanced \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --output comprehensive-scan
```

### CI/CD Integration Examples

```bash
# GitHub Actions
python apileaks.py full \
  --target ${{ vars.API_TARGET_URL }} \
  --jwt ${{ secrets.API_JWT_TOKEN }} \
  --ci-mode \
  --fail-on critical \
  --output github-scan-${{ github.run_id }}

# GitLab CI
python apileaks.py full \
  --target $API_TARGET_URL \
  --jwt $API_JWT_TOKEN \
  --ci-mode \
  --fail-on high \
  --output gitlab-scan-$CI_PIPELINE_ID

# Jenkins
python apileaks.py full \
  --target ${API_TARGET_URL} \
  --jwt ${API_JWT_TOKEN} \
  --ci-mode \
  --fail-on critical \
  --output jenkins-scan-${BUILD_ID}
```

### Configuration File Examples

```bash
# Using YAML configuration
python apileaks.py full --config config/production_api.yaml

# Override config with CLI parameters
python apileaks.py full \
  --config config/base_config.yaml \
  --target https://staging-api.example.com \
  --modules bola,auth
```

### JWT Utility Examples

```bash
# Decode a JWT token
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Create a test JWT token
python apileaks.py jwt encode \
  '{"sub":"testuser","role":"admin","exp":1735689600}' \
  --secret testsecret

# Create JWT with custom algorithm
python apileaks.py jwt encode \
  '{"sub":"user123"}' \
  --header '{"alg":"HS512","typ":"JWT"}' \
  --secret strongsecret

# Test JWT security vulnerabilities
python apileaks.py jwt test-alg-none TOKEN
python apileaks.py jwt brute-secret TOKEN --wordlist secrets.txt
python apileaks.py jwt test-kid-injection TOKEN
```

### Output and Logging Examples

```bash
# Debug logging to file
python apileaks.py full \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug-scan.log

# JSON structured logging
python apileaks.py full \
  --target https://api.example.com \
  --json-logs \
  --log-file structured.log

# Custom output filename
python apileaks.py full \
  --target https://api.example.com \
  --output my-security-audit-2024
```

---

For more detailed information, see:
- [User Guide](user-guide.md) - Comprehensive usage guide
- [Configuration Guide](configuration.md) - Configuration file reference
- [OWASP Modules Guide](owasp-modules-guide.md) - Detailed module documentation
- [Docker Usage](docker-usage.md) - Container deployment guide