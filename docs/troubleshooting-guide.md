# 🔧 APILeak Troubleshooting Guide

This guide covers the most common issues when using APILeak and their solutions.

## 📋 Table of Contents

1. [Connection Issues](#connection-issues)
2. [Authentication Problems](#authentication-problems)
3. [Rate Limiting and Timeouts](#rate-limiting-and-timeouts)
4. [Configuration Issues](#configuration-issues)
5. [Wordlist Problems](#wordlist-problems)
6. [Report Generation Issues](#report-generation-issues)
7. [OWASP Module Problems](#owasp-module-problems)
8. [Performance Issues](#performance-issues)
9. [Logging and Debugging](#logging-and-debugging)

---

## 🌐 Connection Issues

### Error: Connection timeout

**Symptoms:**
```
Error: Connection timeout
requests.exceptions.ConnectTimeout: HTTPSConnectionPool(host='api.example.com', port=443)
```

**Common Causes:**
- API unavailable or slow
- Firewall blocking connections
- Proxy or VPN interference
- Timeout too low

**Solutions:**

```bash
# 1. Increase timeout
python apileaks.py full --target https://api.example.com --config config/high_timeout.yaml
```

```yaml
# config/high_timeout.yaml
target:
  timeout: 60  # Increase to 60 seconds
  verify_ssl: true
```

```bash
# 2. Verify basic connectivity
curl -I https://api.example.com
ping api.example.com

# 3. Try with very low rate limiting
python apileaks.py full --target https://api.example.com --rate-limit 1
```

### Error: SSL Certificate verification failed

**Symptoms:**
```
requests.exceptions.SSLError: HTTPSConnectionPool(host='api.example.com', port=443): 
Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError))
```

**Solutions:**

```yaml
# config/no_ssl_verify.yaml (testing only)
target:
  verify_ssl: false  # ⚠️ Only use in development environments
```

```bash
# Better solution: Add certificate to trust store
python apileaks.py full --target https://api.example.com --config config/no_ssl_verify.yaml
```

### Error: Name resolution failed

**Symptoms:**
```
requests.exceptions.ConnectionError: Failed to establish a new connection: 
[Errno -2] Name or service not known
```

**Solutions:**

```bash
# 1. Verify DNS
nslookup api.example.com
dig api.example.com

# 2. Use direct IP if necessary
python apileaks.py full --target https://192.168.1.100

# 3. Check /etc/hosts (Linux/Mac)
cat /etc/hosts
```

---

## 🔐 Authentication Problems

### Error: JWT token validation failed

**Symptoms:**
```
Warning: JWT token validation failed
Invalid JWT token format
```

**Solutions:**

```bash
# 1. Verify token format
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# 2. Generate test token
python apileaks.py jwt encode '{"sub":"user123","role":"user"}' --secret mysecret

# 3. Verify token is not expired
python apileaks.py jwt decode $JWT_TOKEN | grep exp
```

### Error: 401 Unauthorized on all endpoints

**Symptoms:**
```
All endpoints returning 401 Unauthorized
Authentication context 'anonymous' failed
```

**Solutions:**

```bash
# 1. Verify token manually
curl -H "Authorization: Bearer $JWT_TOKEN" https://api.example.com/

# 2. Try without authentication first
python apileaks.py full --target https://api.example.com --modules bola

# 3. Use configuration with multiple contexts
```

```yaml
# config/multi_auth.yaml
authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "your_jwt_token_here"
      privilege_level: 1
```

### Error: Token expired

**Symptoms:**
```
JWT token expired
exp claim validation failed
```

**Solutions:**

```bash
# 1. Generate new token
# Contact development team for a valid token

# 2. Use token with long expiration for testing
python apileaks.py jwt encode '{"sub":"user123","exp":2000000000}' --secret mysecret

# 3. Configure automatic renewal (if API supports it)
```

---

## ⚡ Rate Limiting and Timeouts

### Error: Too many requests (429)

**Symptoms:**
```
HTTP 429: Too Many Requests
Rate limit exceeded
```

**Solutions:**

```bash
# 1. Drastically reduce rate limiting
python apileaks.py full --target https://api.example.com --rate-limit 1

# 2. Use adaptive mode (default)
python apileaks.py full --target https://api.example.com --modules bola
```

```yaml
# config/conservative_rate.yaml
rate_limiting:
  requests_per_second: 1
  burst_size: 2
  adaptive: true
  respect_retry_after: true
  backoff_factor: 3.0  # More aggressive backoff
```

### Error: Request timeout

**Symptoms:**
```
requests.exceptions.ReadTimeout: HTTPSConnectionPool read timed out
```

**Solutions:**

```yaml
# config/extended_timeout.yaml
target:
  timeout: 120  # 2 minutes

rate_limiting:
  requests_per_second: 2  # Slower but more reliable
```

### Error: Server overloaded

**Symptoms:**
```
HTTP 503: Service Unavailable
Server temporarily overloaded
```

**Solutions:**

```bash
# 1. Wait and retry
sleep 300  # 5 minutes
python apileaks.py full --target https://api.example.com --rate-limit 1

# 2. Run modules separately
python apileaks.py full --target https://api.example.com --modules bola --rate-limit 1
python apileaks.py full --target https://api.example.com --modules auth --rate-limit 1
```

---

## ⚙️ Configuration Issues

### Error: Configuration validation failed

**Symptoms:**
```
Configuration validation failed
Error: target.base_url is required
```

**Solutions:**

```bash
# 1. Verify YAML configuration
python -c "import yaml; yaml.safe_load(open('config/my_config.yaml'))"

# 2. Use minimal valid configuration
```

```yaml
# config/minimal_valid.yaml
target:
  base_url: "https://api.example.com"
  timeout: 30

owasp_testing:
  enabled_modules: ["bola"]

rate_limiting:
  requests_per_second: 5
```

### Error: Invalid YAML format

**Symptoms:**
```
yaml.scanner.ScannerError: while scanning for the next token
found character '\t' that cannot start any token
```

**Solutions:**

```bash
# 1. Verify YAML syntax
yamllint config/my_config.yaml

# 2. Convert tabs to spaces
sed -i 's/\t/  /g' config/my_config.yaml

# 3. Use editor with YAML validation
```

### Error: Module not found

**Symptoms:**
```
Error: Unknown module 'invalid_module'
Available modules: bola, auth, property, resource, function_auth
```

**Solutions:**

```bash
# 1. Check available modules
python apileaks.py full --help

# 2. Use only valid modules
python apileaks.py full --target https://api.example.com --modules bola,auth,property

# 3. Check spelling
# Correct: bola, auth, property, resource, function_auth
# Incorrect: BOLA, authentication, properties
```

---

## 📝 Wordlist Problems

### Error: Wordlist file not found

**Symptoms:**
```
Error: Wordlist file not found: wordlists/custom.txt
FileNotFoundError: [Errno 2] No such file or directory
```

**Solutions:**

```bash
# 1. Verify file exists
ls -la wordlists/
find . -name "*.txt" -path "*/wordlists/*"

# 2. Use default wordlists
python apileaks.py dir --target https://api.example.com  # Uses wordlists/endpoints.txt

# 3. Create custom wordlist
echo -e "/api\n/admin\n/users" > wordlists/custom.txt
```

### Error: Empty wordlist

**Symptoms:**
```
Warning: Wordlist is empty or contains no valid entries
No endpoints to test
```

**Solutions:**

```bash
# 1. Check wordlist content
head -10 wordlists/endpoints.txt
wc -l wordlists/endpoints.txt

# 2. Filter empty lines and comments
grep -v '^#' wordlists/endpoints.txt | grep -v '^$' > wordlists/clean_endpoints.txt

# 3. Use known wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt -O wordlists/api-endpoints.txt
```

### Error: Wordlist encoding issues

**Symptoms:**
```
UnicodeDecodeError: 'utf-8' codec can't decode byte
```

**Solutions:**

```bash
# 1. Convert to UTF-8
iconv -f ISO-8859-1 -t UTF-8 wordlists/original.txt > wordlists/utf8.txt

# 2. Check encoding
file wordlists/endpoints.txt
chardet wordlists/endpoints.txt

# 3. Clean problematic characters
sed 's/[^[:print:]]//g' wordlists/original.txt > wordlists/clean.txt
```

---

## 📊 Report Generation Issues

### Error: Permission denied writing reports

**Symptoms:**
```
PermissionError: [Errno 13] Permission denied: 'reports/scan.json'
```

**Solutions:**

```bash
# 1. Check directory permissions
ls -la reports/
chmod 755 reports/

# 2. Create directory if it doesn't exist
mkdir -p reports
chmod 755 reports

# 3. Use alternative directory
python apileaks.py full --target https://api.example.com --output /tmp/apileak-reports
```

### Error: Disk space full

**Symptoms:**
```
OSError: [Errno 28] No space left on device
```

**Solutions:**

```bash
# 1. Check available space
df -h

# 2. Clean old reports
find reports/ -name "*.json" -mtime +7 -delete

# 3. Use directory with more space
python apileaks.py full --target https://api.example.com --output /var/tmp/apileak-reports
```

### Error: Invalid JSON in report

**Symptoms:**
```
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

**Solutions:**

```bash
# 1. Check if file is complete
tail reports/scan.json

# 2. Check if scan completed correctly
grep -i "error\|exception" apileak.log

# 3. Re-run the scan
python apileaks.py full --target https://api.example.com --log-level DEBUG
```

---

## 🛡️ OWASP Module Problems

### Error: BOLA module failed

**Symptoms:**
```
BOLA testing failed: No valid endpoints found for testing
```

**Solutions:**

```bash
# 1. Run discovery first
python apileaks.py dir --target https://api.example.com

# 2. Verify valid endpoints exist
curl https://api.example.com/users/1
curl https://api.example.com/api/v1/users/1

# 3. Use specific BOLA configuration
python apileaks.py full --config config/examples/bola_testing_config.yaml --target https://api.example.com
```

### Error: Auth module - JWT secrets not found

**Symptoms:**
```
Warning: JWT secrets wordlist not found: wordlists/jwt_secrets.txt
```

**Solutions:**

```bash
# 1. Create JWT secrets wordlist
cat > wordlists/jwt_secrets.txt << EOF
secret
password
123456
admin
jwt_secret
your_secret_key
EOF

# 2. Download common wordlist
wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list -O wordlists/jwt_secrets.txt

# 3. Disable weak secrets testing
```

```yaml
# config/auth_no_secrets.yaml
owasp_testing:
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: ""  # Disable
```

### Error: Resource module - Large payload failed

**Symptoms:**
```
Resource consumption test failed: Payload too large
MemoryError: Unable to allocate memory for payload
```

**Solutions:**

```yaml
# config/smaller_payloads.yaml
owasp_testing:
  resource_testing:
    enabled: true
    large_payload_sizes: [1024, 10240, 102400]  # 1KB, 10KB, 100KB instead of MB
```

```bash
# Run with memory limits
ulimit -v 1000000  # Limit virtual memory
python apileaks.py full --target https://api.example.com --modules resource
```

---

## 🚀 Performance Issues

### Error: Scan taking too long

**Symptoms:**
```
Scan has been running for over 2 hours
No progress visible
```

**Solutions:**

```bash
# 1. Use specific modules
python apileaks.py full --target https://api.example.com --modules bola,auth

# 2. Reduce scope
python apileaks.py dir --target https://api.example.com --wordlist wordlists/small_endpoints.txt

# 3. Increase rate limiting if server allows
python apileaks.py full --target https://api.example.com --rate-limit 20
```

### Error: High memory usage

**Symptoms:**
```
Process killed (OOM - Out of Memory)
Memory usage exceeding system limits
```

**Solutions:**

```bash
# 1. Limit process memory
ulimit -v 2000000  # 2GB virtual memory limit

# 2. Run modules separately
for module in bola auth property; do
  python apileaks.py full --target https://api.example.com --modules $module
done

# 3. Use configuration with less concurrency
```

```yaml
# config/low_memory.yaml
rate_limiting:
  requests_per_second: 2  # Less concurrency

owasp_testing:
  resource_testing:
    large_payload_sizes: [1024]  # Only small payloads
```

### Error: Too many open files

**Symptoms:**
```
OSError: [Errno 24] Too many open files
```

**Solutions:**

```bash
# 1. Increase open files limit
ulimit -n 4096

# 2. Check current limits
ulimit -a

# 3. Configure permanent limits (Linux)
echo "* soft nofile 4096" >> /etc/security/limits.conf
echo "* hard nofile 8192" >> /etc/security/limits.conf
```

---

## 🔍 Logging and Debugging

### Enable Detailed Logging

```bash
# Complete logging
python apileaks.py full --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log \
  --json-logs

# View logs in real-time
tail -f debug.log

# Filter logs by module
grep "bola" debug.log
grep "ERROR" debug.log
```

### HTTP Request Debugging

```bash
# Enable request logging
export PYTHONPATH=$PYTHONPATH:.
python -c "
import logging
import http.client as http_client
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger('requests.packages.urllib3')
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
" && python apileaks.py full --target https://api.example.com --modules bola
```

### Configuration Debugging

```python
# debug_config.py
import yaml
from core import ConfigurationManager

# Load and validate configuration
config_manager = ConfigurationManager()
config = config_manager.load_config('config/my_config.yaml')

# Show loaded configuration
print("Loaded configuration:")
print(yaml.dump(config.__dict__, default_flow_style=False))

# Validate configuration
errors = config_manager.validate_configuration()
if errors:
    print("Validation errors:")
    for error in errors:
        print(f"  - {error}")
else:
    print("✅ Valid configuration")
```

### OWASP Module Debugging

```bash
# Individual module testing
python -c "
from modules.owasp import BOLATestingModule
from core import APILeakCore
import asyncio

async def test_bola():
    # Minimal configuration for testing
    config = type('Config', (), {
        'target': type('Target', (), {'base_url': 'https://api.example.com'})(),
        'authentication': type('Auth', (), {'contexts': []})(),
        'rate_limiting': type('Rate', (), {'requests_per_second': 5})()
    })()
    
    module = BOLATestingModule()
    print('BOLA module initialized successfully')

asyncio.run(test_bola())
"
```

---

## 🆘 Getting Help

### System Information

```bash
# Version information
python apileaks.py --version

# System information
python --version
pip list | grep -E "(requests|aiohttp|click)"

# Network information
curl -I https://httpbin.org/get
```

### Reporting Issues

When reporting an issue, include:

1. **Command executed:**
```bash
python apileaks.py full --target https://api.example.com --modules bola --log-level DEBUG
```

2. **Configuration used:**
```yaml
# config/my_config.yaml
target:
  base_url: "https://api.example.com"
# ... rest of configuration
```

3. **Error logs:**
```
ERROR: Connection timeout
Traceback (most recent call last):
  File "apileaks.py", line 123, in main
# ... complete stack trace
```

4. **Environment information:**
```bash
# Operating system
uname -a

# Python version
python --version

# Dependencies
pip freeze
```

### Additional Resources

- **Documentation:** [CLI Reference](cli-reference.md)
- **Examples:** [config/examples/](../config/examples/)
- **Issues:** Project GitHub Issues
- **Logs:** Always use `--log-level DEBUG` for troubleshooting

---

*This guide covers the most common issues. If you encounter an undocumented issue, please report it to help improve this guide.*