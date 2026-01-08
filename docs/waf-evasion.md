# 🥷 WAF Evasion Features

APILeak includes advanced WAF (Web Application Firewall) evasion capabilities to improve testing effectiveness and bypass common security controls during authorized penetration testing.

## Overview

Web Application Firewalls (WAFs) are designed to filter, monitor, and block HTTP traffic to and from web applications. During legitimate security testing, WAFs can interfere with comprehensive vulnerability assessment. APILeak's WAF evasion features help security professionals conduct thorough API testing while respecting rate limits and avoiding detection.

## User Agent Strategies

APILeak provides multiple user agent strategies to evade WAF detection and improve testing coverage.

### Strategy Overview

| Strategy | Option | Description | Use Case |
|----------|--------|-------------|----------|
| **Random** | `--user-agent-random` | Rotates through built-in realistic user agents | General WAF evasion |
| **Custom** | `--user-agent-custom "Agent"` | Uses a single custom user agent | Specific application testing |
| **File Rotation** | `--user-agent-file file.txt` | Rotates through user agents from file | Advanced evasion campaigns |

### Built-in User Agent Categories

APILeak includes a comprehensive database of realistic user agents across multiple categories:

#### Desktop Browsers
- **Chrome**: Latest versions across Windows, macOS, and Linux
- **Firefox**: Current and ESR versions
- **Safari**: macOS and Windows versions
- **Edge**: Chromium-based and legacy versions
- **Opera**: Standard and GX gaming browser

#### Mobile Browsers
- **iOS Safari**: iPhone and iPad variants
- **Android Chrome**: Various Android versions
- **Samsung Internet**: Galaxy device browsers
- **Mobile Firefox**: Android and iOS versions

#### Search Engine Crawlers
- **Googlebot**: Web and mobile crawlers
- **Bingbot**: Microsoft search crawler
- **Yahoo Slurp**: Yahoo search crawler
- **DuckDuckBot**: DuckDuckGo crawler
- **Baiduspider**: Baidu search crawler

#### API Testing Tools
- **curl**: Various versions and platforms
- **Postman**: Desktop and web versions
- **HTTPie**: Command-line HTTP client
- **Insomnia**: REST client
- **wget**: GNU Wget utility

#### Security Tools
- **OWASP ZAP**: Zed Attack Proxy
- **Burp Suite**: Professional and Community
- **Nmap**: Network scanner HTTP engine
- **Nikto**: Web vulnerability scanner

### Usage Examples

#### Random User Agent Rotation
```bash
# Basic random user agent rotation
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random

# Random user agents with directory fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --rate-limit 10

# Random user agents with parameter fuzzing
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --user-agent-random \
  --methods GET,POST

# Random user agents with full scan
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --modules bola,auth,property
```

#### Custom User Agent
```bash
# Use a specific custom user agent
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-custom "Mozilla/5.0 (Custom Security Scanner)"

# Mimic a specific browser
python apileaks.py par \
  --target https://api.example.com \
  --user-agent-custom "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Use a legitimate tool user agent
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-custom "curl/8.4.0" \
  --modules bola,auth
```

#### File-Based User Agent Rotation
```bash
# Use user agents from a file
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-file wordlists/user_agents.txt

# Advanced evasion with custom user agent list
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-file custom_agents.txt \
  --rate-limit 5 \
  --modules all
```

## User Agent File Format

When using `--user-agent-file`, the file should contain one user agent per line:

```
# Comments start with #
# Desktop Browsers
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36

# Mobile Browsers
Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1
Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36

# API Tools
curl/8.4.0
Postman/10.20.0
HTTPie/3.2.2

# Security Tools
Mozilla/5.0 (compatible; OWASP ZAP 2.14.0)
```

## Advanced Evasion Techniques

### Request Timing Variation
APILeak automatically varies request timing to avoid pattern detection:

```bash
# Use adaptive rate limiting with user agent rotation
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --rate-limit 8 \
  --modules bola,auth,property
```

### Header Randomization
Combined with user agent rotation, APILeak can randomize other headers:

```bash
# Enable comprehensive header randomization
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --wordlist wordlists/endpoints.txt
```

### Method Variation
Use different HTTP methods to avoid detection patterns:

```bash
# Vary HTTP methods with user agent rotation
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --methods GET,POST,PUT,DELETE,PATCH
```

## Integration with Other Features

### Framework Detection
WAF evasion works seamlessly with framework detection:

```bash
# Combine WAF evasion with framework detection
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --detect-framework \
  --framework-confidence 0.8
```

### Status Code Filtering
Reduce noise and focus on specific responses:

```bash
# WAF evasion with status code filtering
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --status-code 200-299,401,403 \
  --wordlist wordlists/endpoints.txt
```

### OWASP Testing
Integrate WAF evasion with OWASP security testing:

```bash
# OWASP testing with WAF evasion
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-file custom_agents.txt \
  --modules bola,auth,property \
  --rate-limit 10
```

## Docker Usage

### Container-Based WAF Evasion
```bash
# Directory fuzzing with WAF evasion in Docker
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 200-299,401,403 \
  --output docker_waf_evasion_scan

# Parameter fuzzing with custom user agent
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "Docker Security Scanner" \
  --status-code 200,500-599 \
  --output param_waf_scan

# Full scan with random user agents
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --user-agent-random \
  --status-code 200,401,403,500 \
  --output full_waf_scan
```

## CI/CD Integration

### Automated WAF Evasion in Pipelines
```bash
# GitHub Actions with WAF evasion
python apileaks.py --no-banner dir \
  --target $API_TARGET \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --status-code 200-299,401,403 \
  --json-logs \
  --output ci_waf_evasion_scan

# GitLab CI with custom user agent
python apileaks.py --no-banner par \
  --target $API_TARGET \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "CI/CD Security Scanner v1.0" \
  --status-code 200,500-599 \
  --json-logs \
  --output ci_param_waf_scan

# Jenkins with user agent file rotation
python apileaks.py --no-banner full \
  --target $API_TARGET \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 200,401,403,500 \
  --json-logs \
  --rate-limit 20 \
  --output ci_full_waf_scan
```

## Configuration

### YAML Configuration
```yaml
# config/waf_evasion_config.yaml
waf_evasion:
  user_agent_strategy: "random"  # random, custom, file
  custom_user_agent: "Custom Security Scanner v1.0"
  user_agent_file: "wordlists/user_agents.txt"
  
  request_timing:
    min_delay: 0.1
    max_delay: 2.0
    adaptive: true
    
  header_randomization:
    enabled: true
    accept_encoding: ["gzip", "deflate", "br"]
    accept_language: ["en-US,en;q=0.9", "en-GB,en;q=0.8"]

rate_limiting:
  requests_per_second: 10
  adaptive: true
  respect_retry_after: true

http_output:
  status_code_filter: [200, 401, 403, 500]
```

### Environment Variables
```bash
# WAF Evasion Configuration
export APILEAK_USER_AGENT_STRATEGY="random"
export APILEAK_USER_AGENT_CUSTOM="Custom Security Scanner"
export APILEAK_USER_AGENT_FILE="wordlists/user_agents.txt"
export APILEAK_RATE_LIMIT="10"
```

## Best Practices

### 1. Respect Rate Limits
```bash
# Always use appropriate rate limiting
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --rate-limit 5 \
  --modules bola,auth
```

### 2. Monitor Response Patterns
```bash
# Use status code filtering to monitor WAF responses
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --status-code 200,403,429 \
  --wordlist wordlists/endpoints.txt
```

### 3. Vary Testing Patterns
```bash
# Combine different evasion techniques
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-file custom_agents.txt \
  --methods GET,POST \
  --rate-limit 8 \
  --modules bola,auth,property
```

### 4. Document Evasion Strategies
Always document the WAF evasion strategies used in your security assessments for reproducibility and compliance.

## Troubleshooting

### Common Issues

#### WAF Still Blocking Requests
- Reduce rate limiting: `--rate-limit 2`
- Use more realistic user agents
- Implement longer delays between requests
- Try different HTTP methods

#### Inconsistent Results
- Use `--user-agent-file` for consistent rotation
- Monitor response patterns with status code filtering
- Check for rate limiting responses (429 status codes)

#### Performance Issues
- Increase rate limiting for faster scanning
- Use `--status-code` filtering to reduce output
- Consider parallel scanning with multiple instances

## Security Considerations

### Authorized Testing Only
WAF evasion features should only be used during authorized security testing with proper permission and scope definition.

### Rate Limiting Respect
Always respect target application rate limits and implement appropriate delays to avoid service disruption.

### Legal Compliance
Ensure all WAF evasion testing complies with applicable laws, regulations, and organizational policies.

---

For more information about integrating WAF evasion with other APILeak features, see the [Usage Examples](usage-examples.md) and [CI/CD Integration](ci-cd-integration.md) documentation.