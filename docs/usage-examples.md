# 🎯 Usage Examples

This guide provides comprehensive examples for using APILeak across different scenarios, from basic scans to advanced security testing workflows.

## Quick Start Commands

APILeak supports multiple scan modes for different use cases. Each mode is optimized for specific types of API security testing.

## Directory/Endpoint Fuzzing

Directory fuzzing helps discover hidden endpoints, administrative interfaces, and forgotten API paths.

### Basic Directory Fuzzing
```bash
# Simple directory fuzzing
python apileaks.py dir --target https://api.example.com

# With custom wordlist
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt
```

### Advanced Directory Fuzzing
```bash
# With WAF evasion and status filtering
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --status-code 200-299,401,403

# With custom user agent and multiple methods
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-custom "Mozilla/5.0 (Custom Security Scanner)" \
  --methods GET,POST,PUT,DELETE \
  --rate-limit 15

# With user agent rotation and error focus
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 500-599 \
  --output error_focused_scan

# With framework detection
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --detect-framework \
  --fuzz-versions \
  --user-agent-random \
  --output comprehensive_discovery
```

## Parameter Fuzzing

Parameter fuzzing identifies hidden parameters, injection points, and input validation issues.

### Basic Parameter Fuzzing
```bash
# Simple parameter fuzzing
python apileaks.py par --target https://api.example.com

# With custom wordlist
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt
```

### Advanced Parameter Fuzzing
```bash
# With authentication and WAF evasion
python apileaks.py par \
  --target https://api.example.com/users \
  --wordlist wordlists/parameters.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --rate-limit 10 \
  --methods GET,POST

# With custom user agent and response filtering
python apileaks.py par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "APILeak Security Scanner v2.0" \
  --status-code 200-299,400-499 \
  --output parameter_discovery

# Focus on injection detection
python apileaks.py par \
  --target https://api.example.com/search \
  --wordlist wordlists/injection_params.txt \
  --status-code 500-599 \
  --user-agent-random \
  --output injection_testing

# With framework detection
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --detect-framework \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output framework_aware_param_scan
```

## Full Comprehensive Scan

Full scans combine endpoint discovery, parameter fuzzing, and OWASP security testing for comprehensive coverage.

### Basic Full Scan
```bash
# Simple full scan
python apileaks.py full --target https://api.example.com

# With configuration file
python apileaks.py full \
  --config config/api_config.yaml \
  --target https://api.example.com
```

### Advanced Full Scan
```bash
# With WAF evasion and OWASP modules
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-file wordlists/user_agents.txt \
  --modules bola,auth,property \
  --rate-limit 5 \
  --output comprehensive_security_scan

# With custom user agent and status filtering
python apileaks.py full \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --user-agent-custom "Enterprise Security Scanner" \
  --status-code 200,401,403,500 \
  --output enterprise_scan

# With framework and version detection
python apileaks.py full \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.8 \
  --user-agent-random \
  --modules all \
  --output advanced_discovery_scan
```

## Advanced Discovery Features

### Framework Detection Only
```bash
# Detect API framework
python apileaks.py full \
  --target https://api.example.com \
  --detect-framework \
  --framework-confidence 0.8 \
  --output framework_detection

# Framework detection with confidence threshold
python apileaks.py full \
  --target https://api.example.com \
  --detect-framework \
  --framework-confidence 0.9 \
  --user-agent-random
```

### Version Fuzzing Only
```bash
# Discover API versions
python apileaks.py full \
  --target https://api.example.com \
  --fuzz-versions \
  --version-patterns "/v1,/v2,/api/v1,/api/v2" \
  --output version_discovery

# Version fuzzing with custom patterns
python apileaks.py full \
  --target https://api.example.com \
  --fuzz-versions \
  --version-patterns "/version1,/version2,/rest/v1,/rest/v2" \
  --user-agent-random
```

### Combined Advanced Discovery
```bash
# Framework detection and version fuzzing
python apileaks.py full \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.7 \
  --user-agent-random \
  --output combined_discovery

# With directory fuzzing integration
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --detect-framework \
  --fuzz-versions \
  --user-agent-random \
  --output integrated_discovery

# Short flags for convenience
python apileaks.py full \
  --target https://api.example.com \
  --df \
  --fv \
  --framework-confidence 0.9 \
  --user-agent-random
```

## Authentication Testing

### JWT Token Testing
```bash
# Basic JWT authentication
python apileaks.py full \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules auth,bola \
  --output jwt_security_test

# JWT with parameter fuzzing
python apileaks.py par \
  --target https://api.example.com/protected \
  --wordlist wordlists/parameters.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output jwt_param_test

# JWT with directory fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/admin_endpoints.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --status-code 200,401,403 \
  --output jwt_endpoint_test
```

### API Key Testing
```bash
# API key in header
python apileaks.py full \
  --target https://api.example.com \
  --header "X-API-Key: your-api-key" \
  --modules auth,bola \
  --output api_key_test

# API key in query parameter
python apileaks.py par \
  --target "https://api.example.com?api_key=your-key" \
  --wordlist wordlists/parameters.txt \
  --output api_key_param_test
```

## OWASP Security Testing

### Specific OWASP Modules
```bash
# BOLA (Broken Object Level Authorization) testing
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output bola_security_test

# Authentication testing
python apileaks.py full \
  --target https://api.example.com \
  --modules auth \
  --user-agent-random \
  --output auth_security_test

# Property-level authorization testing
python apileaks.py full \
  --target https://api.example.com \
  --modules property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output property_auth_test

# Multiple OWASP modules
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output comprehensive_owasp_test
```

### All Available OWASP Modules
```bash
# Run all implemented OWASP modules
python apileaks.py full \
  --target https://api.example.com \
  --modules all \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --rate-limit 8 \
  --output complete_owasp_assessment
```

## Status Code Filtering Examples

### Success Response Focus
```bash
# Only show successful responses
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --status-code 200-299 \
  --user-agent-random \
  --output success_endpoints

# Focus on specific success codes
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --status-code 200,201,202 \
  --output successful_parameters
```

### Error Analysis
```bash
# Server error analysis
python apileaks.py par \
  --target https://api.example.com/search \
  --wordlist wordlists/injection_params.txt \
  --status-code 500-599 \
  --output server_errors

# Client error analysis
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --status-code 400-499 \
  --output client_errors
```

### Authentication Focus
```bash
# Authentication-related responses
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/admin_endpoints.txt \
  --status-code 401,403 \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output auth_responses

# Mixed authentication and success responses
python apileaks.py full \
  --target https://api.example.com \
  --status-code 200,401,403 \
  --modules bola,auth \
  --output auth_focused_scan
```

## Performance Optimization

### High-Speed Scanning
```bash
# Fast directory fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --rate-limit 50 \
  --status-code 200-299 \
  --user-agent-random

# Fast parameter discovery
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --rate-limit 30 \
  --methods GET,POST \
  --status-code 200,500-599
```

### Conservative Scanning
```bash
# Slow and careful scanning
python apileaks.py full \
  --target https://api.example.com \
  --rate-limit 2 \
  --user-agent-random \
  --modules bola,auth \
  --output careful_scan

# Respectful parameter testing
python apileaks.py par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --rate-limit 5 \
  --user-agent-custom "Authorized Security Test" \
  --output respectful_param_test
```

## Legacy Usage (Still Supported)

### Traditional Configuration-Based Usage
```bash
# Traditional usage with config file
python apileaks.py \
  --config config/api_config.yaml \
  --target https://api.example.com

# With custom configuration
python apileaks.py \
  --config config/comprehensive_config.yaml \
  --target https://api.example.com \
  --output legacy_scan
```

## Command Options Reference

### Global Options
- `--no-banner` - Suppress banner output for CI/CD integration
- `--help` - Show help message and available commands

### Common Options (Available in all commands)
- `-t, --target` - Target URL to scan (required)
- `-o, --output` - Output filename for reports (files saved in reports/ directory)
- `--log-level` - Logging level: DEBUG, INFO, WARNING, ERROR (default: WARNING)
- `--log-file` - Log file path (optional)
- `--json-logs` - Output logs in JSON format for structured logging
- `--rate-limit` - Requests per second limit (default: 10)
- `--jwt` - JWT token to use for authentication
- `--response` - Filter by response codes (e.g., 200,301,404 or 200-300)
- `--status-code` - Show only HTTP requests with specific status codes

### WAF Evasion Options (Available in all commands)
- `--user-agent-random` - Use random User-Agent headers from built-in list
- `--user-agent-custom "Custom Agent"` - Use a custom User-Agent string
- `--user-agent-file path/to/file.txt` - Use User-Agent rotation from file

**Note**: Only one user agent option can be used at a time.

### Full Scan Specific Options
- `-c, --config` - Configuration file path (YAML or JSON) - optional
- `--modules` - Comma-separated list of OWASP modules to enable
- `--detect-framework, --df` - Enable framework detection
- `--fuzz-versions, --fv` - Enable API version fuzzing
- `--framework-confidence` - Minimum confidence threshold (0.0-1.0, default: 0.6)
- `--version-patterns` - Custom version patterns for fuzzing

### Directory Fuzzing Specific Options
- `-w, --wordlist` - Wordlist file for directory fuzzing
- `--methods` - HTTP methods to test (default: GET,POST,PUT,DELETE,PATCH)
- `--detect-framework, --df` - Enable framework detection during directory fuzzing
- `--fuzz-versions, --fv` - Enable API version fuzzing during directory discovery

### Parameter Fuzzing Specific Options
- `-w, --wordlist` - Wordlist file for parameter fuzzing
- `--methods` - HTTP methods to test (default: GET,POST)
- `--detect-framework, --df` - Enable framework detection during parameter fuzzing

## Real-World Scenarios

### E-commerce API Testing
```bash
# Comprehensive e-commerce API security assessment
python apileaks.py full \
  --target https://api.ecommerce.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules bola,auth,property \
  --user-agent-random \
  --status-code 200,401,403,500 \
  --detect-framework \
  --output ecommerce_security_assessment
```

### Banking API Security Test
```bash
# Conservative banking API testing
python apileaks.py full \
  --target https://api.bank.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules bola,auth,property \
  --user-agent-custom "Authorized Security Assessment" \
  --rate-limit 2 \
  --status-code 200,401,403 \
  --output banking_security_test
```

### Mobile App API Testing
```bash
# Mobile app backend API testing
python apileaks.py full \
  --target https://mobile-api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modules bola,auth,property \
  --user-agent-file mobile_user_agents.txt \
  --detect-framework \
  --fuzz-versions \
  --output mobile_api_security_test
```

### Microservices Testing
```bash
# Individual microservice testing
python apileaks.py full \
  --target https://user-service.example.com \
  --modules bola,auth \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output user_service_test

python apileaks.py full \
  --target https://payment-service.example.com \
  --modules bola,auth,property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output payment_service_test
```

## Troubleshooting Common Issues

### Rate Limiting Issues
```bash
# If you encounter rate limiting (429 responses)
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 1 \
  --user-agent-random \
  --wordlist wordlists/endpoints.txt
```

### WAF Blocking
```bash
# If WAF is blocking requests
python apileaks.py par \
  --target https://api.example.com \
  --user-agent-file realistic_agents.txt \
  --rate-limit 3 \
  --wordlist wordlists/parameters.txt
```

### Large Response Handling
```bash
# For APIs with large responses
python apileaks.py full \
  --target https://api.example.com \
  --status-code 200-299 \
  --rate-limit 5 \
  --modules bola,auth
```

---

For more specific use cases and advanced configurations, see the [Configuration Guide](configuration.md) and [CI/CD Integration](ci-cd-integration.md) documentation.