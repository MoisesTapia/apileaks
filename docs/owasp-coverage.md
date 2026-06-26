# 🛡️ OWASP API Security Top 10 2023 Coverage

APILeak provides comprehensive coverage of the OWASP API Security Top 10 2023, the industry standard for API security vulnerabilities.

## Coverage Overview

APILeak implements and registers all ten OWASP API Security Top 10 2023 categories. Every module is wired into the engine (`core/engine.py`) and enabled by default via `enabled_modules` (`core/config.py`).

| Category | Module | Status | Enable string | Module file | Description |
|----------|--------|--------|---------------|-------------|-------------|
| **API1** | BOLA Testing | ✅ | `bola` | `modules/owasp/bola_testing.py` | Broken Object Level Authorization |
| **API2** | Auth Testing | ✅ | `auth` | `modules/owasp/auth_testing.py` | Broken Authentication |
| **API3** | Property Auth | ✅ | `property` | `modules/owasp/property_level_auth.py` | Broken Object Property Level Authorization |
| **API4** | Resource Consumption | ✅ | `resource` | `modules/owasp/resource_consumption.py` | Unrestricted Resource Consumption |
| **API5** | Function Auth | ✅ | `function_auth` | `modules/owasp/function_level_auth.py` | Broken Function Level Authorization |
| **API6** | Business Flows | ✅ | `business_flow` | `modules/owasp/business_flows.py` | Unrestricted Access to Sensitive Business Flows |
| **API7** | SSRF Testing | ✅ | `ssrf` | `modules/owasp/ssrf_testing.py` | Server Side Request Forgery |
| **API8** | Security Misconfiguration | ✅ | `security_misconfig` | `modules/owasp/security_misconfiguration.py` | Security Misconfiguration |
| **API9** | Inventory Mgmt | ✅ | `inventory` | `modules/owasp/inventory_management.py` | Improper Inventory Management |
| **API10** | Unsafe Consumption | ✅ | `unsafe_consumption` | `modules/owasp/unsafe_consumption.py` | Unsafe Consumption of APIs |

**Legend**: ✅ Complete

## Detailed Module Information

### API1: Broken Object Level Authorization (BOLA) ✅
**Status**: Complete  
**Module**: `modules/owasp/bola_testing.py`  
**Enable string**: `bola`

BOLA vulnerabilities occur when APIs fail to properly validate that users can only access objects they're authorized to view or modify.

**Testing Capabilities**:
- Object ID enumeration
- Horizontal privilege escalation detection
- Vertical privilege escalation detection
- Cross-tenant data access validation
- Resource ownership verification

**Example Usage**:
```bash
python apileaks.py full --target https://api.example.com --modules bola
```

### API2: Broken Authentication ✅
**Status**: Complete  
**Module**: `modules/owasp/auth_testing.py`  
**Enable string**: `auth`

Authentication vulnerabilities allow attackers to compromise authentication tokens or exploit implementation flaws.

**Testing Capabilities**:
- JWT token validation bypass
- Session fixation attacks
- Credential stuffing detection
- Authentication bypass techniques
- Token expiration validation

**Example Usage**:
```bash
python apileaks.py full --target https://api.example.com --modules auth --jwt "your-jwt-token"
```

### API3: Broken Object Property Level Authorization ✅
**Status**: Complete  
**Module**: `modules/owasp/property_level_auth.py`  
**Enable string**: `property`

Property-level authorization vulnerabilities occur when APIs expose sensitive object properties without proper authorization checks.

**Testing Capabilities**:
- Sensitive field exposure detection
- Mass assignment vulnerabilities
- Property-level access control bypass
- Data leakage through API responses
- Field-level permission validation

**Example Usage**:
```bash
python apileaks.py full --target https://api.example.com --modules property
```

### API4: Unrestricted Resource Consumption ✅
**Status**: Complete  
**Module**: `modules/owasp/resource_consumption.py`  
**Enable string**: `resource`

Resource consumption attacks exploit APIs that don't properly limit resource usage, leading to denial of service.

**Testing Capabilities**:
- Rate limiting bypass
- Resource exhaustion attacks
- Large payload handling
- Concurrent request flooding
- Memory consumption attacks

### API5: Broken Function Level Authorization ✅
**Status**: Complete  
**Module**: `modules/owasp/function_level_auth.py`  
**Enable string**: `function_auth`

Function-level authorization vulnerabilities allow users to access administrative or privileged functions.

**Testing Capabilities**:
- Administrative function access
- Privilege escalation detection
- Role-based access control bypass
- Function enumeration
- Permission boundary testing

### API6: Unrestricted Access to Sensitive Business Flows ✅
**Status**: Complete  
**Module**: `modules/owasp/business_flows.py`  
**Enable string**: `business_flow`

Business flow vulnerabilities occur when APIs don't properly protect sensitive business operations against automated abuse.

**Testing Capabilities**:
- Sensitive business flow identification
- Repeated-request (anti-automation) probing up to the configured repetition limit
- Detection of missing rate limiting / anti-automation controls
- Safe Mode honors non-state-changing methods only

### API7: Server Side Request Forgery (SSRF) ✅
**Status**: Complete  
**Module**: `modules/owasp/ssrf_testing.py`  
**Enable string**: `ssrf`

SSRF vulnerabilities allow attackers to make requests to internal systems through the API server.

**Testing Capabilities**:
- Internal target injection into parameters and SSRF-prone headers
- Cloud metadata / internal-host access detection (`SSRF_INTERNAL_ACCESS`)
- File-protocol access detection (`FILE_PROTOCOL_ACCESS`)
- Safe Mode restricts injection to non-state-changing methods

### API8: Security Misconfiguration ✅
**Status**: Complete  
**Module**: `modules/owasp/security_misconfiguration.py`  
**Enable string**: `security_misconfig`

Security misconfigurations expose APIs to various attacks through improper setup. This module composes the existing `cors_analyzer` and `security_headers_analyzer`.

**Testing Capabilities**:
- CORS misconfiguration detection (`CORS_MISCONFIGURATION`)
- Missing HTTP security headers detection (`MISSING_SECURITY_HEADERS`)
- Read-only (GET/OPTIONS) probing, inherently Safe-Mode compatible

### API9: Improper Inventory Management ✅
**Status**: Complete  
**Module**: `modules/owasp/inventory_management.py`  
**Enable string**: `inventory`

Inventory management issues occur when organizations lose track of their API endpoints and versions. This module reuses the existing `version_fuzzer`.

**Testing Capabilities**:
- API version discovery
- Deprecated API version detection (`DEPRECATED_API_VERSION`)
- Undocumented / shadow version detection (`UNDOCUMENTED_API_VERSION`)
- Non-current versions categorized under API9

### API10: Unsafe Consumption of APIs ✅
**Status**: Complete  
**Module**: `modules/owasp/unsafe_consumption.py`  
**Enable string**: `unsafe_consumption`

Unsafe API consumption vulnerabilities occur when APIs blindly trust data from third-party/upstream APIs.

**Testing Capabilities**:
- Upstream-sourced data identification via configurable indicators
- Malformed/unexpected payload submission
- Reflected unvalidated upstream data detection (`UNSAFE_UPSTREAM_DATA`)
- Safe Mode restricts probing to non-state-changing methods

## Configuration

### Enabling OWASP Modules

You can enable specific OWASP modules using the `--modules` flag:

```bash
# Enable specific modules
python apileaks.py full --target https://api.example.com --modules bola,auth,property

# Enable all available modules
python apileaks.py full --target https://api.example.com --modules all

# Enable modules via configuration file
python apileaks.py full --config config/owasp_config.yaml --target https://api.example.com
```

### Configuration File Example

```yaml
# config/owasp_config.yaml
owasp_testing:
  enabled_modules: ["bola", "auth", "property", "resource", "function_auth", "ssrf", "business_flow", "security_misconfig", "inventory", "unsafe_consumption"]
  
  bola_testing:
    enabled: true
    max_object_ids: 1000
    enumeration_depth: 3
    
  auth_testing:
    enabled: true
    jwt_algorithms: ["HS256", "RS256", "ES256"]
    session_timeout: 3600
    
  property_testing:
    enabled: true
    sensitive_fields: ["password", "ssn", "credit_card"]
    mass_assignment_depth: 2
```

## Integration with Other Features

### Framework Detection
OWASP modules automatically adapt their testing strategies based on detected API frameworks:

```bash
# Combine OWASP testing with framework detection
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --detect-framework \
  --framework-confidence 0.8
```

### WAF Evasion
OWASP modules integrate with WAF evasion techniques:

```bash
# OWASP testing with WAF evasion
python apileaks.py full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --user-agent-random \
  --rate-limit 10
```

### Reporting
OWASP findings are automatically categorized and included in all report formats:

- **JSON Reports**: Machine-readable OWASP categorization
- **HTML Reports**: Visual OWASP coverage dashboard
- **XML Reports**: Structured OWASP compliance data
- **TXT Reports**: Human-readable OWASP summary

## Best Practices

### 1. Comprehensive Testing
```bash
# Run all available OWASP modules
python apileaks.py full \
  --target https://api.example.com \
  --modules all \
  --output comprehensive_owasp_scan
```

### 2. Targeted Testing
```bash
# Focus on authentication vulnerabilities
python apileaks.py full \
  --target https://api.example.com \
  --modules auth,bola \
  --jwt "your-jwt-token" \
  --output auth_focused_scan
```

### 3. CI/CD Integration
```bash
# OWASP testing in CI/CD pipelines
python apileaks.py --no-banner full \
  --target $API_TARGET \
  --modules bola,auth,property \
  --json-logs \
  --output ci_owasp_scan
```

## Roadmap

All ten OWASP API Security Top 10 2023 categories (API1–API10) are implemented and registered. Future work focuses on depth and tooling rather than coverage gaps:

- Enhanced reporting with OWASP compliance scoring
- Advanced OWASP testing automation
- Deeper detection heuristics per category
- Integration with additional OWASP API Security tools

---

For detailed information about specific OWASP modules, see the individual module documentation in the `docs/owasp/` directory.