# 🛡️ OWASP API Security Top 10 2023 Coverage

APILeak provides comprehensive coverage of the OWASP API Security Top 10 2023, the industry standard for API security vulnerabilities.

## Coverage Overview

| Category | Module | Status | Description |
|----------|--------|--------|-------------|
| **API1** | BOLA Testing | ✅ | Broken Object Level Authorization |
| **API2** | Auth Testing | ✅ | Broken Authentication |
| **API3** | Property Auth | ✅ | Broken Object Property Level Authorization |
| **API4** | Resource Testing | 🔄 | Unrestricted Resource Consumption |
| **API5** | Function Auth | 🔄 | Broken Function Level Authorization |
| **API6** | Business Flows | 📋 | Unrestricted Access to Sensitive Business Flows |
| **API7** | SSRF Testing | 🔄 | Server Side Request Forgery |
| **API8** | Security Config | 📋 | Security Misconfiguration |
| **API9** | Inventory Mgmt | 📋 | Improper Inventory Management |
| **API10** | Unsafe Consumption | 📋 | Unsafe Consumption of APIs |

**Legend**: ✅ Complete | 🔄 In Progress | 📋 Planned

## Detailed Module Information

### API1: Broken Object Level Authorization (BOLA) ✅
**Status**: Complete  
**Module**: `modules/owasp/bola_testing.py`

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
**Module**: `modules/owasp/property_auth_testing.py`

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

### API4: Unrestricted Resource Consumption 🔄
**Status**: In Progress  
**Module**: `modules/owasp/resource_testing.py`

Resource consumption attacks exploit APIs that don't properly limit resource usage, leading to denial of service.

**Planned Testing Capabilities**:
- Rate limiting bypass
- Resource exhaustion attacks
- Large payload handling
- Concurrent request flooding
- Memory consumption attacks

### API5: Broken Function Level Authorization 🔄
**Status**: In Progress  
**Module**: `modules/owasp/function_auth_testing.py`

Function-level authorization vulnerabilities allow users to access administrative or privileged functions.

**Planned Testing Capabilities**:
- Administrative function access
- Privilege escalation detection
- Role-based access control bypass
- Function enumeration
- Permission boundary testing

### API6: Unrestricted Access to Sensitive Business Flows 📋
**Status**: Planned  
**Module**: `modules/owasp/business_flows_testing.py`

Business flow vulnerabilities occur when APIs don't properly protect sensitive business operations.

**Planned Testing Capabilities**:
- Business logic bypass
- Workflow manipulation
- Transaction integrity testing
- Process flow validation
- Critical operation protection

### API7: Server Side Request Forgery (SSRF) 🔄
**Status**: In Progress  
**Module**: `modules/owasp/ssrf_testing.py`

SSRF vulnerabilities allow attackers to make requests to internal systems through the API server.

**Planned Testing Capabilities**:
- Internal network scanning
- Cloud metadata access
- Local file system access
- Port scanning through SSRF
- Protocol smuggling attacks

### API8: Security Misconfiguration 📋
**Status**: Planned  
**Module**: `modules/owasp/security_config_testing.py`

Security misconfigurations expose APIs to various attacks through improper setup.

**Planned Testing Capabilities**:
- CORS misconfiguration detection
- HTTP security headers validation
- Debug mode detection
- Default credential testing
- Unnecessary HTTP methods

### API9: Improper Inventory Management 📋
**Status**: Planned  
**Module**: `modules/owasp/inventory_mgmt_testing.py`

Inventory management issues occur when organizations lose track of their API endpoints and versions.

**Planned Testing Capabilities**:
- API version discovery
- Deprecated endpoint detection
- Shadow API identification
- Documentation consistency validation
- Endpoint lifecycle management

### API10: Unsafe Consumption of APIs 📋
**Status**: Planned  
**Module**: `modules/owasp/unsafe_consumption_testing.py`

Unsafe API consumption vulnerabilities occur when APIs blindly trust data from third-party APIs.

**Planned Testing Capabilities**:
- Third-party API validation
- Data sanitization testing
- Input validation bypass
- Upstream dependency security
- API chain attack detection

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
  enabled_modules: ["bola", "auth", "property", "resource", "function"]
  
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

### Short Term (Next Release)
- Complete API4 (Resource Testing) implementation
- Complete API5 (Function Auth) implementation
- Complete API7 (SSRF Testing) implementation

### Medium Term (Next 2 Releases)
- Implement API6 (Business Flows) testing
- Implement API8 (Security Config) testing
- Enhanced reporting with OWASP compliance scoring

### Long Term (Future Releases)
- Complete API9 (Inventory Management) implementation
- Complete API10 (Unsafe Consumption) implementation
- Advanced OWASP testing automation
- Integration with OWASP API Security tools

---

For detailed information about specific OWASP modules, see the individual module documentation in the `docs/owasp/` directory.