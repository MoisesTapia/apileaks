# OWASP API Security Top 10 Coverage

APILeak provides comprehensive coverage of the OWASP API Security Top 10 2023, the definitive list of the most critical API security risks.

## 📊 Coverage Overview

| Rank | Category | Module | Status | Priority | Description |
|------|----------|--------|--------|----------|-------------|
| **API1** | [Broken Object Level Authorization](bola-testing.md) | `bola_testing` | ✅ Complete | P0 | Unauthorized access to objects |
| **API2** | [Broken Authentication](auth-testing.md) | `auth_testing` | ✅ Complete | P0 | Authentication mechanism flaws |
| **API3** | [Broken Object Property Level Authorization](property-level-auth.md) | `property_testing` | ✅ Complete | P0 | Property-level access control issues |
| **API4** | [Unrestricted Resource Consumption](resource-consumption.md) | `resource_testing` | 🔄 In Progress | P1 | DoS through resource exhaustion |
| **API5** | [Broken Function Level Authorization](function-level-auth.md) | `function_auth_testing` | 🔄 In Progress | P0 | Function-level access control flaws |
| **API6** | Unrestricted Access to Sensitive Business Flows | `business_flows` | 📋 Planned | P1 | Business logic bypass |
| **API7** | [Server Side Request Forgery](ssrf-testing.md) | `ssrf_testing` | 🔄 In Progress | P1 | SSRF vulnerabilities |
| **API8** | Security Misconfiguration | `security_config` | 📋 Planned | P1 | Configuration security issues |
| **API9** | Improper Inventory Management | `inventory_mgmt` | 📋 Planned | P2 | API inventory and versioning |
| **API10** | Unsafe Consumption of APIs | `unsafe_consumption` | 📋 Planned | P2 | Third-party API consumption risks |

**Legend**: ✅ Complete | 🔄 In Progress | 📋 Planned

## 🎯 Implementation Strategy

### Phase 1: P0 Modules (Critical - Weeks 1-10)
Focus on the most critical vulnerabilities that pose immediate security risks:

- ✅ **API1 - BOLA Testing**: Complete with comprehensive ID enumeration and privilege escalation detection
- ✅ **API2 - Authentication Testing**: Complete with JWT analysis, weak secrets, and token lifecycle testing  
- ✅ **API3 - Property Level Authorization**: Complete with mass assignment and sensitive data exposure detection
- 🔄 **API5 - Function Level Authorization**: In development - admin access and privilege escalation testing

### Phase 2: P1 Modules (High Priority - Weeks 11-16)
Important vulnerabilities that significantly impact security:

- 🔄 **API4 - Resource Consumption**: DoS testing, rate limiting validation, payload size limits
- 🔄 **API7 - SSRF Testing**: Internal network access, cloud metadata exposure, file protocol abuse
- 📋 **API6 - Business Flows**: Business logic bypass, workflow manipulation
- 📋 **API8 - Security Misconfiguration**: CORS, security headers, framework detection

### Phase 3: P2 Modules (Medium Priority - Weeks 17-20)
Operational and inventory management vulnerabilities:

- 📋 **API9 - Inventory Management**: API versioning, deprecated endpoints, documentation gaps
- 📋 **API10 - Unsafe Consumption**: Third-party API risks, data validation, trust boundaries

## 🛡️ Module Architecture

Each OWASP module follows a consistent architecture pattern:

```python
class OWASPModule(ABC):
    """Base class for OWASP testing modules"""
    
    def __init__(self, config: ModuleConfig, http_client: HTTPClient, auth_contexts: List[AuthContext])
    
    @abstractmethod
    async def execute_tests(self, endpoints: List[Endpoint]) -> List[Finding]
    
    @abstractmethod
    def get_module_name(self) -> str
```

### Common Features

All OWASP modules provide:

- **Multi-Context Testing**: Test with different authentication contexts (anonymous, user, admin)
- **Intelligent Detection**: Pattern-based vulnerability detection with low false positives
- **Severity Classification**: Automatic CRITICAL/HIGH/MEDIUM/LOW severity assignment
- **Evidence Collection**: Detailed evidence and reproduction steps
- **OWASP Categorization**: Proper mapping to OWASP API Security Top 10 categories

## 📈 Testing Methodology

### Property-Based Testing

APILeak uses property-based testing with Hypothesis to ensure comprehensive coverage:

```python
@given(endpoints=endpoint_strategy(), auth_contexts=auth_context_strategy())
@settings(max_examples=100)
def test_bola_detection_property(endpoints, auth_contexts):
    """
    **Feature: BOLA Detection**
    **Validates: Requirements 1.1, 1.2, 1.3**
    
    For any endpoint with object IDs and any authentication contexts,
    BOLA detection should identify unauthorized access patterns.
    """
    # Property implementation
```

### Correctness Properties

Each module implements specific correctness properties:

- **BOLA Module**: ID enumeration, horizontal privilege escalation, object access validation
- **Auth Module**: JWT vulnerability detection, token lifecycle validation, weak secret detection
- **Property Module**: Mass assignment detection, sensitive data exposure, undocumented field identification

## 🔧 Configuration

### Enable All OWASP Modules

```yaml
owasp_testing:
  enabled_modules: ["all"]
```

### Enable Specific Modules

```yaml
owasp_testing:
  enabled_modules: ["bola", "auth", "property", "function_auth"]
```

### Module-Specific Configuration

```yaml
owasp_testing:
  # API1 - BOLA Testing
  bola_testing:
    enabled: true
    id_patterns: ["sequential", "guid", "uuid"]
    enumeration_range: 10
  
  # API2 - Authentication Testing  
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: "wordlists/jwt_secrets.txt"
  
  # API3 - Property Level Authorization
  property_testing:
    enabled: true
    sensitive_fields: ["password", "api_key", "secret"]
    mass_assignment_fields: ["is_admin", "role", "permissions"]
```

## 📊 Coverage Analysis

APILeak provides real-time OWASP coverage analysis:

### Coverage Metrics

```
OWASP API Security Top 10 Coverage:
✓ API1: Broken Object Level Authorization (Risk: CRITICAL, Findings: 2)
✓ API2: Broken Authentication (Risk: HIGH, Findings: 1)  
✓ API3: Broken Object Property Level Authorization (Risk: MEDIUM, Findings: 3)
✗ API4: Unrestricted Resource Consumption
✗ API5: Broken Function Level Authorization
✗ API6: Unrestricted Access to Sensitive Business Flows
✗ API7: Server Side Request Forgery
✗ API8: Security Misconfiguration
✗ API9: Improper Inventory Management
✗ API10: Unsafe Consumption of APIs

Overall Coverage: 30.0% (3/10 categories)
Risk Level: CRITICAL (2 critical findings detected)
```

### Coverage API

```python
# Get coverage programmatically
coverage = findings_collector.get_owasp_coverage()

print(f"Coverage: {coverage['coverage_percentage']:.1f}%")
print(f"Tested Categories: {coverage['tested_categories']}")
print(f"Untested Categories: {coverage['untested_categories']}")
```

## 🎯 Testing Strategies

### Comprehensive Testing

For maximum coverage, use all available authentication contexts:

```yaml
authentication:
  contexts:
    - name: "anonymous"
      privilege_level: 0
    - name: "user"  
      privilege_level: 1
    - name: "moderator"
      privilege_level: 2
    - name: "admin"
      privilege_level: 3
```

### Targeted Testing

Focus on specific vulnerability categories:

```bash
# Test only authentication vulnerabilities
python apileaks.py --config config.yaml --modules auth

# Test privilege escalation vulnerabilities  
python apileaks.py --config config.yaml --modules bola,function_auth

# Test data exposure vulnerabilities
python apileaks.py --config config.yaml --modules property,ssrf
```

### CI/CD Integration

Integrate OWASP testing into CI/CD pipelines:

```yaml
# .github/workflows/api-security.yml
- name: Run OWASP API Security Tests
  run: |
    python apileaks.py \
      --config config/ci.yaml \
      --modules bola,auth,property \
      --no-banner \
      --json-logs
  
- name: Check for Critical Findings
  run: |
    if [ $? -eq 2 ]; then
      echo "Critical security findings detected!"
      exit 1
    fi
```

## 📚 Module Documentation

### Detailed Module Guides

- **[BOLA Testing](bola-testing.md)** - Comprehensive guide to Broken Object Level Authorization testing
- **[Authentication Testing](auth-testing.md)** - JWT vulnerabilities, token lifecycle, and weak authentication
- **[Property Level Authorization](property-level-auth.md)** - Mass assignment, data exposure, and property-level access control
- **[Resource Consumption](resource-consumption.md)** - DoS testing and resource exhaustion detection
- **[Function Level Authorization](function-level-auth.md)** - Admin access and function-level privilege testing
- **[SSRF Testing](ssrf-testing.md)** - Server-Side Request Forgery detection and exploitation

### Quick Reference

| Module | Key Tests | Common Findings |
|--------|-----------|-----------------|
| **BOLA** | ID enumeration, privilege escalation | Unauthorized object access, horizontal escalation |
| **Auth** | JWT analysis, token lifecycle | Weak algorithms, expired tokens, weak secrets |
| **Property** | Mass assignment, data exposure | Admin privilege escalation, sensitive data leaks |
| **Resource** | DoS testing, rate limiting | Missing rate limits, large payload acceptance |
| **Function** | Admin access, method bypass | Unauthorized admin access, HTTP method bypass |
| **SSRF** | Internal network access | Cloud metadata access, internal service exposure |

## 🔍 Finding Analysis

### Severity Classification

APILeak automatically classifies findings by severity:

- **CRITICAL**: Immediate security risk (unauthorized admin access, data exposure)
- **HIGH**: Significant security impact (privilege escalation, authentication bypass)  
- **MEDIUM**: Moderate security concern (information disclosure, missing controls)
- **LOW**: Minor security issue (verbose errors, deprecated features)
- **INFO**: Informational findings (framework detection, endpoint discovery)

### OWASP Mapping

All findings are automatically mapped to OWASP categories:

```python
finding = Finding(
    category="BOLA_ANONYMOUS_ACCESS",
    owasp_category="API1",  # Automatically assigned
    severity=Severity.CRITICAL,
    evidence="Anonymous user can access user object 12345",
    recommendation="Implement proper object-level authorization"
)
```

## 🚀 Getting Started

### Quick OWASP Scan

```bash
# Run all available OWASP modules
python apileaks.py \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --modules all

# Run only P0 (critical) modules
python apileaks.py \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --modules bola,auth,property
```

### Custom OWASP Configuration

```yaml
# config/owasp_comprehensive.yaml
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
    - name: "admin"
      type: "bearer"
      token: "${ADMIN_TOKEN}"
      privilege_level: 3

owasp_testing:
  enabled_modules: ["bola", "auth", "property"]
  
  bola_testing:
    enumeration_range: 20
    max_objects_per_endpoint: 100
  
  auth_testing:
    jwt_testing: true
    test_logout_invalidation: true
  
  property_testing:
    detect_undocumented_fields: true

rate_limiting:
  requests_per_second: 5
  adaptive: true

reporting:
  formats: ["json", "html"]
  include_owasp_coverage: true
```

---

For detailed information about each OWASP module, see the individual module documentation pages. 🛡️