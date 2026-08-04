# OWASP API Security Top 10 Coverage

APILeak provides comprehensive coverage of the OWASP API Security Top 10 2023, the definitive list of the most critical API security risks.

## 📊 Coverage Overview

| Rank | Category | Module key | Status | Priority | Summary |
|------|----------|-----------|--------|----------|---------|
| **API1** | [Broken Object Level Authorization](bola-testing.md) | `bola` | ✅ Complete | P0 | Broken Object Level Authorization (BOLA) detection |
| **API2** | Broken Authentication | `auth` | ✅ Complete | P0 | Broken Authentication detection |
| **API3** | [Broken Object Property Level Authorization](property-level-auth.md) | `property` | ✅ Complete | P0 | Broken Object Property Level Authorization detection |
| **API4** | [Unrestricted Resource Consumption](resource-consumption.md) | `resource` | ✅ Complete | P1 | Unrestricted Resource Consumption detection |
| **API5** | [Broken Function Level Authorization](function-level-auth.md) | `function_auth` | ✅ Complete | P0 | Broken Function Level Authorization detection |
| **API6** | [Unrestricted Access to Sensitive Business Flows](business-flows.md) | `business_flow` | ✅ Complete | P1 | Unrestricted Access to Sensitive Business Flows detection |
| **API7** | [Server-Side Request Forgery](ssrf-testing.md) | `ssrf` | ✅ Complete | P1 | Server-Side Request Forgery (SSRF) detection |
| **API8** | [Security Misconfiguration](security-misconfiguration.md) | `security_misconfig` | ✅ Complete | P1 | Security Misconfiguration detection |
| **API9** | [Improper Inventory Management](inventory-management.md) | `inventory` | ✅ Complete | P2 | Improper Inventory Management detection |
| **API10** | [Unsafe Consumption of APIs](unsafe-consumption.md) | `unsafe_consumption` | ✅ Complete | P2 | Unsafe Consumption of APIs detection |

**Legend**: ✅ Complete

### Running the modules

```bash
# Isolated single-module run (recommended for focused red-team runs)
python apileaks.py owasp bola --target https://api.example.com

# Orchestrated run — all modules by default, or a subset with --modules
python apileaks.py scan --target https://api.example.com
python apileaks.py scan --target https://api.example.com --modules bola,auth
```

> `scan` is the primary orchestrator (discovery + all registered modules by default). `full` and `main` are deprecated, hidden aliases of `scan` (still functional, but they emit a stderr notice). Prefer `apileaks owasp <key>` for a single module — e.g. `full --modules bola` → `apileaks owasp bola`. Only `bola` and `auth` currently own module-specific options; the other eight accept transversal options only. See the [OWASP Command Reference](../owasp-command.md) for the complete `owasp` CLI documentation.

## 🎯 Module Status

All ten OWASP API Security Top 10 2023 modules are fully implemented and registered:

### P0 Modules (Critical)
- ✅ **API1 — `bola`**: Comprehensive ID enumeration, horizontal privilege escalation, anonymous object access, cross-user leakage. Supports composite-key, verb-tampering, parameter-pollution, and id-leakage probes with opt-in destructive mode.
- ✅ **API2 — `auth`**: JWT algorithm confusion, expired-token acceptance, weak HMAC secrets, missing authentication, MFA bypass, OAuth flow abuse, predictable reset tokens. Opt-in aggressive probes (rate-limit burst, revocation race).
- ✅ **API3 — `property`**: Mass assignment detection (dangerous fields injected into POST/PUT/PATCH bodies), sensitive field exposure (passwords, API keys, SSNs in responses), read-only property modification, undocumented field discovery across auth contexts. Configurable sensitive-field and mass-assignment-field lists.
- ✅ **API5 — `function_auth`**: Four attack levels — L1 multi-token matrix replay (admin-discovered endpoints with low-priv/anonymous tokens), L2 HTTP verb tampering + X-HTTP-Method-Override bypass, L3 mass-assignment role injection (registration/profile-update flows), L4 API version downgrade. Configurable admin paths, dangerous methods, role fields/values, version list, and JSON probe-matrix output.

### P1 Modules (High Priority)
- ✅ **API4 — `resource`**: Rate-limit absence (burst of N requests), large-payload acceptance (1MB/10MB), deeply nested JSON, ReDoS-susceptible patterns, complex query strings. Configurable burst size, payload sizes, and nesting depth.
- ✅ **API6 — `business_flow`**: Rate-limit absence detection (N repeated requests with no 429 or anti-automation headers), quota/inventory decrement check (resource fields unchanged across N requests), and multi-step flow bypass (complete ordered transaction sequences repeated end-to-end). Configurable patterns, quota fields, repetition count, and inter-request delay.
- ✅ **API7 — `ssrf`**: Internal network access, cloud metadata endpoint access (`169.254.169.254`), file-protocol abuse, URL-scheme bypass, IP-encoding bypass, blind SSRF via OOB callback, opt-in port scanning and redirect-chain probes.
- ✅ **API8 — `security_misconfig`**: Permissive CORS policy detection (wildcard origins, credentials+wildcard, dangerous methods), missing required security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP). Read-only probes — Safe Mode compatible by design. Configurable required-header list.

### P2 Modules (Medium Priority)
- ✅ **API8 — `security_misconfig`**: Permissive CORS policy detection (wildcard origins, credentials+wildcard, dangerous methods), missing required security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP). Read-only probes — Safe Mode compatible by design. Configurable required-header list.
- ✅ **API9 — `inventory`**: Deprecated, undocumented, and non-current API version detection via version fuzzing. Identifies `/api/v1/` accessible alongside `/api/v3/`, dev/beta endpoints in production, and decommissioned-but-live versions. Configurable deprecated detection toggle.
- ✅ **API10 — `unsafe_consumption`**: Unvalidated upstream data reflection (injection via query params and body), blind redirect following (Location-header and IMDS-signature detection), and cleartext upstream channel (static `http://` scheme check). Configurable upstream indicators, custom payloads, OOB redirect listener support.

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
python apileaks.py owasp auth --config config.yaml

# Test privilege escalation vulnerabilities  
python apileaks.py scan --config config.yaml --modules bola,function_auth

# Test data exposure vulnerabilities
python apileaks.py scan --config config.yaml --modules property,ssrf
```

### CI/CD Integration

Integrate OWASP testing into CI/CD pipelines:

```yaml
# .github/workflows/api-security.yml
- name: Run OWASP API Security Tests
  run: |
    python apileaks.py scan \
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

- **[BOLA Testing (API1)](bola-testing.md)** - Comprehensive guide to Broken Object Level Authorization testing
- **[Property Level Authorization (API3)](property-level-auth.md)** - Mass assignment, data exposure, and property-level access control
- **[SSRF Testing (API7)](ssrf-testing.md)** - Internal network access, cloud metadata, blind SSRF, bypass encodings, port scanning
- **[OWASP Command Reference](../owasp-command.md)** - Full `owasp` CLI reference for all ten modules and module-specific options
- **[Scan Guide](../scan-guide.md)** - Orchestrated multi-module scan with full `scan` option reference

For the `auth` (API2) module JWT attack vectors and manual utilities, see the **[JWT Attacks Guide](../jwt-attacks.md)**.

### Quick Reference

| Module | Key Tests | Common Findings |
|--------|-----------|-----------------|
| **BOLA** | ID enumeration, privilege escalation | Unauthorized object access, horizontal escalation |
| **Auth** | JWT analysis, token lifecycle | Weak algorithms, expired tokens, weak secrets |
| **Property** | Mass assignment, data exposure | Admin privilege escalation, sensitive data leaks |
| **Resource** | DoS testing, rate limiting | Missing rate limits, large payload acceptance |
| **Function** | Admin access, method bypass | Unauthorized admin access, HTTP method bypass |
| **SSRF** | Internal/metadata access, scheme bypass, blind OOB, port scan | Cloud metadata exposure, blocklist bypass, blind SSRF |

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
# Run all available OWASP modules (all enabled by default)
python apileaks.py scan \
  --config config/api_config.yaml \
  --target https://api.example.com

# Run only P0 (critical) modules
python apileaks.py scan \
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