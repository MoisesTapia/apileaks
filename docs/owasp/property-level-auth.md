# Property Level Authorization Testing (API3)

The Property Level Authorization Testing Module detects **OWASP API3 - Broken Object Property Level Authorization** vulnerabilities, including mass assignment, excessive data exposure, and property-level access control issues.

## 📋 Table of Contents

- [Overview](#overview)
- [Vulnerability Types](#vulnerability-types)
- [Testing Methodology](#testing-methodology)
- [Configuration](#configuration)
- [Implementation Details](#implementation-details)
- [Property-Based Testing](#property-based-testing)
- [Common Findings](#common-findings)
- [Remediation](#remediation)

## 🎯 Overview

Property Level Authorization vulnerabilities occur when APIs expose more data than intended or allow modification of properties that should be read-only or restricted. This module comprehensively tests for:

- **Sensitive Data Exposure**: Detection of passwords, API keys, and personal information in responses
- **Mass Assignment**: Testing modification of dangerous properties like `is_admin`, `role`, `permissions`
- **Read-Only Property Modification**: Attempting to modify supposedly immutable fields
- **Undocumented Field Discovery**: Identifying fields that appear inconsistently across authentication contexts

## 🔍 Vulnerability Types

### 1. Sensitive Data Exposure

**Description**: APIs returning sensitive information that should be filtered based on user permissions.

**Examples**:
```json
// Bad: Exposing sensitive fields to regular users
{
  "user_id": 123,
  "username": "john_doe",
  "password": "hashed_password_123",  // ❌ Should not be exposed
  "api_key": "sk_live_abc123def456",  // ❌ Should not be exposed
  "ssn": "123-45-6789",              // ❌ Should not be exposed
  "email": "john@example.com",
  "role": "user"
}

// Good: Filtered response for regular users
{
  "user_id": 123,
  "username": "john_doe",
  "email": "john@example.com",
  "role": "user"
}
```

### 2. Mass Assignment

**Description**: APIs accepting and processing dangerous properties that allow privilege escalation or unauthorized modifications.

**Examples**:
```json
// Attack: Attempting to escalate privileges
POST /api/users/123
{
  "name": "John Doe",
  "email": "john@example.com",
  "is_admin": true,        // ❌ Dangerous field
  "role": "admin",         // ❌ Dangerous field
  "permissions": ["all"]   // ❌ Dangerous field
}

// Result: User gains admin privileges
{
  "user_id": 123,
  "name": "John Doe", 
  "email": "john@example.com",
  "is_admin": true,        // ❌ Mass assignment successful
  "role": "admin",         // ❌ Privilege escalation
  "permissions": ["all"]
}
```

### 3. Read-Only Property Modification

**Description**: APIs allowing modification of fields that should be immutable.

**Examples**:
```json
// Attack: Attempting to modify read-only fields
PUT /api/users/123
{
  "id": 999,                           // ❌ Should be immutable
  "created_at": "2099-01-01T00:00:00Z", // ❌ Should be immutable
  "user_id": 456,                      // ❌ Should be immutable
  "version": 999                       // ❌ Should be immutable
}

// Bad Result: Read-only fields were modified
{
  "id": 999,                           // ❌ ID was changed
  "created_at": "2099-01-01T00:00:00Z", // ❌ Timestamp was modified
  "user_id": 456,                      // ❌ User ID was changed
  "version": 999                       // ❌ Version was modified
}
```

### 4. Undocumented Field Exposure

**Description**: APIs exposing different fields based on authentication context without proper documentation.

**Examples**:
```json
// Response for regular user
{
  "user_id": 123,
  "username": "john_doe",
  "email": "john@example.com"
}

// Response for admin user (same endpoint)
{
  "user_id": 123,
  "username": "john_doe", 
  "email": "john@example.com",
  "internal_notes": "VIP customer",     // ❌ Undocumented field
  "debug_info": {...},                  // ❌ Undocumented field
  "system_flags": [...]                 // ❌ Undocumented field
}
```

## 🧪 Testing Methodology

### 1. Sensitive Data Detection

The module analyzes API responses to detect sensitive information:

```python
# Sensitive field patterns
SENSITIVE_FIELD_PATTERNS = {
    'financial': [
        r'credit_card', r'cc_number', r'account_number', 
        r'routing_number', r'bank_account', r'payment', r'billing'
    ],
    'password': [
        r'password', r'passwd', r'pwd', r'pass', r'secret',
        r'hash', r'encrypted', r'cipher'
    ],
    'api_key': [
        r'api_key', r'apikey', r'key', r'token', r'secret',
        r'access_token', r'refresh_token', r'bearer'
    ],
    'personal_data': [
        r'ssn', r'social_security', r'phone', r'email', 
        r'address', r'birth_date', r'dob'
    ],
    'internal': [
        r'internal', r'debug', r'admin', r'system', r'config',
        r'database', r'db_', r'sql', r'query'
    ]
}
```

**Detection Process**:
1. Make requests with different authentication contexts
2. Parse JSON responses and extract all field names
3. Match field names against sensitive patterns
4. Check field values for sensitive data patterns (SSN, credit cards, API keys)
5. Classify severity based on data type and user privilege level

### 2. Mass Assignment Testing

The module tests for mass assignment vulnerabilities:

```python
# Dangerous fields for mass assignment
MASS_ASSIGNMENT_FIELDS = [
    'is_admin', 'admin', 'role', 'roles', 'permissions', 'privilege',
    'user_id', 'id', 'account_id', 'owner_id', 'created_by',
    'is_active', 'enabled', 'status', 'verified', 'approved',
    'balance', 'credit', 'points', 'score', 'level'
]
```

**Testing Process**:
1. Make baseline request to understand normal response
2. For each dangerous field, create test payload
3. Send POST/PUT/PATCH request with dangerous field
4. Compare response to detect if field was processed
5. Check if dangerous value appears in response or causes privilege escalation

### 3. Read-Only Property Testing

The module attempts to modify supposedly immutable fields:

```python
# Read-only field patterns
READ_ONLY_FIELDS = [
    'id', 'created_at', 'updated_at', 'timestamp', 'created_by',
    'modified_by', 'version', 'revision', 'hash', 'checksum'
]
```

**Testing Process**:
1. Identify read-only fields from baseline response
2. Generate modified values for each read-only field
3. Send modification request with altered read-only fields
4. Check if read-only fields were actually modified
5. Report successful modification as vulnerability

### 4. Undocumented Field Analysis

The module compares responses across authentication contexts:

**Analysis Process**:
1. Make same request with different authentication contexts
2. Extract all field names from each response
3. Compare field sets to find context-specific fields
4. Filter out common metadata fields
5. Report fields that appear only for certain contexts

## ⚙️ Configuration

### Basic Configuration

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
    
    # Dangerous fields for mass assignment
    mass_assignment_fields:
      - "is_admin"
      - "role"
      - "permissions"
      - "user_id"
```

### Advanced Configuration

```yaml
owasp_testing:
  property_testing:
    enabled: true
    
    # Comprehensive sensitive field detection
    sensitive_fields:
      # Authentication & Authorization
      - "password"
      - "passwd"
      - "pwd"
      - "secret"
      - "api_key"
      - "access_token"
      - "refresh_token"
      - "bearer_token"
      
      # Personal Information
      - "ssn"
      - "social_security"
      - "phone"
      - "email"
      - "address"
      - "birth_date"
      - "dob"
      
      # Financial Information
      - "credit_card"
      - "cc_number"
      - "account_number"
      - "routing_number"
      - "bank_account"
      
      # Internal/Debug Information
      - "internal_notes"
      - "debug_info"
      - "system_flags"
      - "admin_notes"
    
    # Mass assignment dangerous fields
    mass_assignment_fields:
      # Privilege Escalation
      - "is_admin"
      - "admin"
      - "role"
      - "roles"
      - "permissions"
      - "privilege"
      - "privilege_level"
      
      # Identity Manipulation
      - "user_id"
      - "id"
      - "account_id"
      - "owner_id"
      - "created_by"
      - "modified_by"
      
      # Status Manipulation
      - "is_active"
      - "enabled"
      - "status"
      - "verified"
      - "approved"
      - "confirmed"
      
      # Financial Manipulation
      - "balance"
      - "credit"
      - "points"
      - "score"
      - "level"
      - "tier"
    
    # Testing options
    test_readonly_fields: true
    detect_undocumented_fields: true
    
    # HTTP methods to use for testing
    test_methods: ["POST", "PUT", "PATCH"]
    
    # Maximum number of fields to test per endpoint
    max_fields_per_endpoint: 50
```

### Authentication Context Setup

Property level authorization testing requires multiple authentication contexts:

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
      token: "${USER_TOKEN}"
      privilege_level: 1
    
    # Moderator/Manager
    - name: "moderator"
      type: "bearer"
      token: "${MODERATOR_TOKEN}"
      privilege_level: 2
    
    # Administrator
    - name: "admin"
      type: "bearer"
      token: "${ADMIN_TOKEN}"
      privilege_level: 3
```

## 🔧 Implementation Details

### Module Architecture

```python
class PropertyLevelAuthModule(OWASPModule):
    """Property Level Authorization Testing Module"""
    
    async def execute_tests(self, endpoints: List[Endpoint]) -> List[Finding]:
        """Execute all property-level authorization tests"""
        findings = []
        
        # Test sensitive data exposure
        sensitive_findings = await self._test_sensitive_data_exposure(endpoints)
        findings.extend(sensitive_findings)
        
        # Test mass assignment
        mass_assignment_findings = await self._test_mass_assignment(endpoints)
        findings.extend(mass_assignment_findings)
        
        # Test read-only property modification
        readonly_findings = await self._test_readonly_property_modification(endpoints)
        findings.extend(readonly_findings)
        
        # Test undocumented fields
        undocumented_findings = await self._test_undocumented_fields(endpoints)
        findings.extend(undocumented_findings)
        
        return findings
```

### Sensitive Data Detection

```python
async def _test_sensitive_data_exposure(self, endpoints: List[Endpoint]) -> List[Finding]:
    """Test for sensitive data exposure"""
    findings = []
    
    for auth_context in self.auth_contexts:
        self.http_client.set_auth_context(auth_context)
        
        for endpoint in endpoints:
            response = await self.http_client.request('GET', endpoint.url)
            
            if response.is_success:
                sensitive_fields = self._detect_sensitive_fields(response, endpoint.url)
                
                for field in sensitive_fields:
                    severity = self._classify_sensitive_data_severity(field, auth_context)
                    
                    finding = Finding(
                        category='SENSITIVE_DATA_EXPOSURE',
                        owasp_category='API3',
                        severity=severity,
                        endpoint=endpoint.url,
                        evidence=f"Sensitive field '{field.field_name}' exposed",
                        recommendation="Implement field-level authorization"
                    )
                    findings.append(finding)
    
    return findings
```

### Mass Assignment Testing

```python
async def _test_mass_assignment(self, endpoints: List[Endpoint]) -> List[Finding]:
    """Test for mass assignment vulnerabilities"""
    findings = []
    
    for endpoint in endpoints:
        # Get baseline response
        baseline_response = await self.http_client.request('GET', endpoint.url)
        existing_fields = self._extract_fields_from_response(baseline_response)
        
        # Test each dangerous field
        for dangerous_field in self.mass_assignment_fields:
            test_payload = {dangerous_field: self._generate_test_value(dangerous_field)}
            test_payload.update(existing_fields)  # Include existing fields
            
            test_response = await self.http_client.request('POST', endpoint.url, json=test_payload)
            
            if self._is_mass_assignment_successful(baseline_response, test_response, dangerous_field):
                finding = Finding(
                    category='MASS_ASSIGNMENT',
                    owasp_category='API3',
                    severity=self._classify_mass_assignment_severity(dangerous_field),
                    endpoint=endpoint.url,
                    evidence=f"Mass assignment successful for field '{dangerous_field}'",
                    recommendation="Use allow-lists for accepted fields"
                )
                findings.append(finding)
    
    return findings
```

## 🧪 Property-Based Testing

The module includes comprehensive property-based tests using Hypothesis:

### Property 8: Mass Assignment Detection

```python
@given(
    baseline_response=response_strategy(),
    test_response=response_strategy(), 
    field_name=st.sampled_from(['is_admin', 'role', 'permissions']),
    test_value=st.one_of(st.booleans(), st.text(), st.integers())
)
@settings(max_examples=100)
def test_mass_assignment_detection_property(self, baseline_response, test_response, field_name, test_value):
    """
    **Feature: apileak-owasp-enhancement, Property 8: Mass Assignment Detection**
    **Validates: Requirements 3.2, 3.3**
    
    For any baseline and test response, mass assignment detection should correctly
    identify when dangerous fields are accepted and processed.
    """
    result = self.module._is_mass_assignment_successful(
        baseline_response, test_response, field_name, test_value
    )
    
    # Property: Result should always be boolean
    assert isinstance(result, bool)
    
    # Property: If test response contains the field with test value, should return True
    if field_name in test_response.json and test_response.json[field_name] == test_value:
        assert result is True
```

### Property 9: Undocumented Field Detection

```python
@given(field_names=st.lists(st.text(min_size=1, max_size=30), min_size=1, max_size=20))
@settings(max_examples=100)
def test_undocumented_field_filtering_property(self, field_names):
    """
    **Feature: apileak-owasp-enhancement, Property 9: Undocumented Field Detection**
    **Validates: Requirements 3.4**
    
    For any list of field names, undocumented field filtering should consistently
    identify potentially undocumented fields while filtering out common metadata.
    """
    for field_name in field_names:
        result = self.module._is_potentially_undocumented(field_name)
        
        # Property: Result should always be boolean
        assert isinstance(result, bool)
        
        # Property: Common metadata fields should be filtered out
        common_fields = ['timestamp', 'created_at', 'updated_at', 'id']
        if any(common in field_name.lower() for common in common_fields):
            assert result is False
```

## 🔍 Common Findings

### Critical Severity Findings

**SENSITIVE_DATA_EXPOSURE - Password/API Key Exposure**
```
Category: SENSITIVE_DATA_EXPOSURE
Severity: CRITICAL
Evidence: Password field 'user_password' exposed in API response to regular user
Endpoint: GET /api/users/123
Recommendation: Remove sensitive fields from API responses or implement proper field-level authorization
```

**MASS_ASSIGNMENT - Admin Privilege Escalation**
```
Category: MASS_ASSIGNMENT  
Severity: CRITICAL
Evidence: Mass assignment successful for field 'is_admin' - user gained admin privileges
Endpoint: POST /api/users/123
Recommendation: Use allow-lists for accepted fields and reject dangerous properties
```

### High Severity Findings

**SENSITIVE_DATA_EXPOSURE - Personal Data to Low-Privilege User**
```
Category: SENSITIVE_DATA_EXPOSURE
Severity: HIGH
Evidence: Personal data field 'ssn' exposed to user with privilege level 1
Endpoint: GET /api/users/456
Recommendation: Implement role-based field filtering for personal information
```

**MASS_ASSIGNMENT - Financial Field Manipulation**
```
Category: MASS_ASSIGNMENT
Severity: HIGH  
Evidence: Mass assignment successful for field 'balance' - user modified account balance
Endpoint: PUT /api/accounts/789
Recommendation: Protect financial fields with strict validation and authorization
```

### Medium Severity Findings

**READONLY_PROPERTY_MODIFICATION - Timestamp Manipulation**
```
Category: READONLY_PROPERTY_MODIFICATION
Severity: HIGH
Evidence: Read-only property 'created_at' was successfully modified from original value
Endpoint: PUT /api/users/123
Recommendation: Implement validation to prevent modification of immutable fields
```

**UNDOCUMENTED_FIELD - Context-Specific Field Exposure**
```
Category: UNDOCUMENTED_FIELD
Severity: MEDIUM
Evidence: Field 'internal_notes' appears only for admin context but not for user context
Endpoint: GET /api/users/123  
Recommendation: Document all API response fields or implement consistent field filtering
```

## 🛠️ Remediation

### 1. Sensitive Data Exposure

**Prevention Strategies**:

```python
# Good: Field-level authorization
class UserSerializer:
    def serialize(self, user, requesting_user):
        data = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email
        }
        
        # Only include sensitive fields for authorized users
        if requesting_user.is_admin or requesting_user.id == user.id:
            data['phone'] = user.phone
            
        # Never include passwords or API keys
        # data['password'] = user.password  # ❌ Never do this
        
        return data
```

**Implementation**:
- Use serializers with field-level permissions
- Implement role-based field filtering
- Never include passwords, API keys, or secrets in responses
- Audit all API responses for sensitive data

### 2. Mass Assignment

**Prevention Strategies**:

```python
# Good: Use allow-lists for accepted fields
class UserUpdateRequest:
    ALLOWED_FIELDS = ['name', 'email', 'phone']  # Only safe fields
    
    def validate(self, data):
        # Reject any fields not in allow-list
        for field in data.keys():
            if field not in self.ALLOWED_FIELDS:
                raise ValidationError(f"Field '{field}' is not allowed")
        
        return data

# Good: Separate DTOs for different operations
class UserCreateDTO:
    allowed_fields = ['name', 'email', 'phone']

class UserUpdateDTO:
    allowed_fields = ['name', 'phone']  # Email changes require separate endpoint

class AdminUserUpdateDTO:
    allowed_fields = ['name', 'email', 'phone', 'role', 'is_active']
```

**Implementation**:
- Use strict allow-lists for input validation
- Separate DTOs for different user roles
- Never accept dangerous fields like `is_admin`, `role`, `permissions`
- Validate all input against expected schema

### 3. Read-Only Property Protection

**Prevention Strategies**:

```python
# Good: Protect immutable fields
class UserModel:
    READONLY_FIELDS = ['id', 'created_at', 'user_id', 'version']
    
    def update(self, data):
        # Remove any read-only fields from update data
        for field in self.READONLY_FIELDS:
            if field in data:
                del data[field]
                # Optionally log security event
                logger.warning(f"Attempt to modify read-only field: {field}")
        
        # Proceed with safe update
        return super().update(data)
```

**Implementation**:
- Define and enforce read-only field lists
- Strip read-only fields from update operations
- Use database constraints to prevent modification
- Log attempts to modify immutable fields

### 4. Consistent Field Exposure

**Prevention Strategies**:

```python
# Good: Consistent field exposure with documentation
class APIResponse:
    def __init__(self, data, user_context):
        self.data = data
        self.user_context = user_context
    
    def serialize(self):
        # Base fields available to all users
        response = {
            'user_id': self.data.id,
            'username': self.data.username,
            'created_at': self.data.created_at
        }
        
        # Documented admin-only fields
        if self.user_context.is_admin:
            response.update({
                'last_login_ip': self.data.last_login_ip,
                'account_status': self.data.status,
                'admin_notes': self.data.admin_notes
            })
        
        return response
```

**Implementation**:
- Document all API response fields
- Implement consistent field filtering logic
- Use role-based serializers
- Regularly audit API responses across different contexts

### Security Headers

Add security headers to prevent information disclosure:

```python
# Add security headers
response.headers.update({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 
    'X-XSS-Protection': '1; mode=block',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache'
})
```

---

The Property Level Authorization Testing Module provides comprehensive detection of API3 vulnerabilities, helping ensure your APIs properly control access to sensitive data and properties. 🛡️