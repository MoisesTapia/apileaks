"""
Property Level Authorization Testing Module
Implements OWASP API3 - Broken Object Property Level Authorization testing
"""

import asyncio
import re
import json
import uuid
import random
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urljoin

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import PropertyTestingConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


@dataclass
class SensitiveField:
    """Represents a sensitive field found in API responses"""
    field_name: str
    field_value: str
    field_path: str  # JSON path to the field
    endpoint: str
    sensitivity_type: str  # 'password', 'api_key', 'personal_data', etc.
    context: str  # Where it was found: 'response_body', 'headers', etc.


@dataclass
class MassAssignmentTest:
    """Result of a mass assignment test"""
    endpoint: str
    method: str
    field_name: str
    original_value: Any
    test_value: Any
    successful: bool
    response_diff: str
    evidence: str


@dataclass
class PropertyTestResult:
    """Result of a property-level authorization test"""
    endpoint: str
    method: str
    test_type: str
    auth_context: Optional[str]
    status_code: int
    response_size: int
    response_time: float
    vulnerability_found: bool
    evidence: str


class PropertyLevelAuthModule(OWASPModule):
    """
    Property Level Authorization Testing Module for detecting Broken Object Property Level Authorization
    
    This module implements comprehensive testing for OWASP API Security Top 10 #3:
    - Detects sensitive fields in responses (passwords, API keys, personal data)
    - Tests mass assignment with dangerous properties
    - Detects read-only properties that can be modified
    - Identifies undocumented fields in responses
    """
    
    # Sensitive field patterns for detection
    SENSITIVE_FIELD_PATTERNS = {
        'financial': [
            r'credit_card', r'cc_number', r'account_number', r'routing_number', 
            r'bank_account', r'payment', r'billing'
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
            r'ssn', r'social_security', r'phone', r'email', r'address', 
            r'birth_date', r'dob'
        ],
        'internal': [
            r'internal', r'debug', r'admin', r'system', r'config',
            r'database', r'db_', r'sql', r'query'
        ]
    }
    
    # Mass assignment dangerous fields
    MASS_ASSIGNMENT_FIELDS = [
        'is_admin', 'admin', 'role', 'roles', 'permissions', 'privilege',
        'user_id', 'id', 'account_id', 'owner_id', 'created_by',
        'is_active', 'enabled', 'status', 'verified', 'approved',
        'balance', 'credit', 'points', 'score', 'level'
    ]
    
    # Read-only field patterns
    READ_ONLY_FIELDS = [
        'id', 'created_at', 'updated_at', 'timestamp', 'created_by',
        'modified_by', 'version', 'revision', 'hash', 'checksum'
    ]
    
    # Common HTTP methods for testing
    TEST_METHODS = ['POST', 'PUT', 'PATCH']
    
    def __init__(self, config: PropertyTestingConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="property_level_auth")
        
        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        
        # Add anonymous context if not present
        if 'anonymous' not in self.auth_context_map:
            anonymous_ctx = AuthContext(
                name='anonymous',
                type=AuthType.BEARER,
                token='',
                privilege_level=0
            )
            self.auth_context_map['anonymous'] = anonymous_ctx
        
        # Combine configured sensitive fields with defaults
        self.sensitive_fields = set(config.sensitive_fields + [
            field for patterns in self.SENSITIVE_FIELD_PATTERNS.values() 
            for field in patterns
        ])
        
        # Combine configured mass assignment fields with defaults
        self.mass_assignment_fields = set(config.mass_assignment_fields + self.MASS_ASSIGNMENT_FIELDS)
        
        self.logger.info("Property Level Authorization Testing Module initialized",
                        auth_contexts=len(self.auth_contexts),
                        sensitive_patterns=len(self.sensitive_fields),
                        mass_assignment_fields=len(self.mass_assignment_fields))
    
    def get_module_name(self) -> str:
        """Get module name"""
        return "property_level_auth"
    
    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute property level authorization tests on discovered endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of property level authorization findings
        """
        self.logger.info("Starting property level authorization testing", endpoints_count=len(endpoints))
        
        findings = []
        
        try:
            # Step 1: Detect sensitive fields in responses
            sensitive_findings = await self._test_sensitive_data_exposure(endpoints)
            findings.extend(sensitive_findings)
            self.logger.debug("Sensitive data exposure testing completed", findings=len(sensitive_findings))
            
            # Step 2: Test mass assignment vulnerabilities
            mass_assignment_findings = await self._test_mass_assignment(endpoints)
            findings.extend(mass_assignment_findings)
            self.logger.debug("Mass assignment testing completed", findings=len(mass_assignment_findings))
            
            # Step 3: Test read-only property modification
            readonly_findings = await self._test_readonly_property_modification(endpoints)
            findings.extend(readonly_findings)
            self.logger.debug("Read-only property testing completed", findings=len(readonly_findings))
            
            # Step 4: Detect undocumented fields
            undocumented_findings = await self._test_undocumented_fields(endpoints)
            findings.extend(undocumented_findings)
            self.logger.debug("Undocumented fields testing completed", findings=len(undocumented_findings))
            
        except Exception as e:
            self.logger.error("Property level authorization testing failed during execution", error=str(e))
            raise
        
        self.logger.info("Property level authorization testing completed",
                        total_findings=len(findings),
                        critical_findings=len([f for f in findings if f.severity == Severity.CRITICAL]))
        
        return findings
    
    async def _test_sensitive_data_exposure(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test for sensitive data exposure in API responses (Requirement 3.1)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for sensitive data exposure
        """
        findings = []
        self.logger.info("Testing sensitive data exposure", endpoints_count=len(endpoints))
        
        # Test with different auth contexts to see what data is exposed
        for auth_context in self.auth_contexts:
            self.http_client.set_auth_context(auth_context)
            
            for endpoint in endpoints:
                endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
                method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
                
                try:
                    # Make request to endpoint
                    response = await self.http_client.request(method, endpoint_url)
                    
                    if response.is_success and response.text:
                        # Analyze response for sensitive fields
                        sensitive_fields = self._detect_sensitive_fields(response, endpoint_url)
                        
                        for sensitive_field in sensitive_fields:
                            # Determine severity based on sensitivity type and auth context
                            severity = self._classify_sensitive_data_severity(
                                sensitive_field, auth_context
                            )
                            
                            finding = Finding(
                                id=str(uuid.uuid4()),
                                scan_id='',
                                category='SENSITIVE_DATA_EXPOSURE',
                                owasp_category='API3',
                                severity=severity,
                                endpoint=endpoint_url,
                                method=method,
                                status_code=response.status_code,
                                response_size=len(response.content),
                                response_time=response.elapsed,
                                evidence=f"Sensitive field '{sensitive_field.field_name}' exposed in response. "
                                        f"Type: {sensitive_field.sensitivity_type}, "
                                        f"Path: {sensitive_field.field_path}, "
                                        f"Context: {sensitive_field.context}, "
                                        f"Auth: {auth_context.name}",
                                recommendation="Remove sensitive fields from API responses or implement "
                                             "proper field-level authorization to hide sensitive data "
                                             "based on user permissions.",
                                payload=f"Field: {sensitive_field.field_name}",
                                response_snippet=response.text[:500] if response.text else None
                            )
                            findings.append(finding)
                            
                            self.logger.warning("Sensitive data exposure detected",
                                              field=sensitive_field.field_name,
                                              type=sensitive_field.sensitivity_type,
                                              endpoint=endpoint_url,
                                              auth_context=auth_context.name)
                
                except Exception as e:
                    self.logger.debug("Sensitive data exposure test failed",
                                    endpoint=endpoint_url,
                                    auth_context=auth_context.name,
                                    error=str(e))
        
        return findings
    
    def _detect_sensitive_fields(self, response: Response, endpoint: str) -> List[SensitiveField]:
        """
        Detect sensitive fields in API response
        
        Args:
            response: HTTP response to analyze
            endpoint: Endpoint URL
            
        Returns:
            List of detected sensitive fields
        """
        sensitive_fields = []
        
        # Check response headers for sensitive data
        for header_name, header_value in response.headers.items():
            if self._is_sensitive_field(header_name.lower()):
                sensitivity_type = self._get_sensitivity_type(header_name.lower())
                sensitive_field = SensitiveField(
                    field_name=header_name,
                    field_value=header_value,
                    field_path=f"headers.{header_name}",
                    endpoint=endpoint,
                    sensitivity_type=sensitivity_type,
                    context='response_headers'
                )
                sensitive_fields.append(sensitive_field)
        
        # Check response body for sensitive data
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                data = json.loads(response.text)
                json_fields = self._extract_sensitive_fields_from_json(data, endpoint)
                sensitive_fields.extend(json_fields)
        except (json.JSONDecodeError, ValueError):
            # If not JSON, check text content for sensitive patterns
            text_fields = self._extract_sensitive_fields_from_text(response.text, endpoint)
            sensitive_fields.extend(text_fields)
        
        return sensitive_fields
    
    def _extract_sensitive_fields_from_json(self, data: Any, endpoint: str, 
                                          path: str = '') -> List[SensitiveField]:
        """Recursively extract sensitive fields from JSON data"""
        sensitive_fields = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if field name is sensitive
                if self._is_sensitive_field(key.lower()):
                    sensitivity_type = self._get_sensitivity_type(key.lower())
                    sensitive_field = SensitiveField(
                        field_name=key,
                        field_value=str(value),
                        field_path=current_path,
                        endpoint=endpoint,
                        sensitivity_type=sensitivity_type,
                        context='response_body'
                    )
                    sensitive_fields.append(sensitive_field)
                
                # Check if field value contains sensitive data
                if isinstance(value, str) and self._contains_sensitive_data(value):
                    sensitivity_type = self._detect_value_sensitivity_type(value)
                    sensitive_field = SensitiveField(
                        field_name=key,
                        field_value=value,
                        field_path=current_path,
                        endpoint=endpoint,
                        sensitivity_type=sensitivity_type,
                        context='response_body'
                    )
                    sensitive_fields.append(sensitive_field)
                
                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    nested_fields = self._extract_sensitive_fields_from_json(
                        value, endpoint, current_path
                    )
                    sensitive_fields.extend(nested_fields)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    nested_fields = self._extract_sensitive_fields_from_json(
                        item, endpoint, f"{path}[{i}]"
                    )
                    sensitive_fields.extend(nested_fields)
        
        return sensitive_fields
    
    def _extract_sensitive_fields_from_text(self, text: str, endpoint: str) -> List[SensitiveField]:
        """Extract sensitive fields from text content using patterns"""
        sensitive_fields = []
        
        # Look for key-value patterns in text
        patterns = [
            r'(\w*(?:password|passwd|pwd|pass|secret)\w*)\s*[:=]\s*([^\s\n]+)',
            r'(\w*(?:api_key|apikey|key|token)\w*)\s*[:=]\s*([^\s\n]+)',
            r'(\w*(?:ssn|social_security|credit_card)\w*)\s*[:=]\s*([^\s\n]+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                field_name = match.group(1)
                field_value = match.group(2)
                sensitivity_type = self._get_sensitivity_type(field_name.lower())
                
                sensitive_field = SensitiveField(
                    field_name=field_name,
                    field_value=field_value,
                    field_path=f"text_content.{field_name}",
                    endpoint=endpoint,
                    sensitivity_type=sensitivity_type,
                    context='response_text'
                )
                sensitive_fields.append(sensitive_field)
        
        return sensitive_fields
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name indicates sensitive data"""
        field_lower = field_name.lower()
        
        # Check against all sensitive field patterns
        for patterns in self.SENSITIVE_FIELD_PATTERNS.values():
            for pattern in patterns:
                if re.search(pattern, field_lower):
                    return True
        
        return False
    
    def _get_sensitivity_type(self, field_name: str) -> str:
        """Determine the type of sensitive data based on field name"""
        field_lower = field_name.lower()
        
        # Check in order of specificity (most specific first)
        for sensitivity_type, patterns in self.SENSITIVE_FIELD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, field_lower):
                    return sensitivity_type
        
        return 'unknown'
    
    def _contains_sensitive_data(self, value: str) -> bool:
        """Check if value contains sensitive data patterns"""
        if not isinstance(value, str) or len(value) < 4:
            return False
        
        # Check for common sensitive data patterns
        sensitive_patterns = [
            r'[A-Za-z0-9]{32,}',  # Long hex strings (API keys)
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 encoded data
            r'\d{3}-\d{2}-\d{4}',  # SSN pattern
            r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',  # Credit card pattern
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',  # Email pattern
            r'sk_[a-zA-Z0-9]{20,}'  # Stripe-style API keys
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, value):
                return True
        
        return False
    
    def _detect_value_sensitivity_type(self, value: str) -> str:
        """Detect sensitivity type based on value patterns"""
        if re.search(r'\b[A-Za-z0-9]{32,}\b', value):
            return 'api_key'
        elif re.search(r'\b\d{3}-\d{2}-\d{4}\b', value):
            return 'personal_data'
        elif re.search(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', value):
            return 'financial'
        elif re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', value):
            return 'personal_data'
        else:
            return 'unknown'
    
    def _classify_sensitive_data_severity(self, sensitive_field: SensitiveField, 
                                        auth_context: AuthContext) -> Severity:
        """
        Classify severity of sensitive data exposure
        
        Args:
            sensitive_field: Detected sensitive field
            auth_context: Authentication context used
            
        Returns:
            Severity level
        """
        # Critical: Passwords, API keys, financial data exposed
        if sensitive_field.sensitivity_type in ['password', 'api_key', 'financial']:
            return Severity.CRITICAL
        
        # High: Personal data exposed to low-privilege users
        if sensitive_field.sensitivity_type == 'personal_data':
            if auth_context.privilege_level < 2:  # Low privilege user
                return Severity.HIGH
            else:
                return Severity.MEDIUM
        
        # Medium: Internal/debug data exposed
        if sensitive_field.sensitivity_type == 'internal':
            return Severity.MEDIUM
        
        # Default to medium for unknown sensitive data
        return Severity.MEDIUM
    
    async def _test_mass_assignment(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test mass assignment vulnerabilities (Requirements 3.2, 3.3)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for mass assignment vulnerabilities
        """
        findings = []
        self.logger.info("Testing mass assignment vulnerabilities", endpoints_count=len(endpoints))
        
        # Test with different auth contexts
        for auth_context in self.auth_contexts:
            self.http_client.set_auth_context(auth_context)
            
            for endpoint in endpoints:
                endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
                
                # Test mass assignment with different HTTP methods
                for method in self.TEST_METHODS:
                    try:
                        mass_assignment_findings = await self._test_endpoint_mass_assignment(
                            endpoint_url, method, auth_context
                        )
                        findings.extend(mass_assignment_findings)
                    
                    except Exception as e:
                        self.logger.debug("Mass assignment test failed",
                                        endpoint=endpoint_url,
                                        method=method,
                                        auth_context=auth_context.name,
                                        error=str(e))
        
        return findings
    
    async def _test_endpoint_mass_assignment(self, endpoint_url: str, method: str, 
                                           auth_context: AuthContext) -> List[Finding]:
        """Test mass assignment for a specific endpoint"""
        findings = []
        
        # First, make a baseline request to understand the endpoint
        try:
            baseline_response = await self.http_client.request('GET', endpoint_url)
            if not baseline_response.is_success:
                return findings
            
            # Extract existing fields from response
            existing_fields = self._extract_fields_from_response(baseline_response)
            
        except Exception as e:
            self.logger.debug("Baseline request failed for mass assignment test",
                            endpoint=endpoint_url,
                            error=str(e))
            return findings
        
        # Test mass assignment with dangerous fields
        for dangerous_field in self.mass_assignment_fields:
            try:
                # Create test payload with dangerous field
                test_payload = {dangerous_field: self._generate_test_value(dangerous_field)}
                
                # Add some existing fields to make request more realistic
                if existing_fields:
                    sample_fields = dict(list(existing_fields.items())[:3])  # Take first 3 fields
                    test_payload.update(sample_fields)
                
                # Make request with mass assignment payload
                test_response = await self.http_client.request(
                    method, endpoint_url, json=test_payload
                )
                
                # Check if mass assignment was successful
                if self._is_mass_assignment_successful(
                    baseline_response, test_response, dangerous_field, test_payload[dangerous_field]
                ):
                    severity = self._classify_mass_assignment_severity(dangerous_field, auth_context)
                    
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='MASS_ASSIGNMENT',
                        owasp_category='API3',
                        severity=severity,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=test_response.status_code,
                        response_size=len(test_response.content),
                        response_time=test_response.elapsed,
                        evidence=f"Mass assignment vulnerability detected. "
                                f"Dangerous field '{dangerous_field}' with value '{test_payload[dangerous_field]}' "
                                f"was accepted and may have been processed. "
                                f"Response status: {test_response.status_code}",
                        recommendation="Implement input validation and use allow-lists for accepted fields. "
                                     "Reject requests containing unexpected or dangerous fields.",
                        payload=json.dumps(test_payload),
                        response_snippet=test_response.text[:500] if test_response.text else None
                    )
                    findings.append(finding)
                    
                    self.logger.warning("Mass assignment vulnerability detected",
                                      field=dangerous_field,
                                      endpoint=endpoint_url,
                                      method=method,
                                      auth_context=auth_context.name)
            
            except Exception as e:
                self.logger.debug("Mass assignment test failed for field",
                                field=dangerous_field,
                                endpoint=endpoint_url,
                                error=str(e))
        
        return findings
    
    def _extract_fields_from_response(self, response: Response) -> Dict[str, Any]:
        """Extract fields from response for baseline comparison"""
        fields = {}
        
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                data = json.loads(response.text)
                if isinstance(data, dict):
                    # Extract top-level fields
                    for key, value in data.items():
                        if isinstance(value, (str, int, float, bool)):
                            fields[key] = value
        except (json.JSONDecodeError, ValueError):
            pass
        
        return fields
    
    def _generate_test_value(self, field_name: str) -> Any:
        """Generate appropriate test value for a field"""
        field_lower = field_name.lower()
        
        if 'admin' in field_lower or 'is_admin' in field_lower:
            return True
        elif 'role' in field_lower:
            return 'admin'
        elif 'permission' in field_lower:
            return ['admin', 'write', 'delete']
        elif 'id' in field_lower:
            return 999999
        elif 'active' in field_lower or 'enabled' in field_lower:
            return True
        elif 'balance' in field_lower or 'credit' in field_lower:
            return 1000000
        elif 'level' in field_lower or 'score' in field_lower:
            return 100
        else:
            return 'test_value'
    
    def _is_mass_assignment_successful(self, baseline_response: Response, 
                                     test_response: Response, field_name: str, 
                                     test_value: Any) -> bool:
        """
        Determine if mass assignment was successful
        
        Args:
            baseline_response: Original response without mass assignment
            test_response: Response after mass assignment attempt
            field_name: Name of the field being tested
            test_value: Value that was sent
            
        Returns:
            True if mass assignment appears successful
        """
        # Success indicators:
        # 1. Request was accepted (2xx status)
        # 2. Response is different from baseline
        # 3. Response contains the test value or field
        
        if not test_response.is_success:
            return False
        
        # Check if response contains the test field or value
        try:
            if test_response.text and 'application/json' in test_response.headers.get('content-type', ''):
                response_data = json.loads(test_response.text)
                
                # Check if field appears in response
                if isinstance(response_data, dict):
                    if field_name in response_data:
                        return True
                    
                    # Check if test value appears in response
                    response_str = json.dumps(response_data).lower()
                    if str(test_value).lower() in response_str:
                        return True
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check if response size changed significantly (indicating processing)
        size_diff = abs(len(test_response.content) - len(baseline_response.content))
        if size_diff > 50:  # Significant change in response size
            return True
        
        # Check if response time increased (indicating processing)
        if test_response.elapsed > baseline_response.elapsed * 1.5:
            return True
        
        return False
    
    def _classify_mass_assignment_severity(self, field_name: str, 
                                         auth_context: AuthContext) -> Severity:
        """Classify severity of mass assignment vulnerability"""
        field_lower = field_name.lower()
        
        # Critical: Admin privilege escalation
        if any(term in field_lower for term in ['admin', 'role', 'permission']):
            return Severity.CRITICAL
        
        # High: User ID manipulation or financial fields
        if any(term in field_lower for term in ['user_id', 'id', 'balance', 'credit']):
            return Severity.HIGH
        
        # Medium: Status or configuration changes
        if any(term in field_lower for term in ['active', 'enabled', 'status']):
            return Severity.MEDIUM
        
        return Severity.MEDIUM
    
    async def _test_readonly_property_modification(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test read-only property modification (Requirement 3.3)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for read-only property modification vulnerabilities
        """
        findings = []
        self.logger.info("Testing read-only property modification", endpoints_count=len(endpoints))
        
        # Test with different auth contexts
        for auth_context in self.auth_contexts:
            self.http_client.set_auth_context(auth_context)
            
            for endpoint in endpoints:
                endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
                
                # Test with different HTTP methods
                for method in self.TEST_METHODS:
                    try:
                        readonly_findings = await self._test_endpoint_readonly_modification(
                            endpoint_url, method, auth_context
                        )
                        findings.extend(readonly_findings)
                    
                    except Exception as e:
                        self.logger.debug("Read-only property test failed",
                                        endpoint=endpoint_url,
                                        method=method,
                                        auth_context=auth_context.name,
                                        error=str(e))
        
        return findings
    
    async def _test_endpoint_readonly_modification(self, endpoint_url: str, method: str,
                                                 auth_context: AuthContext) -> List[Finding]:
        """Test read-only property modification for a specific endpoint"""
        findings = []
        
        # Get baseline response to identify existing fields
        try:
            baseline_response = await self.http_client.request('GET', endpoint_url)
            if not baseline_response.is_success:
                return findings
            
            existing_fields = self._extract_fields_from_response(baseline_response)
            
        except Exception as e:
            self.logger.debug("Baseline request failed for read-only test",
                            endpoint=endpoint_url,
                            error=str(e))
            return findings
        
        # Test modification of read-only fields
        for readonly_field in self.READ_ONLY_FIELDS:
            # Only test if the field exists in the response
            if readonly_field in existing_fields:
                try:
                    # Create payload to modify read-only field
                    original_value = existing_fields[readonly_field]
                    test_value = self._generate_readonly_test_value(readonly_field, original_value)
                    
                    test_payload = {readonly_field: test_value}
                    
                    # Make request to modify read-only field
                    test_response = await self.http_client.request(
                        method, endpoint_url, json=test_payload
                    )
                    
                    # Check if read-only field was modified
                    if self._is_readonly_modification_successful(
                        baseline_response, test_response, readonly_field, test_value
                    ):
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            scan_id='',
                            category='READONLY_PROPERTY_MODIFICATION',
                            owasp_category='API3',
                            severity=Severity.HIGH,
                            endpoint=endpoint_url,
                            method=method,
                            status_code=test_response.status_code,
                            response_size=len(test_response.content),
                            response_time=test_response.elapsed,
                            evidence=f"Read-only property '{readonly_field}' can be modified. "
                                    f"Original value: '{original_value}', "
                                    f"Test value: '{test_value}', "
                                    f"Response status: {test_response.status_code}",
                            recommendation="Implement proper validation to prevent modification of read-only fields. "
                                         "Use separate DTOs for input and output to control field access.",
                            payload=json.dumps(test_payload),
                            response_snippet=test_response.text[:500] if test_response.text else None
                        )
                        findings.append(finding)
                        
                        self.logger.warning("Read-only property modification detected",
                                          field=readonly_field,
                                          endpoint=endpoint_url,
                                          method=method,
                                          auth_context=auth_context.name)
                
                except Exception as e:
                    self.logger.debug("Read-only property test failed for field",
                                    field=readonly_field,
                                    endpoint=endpoint_url,
                                    error=str(e))
        
        return findings
    
    def _generate_readonly_test_value(self, field_name: str, original_value: Any) -> Any:
        """Generate test value for read-only field modification"""
        field_lower = field_name.lower()
        
        if 'id' in field_lower:
            return 999999 if isinstance(original_value, int) else 'modified_id'
        elif 'created' in field_lower or 'updated' in field_lower:
            return '2099-12-31T23:59:59Z'
        elif 'timestamp' in field_lower:
            return '2099-12-31 23:59:59'
        elif 'version' in field_lower or 'revision' in field_lower:
            return 999 if isinstance(original_value, int) else 'modified_version'
        elif 'hash' in field_lower or 'checksum' in field_lower:
            return 'modified_hash_value'
        else:
            return 'modified_readonly_value'
    
    def _is_readonly_modification_successful(self, baseline_response: Response,
                                           test_response: Response, field_name: str,
                                           test_value: Any) -> bool:
        """Determine if read-only field modification was successful"""
        if not test_response.is_success:
            return False
        
        # Check if the test value appears in the response
        try:
            if test_response.text and 'application/json' in test_response.headers.get('content-type', ''):
                response_data = json.loads(test_response.text)
                
                if isinstance(response_data, dict):
                    # Check if field was modified to test value
                    if field_name in response_data:
                        if str(response_data[field_name]) == str(test_value):
                            return True
        except (json.JSONDecodeError, ValueError):
            pass
        
        return False
    
    async def _test_undocumented_fields(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test for undocumented fields in responses (Requirement 3.4)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for undocumented fields
        """
        findings = []
        self.logger.info("Testing for undocumented fields", endpoints_count=len(endpoints))
        
        # Collect all fields from all endpoints and auth contexts
        all_fields = {}  # endpoint -> set of fields
        
        # Test with different auth contexts to see field variations
        for auth_context in self.auth_contexts:
            self.http_client.set_auth_context(auth_context)
            
            for endpoint in endpoints:
                endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
                method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
                
                try:
                    response = await self.http_client.request(method, endpoint_url)
                    
                    if response.is_success and response.text:
                        fields = self._extract_all_fields_from_response(response)
                        
                        if endpoint_url not in all_fields:
                            all_fields[endpoint_url] = {}
                        
                        all_fields[endpoint_url][auth_context.name] = fields
                
                except Exception as e:
                    self.logger.debug("Undocumented fields test failed",
                                    endpoint=endpoint_url,
                                    auth_context=auth_context.name,
                                    error=str(e))
        
        # Analyze field variations to detect undocumented fields
        for endpoint_url, context_fields in all_fields.items():
            undocumented_findings = self._analyze_field_variations(endpoint_url, context_fields)
            findings.extend(undocumented_findings)
        
        return findings
    
    def _extract_all_fields_from_response(self, response: Response) -> Set[str]:
        """Extract all field names from response"""
        fields = set()
        
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                data = json.loads(response.text)
                fields.update(self._get_all_json_fields(data))
        except (json.JSONDecodeError, ValueError):
            pass
        
        return fields
    
    def _get_all_json_fields(self, data: Any, prefix: str = '') -> Set[str]:
        """Recursively get all field names from JSON data"""
        fields = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                field_name = f"{prefix}.{key}" if prefix else key
                fields.add(field_name)
                
                if isinstance(value, (dict, list)):
                    nested_fields = self._get_all_json_fields(value, field_name)
                    fields.update(nested_fields)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    nested_fields = self._get_all_json_fields(item, f"{prefix}[{i}]")
                    fields.update(nested_fields)
        
        return fields
    
    def _analyze_field_variations(self, endpoint_url: str, 
                                context_fields: Dict[str, Set[str]]) -> List[Finding]:
        """Analyze field variations between auth contexts to detect undocumented fields"""
        findings = []
        
        if len(context_fields) < 2:
            return findings  # Need at least 2 contexts to compare
        
        # Find fields that appear only in certain contexts
        all_contexts = list(context_fields.keys())
        
        for i, context1 in enumerate(all_contexts):
            for j, context2 in enumerate(all_contexts[i+1:], i+1):
                fields1 = context_fields[context1]
                fields2 = context_fields[context2]
                
                # Fields only in context1
                unique_to_context1 = fields1 - fields2
                # Fields only in context2
                unique_to_context2 = fields2 - fields1
                
                # Report fields that appear only for certain auth contexts
                for unique_field in unique_to_context1:
                    if self._is_potentially_undocumented(unique_field):
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            scan_id='',
                            category='UNDOCUMENTED_FIELD',
                            owasp_category='API3',
                            severity=Severity.MEDIUM,
                            endpoint=endpoint_url,
                            method='GET',
                            status_code=200,
                            response_size=0,
                            response_time=0.0,
                            evidence=f"Field '{unique_field}' appears only for auth context '{context1}' "
                                    f"but not for '{context2}'. This may indicate undocumented field "
                                    f"or inconsistent API behavior.",
                            recommendation="Document all API response fields or implement consistent "
                                         "field filtering across all user contexts.",
                            payload=f"Field: {unique_field}, Context: {context1}"
                        )
                        findings.append(finding)
                        
                        self.logger.info("Undocumented field detected",
                                       field=unique_field,
                                       endpoint=endpoint_url,
                                       context=context1)
                
                for unique_field in unique_to_context2:
                    if self._is_potentially_undocumented(unique_field):
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            scan_id='',
                            category='UNDOCUMENTED_FIELD',
                            owasp_category='API3',
                            severity=Severity.MEDIUM,
                            endpoint=endpoint_url,
                            method='GET',
                            status_code=200,
                            response_size=0,
                            response_time=0.0,
                            evidence=f"Field '{unique_field}' appears only for auth context '{context2}' "
                                    f"but not for '{context1}'. This may indicate undocumented field "
                                    f"or inconsistent API behavior.",
                            recommendation="Document all API response fields or implement consistent "
                                         "field filtering across all user contexts.",
                            payload=f"Field: {unique_field}, Context: {context2}"
                        )
                        findings.append(finding)
                        
                        self.logger.info("Undocumented field detected",
                                       field=unique_field,
                                       endpoint=endpoint_url,
                                       context=context2)
        
        return findings
    
    def _is_potentially_undocumented(self, field_name: str) -> bool:
        """Check if field is potentially undocumented (filter out common fields)"""
        field_lower = field_name.lower()
        
        # Skip common metadata fields that are expected to vary
        common_fields = [
            'timestamp', 'created_at', 'updated_at', 'id', 'version',
            'status', 'message', 'success', 'error', 'code'
        ]
        
        for common_field in common_fields:
            if common_field in field_lower:
                return False
        
        return True