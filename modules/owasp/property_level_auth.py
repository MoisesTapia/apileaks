"""
Property Level Authorization Testing Module
Implements OWASP API3 - Broken Object Property Level Authorization testing
"""

import asyncio
import re
import json
import math
import uuid
import random
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urljoin

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from utils.safe_mode import SafeModeGuard, SAFE_METHODS
from utils.authz_baseline import NegativeControlMixin
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


class PropertyLevelAuthModule(OWASPModule, NegativeControlMixin, SafeModeGuard):
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

    # Known credential token prefixes. A value carrying one of these prefixes is
    # strong, self-sufficient evidence of an exposed credential (Requirement 12.2).
    CREDENTIAL_PREFIXES = ('sk_', 'pk_', 'AKIA', 'ghp_', 'xoxb-')

    # Minimum Shannon entropy (bits per character) required to treat an otherwise
    # unremarkable long/base64-shaped string as a real secret. Random secrets
    # (hex/base64) sit well above this; slugs, repeated text and predictable
    # identifiers fall below it. Used as corroboration for the credential-shape
    # patterns, which are necessary but not sufficient on their own (Req 12.2).
    CREDENTIAL_ENTROPY_THRESHOLD = 3.5
    
    def __init__(self, config: PropertyTestingConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="property_level_auth")
        
        # Read Safe_Mode flag (Requirement 21.1). When enabled, the module MUST
        # NOT issue any State_Changing_Method request (POST/PUT/PATCH) and
        # restricts its probes to Safe_Methods (GET/HEAD/OPTIONS); each skipped
        # state-changing probe is logged by the guard (Requirements 11.1-11.4).
        self._init_safe_mode(config)
        
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
        
        if self.safe_mode:
            self.logger.info(
                "Safe mode enabled: property-level testing restricts probes to "
                "safe methods (GET/HEAD/OPTIONS); no state-changing "
                "(POST/PUT/PATCH) mass-assignment or read-only modification "
                "probes will be issued",
                module="property_level_auth",
            )
        
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
                # Safe mode: sensitive-data exposure analysis is a read probe;
                # never replay a state-changing method (Requirements 11.1, 21.2,
                # 21.3).
                method = self.safe_read_method(method, "sensitive_data_exposure")

                try:
                    # Make request to endpoint
                    response = await self.http_client.request(method, endpoint_url)
                    
                    if response.is_success and response.text:
                        # Analyze response for sensitive fields
                        sensitive_fields = self._detect_sensitive_fields(response, endpoint_url)
                        
                        for sensitive_field in sensitive_fields:
                            # Personal data exposed only to a context authorized
                            # to view it is NOT a finding (Req 12.3); it is only
                            # reported when exposed to a context not authorized to
                            # view it (Req 12.4). Credentials/financial/internal
                            # data are always reported.
                            if (sensitive_field.sensitivity_type == 'personal_data'
                                    and self._is_authorized_to_view(sensitive_field, auth_context)):
                                self.logger.debug(
                                    "Personal data exposed only to an authorized "
                                    "context; not reporting",
                                    field=sensitive_field.field_name,
                                    endpoint=endpoint_url,
                                    auth_context=auth_context.name,
                                )
                                continue

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
                
                # Check if field value contains sensitive data. The field name is
                # threaded through so the credential-shape corroboration in
                # _contains_sensitive_data can consider it (Requirement 12.2).
                if isinstance(value, str) and self._contains_sensitive_data(value, field_name=key):
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
    
    def _contains_sensitive_data(self, value: str, field_name: Optional[str] = None) -> bool:
        """
        Check if a value contains sensitive data.

        Specific patterns (SSN, credit card, email, ``sk_`` keys) and known
        credential prefixes are sufficient on their own. A generic long
        alphanumeric string (``[A-Za-z0-9]{32,}``) or base64-shaped blob is
        treated as NECESSARY BUT NOT SUFFICIENT: it is only flagged when it is
        corroborated by a sensitive field name, a known credential prefix, or a
        high Shannon-entropy value. Arbitrary 32+ character strings are not
        flagged on their own (Requirement 12.2).

        Args:
            value: The candidate value to inspect.
            field_name: The name of the field the value came from, used as
                corroborating evidence for the credential-shape patterns.

        Returns:
            True if the value is considered sensitive, False otherwise.
        """
        if not isinstance(value, str) or len(value) < 4:
            return False

        # Patterns that are self-sufficient evidence of sensitive data.
        sufficient_patterns = [
            r'\d{3}-\d{2}-\d{4}',                               # SSN pattern
            r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',          # Credit card pattern
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', # Email pattern
            r'sk_[a-zA-Z0-9]{20,}',                             # Stripe-style secret key
        ]
        for pattern in sufficient_patterns:
            if re.search(pattern, value):
                return True

        # A known credential prefix is strong, self-sufficient evidence.
        if any(value.startswith(prefix) for prefix in self.CREDENTIAL_PREFIXES):
            return True

        # Credential-SHAPE patterns: necessary but not sufficient. A match here
        # only counts when corroborated below (Requirement 12.2).
        credential_shape_patterns = [
            r'[A-Za-z0-9]{32,}',            # long alphanumeric (API-key shape)
            r'[A-Za-z0-9+/]{20,}={0,2}',    # base64-encoded blob
        ]
        matches_credential_shape = any(
            re.search(pattern, value) for pattern in credential_shape_patterns
        )
        if not matches_credential_shape:
            return False

        # Corroboration 1: the field name itself indicates a secret/credential.
        if field_name and self._is_sensitive_field(field_name.lower()):
            return True

        # Corroboration 2: high Shannon entropy indicates a genuinely random
        # secret rather than a long-but-predictable identifier or slug.
        if self._shannon_entropy(value) >= self.CREDENTIAL_ENTROPY_THRESHOLD:
            return True

        return False

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        """Compute the Shannon entropy (bits per character) of a string."""
        if not value:
            return 0.0

        counts: Dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1

        length = len(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy
    
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
        Classify severity of sensitive data exposure.

        Severity is driven by the TYPE of exposed data and the PRIVILEGE LEVEL
        of the requesting Auth_Context, never by the mere presence of a single
        email (or any other lone) value (Requirement 12.1).

        Args:
            sensitive_field: Detected sensitive field
            auth_context: Authentication context used

        Returns:
            Severity level
        """
        sensitivity_type = sensitive_field.sensitivity_type
        privilege_level = getattr(auth_context, 'privilege_level', 1)

        # Critical: Passwords, API keys, financial data should never appear in a
        # response body regardless of who requested it.
        if sensitivity_type in ['password', 'api_key', 'financial']:
            return Severity.CRITICAL

        # Personal data: severity scales with how little the requesting context
        # should be seeing personal data. A lone email does not by itself drive
        # an escalation; only the data type and privilege level do.
        if sensitivity_type == 'personal_data':
            if privilege_level <= 0:      # anonymous / unauthenticated
                return Severity.HIGH
            if privilege_level < 2:       # regular user
                return Severity.MEDIUM
            return Severity.LOW           # high-privilege / administrative access

        # Medium: Internal/debug data exposed
        if sensitivity_type == 'internal':
            return Severity.MEDIUM

        # Default to medium for unknown sensitive data
        return Severity.MEDIUM

    def _is_authorized_to_view(self, sensitive_field: SensitiveField,
                               auth_context: AuthContext) -> bool:
        """
        Decide whether the requesting Auth_Context is authorized to view the
        given personal-data field (Requirements 12.3, 12.4).

        The authorization model is consistent with how the module represents
        auth contexts (via ``privilege_level`` and identity):

          * An anonymous / unauthenticated context (``privilege_level <= 0``) is
            never authorized to view personal data.
          * A high-privilege context (``privilege_level >= 2``, e.g. an
            administrator) is authorized to view personal data as part of
            legitimate administrative access.
          * A regular user (``privilege_level == 1``) is authorized only for
            personal data that belongs to that same context (its own record).

        Args:
            sensitive_field: The detected personal-data field.
            auth_context: The auth context under which the data was observed.

        Returns:
            True if the context is authorized to view the data, False otherwise.
        """
        privilege_level = getattr(auth_context, 'privilege_level', 1)

        # Anonymous / unauthenticated contexts are never authorized.
        if privilege_level <= 0:
            return False

        # High-privilege (administrative) contexts legitimately view personal data.
        if privilege_level >= 2:
            return True

        # Regular users are authorized only for data that belongs to them.
        return self._data_belongs_to_context(sensitive_field, auth_context)

    def _data_belongs_to_context(self, sensitive_field: SensitiveField,
                                 auth_context: AuthContext) -> bool:
        """
        Heuristic ownership check: does the personal-data value identify the
        requesting context itself (e.g. the context's own username/email)?

        Without a server-side ownership model, identity is inferred from the
        context's ``username``. When the exposed value contains that identity
        marker, the data is treated as belonging to the requesting context.

        Args:
            sensitive_field: The detected personal-data field.
            auth_context: The auth context under which the data was observed.

        Returns:
            True if the value appears to belong to the requesting context.
        """
        identity_markers = []
        username = getattr(auth_context, 'username', None)
        if username:
            identity_markers.append(username.lower())

        if not identity_markers:
            return False

        value = (sensitive_field.field_value or '').lower()
        return any(marker and marker in value for marker in identity_markers)
    
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
                    # Safe mode restricts probes to Safe_Methods (GET/HEAD/
                    # OPTIONS); skip and log any state-changing probe
                    # (Requirements 11.1, 11.3, 11.4, 21.2, 21.4).
                    if self.skip_if_state_changing(method, "mass_assignment"):
                        continue
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
                
                # Check if mass assignment was successful via persistence verification
                persistence_evidence = await self._is_mass_assignment_successful(
                    test_response, endpoint_url, dangerous_field, test_payload[dangerous_field]
                )
                if persistence_evidence:
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
                                f"Injected field '{dangerous_field}' with value "
                                f"'{test_payload[dangerous_field]}' was bound and persisted. "
                                f"{persistence_evidence}",
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
    
    async def _is_mass_assignment_successful(self, test_response: Response,
                                             endpoint: str, field_name: str,
                                             test_value: Any) -> Optional[str]:
        """
        Determine if mass assignment was successful via persistence verification.

        Success requires the exact injected field value to be reflected in the write
        response body OR in a subsequent safe re-read (GET) of the same object. Response
        size deltas and response-time increases are NOT used as success signals
        (Requirements 10.1, 10.2, 10.3).

        Args:
            test_response: Response returned by the mass-assignment write request
            endpoint: Endpoint URL used to re-read the object
            field_name: Name of the injected field being tested
            test_value: Value that was injected for the field

        Returns:
            A persistence-evidence string when the injected value is confirmed to have
            persisted, otherwise None.
        """
        # The write must at least have been accepted.
        if not test_response.is_success:
            return None

        # 1. Exact field/value reflected directly in the write response body.
        if self._reflects_injected_value(test_response, field_name, test_value):
            return (f"Injected field '{field_name}' with value '{test_value}' was "
                    f"reflected in the write response body "
                    f"(status {test_response.status_code}).")

        # 2. Exact field/value confirmed by a safe re-read of the same object.
        reread_response = await self._reget_object(endpoint)
        if reread_response is not None and self._reflects_injected_value(
            reread_response, field_name, test_value
        ):
            return (f"Injected field '{field_name}' with value '{test_value}' persisted "
                    f"and was confirmed by re-reading the object via GET "
                    f"(status {reread_response.status_code}).")

        # Neither the write response nor the re-read reflected the injected value.
        return None

    def _reflects_injected_value(self, response: Optional[Response], field: str,
                                 value: Any) -> bool:
        """
        Check whether the exact injected field/value pair is reflected in a JSON response.

        Parses the response body as JSON and searches (recursively) for a field whose
        name matches ``field`` and whose value matches ``value`` (Requirement 10.1).

        Args:
            response: Response to inspect
            field: Injected field name to look for
            value: Injected value that must be reflected

        Returns:
            True if the field is present with the injected value, False otherwise.
        """
        if response is None or not getattr(response, 'text', None):
            return False

        content_type = ''
        if response.headers:
            content_type = response.headers.get('content-type', '')
        if 'application/json' not in content_type:
            return False

        try:
            data = json.loads(response.text)
        except (json.JSONDecodeError, ValueError):
            return False

        return self._json_field_reflects_value(data, field, value)

    def _json_field_reflects_value(self, data: Any, field: str, value: Any) -> bool:
        """Recursively search JSON data for a field/value match."""
        if isinstance(data, dict):
            for key, item in data.items():
                if key == field and self._values_match(item, value):
                    return True
                if isinstance(item, (dict, list)) and self._json_field_reflects_value(
                    item, field, value
                ):
                    return True
        elif isinstance(data, list):
            for element in data:
                if isinstance(element, (dict, list)) and self._json_field_reflects_value(
                    element, field, value
                ):
                    return True
        return False

    def _values_match(self, actual: Any, expected: Any) -> bool:
        """Compare a reflected value against the injected value (type-tolerant)."""
        if actual == expected:
            return True
        # Fall back to a normalized string comparison to tolerate serialization
        # differences (e.g. booleans rendered as strings, casing, surrounding space).
        return str(actual).strip().lower() == str(expected).strip().lower()

    async def _reget_object(self, endpoint: str) -> Optional[Response]:
        """
        Perform a safe GET re-read of the same object for persistence verification.

        Args:
            endpoint: Endpoint URL to re-read

        Returns:
            The successful re-read Response, or None when the re-read fails.
        """
        try:
            response = await self.http_client.request('GET', endpoint)
            if response.is_success:
                return response
        except Exception as e:
            self.logger.debug("Re-read GET failed during mass assignment verification",
                              endpoint=endpoint,
                              error=str(e))
        return None
    
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
                    # Safe mode restricts probes to Safe_Methods (GET/HEAD/
                    # OPTIONS); skip and log any state-changing probe
                    # (Requirements 11.1, 11.3, 11.4, 21.2, 21.4).
                    if self.skip_if_state_changing(method, "readonly_property_modification"):
                        continue
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
        Test for undocumented fields in responses (Requirement 13).

        Per-context response comparison requires two or more supplied
        Auth_Contexts (Req 13.1). When fewer than two Auth_Contexts are supplied
        the comparison is skipped and a log entry is recorded (Req 13.2).

        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for undocumented fields
        """
        findings = []

        # Requirement 13 counts the operator-SUPPLIED Auth_Contexts, not the
        # internal ``auth_context_map`` (which always contains an injected
        # 'anonymous' context). The undocumented-field comparison iterates over
        # ``self.auth_contexts`` and per-endpoint comparison in
        # ``_analyze_field_variations`` needs >= 2 distinct contexts, so the
        # gate is keyed on the number of supplied contexts.
        supplied_context_count = len(self.auth_contexts)
        if supplied_context_count < 2:
            self.logger.info(
                "Skipping undocumented-field comparison: fewer than two auth "
                "contexts supplied",
                module="property_level_auth",
                supplied_auth_contexts=supplied_context_count,
            )
            return findings

        self.logger.info("Testing for undocumented fields", endpoints_count=len(endpoints))
        
        # Collect all fields from all endpoints and auth contexts
        all_fields = {}  # endpoint -> set of fields
        
        # Test with different auth contexts to see field variations
        for auth_context in self.auth_contexts:
            self.http_client.set_auth_context(auth_context)
            
            for endpoint in endpoints:
                endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
                method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
                # Safe mode: undocumented-field discovery is a read probe; never
                # replay a state-changing method (Requirements 11.1, 21.2, 21.3).
                method = self.safe_read_method(method, "undocumented_fields")

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