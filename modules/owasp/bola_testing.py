"""
BOLA (Broken Object Level Authorization) Testing Module
Implements OWASP API1 - Broken Object Level Authorization testing
"""

import asyncio
import re
import uuid
import random
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urljoin

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import BOLAConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


@dataclass
class ObjectIdentifier:
    """Represents an object identifier found in API endpoints"""
    value: str
    type: str  # 'sequential', 'guid', 'uuid', 'custom'
    endpoint: str
    parameter_name: str
    location: str  # 'path', 'query', 'body'


@dataclass
class BOLATestResult:
    """Result of a BOLA test"""
    endpoint: str
    method: str
    object_id: str
    auth_context: str
    status_code: int
    response_size: int
    response_time: float
    accessible: bool
    evidence: str


class BOLATestingModule(OWASPModule):
    """
    BOLA Testing Module for detecting Broken Object Level Authorization
    
    This module implements comprehensive testing for OWASP API Security Top 10 #1:
    - Enumerates sequential IDs and GUIDs to detect unauthorized access
    - Tests horizontal privilege escalation between users
    - Validates authorization at object level with multiple auth contexts
    - Detects objects accessible without authentication
    """
    
    # Common ID patterns for detection
    ID_PATTERNS = {
        'sequential': r'^\d+$',
        'guid': r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
        'uuid': r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
        'short_uuid': r'^[0-9a-fA-F]{16,32}$',
        'base64_id': r'^[A-Za-z0-9+/]{16,}={0,2}$'
    }
    
    # Common parameter names that might contain object IDs
    ID_PARAMETER_NAMES = [
        'id', 'user_id', 'userId', 'account_id', 'accountId',
        'object_id', 'objectId', 'resource_id', 'resourceId',
        'document_id', 'documentId', 'file_id', 'fileId',
        'order_id', 'orderId', 'transaction_id', 'transactionId',
        'profile_id', 'profileId', 'session_id', 'sessionId'
    ]
    
    def __init__(self, config: BOLAConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="bola_testing")
        
        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        
        # Add anonymous context if not present
        if 'anonymous' not in self.auth_context_map:
            anonymous_ctx = AuthContext(
                name='anonymous',
                type=AuthType.BEARER,  # Use enum, not string
                token='',
                privilege_level=0
            )
            self.auth_context_map['anonymous'] = anonymous_ctx
        
        self.logger.info("BOLA Testing Module initialized",
                        auth_contexts=len(self.auth_contexts),
                        id_patterns=len(self.ID_PATTERNS))
    
    def get_module_name(self) -> str:
        """Get module name"""
        return "bola_testing"
    
    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute BOLA tests on discovered endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of BOLA findings
        """
        self.logger.info("Starting BOLA testing", endpoints_count=len(endpoints))
        
        findings = []
        
        try:
            # Step 1: Discover object identifiers in endpoints
            object_identifiers = await self._discover_object_identifiers(endpoints)
            self.logger.info("Object identifiers discovered", count=len(object_identifiers))
            
            if not object_identifiers:
                self.logger.warning("No object identifiers found - BOLA testing limited")
                return findings
            
            # Step 2: Test anonymous access to objects
            try:
                anonymous_findings = await self._test_anonymous_access(object_identifiers)
                findings.extend(anonymous_findings)
                self.logger.debug("Anonymous access testing completed", findings=len(anonymous_findings))
            except Exception as e:
                self.logger.error("Anonymous access testing failed", error=str(e))
                raise
            
            # Step 3: Test horizontal privilege escalation
            try:
                horizontal_findings = await self._test_horizontal_privilege_escalation(object_identifiers)
                findings.extend(horizontal_findings)
                self.logger.debug("Horizontal privilege escalation testing completed", findings=len(horizontal_findings))
            except Exception as e:
                self.logger.error("Horizontal privilege escalation testing failed", error=str(e))
                # Don't raise here, continue with other tests
            
            # Step 4: Test object access validation across auth contexts
            try:
                validation_findings = await self._test_object_access_validation(object_identifiers)
                findings.extend(validation_findings)
                self.logger.debug("Object access validation testing completed", findings=len(validation_findings))
            except Exception as e:
                self.logger.error("Object access validation testing failed", error=str(e))
                # Don't raise here, continue with other tests
            
            # Step 5: Test ID enumeration vulnerabilities
            try:
                enumeration_findings = await self._test_id_enumeration(object_identifiers)
                findings.extend(enumeration_findings)
                self.logger.debug("ID enumeration testing completed", findings=len(enumeration_findings))
            except Exception as e:
                self.logger.error("ID enumeration testing failed", error=str(e))
                # Don't raise here, continue with other tests
            
        except Exception as e:
            self.logger.error("BOLA testing failed during execution", error=str(e))
            raise
        
        self.logger.info("BOLA testing completed",
                        total_findings=len(findings),
                        critical_findings=len([f for f in findings if f.severity == Severity.CRITICAL]))
        
        return findings
    
    async def _discover_object_identifiers(self, endpoints: List[Any]) -> List[ObjectIdentifier]:
        """
        Discover object identifiers in API endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of discovered object identifiers
        """
        identifiers = []
        
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            
            # Extract IDs from URL path
            path_ids = self._extract_ids_from_path(endpoint_url)
            identifiers.extend(path_ids)
            
            # Test endpoint to discover query parameters and body parameters
            if hasattr(endpoint, 'method'):
                method = endpoint.method
            else:
                method = 'GET'
            
            # Make a test request to discover parameters
            try:
                # Use first available auth context for discovery
                auth_context = None
                if self.auth_contexts:
                    auth_context = self.auth_contexts[0]
                
                if auth_context:
                    self.http_client.set_auth_context(auth_context)
                
                response = await self.http_client.request(method, endpoint_url)
                
                # Extract IDs from response content
                response_ids = self._extract_ids_from_response(response, endpoint_url)
                identifiers.extend(response_ids)
                
            except Exception as e:
                self.logger.debug("Failed to test endpoint for ID discovery",
                                endpoint=endpoint_url,
                                error=str(e))
        
        # Deduplicate identifiers
        unique_identifiers = []
        seen = set()
        
        for identifier in identifiers:
            # Debug logging
            self.logger.debug("Processing discovered identifier",
                            identifier_type=type(identifier),
                            identifier_value=str(identifier))
            
            # Ensure identifier is an ObjectIdentifier instance
            if not isinstance(identifier, ObjectIdentifier):
                self.logger.warning("Invalid identifier type found", 
                                  identifier_type=type(identifier),
                                  identifier_value=str(identifier))
                continue
                
            key = f"{identifier.endpoint}:{identifier.parameter_name}:{identifier.value}"
            if key not in seen:
                seen.add(key)
                unique_identifiers.append(identifier)
        
        self.logger.debug("Unique identifiers after deduplication", count=len(unique_identifiers))
        return unique_identifiers
    
    def _extract_ids_from_path(self, url: str) -> List[ObjectIdentifier]:
        """Extract object identifiers from URL path"""
        identifiers = []
        parsed_url = urlparse(url)
        path_segments = [seg for seg in parsed_url.path.split('/') if seg]
        
        for i, segment in enumerate(path_segments):
            for id_type, pattern in self.ID_PATTERNS.items():
                # Use re.match for anchored patterns
                if re.match(pattern, segment):
                    # Try to determine parameter name from context
                    param_name = 'id'
                    if i > 0:
                        prev_segment = path_segments[i-1]
                        if prev_segment in ['user', 'users']:
                            param_name = 'user_id'
                        elif prev_segment in ['account', 'accounts']:
                            param_name = 'account_id'
                        elif prev_segment in ['order', 'orders']:
                            param_name = 'order_id'
                        else:
                            param_name = f"{prev_segment}_id"
                    
                    identifier = ObjectIdentifier(
                        value=segment,
                        type=id_type,
                        endpoint=url,
                        parameter_name=param_name,
                        location='path'
                    )
                    identifiers.append(identifier)
                    break  # Only match first pattern that works
        
        return identifiers
    
    def _extract_ids_from_response(self, response: Response, endpoint: str) -> List[ObjectIdentifier]:
        """Extract object identifiers from response content"""
        identifiers = []
        
        # Look for IDs in JSON responses
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                import json
                data = json.loads(response.text)
                ids = self._extract_ids_from_json(data, endpoint)
                identifiers.extend(ids)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Look for IDs in response text using patterns
        # Use word boundary patterns for text search
        text_patterns = {
            'sequential': r'\b\d+\b',
            'guid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
            'uuid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
            'short_uuid': r'\b[0-9a-fA-F]{16,32}\b',
            'base64_id': r'\b[A-Za-z0-9+/]{16,}={0,2}\b'
        }
        
        for id_type, pattern in text_patterns.items():
            matches = re.findall(pattern, response.text)
            for match in matches:
                identifier = ObjectIdentifier(
                    value=match,
                    type=id_type,
                    endpoint=endpoint,
                    parameter_name='discovered_id',
                    location='response'
                )
                identifiers.append(identifier)
        
        return identifiers
    
    def _extract_ids_from_json(self, data: Any, endpoint: str, prefix: str = '') -> List[ObjectIdentifier]:
        """Recursively extract IDs from JSON data"""
        identifiers = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                # Check if key suggests an ID parameter
                if any(id_param in key.lower() for id_param in self.ID_PARAMETER_NAMES):
                    if isinstance(value, (str, int)):
                        str_value = str(value)
                        # Determine ID type
                        id_type = self._determine_id_type(str_value)
                        if id_type:
                            identifier = ObjectIdentifier(
                                value=str_value,
                                type=id_type,
                                endpoint=endpoint,
                                parameter_name=key,
                                location='response'
                            )
                            identifiers.append(identifier)
                
                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    nested_ids = self._extract_ids_from_json(value, endpoint, full_key)
                    identifiers.extend(nested_ids)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    nested_ids = self._extract_ids_from_json(item, endpoint, f"{prefix}[{i}]")
                    identifiers.extend(nested_ids)
        
        return identifiers
    
    def _determine_id_type(self, value: str) -> Optional[str]:
        """Determine the type of an ID value"""
        for id_type, pattern in self.ID_PATTERNS.items():
            if re.match(pattern, value):
                return id_type
        return None
    
    async def _test_anonymous_access(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """
        Test anonymous access to objects (Requirement 1.2)
        
        Args:
            identifiers: List of object identifiers to test
            
        Returns:
            List of findings for anonymous access vulnerabilities
        """
        findings = []
        self.logger.info("Testing anonymous access to objects", count=len(identifiers))
        
        # Set anonymous context (no authentication)
        try:
            # For anonymous access, we don't set any auth context
            # This ensures no authentication headers are added
            self.http_client.current_auth_context = None
            self.logger.debug("Set anonymous context (no authentication)")
        except Exception as e:
            self.logger.error("Failed to set anonymous context", error=str(e))
            raise
        
        for i, identifier in enumerate(identifiers):
            self.logger.debug("Processing identifier", 
                            index=i, 
                            identifier_type=type(identifier),
                            identifier_value=str(identifier))
            
            # Skip if not an ObjectIdentifier instance
            if not isinstance(identifier, ObjectIdentifier):
                self.logger.warning("Skipping invalid identifier", 
                                  identifier_type=type(identifier),
                                  identifier_value=str(identifier))
                continue
                
            try:
                # Test access to the object without authentication
                self.logger.debug("About to test object access", 
                                identifier_value=identifier.value,
                                identifier_type=type(identifier))
                response = await self._test_object_access(identifier, 'anonymous')
                
                # Check if object is accessible without authentication
                if self._is_object_accessible(response):
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',  # Will be set by findings collector
                        category='BOLA_ANONYMOUS_ACCESS',
                        owasp_category='API1',
                        severity=Severity.CRITICAL,
                        endpoint=identifier.endpoint,
                        method='GET',
                        status_code=response.status_code,
                        response_size=len(response.content),
                        response_time=response.elapsed,
                        evidence=f"Object {identifier.value} accessible without authentication. "
                                f"Status: {response.status_code}, Size: {len(response.content)} bytes",
                        recommendation="Implement proper authentication checks for object access. "
                                     "Ensure all object endpoints require valid authentication.",
                        payload=identifier.value,
                        response_snippet=response.text[:500] if response.text else None
                    )
                    findings.append(finding)
                    
                    self.logger.warning("Anonymous access detected",
                                      object_id=identifier.value,
                                      endpoint=identifier.endpoint,
                                      status_code=response.status_code)
            
            except Exception as e:
                self.logger.error("Anonymous access test failed for identifier",
                                identifier_index=i,
                                identifier_type=type(identifier),
                                identifier_value=str(identifier),
                                error=str(e))
                raise  # Re-raise to see the full stack trace
        
        return findings
    
    async def _test_horizontal_privilege_escalation(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """
        Test horizontal privilege escalation between users (Requirement 1.3)
        
        Args:
            identifiers: List of object identifiers to test
            
        Returns:
            List of findings for horizontal privilege escalation
        """
        findings = []
        self.logger.info("Testing horizontal privilege escalation", count=len(identifiers))
        
        # Get user-level auth contexts (privilege level 1)
        user_contexts = [ctx for ctx in self.auth_contexts if ctx.privilege_level == 1]
        
        if len(user_contexts) < 2:
            self.logger.warning("Need at least 2 user contexts for horizontal escalation testing")
            return findings
        
        # Test each object with different user contexts
        for identifier in identifiers:
            # First, establish baseline - what objects are accessible to user1
            user1_context = user_contexts[0]
            self.http_client.set_auth_context(user1_context)
            
            try:
                user1_response = await self._test_object_access(identifier, user1_context.name)
                
                # If user1 can access the object, test if user2 can also access it
                if self._is_object_accessible(user1_response):
                    # Test with user2
                    user2_context = user_contexts[1]
                    self.http_client.set_auth_context(user2_context)
                    
                    user2_response = await self._test_object_access(identifier, user2_context.name)
                    
                    # If user2 can also access user1's object, it's horizontal escalation
                    if self._is_object_accessible(user2_response):
                        # Additional check: responses should be similar (indicating same object)
                        if self._responses_indicate_same_object(user1_response, user2_response):
                            finding = Finding(
                                id=str(uuid.uuid4()),
                                scan_id='',
                                category='BOLA_HORIZONTAL_ESCALATION',
                                owasp_category='API1',
                                severity=Severity.CRITICAL,
                                endpoint=identifier.endpoint,
                                method='GET',
                                status_code=user2_response.status_code,
                                response_size=len(user2_response.content),
                                response_time=user2_response.elapsed,
                                evidence=f"User '{user2_context.name}' can access object {identifier.value} "
                                        f"that belongs to user '{user1_context.name}'. "
                                        f"Both users received similar responses (sizes: {len(user1_response.content)} vs {len(user2_response.content)})",
                                recommendation="Implement proper object-level authorization checks. "
                                             "Ensure users can only access their own objects.",
                                payload=identifier.value,
                                response_snippet=user2_response.text[:500] if user2_response.text else None
                            )
                            findings.append(finding)
                            
                            self.logger.warning("Horizontal privilege escalation detected",
                                              object_id=identifier.value,
                                              endpoint=identifier.endpoint,
                                              user1=user1_context.name,
                                              user2=user2_context.name)
            
            except Exception as e:
                self.logger.debug("Horizontal escalation test failed",
                                object_id=identifier.value,
                                endpoint=identifier.endpoint,
                                error=str(e))
        
        return findings
    
    async def _test_object_access_validation(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """
        Test object access validation with multiple auth contexts (Requirement 1.4)
        
        Args:
            identifiers: List of object identifiers to test
            
        Returns:
            List of findings for object access validation issues
        """
        findings = []
        self.logger.info("Testing object access validation", count=len(identifiers))
        
        # Test each object with all available auth contexts
        for identifier in identifiers:
            access_results = {}
            
            # Test with each auth context
            for auth_context in self.auth_contexts:
                self.http_client.set_auth_context(auth_context)
                
                try:
                    response = await self._test_object_access(identifier, auth_context.name)
                    access_results[auth_context.name] = {
                        'accessible': self._is_object_accessible(response),
                        'response': response,
                        'privilege_level': auth_context.privilege_level
                    }
                
                except Exception as e:
                    self.logger.debug("Object access validation test failed",
                                    object_id=identifier.value,
                                    auth_context=auth_context.name,
                                    error=str(e))
                    access_results[auth_context.name] = {
                        'accessible': False,
                        'response': None,
                        'privilege_level': auth_context.privilege_level
                    }
            
            # Analyze access patterns
            validation_finding = self._analyze_access_patterns(identifier, access_results)
            if validation_finding:
                findings.append(validation_finding)
        
        return findings
    
    def _analyze_access_patterns(self, identifier: ObjectIdentifier, 
                               access_results: Dict[str, Dict]) -> Optional[Finding]:
        """
        Analyze access patterns to detect authorization issues
        
        Args:
            identifier: Object identifier being tested
            access_results: Results of access tests with different auth contexts
            
        Returns:
            Finding if authorization issue detected, None otherwise
        """
        accessible_contexts = [name for name, result in access_results.items() 
                             if result['accessible']]
        
        if not accessible_contexts:
            return None  # Object not accessible to anyone - likely protected
        
        # Check if lower privilege users can access objects that higher privilege users can access
        privilege_levels = {name: result['privilege_level'] 
                          for name, result in access_results.items() 
                          if result['accessible']}
        
        if len(privilege_levels) > 1:
            min_privilege = min(privilege_levels.values())
            max_privilege = max(privilege_levels.values())
            
            # If there's a significant privilege gap, it might be an issue
            if max_privilege - min_privilege > 1:
                evidence = f"Object {identifier.value} accessible to users with privilege levels {sorted(privilege_levels.values())}. "
                evidence += f"Accessible contexts: {', '.join(accessible_contexts)}"
                
                return Finding(
                    id=str(uuid.uuid4()),
                    scan_id='',
                    category='BOLA_OBJECT_ACCESS',
                    owasp_category='API1',
                    severity=Severity.HIGH,
                    endpoint=identifier.endpoint,
                    method='GET',
                    status_code=200,  # Assuming successful access
                    response_size=0,
                    response_time=0.0,
                    evidence=evidence,
                    recommendation="Review object access controls. Ensure objects are only accessible "
                                 "to users with appropriate privilege levels.",
                    payload=identifier.value
                )
        
        return None
    
    async def _test_id_enumeration(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """
        Test ID enumeration vulnerabilities (Requirement 1.1)
        
        Args:
            identifiers: List of object identifiers to test
            
        Returns:
            List of findings for ID enumeration vulnerabilities
        """
        findings = []
        self.logger.info("Testing ID enumeration", count=len(identifiers))
        
        # Group identifiers by type for efficient testing
        sequential_ids = [id for id in identifiers if id.type == 'sequential']
        guid_ids = [id for id in identifiers if id.type in ['guid', 'uuid']]
        
        # Test sequential ID enumeration
        if sequential_ids:
            enum_findings = await self._test_sequential_enumeration(sequential_ids)
            findings.extend(enum_findings)
        
        # Test GUID enumeration (less likely but possible)
        if guid_ids:
            guid_findings = await self._test_guid_enumeration(guid_ids)
            findings.extend(guid_findings)
        
        return findings
    
    async def _test_sequential_enumeration(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """Test sequential ID enumeration"""
        findings = []
        
        # Use first available auth context for enumeration testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        for identifier in identifiers:
            try:
                original_id = int(identifier.value)
                accessible_ids = []
                
                # Test a range of IDs around the original
                test_range = range(max(1, original_id - 5), original_id + 10)
                
                for test_id in test_range:
                    if test_id == original_id:
                        continue  # Skip the original ID
                    
                    # Create test identifier
                    test_identifier = ObjectIdentifier(
                        value=str(test_id),
                        type=identifier.type,
                        endpoint=identifier.endpoint,
                        parameter_name=identifier.parameter_name,
                        location=identifier.location
                    )
                    
                    response = await self._test_object_access(test_identifier, 'enumeration_test')
                    
                    if self._is_object_accessible(response):
                        accessible_ids.append(test_id)
                
                # If multiple sequential IDs are accessible, it's enumeration vulnerability
                if len(accessible_ids) >= 2:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='BOLA_ID_ENUMERATION',
                        owasp_category='API1',
                        severity=Severity.HIGH,
                        endpoint=identifier.endpoint,
                        method='GET',
                        status_code=200,
                        response_size=0,
                        response_time=0.0,
                        evidence=f"Sequential ID enumeration possible. Original ID: {original_id}, "
                                f"Accessible IDs: {accessible_ids}. Total accessible: {len(accessible_ids)}",
                        recommendation="Use non-sequential, unpredictable object identifiers (UUIDs). "
                                     "Implement proper authorization checks for all object access.",
                        payload=f"Original: {original_id}, Enumerated: {accessible_ids}"
                    )
                    findings.append(finding)
                    
                    self.logger.warning("Sequential ID enumeration detected",
                                      endpoint=identifier.endpoint,
                                      original_id=original_id,
                                      accessible_count=len(accessible_ids))
            
            except (ValueError, Exception) as e:
                self.logger.debug("Sequential enumeration test failed",
                                object_id=identifier.value,
                                error=str(e))
        
        return findings
    
    async def _test_guid_enumeration(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """Test GUID enumeration (less common but possible with predictable GUIDs)"""
        findings = []
        
        # For GUIDs, we'll test a few random variations
        # This is less likely to succeed but worth checking
        
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        for identifier in identifiers:
            try:
                accessible_guids = []
                
                # Generate a few test GUIDs
                test_guids = [str(uuid.uuid4()) for _ in range(5)]
                
                for test_guid in test_guids:
                    test_identifier = ObjectIdentifier(
                        value=test_guid,
                        type=identifier.type,
                        endpoint=identifier.endpoint,
                        parameter_name=identifier.parameter_name,
                        location=identifier.location
                    )
                    
                    response = await self._test_object_access(test_identifier, 'guid_enumeration_test')
                    
                    if self._is_object_accessible(response):
                        accessible_guids.append(test_guid)
                
                # If any random GUIDs are accessible, it might indicate weak GUID generation
                if accessible_guids:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='BOLA_GUID_ENUMERATION',
                        owasp_category='API1',
                        severity=Severity.MEDIUM,
                        endpoint=identifier.endpoint,
                        method='GET',
                        status_code=200,
                        response_size=0,
                        response_time=0.0,
                        evidence=f"Random GUID enumeration successful. Original GUID: {identifier.value}, "
                                f"Accessible random GUIDs: {accessible_guids}",
                        recommendation="Ensure GUID generation is truly random and unpredictable. "
                                     "Implement proper authorization checks regardless of ID format.",
                        payload=f"Original: {identifier.value}, Random accessible: {accessible_guids}"
                    )
                    findings.append(finding)
            
            except Exception as e:
                self.logger.debug("GUID enumeration test failed",
                                object_id=identifier.value,
                                error=str(e))
        
        return findings
    
    async def _test_object_access(self, identifier: ObjectIdentifier, context_name: str) -> Response:
        """
        Test access to a specific object
        
        Args:
            identifier: Object identifier to test
            context_name: Name of auth context being used
            
        Returns:
            HTTP response from the test
        """
        # Construct the test URL based on identifier location
        if identifier.location == 'path':
            # Replace the original ID in the path with the test ID
            # Handle different URL patterns
            original_endpoint = identifier.endpoint
            
            # Find the original ID in the URL and replace it
            if f"/{identifier.value}/" in original_endpoint:
                test_url = original_endpoint.replace(f"/{identifier.value}/", f"/{identifier.value}/")
            elif f"/{identifier.value}" in original_endpoint:
                # Replace at the end of the path
                test_url = original_endpoint.replace(f"/{identifier.value}", f"/{identifier.value}")
            else:
                # If we can't find the exact pattern, construct new URL
                # This handles cases where we're testing different IDs
                base_url = original_endpoint.rsplit('/', 1)[0]  # Remove last path segment
                test_url = f"{base_url}/{identifier.value}"
        else:
            # For query parameters, add the ID as a parameter
            test_url = f"{identifier.endpoint}?{identifier.parameter_name}={identifier.value}"
        
        # Make the request
        response = await self.http_client.request('GET', test_url)
        
        self.logger.debug("Object access test",
                         object_id=identifier.value,
                         endpoint=test_url,
                         context=context_name,
                         status_code=response.status_code,
                         response_size=len(response.content))
        
        return response
    
    def _is_object_accessible(self, response: Response) -> bool:
        """
        Determine if an object is accessible based on response
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            True if object appears to be accessible, False otherwise
        """
        # Consider object accessible if:
        # - Status code is 2xx (success)
        # - Status code is 3xx (redirect, but object exists)
        # - Response has substantial content (not just error message)
        
        if response.status_code == 0:  # Request failed
            return False
        
        if 200 <= response.status_code < 400:
            # Additional check: response should have meaningful content
            if len(response.content) > 50:  # Arbitrary threshold
                return True
            
            # Check if response looks like actual data vs error message
            if response.text:
                error_indicators = ['error', 'not found', 'unauthorized', 'forbidden', 'invalid']
                response_lower = response.text.lower()
                
                # If response contains error indicators, it's likely not accessible
                if any(indicator in response_lower for indicator in error_indicators):
                    return False
                
                return True
        
        return False
    
    def _responses_indicate_same_object(self, response1: Response, response2: Response) -> bool:
        """
        Check if two responses indicate access to the same object
        
        Args:
            response1: First response
            response2: Second response
            
        Returns:
            True if responses appear to be for the same object
        """
        # Both responses must be successful
        if not (response1.is_success and response2.is_success):
            return False
        
        # If response sizes are very similar (within 10%), likely same object
        if response1.content and response2.content:
            size1, size2 = len(response1.content), len(response2.content)
            if size1 > 0 and size2 > 0:
                size_diff = abs(size1 - size2) / max(size1, size2)
                if size_diff < 0.1:  # Less than 10% difference
                    return True
        
        # More sophisticated check: compare response content similarity
        if response1.text and response2.text:
            # Simple similarity check based on common words
            words1 = set(response1.text.lower().split())
            words2 = set(response2.text.lower().split())
            
            if words1 and words2:
                intersection = len(words1.intersection(words2))
                union = len(words1.union(words2))
                similarity = intersection / union if union > 0 else 0
                
                # If responses are >80% similar, likely same object
                return similarity > 0.8
        
        return False