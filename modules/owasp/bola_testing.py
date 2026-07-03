"""
BOLA (Broken Object Level Authorization) Testing Module
Implements OWASP API1 - Broken Object Level Authorization testing
"""

import asyncio
import base64
import copy
import hashlib
import json
import math
import re
import uuid
import random
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass
from urllib.parse import (
    urlparse,
    urlunparse,
    parse_qs,
    urlencode,
    urljoin,
    quote,
    unquote,
)

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from utils.safe_mode import SafeModeGuard, STATE_CHANGING_METHODS, SAFE_METHODS
from utils.authz_baseline import (
    NegativeControlMixin,
    NegativeControlBaseline,
    extract_identifying_fields,
    responses_identify_same_object,
    responses_equivalent,
)
from core.config import BOLAConfig, AuthContext, AuthType, Severity
from core.logging import get_logger
from utils.typed_payload import build_typed_payload, apply_actor_profile


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


@dataclass
class CompositeIdentifierSlot:
    """A single identifier slot within a CompositeIdentifier (Requirement 29).

    Records the identifier value, its detected type, an inferred parameter name,
    the EXACT position of the value within the endpoint's raw path split (so a
    single slot can be substituted while every other segment is preserved), and
    the slot's hierarchical role (``'parent'`` for the leftmost slot, ``'child'``
    for subsequent slots).
    """
    value: str
    type: str            # 'sequential' | 'guid' | 'uuid' | ...
    name: str            # inferred, e.g. 'tenant_id', 'project_id'
    segment_index: int   # exact position in the raw path split
    role: str            # 'parent' | 'child' (leftmost slot = parent)


@dataclass
class CompositeIdentifier:
    """An endpoint with two or more hierarchically arranged identifier slots.

    Example: ``/tenants/{tenant_id}/projects/{project_id}`` yields two slots
    ordered parent..child. Slots are ordered by their position in the path so
    ``slots[0]`` is the outermost (parent) identifier and ``slots[-1]`` is the
    innermost (child) identifier (Requirement 29).
    """
    endpoint: str
    slots: List[CompositeIdentifierSlot]   # >= 2, ordered parent..child


@dataclass
class IdentifierPredictability:
    """Assessment of how guessable an observed identifier scheme is (Req 30.4).

    ``scheme`` is one of ``'sequential-integer'``, ``'timestamp-based'``,
    ``'uuid-v1'`` (time-based UUID), ``'uuid-v4'`` (random UUID),
    ``'hash-of-known-input'`` (a hash of a known value such as ``MD5(email)``),
    or ``'unknown'``. ``predictable`` is ``True`` for the enumerable/guessable
    schemes (sequential-integer, timestamp-based, uuid-v1, hash-of-known-input)
    and ``False`` for a random UUIDv4 or an unclassifiable scheme (Req 30.5,
    30.6, 40.1). ``rationale`` is a short human-readable explanation included in
    finding evidence.
    """
    scheme: str
    predictable: bool
    rationale: str


@dataclass
class EvidenceChain:
    """Structured Evidence_Chain attached to every advanced BOLA finding (Req 33.1).

    Captures the exact request line and method, the substituted and original
    identifiers, the Auth_Context NAME used (never the token — Req 33.1), the
    outcome of the Negative_Control_Baseline comparison, a response snippet that
    is ALWAYS passed through :meth:`BOLATestingModule.redact_secrets` before it
    is stored (Req 33.3), and a Confidence_Score (Req 33.2).
    """
    request_line: str            # e.g. "PATCH /users/42 HTTP/1.1"
    method: str
    original_id: str
    substituted_id: str
    auth_context: str            # context name only, never the token
    baseline_comparison: str     # outcome vs the Negative_Control_Baseline
    response_snippet: str        # redacted (Req 33.3)
    confidence: str              # 'high' | 'medium' | 'low' (Req 33.2)


class BOLATestingModule(OWASPModule, NegativeControlMixin, SafeModeGuard):
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

    # Identifying_Field names (lowercased) that denote an object's OWNER. Used by
    # ownership-aware enumeration to decide whether an accessed object belongs to
    # the requesting Auth_Context (Requirement 4.1).
    OWNER_FIELD_NAMES = {
        'user_id', 'userid', 'owner_id', 'ownerid',
        'account_id', 'accountid', 'email',
    }

    # Unauthorized_Endpoint_Assertion classification for this module (Req 55.2,
    # 56.2): BOLA emits within API1.
    UNAUTHORIZED_ASSERTION_CATEGORY = "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS"
    UNAUTHORIZED_ASSERTION_OWASP = "API1"

    def __init__(self, config: BOLAConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext], spec_schema=None):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="bola_testing")

        # Optional merged Spec_Schema threaded from the ``full`` command's
        # ``--openapi`` / ``--postman`` sources (Requirements 49.2, 49.5). It is
        # additive and defaults to ``None``; every consumer guards on
        # ``if self.spec_schema is not None`` so the no-spec path (discovered
        # endpoints only) is unchanged (Requirements 49.3, 53.2).
        self.spec_schema = spec_schema

        # Read Safe_Mode flag (Requirement 21.1). BOLA issues only GET probes so
        # it is read-only by construction; the guard is wired for uniformity and
        # to gate any future state-changing probe.
        self._init_safe_mode(config)

        # One Negative_Control_Baseline cached per (endpoint, auth_context) to
        # bound the extra requests issued for calibration (Requirement 3, 25).
        self._baseline_cache: Dict[Tuple[str, str], NegativeControlBaseline] = {}

        # Negative_Control_Baseline cache for composite endpoints, keyed on
        # (endpoint, auth_context, slot_index) so each composite slot's
        # calibration is issued at most once (Requirements 29.5, 3, 25).
        self._composite_baseline_cache: Dict[Tuple[str, str, int], NegativeControlBaseline] = {}

        # Report-only records of Destructive_Probes that would have been issued
        # while Dry_Run is enabled. Each entry captures the intended method,
        # target URL, substituted identifier, and intended body WITHOUT any
        # request being sent (Requirement 28.6).
        self._dry_run_records: List[Dict[str, Any]] = []

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

        if self.safe_mode:
            self.logger.info(
                "Safe mode enabled: BOLA operates read-only (GET-only probes); "
                "no state-changing requests will be issued",
                module="bola_testing",
            )

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

            # Step 6: Composite / multi-tenant BOLA (opt-in, Requirement 29).
            # Gated by BOLAConfig.enable_composite (defaults False) so the
            # existing default scan behavior is preserved (Requirement 34.2).
            if getattr(self.config, 'enable_composite', False):
                try:
                    composites = self._discover_composite_identifiers(endpoints)
                    self.logger.info("Composite identifiers discovered", count=len(composites))
                    composite_findings = await self._test_composite_bola(composites)
                    findings.extend(composite_findings)
                    self.logger.debug("Composite BOLA testing completed",
                                      findings=len(composite_findings))
                except Exception as e:
                    self.logger.error("Composite BOLA testing failed", error=str(e))
                    # Don't raise here, continue with other tests

            # Step 7: ID leakage harvesting + identifier predictability (opt-in,
            # Requirement 30). Gated by BOLAConfig.enable_id_leakage (defaults
            # False) so existing default scan behavior is preserved
            # (Requirement 34.2). Uses safe GET probes only.
            if getattr(self.config, 'enable_id_leakage', False):
                try:
                    harvested = await self._harvest_identifiers(endpoints)
                    self.logger.info("Identifiers harvested for leakage testing",
                                     count=len(harvested))

                    leakage_findings = await self._test_id_leakage(
                        harvested, object_identifiers
                    )
                    findings.extend(leakage_findings)
                    self.logger.debug("ID leakage testing completed",
                                      findings=len(leakage_findings))

                    predictability_findings = self._test_identifier_predictability(
                        harvested
                    )
                    findings.extend(predictability_findings)
                    self.logger.debug("Identifier predictability analysis completed",
                                      findings=len(predictability_findings))
                except Exception as e:
                    self.logger.error("ID leakage / predictability testing failed",
                                      error=str(e))
                    # Don't raise here, continue with other tests

            # Step 8: Declarative Unauthorized_Endpoint_Assertions (Req 55). Only
            # runs when at least one auth context carries operator-declared
            # patterns; otherwise the module behaves exactly as before (Req 55.5).
            try:
                assertion_findings = await self._run_unauthorized_assertions(endpoints)
                findings.extend(assertion_findings)
                self.logger.debug("Unauthorized-endpoint assertion evaluation completed",
                                  findings=len(assertion_findings))
            except Exception as e:
                self.logger.error("Unauthorized-endpoint assertion evaluation failed",
                                  error=str(e))
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

            # Safe mode: object-identifier discovery is a read-only probe, so an
            # endpoint's declared State_Changing_Method must never be issued.
            # Downgrade the discovery request to GET (a Safe_Method) and log the
            # downgrade (Requirements 21.2, 21.3, 21.4).
            method = self.safe_read_method(method, "bola_id_discovery")

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
        """Extract object identifiers from response content.

        Extraction is restricted to values associated with recognized
        Identifying_Field names (via :meth:`_extract_ids_from_json`) rather than
        matching every integer in the response body. The previous broad
        ``\\b\\d+\\b`` text regex - which treated any integer as an identifier -
        has been removed (Requirement 4.4).
        """
        identifiers = []

        # Look for IDs in JSON responses, keyed on recognized Identifying_Field
        # names only.
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                import json
                data = json.loads(response.text)
                ids = self._extract_ids_from_json(data, endpoint)
                identifiers.extend(ids)
        except (json.JSONDecodeError, ValueError):
            pass

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
                # Build a negative-control baseline for this endpoint under the
                # anonymous context (Requirements 3.1, 25.1).
                baseline = await self._get_negative_control(identifier, None)
                # Re-assert anonymous context for the real probe (the baseline
                # build leaves the anonymous context untouched).
                self.http_client.current_auth_context = None

                if baseline.non_discriminating:
                    self.logger.info(
                        "Suppressing anonymous-access finding: endpoint is "
                        "non-discriminating (returns success for an invalid id)",
                        endpoint=identifier.endpoint,
                        object_id=identifier.value,
                    )
                    continue

                # Test access to the object without authentication
                self.logger.debug("About to test object access", 
                                identifier_value=identifier.value,
                                identifier_type=type(identifier))
                response = await self._test_object_access(identifier, 'anonymous')
                
                # Check if object is accessible without authentication
                if self._is_object_accessible(response, baseline):
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
            # Structured skip log: the test is unreachable without >= 2 user
            # contexts (Requirement 5.2). Reachability comes from the CLI
            # --auth-context option supplying multiple user contexts.
            self.logger.info(
                "Skipping horizontal privilege escalation: fewer than two "
                "user-level auth contexts supplied",
                user_contexts=len(user_contexts),
                required=2,
            )
            return findings
        
        # Test each object with different user contexts
        for identifier in identifiers:
            # First, establish baseline - what objects are accessible to user1
            user1_context = user_contexts[0]

            try:
                baseline1 = await self._get_negative_control(identifier, user1_context)
                if baseline1.non_discriminating:
                    self.logger.info(
                        "Suppressing horizontal escalation finding: endpoint is "
                        "non-discriminating for the owning user context",
                        endpoint=identifier.endpoint,
                        object_id=identifier.value,
                        user=user1_context.name,
                    )
                    continue

                # Request the object under user1's own credentials.
                self.http_client.set_auth_context(user1_context)
                user1_response = await self._test_object_access(identifier, user1_context.name)

                # If user1 can access the object, test whether EACH other user
                # context can also access the same object (Requirement 5.3).
                if not self._is_object_accessible(user1_response, baseline1):
                    continue

                for user2_context in user_contexts[1:]:
                    baseline2 = await self._get_negative_control(identifier, user2_context)
                    if baseline2.non_discriminating:
                        self.logger.info(
                            "Suppressing horizontal escalation finding: endpoint "
                            "is non-discriminating for the probing user context",
                            endpoint=identifier.endpoint,
                            object_id=identifier.value,
                            user=user2_context.name,
                        )
                        continue

                    # Request the same object under user2's own credentials.
                    self.http_client.set_auth_context(user2_context)
                    user2_response = await self._test_object_access(identifier, user2_context.name)

                    if not self._is_object_accessible(user2_response, baseline2):
                        continue

                    # Identity-aware comparison: only a finding when both
                    # responses expose a matching Identifying_Field value
                    # (Requirement 2). No finding on size/word similarity.
                    same, field_name, field_value = responses_identify_same_object(
                        user1_response, user2_response
                    )
                    if same:
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
                            evidence=f"User '{user2_context.name}' can access object "
                                    f"{identifier.value} that belongs to user "
                                    f"'{user1_context.name}'. Both responses expose the "
                                    f"same identifying field '{field_name}'={field_value!r}.",
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
                                          user2=user2_context.name,
                                          identifying_field=field_name)
            
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
                try:
                    baseline = await self._get_negative_control(identifier, auth_context)
                    self.http_client.set_auth_context(auth_context)
                    response = await self._test_object_access(identifier, auth_context.name)
                    accessible = (
                        not baseline.non_discriminating
                        and self._is_object_accessible(response, baseline)
                    )
                    access_results[auth_context.name] = {
                        'accessible': accessible,
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
        """Ownership-aware sequential ID enumeration (Requirement 4).

        The candidate range is derived from ``BOLAConfig.enumeration_bound``
        rather than a fixed window (Requirement 4.2). Accessibility is calibrated
        against a Negative_Control_Baseline, and a ``BOLA_ID_ENUMERATION`` finding
        is raised only for accessed objects whose Identifying_Field shows they do
        NOT belong to the requesting context (Requirement 4.1). Non-sequential
        identifiers are skipped with a log entry (Requirement 4.3).
        """
        findings = []

        # Use the first available auth context as the requesting context.
        auth_context = self.auth_contexts[0] if self.auth_contexts else None

        bound = max(2, getattr(self.config, 'enumeration_bound', 25))
        half = bound // 2

        for identifier in identifiers:
            # Only genuinely sequential (integer) identifiers are enumerable.
            if identifier.type != 'sequential' or not str(identifier.value).isdigit():
                self.logger.info(
                    "Skipping sequential enumeration for non-sequential identifier",
                    object_id=identifier.value,
                    identifier_type=identifier.type,
                    endpoint=identifier.endpoint,
                )
                continue

            try:
                original_id = int(identifier.value)

                # Calibrate accessibility against a negative-control baseline for
                # this endpoint/context (Requirements 3.1, 25.1).
                baseline = await self._get_negative_control(identifier, auth_context)
                if baseline.non_discriminating:
                    self.logger.info(
                        "Suppressing enumeration finding: endpoint is "
                        "non-discriminating (returns success for an invalid id)",
                        endpoint=identifier.endpoint,
                        object_id=identifier.value,
                    )
                    continue

                if auth_context is not None:
                    self.http_client.set_auth_context(auth_context)

                # Fetch the requester's OWN object to establish the ownership
                # reference (Requirement 4.1).
                own_response = await self._test_object_access(
                    identifier, 'enumeration_owner', candidate_id=identifier.value
                )
                own_fields = extract_identifying_fields(own_response)

                # Candidate range derived from the configurable bound.
                test_range = range(max(1, original_id - half), original_id + (bound - half) + 1)

                unauthorized_ids = []
                for test_id in test_range:
                    if test_id == original_id:
                        continue  # Skip the original ID

                    response = await self._test_object_access(
                        identifier, 'enumeration_test', candidate_id=str(test_id)
                    )

                    if not self._is_object_accessible(response, baseline):
                        continue

                    # An accessed object is a vulnerability only when it does NOT
                    # belong to the requesting context (Requirement 4.1).
                    candidate_fields = extract_identifying_fields(response)
                    if self._object_belongs_to_context(candidate_fields, own_fields):
                        continue

                    unauthorized_ids.append(test_id)

                # Multiple foreign objects accessible => enumeration vulnerability.
                if len(unauthorized_ids) >= 2:
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
                        evidence=f"Sequential ID enumeration exposed objects not owned by the "
                                f"requesting context. Original ID: {original_id}, "
                                f"Unauthorized accessible IDs: {unauthorized_ids}. "
                                f"Total unauthorized: {len(unauthorized_ids)}",
                        recommendation="Use non-sequential, unpredictable object identifiers (UUIDs). "
                                     "Implement proper authorization checks for all object access.",
                        payload=f"Original: {original_id}, Unauthorized: {unauthorized_ids}"
                    )
                    findings.append(finding)

                    self.logger.warning("Sequential ID enumeration detected",
                                      endpoint=identifier.endpoint,
                                      original_id=original_id,
                                      unauthorized_count=len(unauthorized_ids))

            except ValueError as e:
                self.logger.info("Skipping sequential enumeration for non-integer identifier",
                                object_id=identifier.value,
                                error=str(e))
            except Exception as e:
                self.logger.debug("Sequential enumeration test failed",
                                object_id=identifier.value,
                                error=str(e))

        return findings

    async def _test_guid_enumeration(self, identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """GUID enumeration is not attempted (Requirement 4.3).

        Random GUIDs are non-sequential, so probing random variations cannot
        constitute meaningful sequential enumeration. The previous random-GUID
        probing has been removed in favor of a skip-with-log so no spurious
        ``BOLA_GUID_ENUMERATION`` findings are produced.
        """
        for identifier in identifiers:
            self.logger.info(
                "Skipping enumeration for non-sequential (GUID/UUID) identifier",
                object_id=identifier.value,
                identifier_type=identifier.type,
                endpoint=identifier.endpoint,
            )
        return []

    
    async def _test_object_access(self, identifier: ObjectIdentifier, context_name: str,
                                  candidate_id: Optional[Any] = None) -> Response:
        """
        Test access to a specific object by substituting a candidate identifier.

        Args:
            identifier: Object identifier carrying the original id and its
                location (path segment or query parameter)
            context_name: Name of auth context being used (for logging)
            candidate_id: The identifier to substitute into the request URL. When
                ``None`` the original ``identifier.value`` is used, so the issued
                URL matches the original endpoint (Requirement 1.4).

        Returns:
            HTTP response from the test
        """
        target_id = candidate_id if candidate_id is not None else identifier.value
        test_url = self._substitute_identifier(identifier, target_id)

        # Make the request
        response = await self.http_client.request('GET', test_url)

        self.logger.debug("Object access test",
                         object_id=target_id,
                         endpoint=test_url,
                         context=context_name,
                         status_code=response.status_code,
                         response_size=len(response.content))

        return response

    def _substitute_identifier(self, identifier: ObjectIdentifier, candidate_id: Any) -> str:
        """Build a URL with ``candidate_id`` substituted for the original id.

        The original identifier is replaced at its exact path segment
        (Requirement 1.2) or query parameter (Requirement 1.3) while every other
        path segment and query parameter is preserved unchanged (Requirement
        1.5). When ``candidate_id`` differs from the original ``identifier.value``
        the resulting URL differs from the original endpoint URL; when it equals
        the original the URL is unchanged (Requirement 1.4).
        """
        candidate_id = str(candidate_id)
        parsed = urlparse(identifier.endpoint)

        if identifier.location == 'path':
            # Replace only the segment(s) equal to the original identifier value,
            # leaving all other path segments intact.
            segments = parsed.path.split('/')
            new_segments = [
                candidate_id if seg == identifier.value else seg
                for seg in segments
            ]
            new_path = '/'.join(new_segments)
            return urlunparse(parsed._replace(path=new_path))

        # Query-string (or response-discovered) identifier: substitute the target
        # query parameter, preserving every other parameter.
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[identifier.parameter_name] = [candidate_id]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _spec_path_slots(self, operation) -> List[Any]:
        """Return the declared ``path`` Spec_Parameters for ``operation`` in path
        order (Requirements 53.1, 53.4).

        The parameters are ordered by the position of their ``{name}`` placeholder
        within the operation's declared path so the returned list matches the
        left-to-right slot order of the URL. Returns an empty list when
        ``operation`` is ``None`` or declares no ``path`` parameter, which signals
        the caller to fall back to the existing regex-based ``ObjectIdentifier``
        inference (Requirement 53.2). No substitution mechanics are performed
        here; this method only selects WHICH declared slot(s) exist.
        """
        if operation is None:
            return []

        path_params = [
            param for param in getattr(operation, 'parameters', []) or []
            if getattr(param, 'location', None) == 'path'
        ]
        if not path_params:
            return []

        template = getattr(operation, 'path', '') or ''

        def _placeholder_pos(param) -> int:
            token = '{' + param.name + '}'
            pos = template.find(token)
            # Parameters that do not appear in the declared path sort after those
            # that do; ``sorted`` is stable so their relative order is preserved.
            return pos if pos != -1 else len(template) + 1

        return sorted(path_params, key=_placeholder_pos)

    def _identifier_from_spec(self, operation, endpoint: str,
                              slot_index: int = 0) -> Optional[ObjectIdentifier]:
        """Build an :class:`ObjectIdentifier` targeting a declared ``path`` slot.

        The returned identifier has ``location='path'``, ``parameter_name`` set to
        the declared parameter's name, and ``value`` set to the concrete value
        occupying that ``{param}`` position in ``endpoint`` (Requirement 53.1).
        Because the value is the exact concrete path segment, feeding the returned
        identifier to the EXISTING :meth:`_substitute_identifier` (unchanged) lands
        the candidate in precisely the declared slot while every other path segment
        and query parameter is preserved (Requirements 53.3, consistent with
        Requirement 1). For an operation declaring multiple ``path`` parameters,
        ``slot_index`` selects the single targeted slot; the values of the other
        declared slots are preserved (Requirement 53.4, consistent with the
        composite behavior of Requirement 29).

        Returns ``None`` when the operation declares no ``path`` parameter, when
        ``slot_index`` is out of range, or when the concrete value cannot be
        resolved from ``endpoint`` - in every such case the caller falls back to
        the existing regex-based inference (Requirement 53.2).
        """
        slots = self._spec_path_slots(operation)
        if not slots:
            return None
        if slot_index < 0 or slot_index >= len(slots):
            return None

        target = slots[slot_index]
        template = getattr(operation, 'path', '') or ''
        template_segments = template.split('/')
        token = '{' + target.name + '}'

        placeholder_index = None
        for idx, segment in enumerate(template_segments):
            if token in segment:
                placeholder_index = idx
                break
        if placeholder_index is None:
            return None

        concrete_segments = urlparse(endpoint).path.split('/')
        # Right-align the declared template against the concrete path so an
        # optional base prefix (e.g. ``/v1``) on the concrete endpoint is
        # tolerated; both share a leading empty segment when rooted at ``/``.
        offset = len(concrete_segments) - len(template_segments)
        if offset < 0:
            return None
        concrete_index = offset + placeholder_index
        if concrete_index < 0 or concrete_index >= len(concrete_segments):
            return None

        value = concrete_segments[concrete_index]
        if not value:
            return None

        return ObjectIdentifier(
            value=value,
            type=self._determine_id_type(value) or 'custom',
            endpoint=endpoint,
            parameter_name=target.name,
            location='path',
        )

    async def _get_negative_control(self, identifier: ObjectIdentifier,
                                    auth_context: Optional[AuthContext]) -> NegativeControlBaseline:
        """Return a cached Negative_Control_Baseline for ``(endpoint, auth_context)``.

        The baseline is built once per endpoint/context pair by requesting a
        known-invalid identifier under the same auth context, substituted into
        the correct path segment or query parameter (Requirements 3.1, 25.1).
        """
        context_key = auth_context.name if auth_context is not None else 'anonymous'
        cache_key = (identifier.endpoint, context_key)

        if cache_key not in self._baseline_cache:
            baseline = await self.build_negative_control(
                endpoint=identifier.endpoint,
                auth_context=auth_context,
                invalid_id="0",
                substitute=lambda cid: self._substitute_identifier(identifier, cid),
            )
            self._baseline_cache[cache_key] = baseline

        return self._baseline_cache[cache_key]

    def _object_belongs_to_context(self, candidate_fields: Dict[str, Any],
                                   own_fields: Dict[str, Any]) -> bool:
        """Decide whether an accessed object belongs to the requesting context.

        Compares the accessed object's Identifying_Field values against the
        requester's own object (Requirement 4.1). Owner-type fields
        (``user_id``/``owner_id``/``account_id``/``email``) are preferred; when
        none are comparable, the primary ``id`` identity is used. When the
        candidate exposes no recognized Identifying_Field, ownership cannot be
        disproved and the object is treated as belonging (no finding raised) to
        avoid identity-less false positives (Requirement 2.4, 4.4).
        """
        if not candidate_fields:
            return True

        owner_keys = [k for k in candidate_fields if k in self.OWNER_FIELD_NAMES]
        for key in owner_keys:
            if key in own_fields:
                return candidate_fields[key] == own_fields[key]

        if 'id' in candidate_fields and 'id' in own_fields:
            return candidate_fields['id'] == own_fields['id']

        # No comparable identifying field between the two objects.
        return True
    
    def _is_object_accessible(self, response: Response,
                              baseline: Optional[NegativeControlBaseline] = None) -> bool:
        """
        Determine if an object is genuinely accessible.

        Accessibility is calibrated against a Negative_Control_Baseline rather
        than a fixed response-size byte threshold (Requirement 3.5). When a
        baseline is supplied:

        * a non-discriminating baseline (the endpoint returns success for an
          invalid id) yields ``False`` so no accessibility finding is raised for
          it (Requirements 3.4, 25.3 - suppression/logging is handled by the
          caller);
        * otherwise the object is accessible when the candidate response is NOT
          equivalent to the baseline, i.e. it surfaces real, distinct
          identifying data (Requirements 3.2, 3.3, 25.2).

        When no baseline is available the method falls back to a conservative
        status-and-error-body check.

        Args:
            response: HTTP response to analyze
            baseline: Negative_Control_Baseline for the endpoint/context, if built

        Returns:
            True if object appears to be genuinely accessible, False otherwise
        """
        if response is None or response.status_code == 0:  # Request failed
            return False

        if baseline is not None:
            if baseline.non_discriminating:
                return False
            # Accessible when the candidate is NOT equivalent to the baseline.
            return not responses_equivalent(response, baseline)

        # Fallback (no negative-control available): status + error-body check.
        if 200 <= response.status_code < 400:
            if response.text:
                error_indicators = ['error', 'not found', 'unauthorized', 'forbidden', 'invalid']
                response_lower = response.text.lower()
                if any(indicator in response_lower for indicator in error_indicators):
                    return False
            return True

        return False

    def _responses_indicate_same_object(self, response1: Response, response2: Response) -> bool:
        """
        Check if two responses indicate access to the same object.

        Identity is decided by comparing recognized Identifying_Field values
        rather than response size or word similarity (Requirement 2). Returns
        ``True`` only when both responses expose a recognized Identifying_Field
        sharing an equal value; when no Identifying_Field is extractable the
        result is ``False`` so no finding is raised on size alone (Requirement
        2.4).
        """
        same, _field_name, _value = responses_identify_same_object(response1, response2)
        return same

    # ------------------------------------------------------------------
    # Destructive safety guardrails + dry-run (Requirement 28)
    # ------------------------------------------------------------------

    def _destructive_allowed(self) -> bool:
        """Return True only when a Destructive_Probe may be issued.

        A probe that changes server state is permitted only when BOTH Safe_Mode
        is disabled AND the Destructive_Opt_In (``config.allow_destructive``) is
        present (Requirements 28.1, 28.2, 28.3). The gate is fail-closed:
        destructive probing is disabled by default because
        ``config.allow_destructive`` defaults to ``False`` (Requirement 28.1).
        """
        return (not self.safe_mode) and bool(
            getattr(self.config, "allow_destructive", False)
        )

    def _select_write_method(self) -> Optional[str]:
        """Pick the least-destructive configured State_Changing_Method.

        Selection prefers ``PATCH`` over ``PUT`` over ``POST`` and NEVER returns
        ``DELETE`` unless ``DELETE`` is explicitly included in
        ``config.destructive_methods`` (Requirement 28.4). The returned method is
        always a member of the configured set, so a method absent from the set is
        never issued. Returns ``None`` when no write method is configured (a
        controlled skip, never an issued request).
        """
        configured = {
            str(m).upper() for m in getattr(self.config, "destructive_methods", set())
        }
        for method in ("PATCH", "PUT", "POST"):
            if method in configured:
                return method
        if "DELETE" in configured:  # only when explicitly opted in
            return "DELETE"
        return None

    def _dry_run_record(self, method: str, url: str, substituted_id: Any,
                        body: Optional[Any] = None) -> Dict[str, Any]:
        """Record an intended Destructive_Probe WITHOUT issuing the request.

        When Dry_Run is enabled, each state-changing probe the module would
        otherwise issue is captured as a report-only record of its method, target
        URL, substituted identifier, and intended body, and NO HTTP request is
        made (Requirement 28.6). The record is appended to ``self._dry_run_records``
        and also logged so the operator can see exactly what would have been sent.
        """
        record = {
            "method": str(method).upper(),
            "url": url,
            "substituted_id": str(substituted_id) if substituted_id is not None else None,
            "body": body,
        }
        self._dry_run_records.append(record)
        self.logger.info("Dry-run: destructive BOLA probe recorded (not issued)",
                         method=record["method"],
                         url=url,
                         substituted_id=record["substituted_id"])
        return record

    async def _issue_guarded_write_probe(self, url: str, substituted_id: Any,
                                         body: Optional[Any] = None,
                                         test_name: str = "write_bola") -> Optional[Response]:
        """Issue a single State_Changing_Method_Probe through the destructive guardrails.

        This is the single choke point every advanced state-changing BOLA probe
        (write BOLA, chained state manipulation, verb tampering, composite, and
        ID-leakage write probes) routes through before any request is issued.
        The request is sent ONLY when all guardrails permit it; otherwise the
        method returns ``None`` and NO request reaches the HTTP engine:

        * the destructive gate must allow it - Safe_Mode off AND the
          Destructive_Opt_In present (Requirements 28.2, 28.3);
        * a write method must be configured (``_select_write_method`` is not
          ``None``);
        * the Safe_Mode guard (``skip_if_state_changing``) must not veto it
          (belt-and-suspenders with the gate, Requirement 21.3);
        * Dry_Run must be off - when on, the probe is recorded via
          :meth:`_dry_run_record` and no request is issued (Requirement 28.6).

        When permitted, a log entry records the method, target URL, and
        substituted identifier of the probe (Requirement 28.5).
        """
        method = self._select_write_method()
        if method is None or not self._destructive_allowed():
            self.logger.info("Skipping destructive BOLA probe",
                             reason="opt-in absent, safe mode, or no write method",
                             test=test_name,
                             url=url)
            return None

        # Belt-and-suspenders Safe_Mode check: never issue a State_Changing_Method
        # while Safe_Mode is enabled, even if the gate above somehow allowed it.
        if self.skip_if_state_changing(method, test_name):
            return None

        if getattr(self.config, "dry_run", False):
            self._dry_run_record(method, url, substituted_id, body)
            return None

        self.logger.info("Issuing destructive BOLA probe",
                         method=method,
                         url=url,
                         substituted_id=str(substituted_id))
        return await self.http_client.request(method, url, json=body)

    # ------------------------------------------------------------------
    # Write-method BOLA + persistence verification (Requirement 27)
    # ------------------------------------------------------------------

    # Credential-class field names (lowercased) whose persisted mutation on a
    # foreign object constitutes account takeover rather than mere write
    # escalation (Requirement 27.4).
    CREDENTIAL_FIELD_NAMES = {
        "email", "password", "passwd", "secret",
        "api_key", "apikey", "token", "credential",
    }

    def _is_credential_field(self, field: str) -> bool:
        """Return True for email/password/credential-class fields (Req 27.4).

        A persisted mutation to one of these fields on a foreign object is
        classified as ``BOLA_ACCOUNT_TAKEOVER``; any other persisted mutation on
        a foreign object is a ``BOLA_WRITE_ESCALATION`` (Req 27.5).
        """
        if not isinstance(field, str):
            return False
        return field.lower() in self.CREDENTIAL_FIELD_NAMES

    def _classify_write_outcome(self, field: str, victim_fields: Dict[str, Any],
                                own_fields: Dict[str, Any]) -> Optional[str]:
        """Classify a persisted mutation on the target object (Reqs 27.4, 27.5).

        Foreign ownership is decided via the existing
        :meth:`_object_belongs_to_context` (Identifying_Field comparison,
        Requirement 2), so no new ownership logic is introduced. Returns:

        * ``'BOLA_ACCOUNT_TAKEOVER'`` when the persisted field is a credential
          field on an object belonging to a DIFFERENT Auth_Context (Req 27.4);
        * ``'BOLA_WRITE_ESCALATION'`` when a non-credential field is persisted on
          a foreign object (Req 27.5);
        * ``None`` when the object belongs to the requesting context, so no
          finding is raised (Req 27.3 ownership guard).
        """
        # _object_belongs_to_context returns True when the object belongs to the
        # requesting context (own object) -> no finding.
        if self._object_belongs_to_context(victim_fields, own_fields):
            return None

        if self._is_credential_field(field):
            return "BOLA_ACCOUNT_TAKEOVER"
        return "BOLA_WRITE_ESCALATION"

    # ------------------------------------------------------------------
    # Evidence chain, confidence scoring, and secret redaction (Req 33)
    # ------------------------------------------------------------------

    # Field-name keywords (lowercased, substring-matched) that denote a
    # credential/secret VALUE. When such a name keys a value in a response
    # snippet, the value is redacted regardless of its shape (Req 33.3).
    SECRET_FIELD_KEYWORDS = (
        'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key',
        'api-key', 'accesskey', 'access_key', 'access-key', 'access_token',
        'refresh_token', 'private_key', 'privatekey', 'client_secret',
        'clientsecret', 'authorization', 'credential', 'session_token',
        'sessionid', 'session_id', 'auth_token', 'bearer',
    )

    # Known credential token prefixes: a value carrying one of these prefixes is
    # self-sufficient evidence of an exposed secret (mirrors the Property_Module
    # discipline, Req 12.2 / Req 33.3).
    CREDENTIAL_PREFIXES = ('sk_', 'pk_', 'AKIA', 'ghp_', 'xoxb-')

    # Minimum Shannon entropy (bits/char) to treat an otherwise unremarkable
    # long/base64-shaped token as a genuine random secret rather than a slug or
    # predictable identifier (corroboration, mirrors the Property_Module).
    CREDENTIAL_ENTROPY_THRESHOLD = 3.5

    # Marker substituted for any redacted secret value.
    REDACTION_MARKER = '<redacted>'

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        """Compute the Shannon entropy (bits per character) of ``value``."""
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

    def _token_is_secret(self, token: str) -> bool:
        """Corroboration-based test for whether a bare token is a secret value.

        Mirrors the Property_Module's ``_contains_sensitive_data`` discipline
        (Req 12.2): self-sufficient patterns (SSN, credit card, ``sk_`` keys) and
        known credential prefixes are sufficient on their own; a generic long
        alphanumeric / base64-shaped blob is necessary-but-not-sufficient and is
        only treated as a secret when corroborated by high Shannon entropy
        (Req 33.3).
        """
        if not isinstance(token, str) or len(token) < 8:
            return False

        # Self-sufficient patterns.
        sufficient_patterns = (
            r'^\d{3}-\d{2}-\d{4}$',                              # SSN
            r'^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$',         # Credit card
            r'^sk_[a-zA-Z0-9]{20,}$',                            # Stripe-style key
        )
        for pattern in sufficient_patterns:
            if re.fullmatch(pattern, token):
                return True

        # A known credential prefix is self-sufficient evidence.
        if any(token.startswith(prefix) for prefix in self.CREDENTIAL_PREFIXES):
            return True

        # Credential-SHAPE: long alphanumeric or base64-shaped blob. Necessary
        # but not sufficient - require high-entropy corroboration.
        credential_shape = (
            re.fullmatch(r'[A-Za-z0-9]{32,}', token)
            or re.fullmatch(r'[A-Za-z0-9+/]{20,}={0,2}', token)
            or re.fullmatch(r'[A-Za-z0-9._-]{32,}', token)   # JWT / dotted tokens
        )
        if not credential_shape:
            return False

        return self._shannon_entropy(token) >= self.CREDENTIAL_ENTROPY_THRESHOLD

    def redact_secrets(self, snippet: str) -> str:
        """Redact credential values within an Evidence_Chain response snippet.

        Passwords, tokens, API keys, and long high-entropy secrets are replaced
        with ``<redacted>`` so a full secret value is never echoed into a finding
        or report (Req 33.3). Reuses the corroboration-based credential-pattern
        discipline mirrored from the Property_Module's ``_contains_sensitive_data``
        (Req 12.2): the value of any credential-named field is always redacted,
        while a bare token is redacted only when it is self-sufficient evidence
        (credential prefix / structured secret) or a credential-shaped blob
        corroborated by high entropy.
        """
        if not snippet or not isinstance(snippet, str):
            return snippet

        text = snippet
        marker = self.REDACTION_MARKER
        keyword_alt = '|'.join(re.escape(k) for k in self.SECRET_FIELD_KEYWORDS)

        # 1. JSON-style credential-named field: "password": "value" (value may be
        #    a quoted string or a bare literal). The value is always redacted.
        text = re.sub(
            r'("(?:[A-Za-z0-9_.\-]*(?:' + keyword_alt + r')[A-Za-z0-9_.\-]*)"\s*:\s*)'
            r'"[^"]*"',
            lambda m: m.group(1) + '"' + marker + '"',
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r'("(?:[A-Za-z0-9_.\-]*(?:' + keyword_alt + r')[A-Za-z0-9_.\-]*)"\s*:\s*)'
            r'(?!")([^\s,}\]]+)',
            lambda m: m.group(1) + '"' + marker + '"',
            text,
            flags=re.IGNORECASE,
        )

        # 2. key=value credential-named field (query string / form / header):
        #    password=value, Authorization: Bearer value.
        text = re.sub(
            r'((?:' + keyword_alt + r')\s*[=:]\s*)(?:Bearer\s+)?([^\s,&;"}\]]+)',
            lambda m: m.group(1) + marker,
            text,
            flags=re.IGNORECASE,
        )

        # 3. Bare secret tokens anywhere in the snippet (credential prefixes,
        #    structured secrets, or high-entropy blobs), corroboration-based.
        def _redact_token(match: 're.Match') -> str:
            token = match.group(0)
            return marker if self._token_is_secret(token) else token

        text = re.sub(r'[A-Za-z0-9+/._-]{8,}={0,2}', _redact_token, text)

        return text

    def _score_confidence(self, *, persisted: bool, baseline_discriminating: bool,
                          identity_matched: bool) -> str:
        """Derive a Confidence_Score from the strength of the evidence (Req 33.2).

        A persisted mutation observed against a discriminating
        Negative_Control_Baseline with a confirmed Identifying_Field identity
        match is the strongest evidence => ``'high'``. Two of the three signals
        => ``'medium'``; anything weaker => ``'low'``.
        """
        signals = sum(
            1 for present in (persisted, baseline_discriminating, identity_matched)
            if present
        )
        if signals >= 3:
            return 'high'
        if signals == 2:
            return 'medium'
        return 'low'

    def _build_evidence_chain(self, *, method: str, endpoint: str,
                              original_id: Any, substituted_id: Any,
                              auth_context: Optional[str],
                              baseline_comparison: str,
                              response_snippet: Optional[str],
                              confidence: str) -> EvidenceChain:
        """Build an :class:`EvidenceChain` for an advanced BOLA finding (Req 33.1).

        The response snippet is ALWAYS passed through :meth:`redact_secrets`
        before being stored, so a redaction gap can never leak a secret into a
        report (Req 33.3). The Auth_Context NAME is recorded, never the token
        (Req 33.1).
        """
        parsed = urlparse(endpoint)
        request_target = parsed.path or endpoint
        if parsed.query:
            request_target = f"{request_target}?{parsed.query}"
        request_line = f"{method} {request_target} HTTP/1.1"

        redacted_snippet = self.redact_secrets(response_snippet or "")

        return EvidenceChain(
            request_line=request_line,
            method=method,
            original_id=str(original_id),
            substituted_id=str(substituted_id),
            auth_context=(auth_context or 'anonymous'),
            baseline_comparison=baseline_comparison,
            response_snippet=redacted_snippet,
            confidence=confidence,
        )

    def _field_value_reflected(self, response: Optional[Response],
                               field: str, value: Any) -> bool:
        """Return True when ``field`` is present in the response body with ``value``.

        The JSON body is parsed and searched at the top level (or the first
        object inside a top-level list, mirroring
        :func:`extract_identifying_fields`). The comparison is scalar and
        case-insensitive on the key; the value is compared directly and, as a
        fallback, by string form so that a reflected ``"1"`` matches a submitted
        ``1``. Non-JSON / unparseable bodies degrade to ``False`` rather than
        raising (Requirement 27.2).
        """
        if response is None or not getattr(response, "text", None):
            return False
        try:
            body = json.loads(response.text)
        except (ValueError, TypeError):
            return False

        obj: Optional[Dict[str, Any]] = None
        if isinstance(body, dict):
            obj = body
        elif isinstance(body, list):
            for item in body:
                if isinstance(item, dict):
                    obj = item
                    break
        if not isinstance(obj, dict):
            return False

        target = field.lower() if isinstance(field, str) else field
        for key, reflected in obj.items():
            if isinstance(key, str) and key.lower() == target:
                return self._scalar_value_equal(reflected, value)
        return False

    @staticmethod
    def _scalar_value_equal(a: Any, b: Any) -> bool:
        """Compare two scalar values, treating booleans as distinct from ints.

        Direct equality is tried first; when that fails, a string-form
        comparison catches type-crossing reflections (e.g. an integer submitted
        and returned as a JSON string). Booleans never compare equal to numbers.
        """
        if isinstance(a, bool) != isinstance(b, bool):
            return False
        if a == b:
            return True
        try:
            return str(a) == str(b)
        except Exception:
            return False

    async def _verify_persistence(self, endpoint: str, field: str, value: Any,
                                  auth_context: Optional[AuthContext]
                                  ) -> Tuple[bool, Optional[Response]]:
        """Persistence_Verification of a write probe (Reqs 27.2, 27.3).

        Issue a SAFE ``GET`` re-read of the target object (always a Safe_Method,
        so it is issued even when destructive writes are gated), parse it, and
        confirm the submitted mutation persisted by checking BOTH that the exact
        field/value is reflected AND that the object's Identifying_Field still
        resolves (reusing :func:`extract_identifying_fields`). Success is
        determined solely by persistence, never by the write response status
        code (Req 27.2).

        Returns ``(persisted, reread_response)``. ``persisted`` is ``False`` when
        the re-read does not reflect the mutation (Req 27.3) or when the object
        no longer resolves.
        """
        if auth_context is not None:
            self.http_client.set_auth_context(auth_context)

        reread = await self.http_client.request("GET", endpoint)

        if reread is None or not (200 <= reread.status_code < 300):
            return False, reread

        # The object must still resolve to a recognized Identifying_Field, and
        # the submitted mutation must be reflected in the re-read.
        identifying = extract_identifying_fields(reread)
        persisted = bool(identifying) and self._field_value_reflected(reread, field, value)
        return persisted, reread

    def _build_write_candidates(self, response: Optional[Response]
                                ) -> Dict[str, Any]:
        """Derive mutable candidate fields and mutation values from an object body.

        The victim object's currently exposed scalar fields become the candidate
        set (only fields visible on a Safe_Method re-read can be persistence
        verified). The primary ``id`` field is skipped because mutating it would
        change object identity rather than exercise object-level authorization.
        Each candidate maps to a clearly attacker-controlled mutation value so a
        successful write is unambiguous evidence.
        """
        candidates: Dict[str, Any] = {}
        if response is None or not getattr(response, "text", None):
            return candidates
        try:
            body = json.loads(response.text)
        except (ValueError, TypeError):
            return candidates

        obj: Optional[Dict[str, Any]] = None
        if isinstance(body, dict):
            obj = body
        elif isinstance(body, list):
            for item in body:
                if isinstance(item, dict):
                    obj = item
                    break
        if not isinstance(obj, dict):
            return candidates

        for key, current in obj.items():
            if not isinstance(key, str):
                continue
            if key.lower() == "id":
                continue
            if current is None or isinstance(current, (dict, list)):
                continue
            candidates[key] = self._generate_write_mutation(key, current)
        return candidates

    def _generate_write_mutation(self, field: str, current: Any) -> Any:
        """Produce an attacker-controlled mutation value for ``field``.

        Values are chosen to be clearly distinct from the current value so a
        persisted change is unambiguous. Credential fields receive
        attacker-controlled credentials (the account-takeover payload); numeric
        and boolean fields are altered by type; everything else gets a marked
        string.
        """
        lname = field.lower()
        if lname == "email":
            return "attacker.bola@evil.example"
        if self._is_credential_field(field):
            return "bola-takeover-value"
        if isinstance(current, bool):
            return not current
        if isinstance(current, (int, float)):
            return current + 1
        return f"bola-mutated-{field}"

    async def _test_write_bola(self, identifier: ObjectIdentifier, victim_id: str,
                               contexts: List[AuthContext]) -> List[Finding]:
        """Write_BOLA against a victim object with persistence verification (Req 27).

        Gated by :meth:`_destructive_allowed` and Safe_Mode: no
        State_Changing_Method_Probe is issued unless Safe_Mode is off AND the
        Destructive_Opt_In is present (Reqs 27.1, 28.2, 28.3). Every write is
        routed through :meth:`_issue_guarded_write_probe`, so Dry_Run records the
        intent without issuing a request (Req 28.6).

        For each mutable candidate field on the victim object, the field is
        mutated via the selected least-destructive write method against the
        substituted victim URL (reusing :meth:`_substitute_identifier`, so every
        other request component is preserved - Req 27.1), then re-read with a
        Safe_Method to confirm persistence (Req 27.2). A persisted mutation on a
        foreign object is classified as ``BOLA_ACCOUNT_TAKEOVER`` (credential
        field, Req 27.4) or ``BOLA_WRITE_ESCALATION`` (non-credential, Req 27.5);
        no finding is raised when the object belongs to the requesting context
        or the mutation does not persist (Req 27.3).
        """
        findings: List[Finding] = []

        # Gate 1: the destructive gate must permit state-changing probing.
        if not self._destructive_allowed():
            self.logger.info(
                "Skipping write BOLA: destructive probing not permitted",
                reason="opt-in absent or safe mode",
                endpoint=identifier.endpoint,
            )
            return findings

        method = self._select_write_method()
        if method is None:
            self.logger.info(
                "Skipping write BOLA: no write method configured",
                endpoint=identifier.endpoint,
            )
            return findings

        requesting_context = contexts[0] if contexts else None

        # When a Spec_Schema is threaded in and declares an operation for this
        # (endpoint, method), start the mutation body from a schema-valid
        # Typed_Payload so the write passes input validation and the mutated
        # field reaches the target logic (Reqs 52.1, 56.3). When no schema or no
        # matching operation is available, the existing minimal body is used
        # unchanged (Req 52.6). This is data only; the destructive gate and
        # Safe_Mode (both checked above) still decide whether it is ever issued
        # (Reqs 52.4, 52.5, 56.4, 56.5).
        write_operation = None
        if self.spec_schema is not None:
            try:
                write_operation = self.spec_schema.operation_for(
                    identifier.endpoint, method
                )
            except Exception:
                write_operation = None

        # Build the requester's-own and victim URLs by reusing the shared
        # substitution helper (preserves every other request component).
        own_url = self._substitute_identifier(identifier, identifier.value)
        victim_url = self._substitute_identifier(identifier, victim_id)

        try:
            # Establish the requester's own Identifying_Fields for the ownership
            # comparison in _classify_write_outcome.
            if requesting_context is not None:
                self.http_client.set_auth_context(requesting_context)
            own_response = await self.http_client.request("GET", own_url)
            own_fields = extract_identifying_fields(own_response)

            # Discover mutable candidate fields from the victim object (Safe GET).
            victim_response = await self.http_client.request("GET", victim_url)
            candidate_fields = self._build_write_candidates(victim_response)

            if not candidate_fields:
                self.logger.info(
                    "Write BOLA found no mutable candidate fields",
                    endpoint=identifier.endpoint,
                    substituted_id=str(victim_id),
                )
                return findings

            for field, mutated_value in candidate_fields.items():
                if write_operation is not None:
                    # Schema present: start from a schema-valid Typed_Payload and
                    # inject the mutated field on top (Reqs 52.1, 52.5).
                    body = build_typed_payload(
                        write_operation, overrides={field: mutated_value}
                    )
                else:
                    body = {field: mutated_value}

                # Overlay any Actor_Profile per-endpoint body values for the
                # requesting Auth_Context on top of the typed base, profile
                # values taking precedence (Requirement 54.2). Absent profile or
                # endpoint leaves the body unchanged (Requirements 54.3, 54.4).
                _, body = apply_actor_profile(
                    requesting_context, identifier.endpoint, body=body
                )

                # Issue the write through the single destructive choke point.
                write_response = await self._issue_guarded_write_probe(
                    victim_url, victim_id, body=body, test_name="write_bola"
                )
                if write_response is None:
                    # Skipped (gate/safe-mode) or recorded (dry-run): no request.
                    continue

                # Success is determined solely by persistence (Req 27.2, 27.3).
                persisted, reread = await self._verify_persistence(
                    victim_url, field, mutated_value, requesting_context
                )
                if not persisted:
                    self.logger.debug(
                        "Write BOLA probe did not persist",
                        endpoint=identifier.endpoint,
                        field=field,
                        substituted_id=str(victim_id),
                    )
                    continue

                victim_fields = extract_identifying_fields(reread)
                category = self._classify_write_outcome(field, victim_fields, own_fields)
                if category is None:
                    # Object belongs to the requesting context -> no finding.
                    continue

                findings.append(
                    self._build_write_finding(
                        identifier=identifier,
                        victim_id=victim_id,
                        field=field,
                        mutated_value=mutated_value,
                        method=method,
                        category=category,
                        write_response=write_response,
                        reread=reread,
                        victim_fields=victim_fields,
                        requesting_context=requesting_context,
                    )
                )

                self.logger.warning(
                    "Write-method BOLA detected",
                    category=category,
                    endpoint=identifier.endpoint,
                    field=field,
                    original_id=identifier.value,
                    substituted_id=str(victim_id),
                )

        except Exception as e:
            self.logger.debug(
                "Write BOLA test failed",
                endpoint=identifier.endpoint,
                substituted_id=str(victim_id),
                error=str(e),
            )

        return findings

    def _build_write_finding(self, identifier: ObjectIdentifier, victim_id: str,
                             field: str, mutated_value: Any, method: str,
                             category: str, write_response: Response,
                             reread: Optional[Response],
                             victim_fields: Dict[str, Any],
                             requesting_context: Optional[AuthContext] = None) -> Finding:
        """Assemble a Write_BOLA Finding with the Req 27.6 evidence.

        Evidence includes the mutated field name, the original and substituted
        identifiers, and the Persistence_Verification evidence. Credential values
        are redacted so the finding never echoes a submitted secret. A redacted
        Evidence_Chain and Confidence_Score are attached (Req 33.1, 33.2, 33.3).
        """
        severity = (Severity.CRITICAL if category == "BOLA_ACCOUNT_TAKEOVER"
                    else Severity.HIGH)

        submitted_display = ("<redacted>" if self._is_credential_field(field)
                             else repr(mutated_value))

        owner_field = next(iter(victim_fields.items()), None)
        reread_status = reread.status_code if reread is not None else None

        evidence = (
            f"Write-method BOLA ({category}): field '{field}' was mutated via a "
            f"{method} probe on a foreign object and persisted. Original id "
            f"{identifier.value!r} substituted with {victim_id!r}. Submitted "
            f"value: {submitted_display}. Persistence verified by a safe GET "
            f"re-read (status {reread_status}, field present) on an object whose "
            f"identifying field {owner_field!r} indicates a different auth "
            f"context."
        )

        recommendation = (
            "Enforce object-level authorization on state-changing methods: verify "
            "the authenticated principal owns the target object before applying "
            "any mutation, and reject writes to objects owned by other users."
        )

        response_snippet = (reread.text[:500] if reread is not None and reread.text
                            else None)

        identity_matched = bool(victim_fields)
        confidence = self._score_confidence(
            persisted=True,
            baseline_discriminating=reread is not None,
            identity_matched=identity_matched,
        )
        evidence_chain = self._build_evidence_chain(
            method=method,
            endpoint=identifier.endpoint,
            original_id=identifier.value,
            substituted_id=victim_id,
            auth_context=(requesting_context.name if requesting_context else None),
            baseline_comparison=(
                f"Persistence confirmed via safe GET re-read (status "
                f"{reread_status}); foreign ownership established via "
                f"Identifying_Field comparison ({owner_field!r})."
            ),
            response_snippet=response_snippet,
            confidence=confidence,
        )

        return Finding(
            id=str(uuid.uuid4()),
            scan_id="",
            category=category,
            owasp_category="API1",
            severity=severity,
            endpoint=identifier.endpoint,
            method=method,
            status_code=write_response.status_code,
            response_size=len(write_response.content) if write_response.content else 0,
            response_time=write_response.elapsed,
            evidence=evidence,
            recommendation=recommendation,
            payload=str(victim_id),
            response_snippet=response_snippet,
            evidence_chain=evidence_chain,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Chained state manipulation / mass assignment (Requirement 32)
    # ------------------------------------------------------------------

    # Privileged / state-transition fields whose injection into a victim-object
    # write attempts to elevate privilege or force an unauthorized state
    # transition (Requirement 32.1). Each maps to a clearly attacker-controlled
    # target value so a persisted change is unambiguous evidence of a successful
    # state manipulation.
    PRIVILEGED_INJECTION_FIELDS: Dict[str, Any] = {
        "role": "admin",
        "roles": "admin",
        "is_admin": True,
        "admin": True,
        "is_staff": True,
        "is_superuser": True,
        "superuser": True,
        "privilege_level": 99,
        "permissions": "all",
        "status": "approved",
        "state": "active",
        "account_status": "active",
        "approved": True,
        "verified": True,
        "is_verified": True,
        "enabled": True,
    }

    @staticmethod
    def _chained_probe_successful(unauthorized_access_confirmed: bool,
                                  injected_value_persisted: bool) -> bool:
        """Decide chained-probe success (Requirements 32.2, 32.3).

        A chained state-manipulation probe is successful IF AND ONLY IF BOTH the
        unauthorized access to the victim object AND the persistence of the
        injected privileged/state-transition value are confirmed. If either is
        unconfirmed the probe is unsuccessful (Requirement 32.3).
        """
        return bool(unauthorized_access_confirmed and injected_value_persisted)

    def _privileged_injection_candidates(self, victim_response: Optional[Response]
                                         ) -> Dict[str, Any]:
        """Select privileged/state-transition fields to inject (Requirement 32.1).

        Every field in :data:`PRIVILEGED_INJECTION_FIELDS` is a candidate. When a
        field is already present in the victim object with a value equal to its
        injection target it is skipped (there is nothing to change, so a "persisted"
        reflection would be meaningless). The victim body is parsed best-effort;
        an unparseable body simply yields the full catalog.
        """
        candidates = dict(self.PRIVILEGED_INJECTION_FIELDS)

        current: Dict[str, Any] = {}
        text = getattr(victim_response, "text", None) if victim_response else None
        if text:
            try:
                body = json.loads(text)
            except (ValueError, TypeError):
                body = None
            obj: Optional[Dict[str, Any]] = None
            if isinstance(body, dict):
                obj = body
            elif isinstance(body, list):
                for item in body:
                    if isinstance(item, dict):
                        obj = item
                        break
            if isinstance(obj, dict):
                current = {k.lower(): v for k, v in obj.items()
                           if isinstance(k, str)}

        return {
            field: value
            for field, value in candidates.items()
            if not (field in current and self._scalar_value_equal(current[field], value))
        }

    async def _test_chained_state_manipulation(
        self, identifier: ObjectIdentifier, victim_id: str,
        contexts: List[AuthContext]
    ) -> List[Finding]:
        """Chain a victim-object Write_BOLA with privileged-field injection (Req 32).

        Combines a state-changing write against a FOREIGN victim object with the
        injection of a privileged or state-transition field into the request body
        (Requirement 32.1), then verifies BOTH:

        * unauthorized access to the victim object - the object is accessible
          under the requesting context AND its Identifying_Field shows it belongs
          to a DIFFERENT Auth_Context (reusing :meth:`_is_object_accessible`
          calibrated against a Negative_Control_Baseline and
          :meth:`_object_belongs_to_context`); and
        * persistence of the injected value - a safe ``GET`` re-read reflects the
          exact injected value (reusing :meth:`_verify_persistence`, the same
          Persistence_Verification approach as Requirements 10 and 27).

        The probe is successful only when BOTH are confirmed (Requirements 32.2,
        32.3); such a case is reported as a ``BOLA_STATE_MANIPULATION`` finding
        whose OWASP_Category is ``API1`` (within the required set {API1, API3},
        Requirement 32.4). Every write is routed through
        :meth:`_issue_guarded_write_probe`, so the destructive guardrails from
        Task 16 apply: no State_Changing_Method_Probe is issued unless Safe_Mode
        is off AND the Destructive_Opt_In is present, and Dry_Run records the
        intent without issuing a request (Requirements 32.1, 28.2, 28.3, 28.6).
        """
        findings: List[Finding] = []

        # Gate 1: the destructive gate must permit state-changing probing
        # (Safe_Mode off AND Destructive_Opt_In present).
        if not self._destructive_allowed():
            self.logger.info(
                "Skipping chained state manipulation: destructive probing not permitted",
                reason="opt-in absent or safe mode",
                endpoint=identifier.endpoint,
            )
            return findings

        method = self._select_write_method()
        if method is None:
            self.logger.info(
                "Skipping chained state manipulation: no write method configured",
                endpoint=identifier.endpoint,
            )
            return findings

        requesting_context = contexts[0] if contexts else None

        # Reuse the shared substitution helper so every other request component
        # is preserved (Requirement 32.1).
        own_url = self._substitute_identifier(identifier, identifier.value)
        victim_url = self._substitute_identifier(identifier, victim_id)

        try:
            # Establish the requester's own Identifying_Fields for the foreign
            # ownership comparison.
            if requesting_context is not None:
                self.http_client.set_auth_context(requesting_context)
            own_response = await self.http_client.request("GET", own_url)
            own_fields = extract_identifying_fields(own_response)

            # Calibrate accessibility against a Negative_Control_Baseline built
            # under the same auth context (Requirement 3, reused here).
            baseline = await self._get_negative_control(identifier, requesting_context)

            # Re-assert the requesting context for the real probe (the baseline
            # build may have changed the active auth context).
            if requesting_context is not None:
                self.http_client.set_auth_context(requesting_context)

            # Confirm unauthorized access to the victim object: accessible AND
            # foreign (belongs to a different Auth_Context).
            victim_response = await self.http_client.request("GET", victim_url)
            victim_fields = extract_identifying_fields(victim_response)
            unauthorized_access_confirmed = (
                self._is_object_accessible(victim_response, baseline)
                and not self._object_belongs_to_context(victim_fields, own_fields)
            )

            injection_candidates = self._privileged_injection_candidates(victim_response)
            if not injection_candidates:
                self.logger.info(
                    "Chained state manipulation found no privileged fields to inject",
                    endpoint=identifier.endpoint,
                    substituted_id=str(victim_id),
                )
                return findings

            for field, injected_value in injection_candidates.items():
                body = {field: injected_value}

                # Issue the state-changing write through the single destructive
                # choke point (gate + Safe_Mode + Dry_Run all enforced there).
                write_response = await self._issue_guarded_write_probe(
                    victim_url, victim_id, body=body,
                    test_name="chained_state_manipulation",
                )
                if write_response is None:
                    # Skipped (gate/safe-mode) or recorded (dry-run): no request.
                    continue

                # Persistence of the injected state-transition value (Req 32.2).
                injected_value_persisted, reread = await self._verify_persistence(
                    victim_url, field, injected_value, requesting_context
                )

                # Success requires BOTH unauthorized access AND persistence
                # (Requirements 32.2, 32.3).
                if not self._chained_probe_successful(
                    unauthorized_access_confirmed, injected_value_persisted
                ):
                    self.logger.debug(
                        "Chained state manipulation probe unsuccessful",
                        endpoint=identifier.endpoint,
                        field=field,
                        substituted_id=str(victim_id),
                        unauthorized_access_confirmed=unauthorized_access_confirmed,
                        injected_value_persisted=injected_value_persisted,
                    )
                    continue

                findings.append(
                    self._build_chained_finding(
                        identifier=identifier,
                        victim_id=victim_id,
                        field=field,
                        injected_value=injected_value,
                        method=method,
                        write_response=write_response,
                        victim_response=victim_response,
                        reread=reread,
                        victim_fields=victim_fields,
                        requesting_context=requesting_context,
                    )
                )

                self.logger.warning(
                    "Chained state-manipulation BOLA detected",
                    category="BOLA_STATE_MANIPULATION",
                    endpoint=identifier.endpoint,
                    field=field,
                    original_id=identifier.value,
                    substituted_id=str(victim_id),
                )

        except Exception as e:
            self.logger.debug(
                "Chained state manipulation test failed",
                endpoint=identifier.endpoint,
                substituted_id=str(victim_id),
                error=str(e),
            )

        return findings

    def _build_chained_finding(self, identifier: ObjectIdentifier, victim_id: str,
                               field: str, injected_value: Any, method: str,
                               write_response: Response,
                               victim_response: Optional[Response],
                               reread: Optional[Response],
                               victim_fields: Dict[str, Any],
                               requesting_context: Optional[AuthContext] = None) -> Finding:
        """Assemble a ``BOLA_STATE_MANIPULATION`` Finding (Requirements 32.4, 32.5).

        Evidence includes the injected privileged field name, the substituted
        identifier, and the Persistence_Verification evidence for BOTH the
        unauthorized access (the accessible foreign object read) and the state
        transition (the injected value reflected in the safe re-read). Credential
        values are redacted so the finding never echoes a submitted secret. A
        redacted Evidence_Chain and Confidence_Score are attached (Req 33).
        """
        injected_display = ("<redacted>" if self._is_credential_field(field)
                            else repr(injected_value))

        owner_field = next(iter(victim_fields.items()), None)
        access_status = (victim_response.status_code
                         if victim_response is not None else None)
        reread_status = reread.status_code if reread is not None else None

        evidence = (
            f"Chained state manipulation (BOLA_STATE_MANIPULATION): a "
            f"{method} probe against a foreign victim object injected the "
            f"privileged/state-transition field '{field}' (value "
            f"{injected_display}) which then persisted. Original id "
            f"{identifier.value!r} substituted with {victim_id!r}. Unauthorized "
            f"access confirmed by a safe GET (status {access_status}) on an "
            f"object whose identifying field {owner_field!r} indicates a "
            f"different auth context; state transition confirmed by a safe GET "
            f"re-read (status {reread_status}) reflecting the injected value."
        )

        recommendation = (
            "Enforce object-level authorization on state-changing methods AND "
            "reject client-supplied privileged/state-transition fields "
            "(mass-assignment protection): allow-list writable fields, verify the "
            "authenticated principal owns the target object, and gate state "
            "transitions through server-side authorization checks."
        )

        response_snippet = (reread.text[:500] if reread is not None and reread.text
                            else None)

        confidence = self._score_confidence(
            persisted=True,
            baseline_discriminating=victim_response is not None,
            identity_matched=bool(victim_fields),
        )
        evidence_chain = self._build_evidence_chain(
            method=method,
            endpoint=identifier.endpoint,
            original_id=identifier.value,
            substituted_id=victim_id,
            auth_context=(requesting_context.name if requesting_context else None),
            baseline_comparison=(
                f"Unauthorized access confirmed via safe GET (status "
                f"{access_status}); injected value persistence confirmed via safe "
                f"GET re-read (status {reread_status}); foreign ownership via "
                f"Identifying_Field comparison ({owner_field!r})."
            ),
            response_snippet=response_snippet,
            confidence=confidence,
        )

        return Finding(
            id=str(uuid.uuid4()),
            scan_id="",
            category="BOLA_STATE_MANIPULATION",
            owasp_category="API1",
            severity=Severity.CRITICAL,
            endpoint=identifier.endpoint,
            method=method,
            status_code=write_response.status_code,
            response_size=len(write_response.content) if write_response.content else 0,
            response_time=write_response.elapsed,
            evidence=evidence,
            recommendation=recommendation,
            payload=str(victim_id),
            response_snippet=response_snippet,
            evidence_chain=evidence_chain,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Composite / multi-tenant / hierarchical BOLA (Requirement 29)
    # ------------------------------------------------------------------

    # Parent-slot names (lowercased) that denote a TENANT / organization
    # boundary. When the preserved parent slot is a tenant boundary, an
    # accessible foreign child is classified as BOLA_CROSS_TENANT (Req 29.4);
    # otherwise it is a BOLA_BROKEN_OBJECT_RELATIONSHIP (Req 29.3).
    TENANT_SLOT_NAMES = {
        'tenant_id', 'tenantid', 'org_id', 'orgid',
        'organization_id', 'organizationid', 'account_id', 'accountid',
        'workspace_id', 'workspaceid', 'company_id', 'companyid',
    }

    def _discover_composite_identifiers(self, endpoints: List[Any]) -> List[CompositeIdentifier]:
        """Discover endpoints carrying two or more hierarchical identifier slots.

        Scans each endpoint's URL path for id-bearing segments (reusing the same
        ``ID_PATTERNS`` detection as single-slot discovery via
        :meth:`_determine_id_type`). An endpoint with two or more identifier
        segments (e.g. ``/tenants/{tenant_id}/projects/{project_id}``) becomes a
        :class:`CompositeIdentifier`; endpoints with fewer than two identifier
        slots are ignored here (they are handled by single-slot discovery).
        Slots are ordered by path position, so ``slots[0]`` is the parent and
        ``slots[-1]`` is the innermost child (Requirement 29).
        """
        composites: List[CompositeIdentifier] = []
        seen: Set[str] = set()

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            if endpoint_url in seen:
                continue
            seen.add(endpoint_url)

            composite = self._extract_composite_from_path(endpoint_url)
            if composite is not None:
                composites.append(composite)
                self.logger.debug(
                    "Composite identifier discovered",
                    endpoint=endpoint_url,
                    slots=[(s.name, s.role, s.value) for s in composite.slots],
                )

        return composites

    def _extract_composite_from_path(self, url: str) -> Optional[CompositeIdentifier]:
        """Build a :class:`CompositeIdentifier` from a URL, or ``None``.

        Returns ``None`` unless the path exposes two or more identifier slots.
        Each slot records the EXACT index of its value within the raw path split
        (``path.split('/')``) so :meth:`_substitute_composite_slot` can replace a
        single slot while preserving every other segment.
        """
        parsed = urlparse(url)
        raw_segments = parsed.path.split('/')

        slots: List[CompositeIdentifierSlot] = []
        for idx, segment in enumerate(raw_segments):
            if not segment:
                continue
            id_type = self._determine_id_type(segment)
            if not id_type:
                continue
            prev_segment = raw_segments[idx - 1] if idx > 0 else ''
            slots.append(
                CompositeIdentifierSlot(
                    value=segment,
                    type=id_type,
                    name=self._infer_slot_name(prev_segment),
                    segment_index=idx,
                    role='',  # assigned below once ordering is known
                )
            )

        if len(slots) < 2:
            return None

        # Leftmost slot is the parent; every subsequent slot is a child.
        for position, slot in enumerate(slots):
            slot.role = 'parent' if position == 0 else 'child'

        return CompositeIdentifier(endpoint=url, slots=slots)

    def _infer_slot_name(self, prev_segment: str) -> str:
        """Infer an identifier slot name from the preceding path segment.

        Mirrors the naming heuristic in :meth:`_extract_ids_from_path` and
        singularizes a trailing plural so ``tenants`` -> ``tenant_id`` and
        ``projects`` -> ``project_id``.
        """
        if not prev_segment:
            return 'id'
        if prev_segment in ('user', 'users'):
            return 'user_id'
        if prev_segment in ('account', 'accounts'):
            return 'account_id'
        if prev_segment in ('order', 'orders'):
            return 'order_id'
        base = prev_segment[:-1] if prev_segment.endswith('s') else prev_segment
        return f"{base}_id"

    def _substitute_composite_slot(self, composite: CompositeIdentifier,
                                   slot_index: int, candidate: str) -> str:
        """Swap EXACTLY one identifier slot with ``candidate`` (Requirement 29.1).

        Splits the endpoint path, replaces ONLY the segment at
        ``composite.slots[slot_index].segment_index`` with ``candidate``, and
        rebuilds the URL. Every other identifier slot, every non-identifier path
        segment, and every query parameter is preserved unchanged. Reuses the
        same ``urlparse``/``urlunparse`` preservation discipline as
        :meth:`_substitute_identifier`.
        """
        candidate = str(candidate)
        parsed = urlparse(composite.endpoint)
        segments = parsed.path.split('/')

        target_index = composite.slots[slot_index].segment_index
        new_segments = list(segments)
        if 0 <= target_index < len(new_segments):
            new_segments[target_index] = candidate

        new_path = '/'.join(new_segments)
        return urlunparse(parsed._replace(path=new_path))

    def _composite_requesting_context(self) -> Optional[AuthContext]:
        """Pick the Auth_Context that acts as the requesting (attacker) principal.

        Prefers a user-level context (privilege level 1) to mirror the
        horizontal-escalation flow; otherwise the first configured context, or
        ``None`` when no contexts are available.
        """
        user_contexts = [ctx for ctx in self.auth_contexts if ctx.privilege_level == 1]
        if user_contexts:
            return user_contexts[0]
        return self.auth_contexts[0] if self.auth_contexts else None

    def _composite_child_candidates(self, child_slot: CompositeIdentifierSlot) -> List[str]:
        """Derive candidate victim child identifiers to substitute into the child slot.

        Only genuinely sequential (integer) child identifiers can be
        meaningfully enumerated; the candidate window is derived from
        ``BOLAConfig.enumeration_bound`` (consistent with sequential
        enumeration). Non-sequential (GUID/UUID) child slots return an empty
        list because random identifiers cannot be guessed.
        """
        if child_slot.type != 'sequential' or not str(child_slot.value).isdigit():
            return []

        original = int(child_slot.value)
        bound = max(2, getattr(self.config, 'enumeration_bound', 25))
        half = bound // 2

        candidates: List[str] = []
        for test_id in range(max(1, original - half), original + (bound - half) + 1):
            if test_id != original:
                candidates.append(str(test_id))
        return candidates

    async def _get_composite_negative_control(self, composite: CompositeIdentifier,
                                              slot_index: int,
                                              auth_context: Optional[AuthContext]
                                              ) -> NegativeControlBaseline:
        """Cached Negative_Control_Baseline for one composite slot (Req 29.5).

        Built once per ``(endpoint, auth_context, slot_index)`` by substituting a
        known-invalid identifier into the targeted slot under the SAME auth
        context that will issue the real probes, reusing the shared
        :meth:`build_negative_control` (Requirements 3.1, 25.1).
        """
        context_key = auth_context.name if auth_context is not None else 'anonymous'
        cache_key = (composite.endpoint, context_key, slot_index)

        if cache_key not in self._composite_baseline_cache:
            baseline = await self.build_negative_control(
                endpoint=composite.endpoint,
                auth_context=auth_context,
                invalid_id="0",
                substitute=lambda cid: self._substitute_composite_slot(
                    composite, slot_index, cid
                ),
            )
            self._composite_baseline_cache[cache_key] = baseline

        return self._composite_baseline_cache[cache_key]

    async def _test_composite_bola(self, composites: List[CompositeIdentifier]
                                   ) -> List[Finding]:
        """Test parent-child / cross-tenant BOLA on composite endpoints (Req 29).

        For each :class:`CompositeIdentifier`, the requesting Auth_Context's own
        authorized parent identifier is PRESERVED while the child slot is
        substituted with candidate victim child identifiers (Req 29.2). A foreign
        child that is accessible under the requester's own parent context is
        reported as ``BOLA_BROKEN_OBJECT_RELATIONSHIP`` (Req 29.3), or as
        ``BOLA_CROSS_TENANT`` when the preserved parent slot is a tenant boundary
        (Req 29.4). Accessibility is calibrated against a
        Negative_Control_Baseline and identity is decided with
        Identifying_Fields (Req 29.5).
        """
        findings: List[Finding] = []
        if not composites:
            return findings

        requesting_context = self._composite_requesting_context()

        for composite in composites:
            try:
                findings.extend(
                    await self._test_single_composite(composite, requesting_context)
                )
            except Exception as e:
                self.logger.debug(
                    "Composite BOLA test failed",
                    endpoint=composite.endpoint,
                    error=str(e),
                )

        return findings

    async def _test_single_composite(self, composite: CompositeIdentifier,
                                     requesting_context: Optional[AuthContext]
                                     ) -> List[Finding]:
        """Probe a single composite endpoint (helper for :meth:`_test_composite_bola`)."""
        findings: List[Finding] = []

        if len(composite.slots) < 2:
            return findings

        parent_slot = composite.slots[0]
        child_index = len(composite.slots) - 1
        child_slot = composite.slots[child_index]

        # Calibrate the child slot against a negative-control baseline. A
        # non-discriminating endpoint (returns success for an invalid child id)
        # cannot yield an accessibility decision, so suppress (Req 29.5, 3.4).
        baseline = await self._get_composite_negative_control(
            composite, child_index, requesting_context
        )
        if baseline.non_discriminating:
            self.logger.info(
                "Suppressing composite BOLA finding: child slot is "
                "non-discriminating (returns success for an invalid id)",
                endpoint=composite.endpoint,
                child_slot=child_slot.name,
            )
            return findings

        # Establish the requester's OWN child object (own parent + own child) to
        # anchor the ownership comparison (Req 29.5, consistent with Req 2).
        if requesting_context is not None:
            self.http_client.set_auth_context(requesting_context)
        own_url = self._substitute_composite_slot(composite, child_index, child_slot.value)
        own_response = await self.http_client.request('GET', own_url)
        own_fields = extract_identifying_fields(own_response)

        candidates = self._composite_child_candidates(child_slot)
        if not candidates:
            self.logger.info(
                "Skipping composite BOLA: child slot is not enumerable",
                endpoint=composite.endpoint,
                child_slot=child_slot.name,
                child_type=child_slot.type,
            )
            return findings

        is_tenant_boundary = parent_slot.name.lower() in self.TENANT_SLOT_NAMES

        for candidate in candidates:
            # Preserve the requester's own parent id; substitute ONLY the child
            # slot with the candidate victim child id (Req 29.1, 29.2).
            if requesting_context is not None:
                self.http_client.set_auth_context(requesting_context)
            test_url = self._substitute_composite_slot(composite, child_index, candidate)
            response = await self.http_client.request('GET', test_url)

            if not self._is_object_accessible(response, baseline):
                continue

            # A foreign child object is a vulnerability only when it does NOT
            # belong to the requesting context (Req 29.5, consistent with Req 2).
            candidate_fields = extract_identifying_fields(response)
            if self._object_belongs_to_context(candidate_fields, own_fields):
                continue

            category = ('BOLA_CROSS_TENANT' if is_tenant_boundary
                        else 'BOLA_BROKEN_OBJECT_RELATIONSHIP')

            findings.append(
                self._build_composite_finding(
                    composite=composite,
                    parent_slot=parent_slot,
                    child_slot=child_slot,
                    candidate=candidate,
                    category=category,
                    response=response,
                    candidate_fields=candidate_fields,
                    requesting_context=requesting_context,
                )
            )

            self.logger.warning(
                "Composite BOLA detected",
                category=category,
                endpoint=composite.endpoint,
                parent_slot=parent_slot.name,
                own_parent=parent_slot.value,
                child_slot=child_slot.name,
                own_child=child_slot.value,
                foreign_child=candidate,
            )

        return findings

    def _build_composite_finding(self, composite: CompositeIdentifier,
                                 parent_slot: CompositeIdentifierSlot,
                                 child_slot: CompositeIdentifierSlot,
                                 candidate: str, category: str,
                                 response: Response,
                                 candidate_fields: Dict[str, Any],
                                 requesting_context: Optional[AuthContext] = None) -> Finding:
        """Assemble a composite BOLA Finding (Req 29.3, 29.4).

        Both composite categories map to OWASP ``API1``. Evidence captures the
        preserved parent identifier, the substituted child identifier, and the
        foreign object's Identifying_Fields that establish it belongs to a
        different context/tenant. A redacted Evidence_Chain and Confidence_Score
        are attached (Req 33).
        """
        if category == 'BOLA_CROSS_TENANT':
            evidence = (
                f"Cross-tenant access: while operating within the requesting "
                f"context's own {parent_slot.name}={parent_slot.value!r}, a child "
                f"object {child_slot.name}={candidate!r} belonging to a foreign "
                f"tenant was accessible. Foreign object identifying fields: "
                f"{candidate_fields!r}."
            )
            recommendation = (
                "Enforce tenant isolation: validate that the child object belongs "
                "to the authenticated principal's tenant before returning it, not "
                "merely that the parent (tenant) identifier is well-formed."
            )
        else:
            evidence = (
                f"Broken object relationship: the requesting context retained its "
                f"own authorized {parent_slot.name}={parent_slot.value!r} but a "
                f"foreign child {child_slot.name}={candidate!r} (original "
                f"{child_slot.value!r}) was accessible. Foreign object identifying "
                f"fields: {candidate_fields!r}."
            )
            recommendation = (
                "Validate the parent-child relationship on every request: verify "
                "the child object actually belongs to the supplied parent and that "
                "the authenticated principal is authorized for that parent."
            )

        response_snippet = response.text[:500] if response.text else None

        # A foreign child is accessible (read) vs a discriminating baseline with
        # a confirmed foreign Identifying_Field, but no mutation was persisted.
        confidence = self._score_confidence(
            persisted=False,
            baseline_discriminating=True,
            identity_matched=bool(candidate_fields),
        )
        evidence_chain = self._build_evidence_chain(
            method='GET',
            endpoint=composite.endpoint,
            original_id=child_slot.value,
            substituted_id=candidate,
            auth_context=(requesting_context.name if requesting_context else None),
            baseline_comparison=(
                f"Foreign child accessible (status {response.status_code}) vs a "
                f"discriminating Negative_Control_Baseline (invalid id in the "
                f"'{child_slot.name}' slot); foreign ownership established via "
                f"Identifying_Field comparison ({candidate_fields!r})."
            ),
            response_snippet=response_snippet,
            confidence=confidence,
        )

        return Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category=category,
            owasp_category='API1',
            severity=Severity.HIGH,
            endpoint=composite.endpoint,
            method='GET',
            status_code=response.status_code,
            response_size=len(response.content) if response.content else 0,
            response_time=response.elapsed,
            evidence=evidence,
            recommendation=recommendation,
            payload=f"{parent_slot.name}={parent_slot.value}, "
                    f"{child_slot.name}={candidate}",
            response_snippet=response_snippet,
            evidence_chain=evidence_chain,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # ID leakage harvesting + identifier predictability (Requirement 30)
    # ------------------------------------------------------------------

    async def _harvest_identifiers(self, endpoints: List[Any]) -> Set[str]:
        """Collect object identifiers exposed by list/public/feed endpoints.

        Issues a Safe_Method (GET) request against each endpoint and reuses the
        existing :meth:`_extract_ids_from_response` /
        :meth:`_extract_ids_from_json` extraction - which keys strictly on the
        recognized Identifying_Field names (``ID_PARAMETER_NAMES``) - so every
        exposed identifier value, including UUIDs, is collected into a harvested
        set while values that are not under a recognized field are ignored
        (Requirement 30.1). No new field-name list is introduced.

        Safe Mode is honored: any declared State_Changing_Method is downgraded to
        GET for this read-only harvesting probe (Requirements 21.2-21.4).
        """
        harvested: Set[str] = set()

        # Harvest under the first available auth context (a list/feed endpoint is
        # typically accessible to an authenticated principal).
        auth_context = self.auth_contexts[0] if self.auth_contexts else None
        if auth_context is not None:
            self.http_client.set_auth_context(auth_context)

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
            # Read-only harvesting: never issue a state-changing verb.
            method = self.safe_read_method(method, "bola_id_harvest")

            try:
                response = await self.http_client.request(method, endpoint_url)
                for obj_id in self._extract_ids_from_response(response, endpoint_url):
                    if isinstance(obj_id, ObjectIdentifier):
                        harvested.add(str(obj_id.value))
            except Exception as e:
                self.logger.debug("Identifier harvesting failed for endpoint",
                                  endpoint=endpoint_url,
                                  error=str(e))

        self.logger.info("Identifier harvesting complete", harvested=len(harvested))
        return harvested

    def _leakage_probe_context(self) -> Optional[AuthContext]:
        """Pick the lower-privilege / anonymous context used to replay harvested ids.

        Prefers the lowest-privilege configured Auth_Context; when the lowest
        configured privilege level is anonymous (level 0) or no contexts are
        available, ``None`` is returned so the probe is issued anonymously
        (Requirement 30.2).
        """
        if not self.auth_contexts:
            return None
        lowest = min(self.auth_contexts, key=lambda c: c.privilege_level)
        if lowest.privilege_level <= 0:
            return None
        return lowest

    async def _test_id_leakage(self, harvested: Set[str],
                               identifiers: List[ObjectIdentifier]) -> List[Finding]:
        """Inject harvested identifiers into object endpoints under lower privilege.

        For each recognized object endpoint, every harvested identifier is
        substituted (via the shared :meth:`_substitute_identifier`) and requested
        under a LOWER-privilege or anonymous Auth_Context (Requirement 30.2).
        Accessibility is calibrated against the endpoint's
        Negative_Control_Baseline (reusing :meth:`_get_negative_control`); a
        non-discriminating baseline suppresses findings for that endpoint
        (Requirements 3.4, 25.3). When a harvested identifier is accessible under
        that context AND the accessed object does not belong to it (decided via
        Identifying_Fields, consistent with Requirement 2), a ``BOLA_ID_LEAKAGE``
        finding (OWASP API1) is reported (Requirement 30.3).
        """
        findings: List[Finding] = []
        if not harvested or not identifiers:
            return findings

        probe_context = self._leakage_probe_context()
        context_label = probe_context.name if probe_context is not None else 'anonymous'

        # Deduplicate object endpoints/parameters so each is probed once.
        seen: Set[Tuple[str, str, str]] = set()
        unique_identifiers: List[ObjectIdentifier] = []
        for identifier in identifiers:
            key = (identifier.endpoint, identifier.parameter_name, identifier.location)
            if key not in seen:
                seen.add(key)
                unique_identifiers.append(identifier)

        for identifier in unique_identifiers:
            try:
                # Assert the probe context (anonymous => no credentials) BEFORE
                # building the baseline so calibration uses the same context.
                if probe_context is not None:
                    self.http_client.set_auth_context(probe_context)
                else:
                    self.http_client.current_auth_context = None

                baseline = await self._get_negative_control(identifier, probe_context)

                # Re-assert anonymous context for the real probes (building the
                # baseline may not touch the anonymous context).
                if probe_context is None:
                    self.http_client.current_auth_context = None

                if baseline.non_discriminating:
                    self.logger.info(
                        "Suppressing ID-leakage finding: endpoint is "
                        "non-discriminating (returns success for an invalid id)",
                        endpoint=identifier.endpoint,
                        context=context_label,
                    )
                    continue

                # For an authenticated lower-privilege context, establish the
                # requester's OWN object so ownership can be disproved. Anonymous
                # owns no object, so own_fields stays empty and any accessible
                # object carrying identifying data is a leakage.
                own_fields: Dict[str, Any] = {}
                if probe_context is not None:
                    self.http_client.set_auth_context(probe_context)
                    own_response = await self._test_object_access(
                        identifier, context_label
                    )
                    own_fields = extract_identifying_fields(own_response)

                for harvested_id in harvested:
                    # Skip the endpoint's own original identifier value.
                    if str(harvested_id) == str(identifier.value):
                        continue

                    if probe_context is not None:
                        self.http_client.set_auth_context(probe_context)
                    else:
                        self.http_client.current_auth_context = None

                    response = await self._test_object_access(
                        identifier, context_label, candidate_id=harvested_id
                    )

                    if not self._is_object_accessible(response, baseline):
                        continue

                    candidate_fields = extract_identifying_fields(response)
                    # Require real identifying data so an identity-less body does
                    # not raise a false positive (Requirement 2.4).
                    if not candidate_fields:
                        continue

                    # A lower-privilege authenticated principal accessing its own
                    # object is not leakage; anonymous owns nothing so any
                    # identified object is foreign (Requirement 30.3).
                    if probe_context is not None and self._object_belongs_to_context(
                        candidate_fields, own_fields
                    ):
                        continue

                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            scan_id='',
                            category='BOLA_ID_LEAKAGE',
                            owasp_category='API1',
                            severity=Severity.MEDIUM,
                            endpoint=identifier.endpoint,
                            method='GET',
                            status_code=response.status_code,
                            response_size=len(response.content) if response.content else 0,
                            response_time=response.elapsed,
                            evidence=(
                                f"Harvested identifier {harvested_id!r} (exposed by a "
                                f"list/public/feed endpoint) was accessible under the "
                                f"'{context_label}' context at {identifier.endpoint} and "
                                f"returned an object that does not belong to that "
                                f"context. Foreign object identifying fields: "
                                f"{candidate_fields!r}."
                            ),
                            recommendation=(
                                "Do not expose object identifiers in list/public/feed "
                                "responses that can be replayed against private object "
                                "endpoints. Enforce object-level authorization on every "
                                "access regardless of how the identifier was obtained."
                            ),
                            payload=str(harvested_id),
                            response_snippet=response.text[:500] if response.text else None,
                            evidence_chain=self._build_evidence_chain(
                                method='GET',
                                endpoint=identifier.endpoint,
                                original_id=identifier.value,
                                substituted_id=harvested_id,
                                auth_context=context_label,
                                baseline_comparison=(
                                    f"Harvested id accessible (status "
                                    f"{response.status_code}) under the "
                                    f"'{context_label}' context vs a discriminating "
                                    f"Negative_Control_Baseline; ownership disproved "
                                    f"via Identifying_Field comparison "
                                    f"({candidate_fields!r})."
                                ),
                                response_snippet=(response.text[:500]
                                                  if response.text else None),
                                confidence=self._score_confidence(
                                    persisted=False,
                                    baseline_discriminating=True,
                                    identity_matched=bool(candidate_fields),
                                ),
                            ),
                            confidence=self._score_confidence(
                                persisted=False,
                                baseline_discriminating=True,
                                identity_matched=bool(candidate_fields),
                            ),
                        )
                    )

                    self.logger.warning(
                        "ID leakage detected",
                        endpoint=identifier.endpoint,
                        harvested_id=harvested_id,
                        context=context_label,
                    )

            except Exception as e:
                self.logger.debug("ID leakage test failed",
                                  endpoint=identifier.endpoint,
                                  error=str(e))

        return findings

    @staticmethod
    def _uuid_version(value: str) -> Optional[int]:
        """Return the RFC 4122 version of ``value`` if it is a valid UUID, else None.

        The version is read from the 13th hex nibble (the first character of the
        third dash-delimited group), per RFC 4122. Non-UUID strings return
        ``None``.
        """
        if not isinstance(value, str):
            return None
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError, TypeError):
            return None
        return parsed.version

    # Plausible epoch bounds. Seconds: ~2001-09-09 (1e9) .. year 2100. The
    # millisecond band is the same window scaled by 1000.
    _EPOCH_SECONDS_MIN = 1_000_000_000
    _EPOCH_SECONDS_MAX = 4_102_444_800          # 2100-01-01 in seconds
    _EPOCH_MILLIS_MIN = 1_000_000_000_000
    _EPOCH_MILLIS_MAX = 4_102_444_800_000       # 2100-01-01 in milliseconds

    @classmethod
    def _is_plausible_epoch(cls, value: int) -> bool:
        """True when ``value`` falls in a plausible Unix epoch seconds/ms window."""
        return (
            cls._EPOCH_SECONDS_MIN <= value <= cls._EPOCH_SECONDS_MAX
            or cls._EPOCH_MILLIS_MIN <= value <= cls._EPOCH_MILLIS_MAX
        )

    def analyze_identifier_predictability(
        self, samples: Union[str, List[str]], known_inputs: Optional[List[str]] = None
    ) -> IdentifierPredictability:
        """Classify how guessable an identifier scheme is (Requirement 30.4).

        Accepts a single sample or a list of samples drawn from the same scheme
        and returns an :class:`IdentifierPredictability`:

        * a set of valid UUIDs is classified by their version nibble - version
          ``1`` (time-based) -> ``'uuid-v1'`` (predictable); version ``4``
          (random) -> ``'uuid-v4'`` (NOT predictable, Requirement 30.6); any
          other/mixed version -> ``'unknown'`` (not predictable);
        * all-digit samples that step monotonically by a small constant ->
          ``'sequential-integer'`` (predictable);
        * all-digit samples that decode to plausible epoch timestamps ->
          ``'timestamp-based'`` (predictable);
        * any other all-digit samples default to ``'sequential-integer'``
          (predictable);
        * anything else (non-integer, non-UUID) -> ``'unknown'`` (not
          predictable) so malformed values raise no finding.

        EXTENDED (Requirement 40.1): when ``known_inputs`` (e.g. account email
        addresses) are supplied, a sample that equals a common hash
        (md5/sha1/sha256) of any known input - such as ``MD5(email)`` - is
        classified as predictable with scheme ``'hash-of-known-input'``. This
        check is additive and only runs when ``known_inputs`` is provided, so
        the existing schemes and the uuid-v4 "not predictable" outcome remain
        unchanged and the method stays backward compatible
        (``known_inputs`` defaults to ``None``).
        """
        if isinstance(samples, str):
            samples = [samples]
        cleaned = [str(s) for s in samples if s is not None and str(s) != '']

        if not cleaned:
            return IdentifierPredictability(
                scheme='unknown',
                predictable=False,
                rationale='No identifier samples were available to analyze.',
            )

        # --- Hash-of-known-input scheme (Req 40.1) ---
        # Only evaluated when the operator supplies known inputs (e.g. emails).
        # A token equal to a common hash of a known value is trivially
        # reproducible by an attacker who knows that value.
        if known_inputs:
            matched_input, matched_algo = self._match_hash_of_known_input(
                cleaned, known_inputs
            )
            if matched_input is not None:
                return IdentifierPredictability(
                    scheme='hash-of-known-input',
                    predictable=True,
                    rationale=(
                        f'Identifier equals the {matched_algo.upper()} hash of a '
                        f'known input, making it reproducible by anyone who knows '
                        f'that value.'
                    ),
                )

        # --- UUID scheme (classified by version nibble) ---
        versions = [self._uuid_version(s) for s in cleaned]
        if all(v is not None for v in versions):
            distinct = set(versions)
            if distinct == {1}:
                return IdentifierPredictability(
                    scheme='uuid-v1',
                    predictable=True,
                    rationale=(
                        'Identifiers are time-based UUIDs (version 1); the '
                        'embedded timestamp and node make them partially '
                        'predictable and enumerable.'
                    ),
                )
            if distinct == {4}:
                return IdentifierPredictability(
                    scheme='uuid-v4',
                    predictable=False,
                    rationale=(
                        'Identifiers are random UUIDs (version 4); no exploitable '
                        'structure was found.'
                    ),
                )
            return IdentifierPredictability(
                scheme='unknown',
                predictable=False,
                rationale=(
                    f'Identifiers are UUIDs of version(s) {sorted(distinct)}; '
                    'no predictable structure is assumed.'
                ),
            )

        # --- Integer schemes (sequential vs timestamp-based) ---
        if all(s.isdigit() for s in cleaned):
            ints = [int(s) for s in cleaned]

            # Monotonic small-step sequence => sequential integers.
            if len(ints) >= 2:
                diffs = [b - a for a, b in zip(ints, ints[1:])]
                if diffs and all(d == diffs[0] for d in diffs) and 0 < diffs[0] <= 1000:
                    return IdentifierPredictability(
                        scheme='sequential-integer',
                        predictable=True,
                        rationale=(
                            f'Identifiers are all-digit values increasing by a '
                            f'constant step of {diffs[0]}, indicating a sequential '
                            f'integer scheme that is trivially enumerable.'
                        ),
                    )

            # Values in a plausible epoch window => timestamp-based.
            if all(self._is_plausible_epoch(v) for v in ints):
                return IdentifierPredictability(
                    scheme='timestamp-based',
                    predictable=True,
                    rationale=(
                        'Identifiers decode to plausible Unix epoch timestamps, '
                        'making them predictable from the time of creation.'
                    ),
                )

            # Default all-digit case: treat as a sequential integer scheme.
            return IdentifierPredictability(
                scheme='sequential-integer',
                predictable=True,
                rationale=(
                    'Identifiers are all-digit integer values, a sequential '
                    'integer scheme that is enumerable.'
                ),
            )

        # --- Unclassifiable ---
        return IdentifierPredictability(
            scheme='unknown',
            predictable=False,
            rationale=(
                'Identifiers are neither all-digit integers, plausible epoch '
                'timestamps, nor valid UUIDs; no predictable structure detected.'
            ),
        )

    @staticmethod
    def _match_hash_of_known_input(
        samples: List[str], known_inputs: List[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(known_input, algorithm)`` when any sample equals a common
        hash of a known input, else ``(None, None)`` (Req 40.1).

        Each known input is hashed with md5/sha1/sha256 (both the raw value and
        a whitespace/case-normalized variant, since emails are commonly
        lower-cased before hashing). Comparison against samples is done on the
        lower-cased hex digest so it is case-insensitive.
        """
        algorithms = ('md5', 'sha1', 'sha256')
        sample_set = {s.strip().lower() for s in samples if s}

        for known in known_inputs:
            if known is None:
                continue
            raw = str(known)
            variants = {raw, raw.strip().lower()}
            for variant in variants:
                encoded = variant.encode('utf-8')
                for algo in algorithms:
                    digest = hashlib.new(algo, encoded).hexdigest()
                    if digest.lower() in sample_set:
                        return raw, algo
        return None, None

    def _test_identifier_predictability(self, harvested: Set[str]) -> List[Finding]:
        """Analyze harvested identifier schemes and emit predictability findings.

        Harvested identifiers are grouped into homogeneous schemes (each UUID
        version separately, and all-digit values together) so
        :meth:`analyze_identifier_predictability` receives same-scheme samples.
        A ``BOLA_PREDICTABLE_IDENTIFIER`` finding (OWASP API1) is emitted ONLY
        for schemes classified as predictable (sequential-integer, timestamp-
        based, uuid-v1); a random UUIDv4 scheme yields the assessment but no
        finding (Requirements 30.5, 30.6).
        """
        findings: List[Finding] = []
        if not harvested:
            return findings

        # Partition into homogeneous scheme groups.
        groups: Dict[str, List[str]] = {}
        for value in harvested:
            version = self._uuid_version(value)
            if version is not None:
                groups.setdefault(f'uuid-v{version}', []).append(value)
            elif str(value).isdigit():
                groups.setdefault('digits', []).append(value)
            else:
                groups.setdefault('other', []).append(value)

        for group_key, samples in groups.items():
            # Sort digit samples so monotonic stepping can be detected.
            if group_key == 'digits':
                samples = sorted(samples, key=lambda s: int(s))

            assessment = self.analyze_identifier_predictability(samples)

            if not assessment.predictable:
                self.logger.info(
                    "Identifier scheme assessed as not predictable; no finding",
                    scheme=assessment.scheme,
                    sample_count=len(samples),
                )
                continue

            sample_preview = samples[:5]
            confidence = self._score_confidence(
                persisted=False,
                baseline_discriminating=False,
                identity_matched=False,
            )
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    scan_id='',
                    category='BOLA_PREDICTABLE_IDENTIFIER',
                    owasp_category='API1',
                    severity=Severity.MEDIUM,
                    endpoint='(identifier scheme)',
                    method='GET',
                    status_code=0,
                    response_size=0,
                    response_time=0.0,
                    evidence=(
                        f"Observed identifier scheme classified as "
                        f"'{assessment.scheme}' (predictable). {assessment.rationale} "
                        f"Sample identifiers: {sample_preview}."
                    ),
                    recommendation=(
                        "Use unpredictable, randomly generated identifiers (such as "
                        "UUIDv4) for objects so identifiers cannot be guessed or "
                        "enumerated."
                    ),
                    payload=', '.join(str(s) for s in sample_preview),
                    evidence_chain=self._build_evidence_chain(
                        method='GET',
                        endpoint='(identifier scheme)',
                        original_id=(sample_preview[0] if sample_preview else ''),
                        substituted_id='(scheme analysis)',
                        auth_context='(scheme analysis)',
                        baseline_comparison=(
                            f"Static Identifier_Predictability analysis of "
                            f"{len(samples)} harvested sample(s); scheme "
                            f"'{assessment.scheme}' classified predictable. "
                            f"No live access probe was issued."
                        ),
                        response_snippet=None,
                        confidence=confidence,
                    ),
                    confidence=confidence,
                )
            )

            self.logger.warning(
                "Predictable identifier scheme detected",
                scheme=assessment.scheme,
                sample_count=len(samples),
            )

        return findings

    # ------------------------------------------------------------------
    # Advanced request-mutation techniques (Requirement 31)
    #
    # Each builder below produces one or more probe Requests that vary a SINGLE
    # dimension of a base Request (the HTTP method, a duplicated query
    # parameter, or the placement of an identifier) while preserving every other
    # request component unchanged (Requirements 31.1, 31.3, 31.4). The builders
    # are pure functions of their inputs - they construct Request descriptors and
    # never issue traffic - so any actual request must still be routed through
    # the HTTP engine (and, for state-changing methods, the destructive
    # guardrails of Requirement 28). WHILE Safe_Mode is enabled, all advanced
    # mutations are restricted to Safe_Methods (Requirement 31.6).
    # ------------------------------------------------------------------

    # Candidate HTTP methods explored by verb tampering. Ordered safe-first so a
    # Safe_Mode run naturally keeps only the leading (safe) variants.
    VERB_TAMPERING_METHODS: Tuple[str, ...] = (
        "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE",
    )

    # Header used by frameworks to override the effective HTTP method. A request
    # sent as one method but carrying this header may be dispatched by the server
    # as the overridden (effective) method.
    METHOD_OVERRIDE_HEADER = "X-HTTP-Method-Override"

    def _clone_request(self, base: Request, **overrides: Any) -> Request:
        """Return a deep copy of ``base`` with the given fields overridden.

        Every field not present in ``overrides`` is copied from ``base`` (dict
        and body fields are deep-copied so the clone never aliases the base
        request's mutable state). This is the single primitive the advanced
        mutation builders use to guarantee that every request component except
        the one being mutated is preserved unchanged (Requirements 31.1, 31.3,
        31.4).
        """
        return Request(
            method=overrides.get("method", base.method),
            url=overrides.get("url", base.url),
            headers=overrides["headers"] if "headers" in overrides
                    else dict(base.headers),
            params=overrides["params"] if "params" in overrides
                   else dict(base.params),
            data=overrides["data"] if "data" in overrides
                 else copy.deepcopy(base.data),
            json=overrides["json"] if "json" in overrides
                 else copy.deepcopy(base.json),
            timeout=overrides.get("timeout", base.timeout),
            auth_context=overrides.get("auth_context", base.auth_context),
        )

    def _effective_method_is_state_changing(self, wire_method: str,
                                            override_method: Optional[str]) -> bool:
        """True when a verb-tampering probe's effective method changes state.

        A probe's effective method is the method the server acts upon: the
        ``X-HTTP-Method-Override`` value when present, otherwise the wire method.
        Because a method-override header is transmitted on top of a wire method
        that itself reaches the server, the probe is treated as state-changing
        when EITHER the wire method OR the overridden method is a
        State_Changing_Method. This keeps the destructive gate fail-safe
        (Requirement 31.2, 28).
        """
        if self.is_state_changing(wire_method):
            return True
        if override_method is not None and self.is_state_changing(override_method):
            return True
        return False

    def _build_verb_tampering_probes(self, base_request: Request,
                                     test_name: str = "verb_tampering") -> List[Request]:
        """Build verb-tampering probes that vary the effective HTTP method (Req 31.1).

        For each candidate method different from the base request's method two
        probes are produced, each preserving every other request component
        unchanged (Requirement 31.1):

        * a direct variant whose wire method is the candidate method;
        * an ``X-HTTP-Method-Override`` variant that keeps the base wire method
          but adds the override header carrying the candidate method.

        Gating:

        * WHILE Safe_Mode is enabled, only probes whose effective method is a
          Safe_Method are emitted (Requirement 31.6). Because the override
          variant still transmits the base wire method, it is suppressed whenever
          the base method is itself state-changing.
        * When a probe's effective method is a State_Changing_Method it is gated
          behind the Requirement 28 destructive guardrails and only emitted when
          :meth:`_destructive_allowed` permits it (Requirement 31.2).
        """
        probes: List[Request] = []
        base_method = base_request.method.upper()

        for candidate in self.VERB_TAMPERING_METHODS:
            if candidate == base_method:
                continue

            # --- Direct-method variant (wire method == candidate) ---------
            if self._verb_probe_permitted(candidate, None, test_name):
                probes.append(self._clone_request(base_request, method=candidate))

            # --- X-HTTP-Method-Override variant (wire method == base) -----
            # Effective method is the override candidate, but the base wire
            # method still reaches the server, so gating considers both.
            if self._verb_probe_permitted(base_method, candidate, test_name):
                override_headers = dict(base_request.headers)
                override_headers[self.METHOD_OVERRIDE_HEADER] = candidate
                probes.append(self._clone_request(base_request, headers=override_headers))

        return probes

    def _verb_probe_permitted(self, wire_method: str, override_method: Optional[str],
                              test_name: str) -> bool:
        """Return True when a verb-tampering probe may be emitted.

        Applies the Safe_Mode restriction to Safe_Methods (Requirement 31.6) and
        the destructive guardrails for state-changing effective methods
        (Requirements 31.2, 28). A skipped probe is logged so the operator can
        see what was suppressed.
        """
        state_changing = self._effective_method_is_state_changing(wire_method, override_method)

        if self.safe_mode and state_changing:
            self.logger.info("Skipping verb-tampering probe in safe mode",
                             test=test_name,
                             wire_method=wire_method.upper(),
                             override_method=(override_method.upper()
                                              if override_method else None))
            return False

        if state_changing and not self._destructive_allowed():
            self.logger.info("Skipping state-changing verb-tampering probe",
                             reason="destructive opt-in absent",
                             test=test_name,
                             wire_method=wire_method.upper(),
                             override_method=(override_method.upper()
                                              if override_method else None))
            return False

        return True

    def _build_parameter_pollution_probe(self, base_request: Request,
                                         parameter_name: str, own_id: Any,
                                         victim_id: Any,
                                         test_name: str = "parameter_pollution"
                                         ) -> Optional[Request]:
        """Build an HTTP parameter-pollution probe (Requirement 31.3).

        Supplies a DUPLICATED identifier query parameter that pairs the
        requesting context's own identifier with the victim identifier - i.e.
        ``?<name>=<own_id>&<name>=<victim_id>`` - encoded via
        ``urlencode(..., doseq=True)``. Every other query parameter and every
        other request component is preserved unchanged (Requirement 31.3).

        WHILE Safe_Mode is enabled the probe is restricted to Safe_Methods:
        ``None`` is returned (and the skip logged) when the base request uses a
        State_Changing_Method (Requirement 31.6).
        """
        if self.safe_mode and self.is_state_changing(base_request.method):
            self.logger.info("Skipping parameter-pollution probe in safe mode",
                             test=test_name, method=base_request.method.upper())
            return None

        parsed = urlparse(base_request.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        # Duplicate the identifier parameter: own id first, victim id second.
        qs[parameter_name] = [str(own_id), str(victim_id)]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        return self._clone_request(base_request, url=new_url)

    def _build_placement_probes(self, base_request: Request,
                                identifier: ObjectIdentifier, candidate_id: Any,
                                test_name: str = "placement"
                                ) -> Dict[str, Request]:
        """Build identifier-placement probes across path, query, body, headers (Req 31.4).

        Produces one probe per placement that substitutes ``candidate_id`` into a
        single location while preserving every other request component unchanged
        (Requirement 31.4):

        * ``path``   - the candidate is substituted into the URL path (reusing
          :meth:`_substitute_identifier` for the path/query preservation
          discipline);
        * ``query``  - the candidate is set on the identifier's query parameter;
        * ``body``   - the candidate is set on the identifier's field in the JSON
          request body;
        * ``header`` - the candidate is set on a header named after the
          identifier's parameter.

        WHILE Safe_Mode is enabled the probes are restricted to Safe_Methods: an
        empty mapping is returned (and the skip logged) when the base request
        uses a State_Changing_Method (Requirement 31.6).
        """
        if self.safe_mode and self.is_state_changing(base_request.method):
            self.logger.info("Skipping placement probes in safe mode",
                             test=test_name, method=base_request.method.upper())
            return {}

        candidate = str(candidate_id)
        param_name = identifier.parameter_name or "id"
        probes: Dict[str, Request] = {}

        # --- path placement ------------------------------------------------
        # Reuse _substitute_identifier where it applies (path-located id);
        # otherwise substitute the identifier value directly in the path segment.
        if identifier.location == "path":
            path_url = self._substitute_identifier(identifier, candidate)
        else:
            parsed = urlparse(base_request.url)
            segments = parsed.path.split('/')
            new_segments = [candidate if seg == identifier.value else seg
                            for seg in segments]
            path_url = urlunparse(parsed._replace(path='/'.join(new_segments)))
        probes["path"] = self._clone_request(base_request, url=path_url)

        # --- query placement ----------------------------------------------
        parsed = urlparse(base_request.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [candidate]
        query_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        probes["query"] = self._clone_request(base_request, url=query_url)

        # --- body placement (JSON) -----------------------------------------
        new_body = copy.deepcopy(base_request.json) if isinstance(base_request.json, dict) else {}
        new_body[param_name] = candidate
        probes["body"] = self._clone_request(base_request, json=new_body)

        # --- header placement ----------------------------------------------
        new_headers = dict(base_request.headers)
        new_headers[param_name] = candidate
        probes["header"] = self._clone_request(base_request, headers=new_headers)

        return probes

    def encode_identifier_variants(self, identifier_value: Any) -> Dict[str, Any]:
        """Produce encoded representations of an identifier (Requirement 31.5).

        Returns a mapping with three encoded forms of ``identifier_value``:

        * ``base64``         - the base64 encoding of the identifier's UTF-8
          bytes (``base64.b64decode`` round-trips it back to the original
          string);
        * ``url_encoded``    - the percent-encoding of the identifier
          (``urllib.parse.unquote`` round-trips it back);
        * ``object_wrapped`` - the identifier wrapped as ``{"id": <value>}``
          (reading key ``"id"`` round-trips it back).

        The identifier is normalized to its string form so all three variants
        round-trip to the same original value (Requirement 31.5, Property 12).
        """
        value = str(identifier_value)
        return {
            "base64": base64.b64encode(value.encode("utf-8")).decode("ascii"),
            "url_encoded": quote(value, safe=""),
            "object_wrapped": {"id": value},
        }
