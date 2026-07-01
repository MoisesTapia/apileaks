"""
Authentication Testing Module
Implements OWASP API2 - Broken Authentication testing
"""

import asyncio
import re
import json
import base64
import hmac
import hashlib
import time
import uuid
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from utils.safe_mode import SafeModeGuard, SAFE_METHODS, STATE_CHANGING_METHODS
from utils.authz_baseline import extract_identifying_fields, responses_identify_same_object
from utils import jwt_utils
from core.config import AuthTestingConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


# Sentinel used to distinguish "public key not yet resolved" from a resolved
# value of ``None`` (no public key available) so resolution runs at most once.
_UNRESOLVED = object()


@dataclass
class JWTToken:
    """Represents a JWT token with parsed components"""
    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    is_valid: bool = True
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class AuthTestResult:
    """Result of an authentication test"""
    endpoint: str
    method: str
    test_type: str
    auth_context: Optional[str]
    status_code: int
    response_size: int
    response_time: float
    accessible: bool
    evidence: str
    vulnerability_type: Optional[str] = None


class AuthenticationTestingModule(OWASPModule, SafeModeGuard):
    """
    Authentication Testing Module for detecting Broken Authentication
    
    This module implements comprehensive testing for OWASP API Security Top 10 #2:
    - Analyzes JWT vulnerabilities (weak algorithms, algorithm confusion)
    - Tests token expiration validation
    - Detects tokens valid after logout
    - Verifies weak secrets in JWT against wordlist
    - Detects endpoints accessible without authentication
    """
    
    # Algorithms that are inherently weak regardless of context. Only 'none'
    # qualifies: it bypasses signature verification entirely. HS256/RS256 are
    # NOT inherently weak and are labeled weak only when a weakness is
    # demonstrated (e.g. a recovered HMAC secret) - see ``_is_weak_algorithm``
    # (Requirements 9.1, 9.2).
    WEAK_ALGORITHMS = ['none']

    # Response field names (lowercased) that indicate protected/personal data.
    # Used by evidence-based anonymous-access classification so detection and
    # severity are driven by the kind and amount of exposed data rather than the
    # presence of a single keyword such as ``email`` (Requirements 7.2, 7.3).
    PROTECTED_DATA_FIELDS = {
        'email', 'phone', 'phone_number', 'address', 'ssn', 'password',
        'token', 'access_token', 'refresh_token', 'api_key', 'apikey',
        'secret', 'user_id', 'userid', 'account_id', 'accountid', 'owner_id',
        'role', 'roles', 'permissions', 'credit_card', 'card_number',
        'first_name', 'last_name', 'full_name', 'dob', 'date_of_birth',
        'salary', 'balance',
    }

    # Subset of PROTECTED_DATA_FIELDS whose exposure is credential-grade and
    # therefore always escalates anonymous-access severity to CRITICAL.
    CREDENTIAL_DATA_FIELDS = {
        'password', 'token', 'access_token', 'refresh_token', 'api_key',
        'apikey', 'secret', 'credit_card', 'card_number', 'ssn',
    }
    
    # Common JWT header parameters
    JWT_HEADER_PARAMS = [
        'alg',  # Algorithm
        'typ',  # Type
        'kid',  # Key ID
        'jku',  # JWK Set URL
        'jwk',  # JSON Web Key
        'x5u',  # X.509 URL
        'x5c',  # X.509 Certificate Chain
        'x5t',  # X.509 Certificate SHA-1 Thumbprint
        'crit'  # Critical
    ]
    
    # Common JWT payload claims
    JWT_PAYLOAD_CLAIMS = [
        'iss',  # Issuer
        'sub',  # Subject
        'aud',  # Audience
        'exp',  # Expiration Time
        'nbf',  # Not Before
        'iat',  # Issued At
        'jti',  # JWT ID
        'scope',  # Scope
        'role',   # Role
        'permissions'  # Permissions
    ]
    
    def __init__(self, config: AuthTestingConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="auth_testing")

        # Read the Safe_Mode flag (Requirement 21.1). State-changing auth tests
        # (logout invalidation, credential/session mutations) are gated through
        # ``skip_if_state_changing`` so they are skipped under Safe Mode.
        self._init_safe_mode(config)

        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        
        # Load weak secrets wordlist
        self.weak_secrets = self._load_weak_secrets_wordlist()

        # A weak HMAC secret recovered by ``_test_jwt_weak_secrets``. When set it
        # is reused as a known signing key to construct a validly-signed-but-
        # expired token (Requirement 8.1) and to demonstrate a weak HMAC
        # algorithm (Requirement 9.1).
        self._recovered_secret: Optional[str] = None

        # Cached resolved public-key bytes for the algorithm-confusion attack.
        # ``_UNRESOLVED`` means resolution has not run yet; ``None`` means no
        # public key is available (Requirement 6.3).
        self._public_key_bytes: Any = _UNRESOLVED

        # Track tested tokens to avoid duplicates
        self.tested_tokens: Set[str] = set()
        
        self.logger.info("Authentication Testing Module initialized",
                        auth_contexts=len(self.auth_contexts),
                        weak_secrets_loaded=len(self.weak_secrets),
                        jwt_testing_enabled=config.jwt_testing)
    
    def get_module_name(self) -> str:
        """Get module name"""
        return "auth_testing"
    
    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute authentication tests on discovered endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of authentication findings
        """
        self.logger.info("Starting authentication testing", endpoints_count=len(endpoints))
        
        findings = []
        
        try:
            # Step 1: Test endpoints accessible without authentication
            anonymous_findings = await self._test_anonymous_access(endpoints)
            findings.extend(anonymous_findings)
            self.logger.debug("Anonymous access testing completed", findings=len(anonymous_findings))
            
            # Step 2: Analyze JWT tokens if JWT testing is enabled
            if self.config.jwt_testing:
                jwt_findings = await self._test_jwt_vulnerabilities(endpoints)
                findings.extend(jwt_findings)
                self.logger.debug("JWT vulnerability testing completed", findings=len(jwt_findings))
            
            # Step 3: Test token expiration validation
            expiration_findings = await self._test_token_expiration(endpoints)
            findings.extend(expiration_findings)
            self.logger.debug("Token expiration testing completed", findings=len(expiration_findings))
            
            # Step 4: Test logout token invalidation. Gating (config flag and
            # Safe Mode) is handled inside the method (Requirements 9.3, 9.5).
            logout_findings = await self._test_logout_invalidation(endpoints)
            findings.extend(logout_findings)
            self.logger.debug("Logout invalidation testing completed", findings=len(logout_findings))
            
        except Exception as e:
            self.logger.error("Authentication testing failed during execution", error=str(e))
            raise
        
        self.logger.info("Authentication testing completed",
                        total_findings=len(findings),
                        critical_findings=len([f for f in findings if f.severity == Severity.CRITICAL]))
        
        return findings
    
    def _load_weak_secrets_wordlist(self) -> List[str]:
        """Load weak secrets wordlist for JWT testing"""
        wordlist_path = Path(self.config.weak_secrets_wordlist)
        weak_secrets = []
        
        try:
            if wordlist_path.exists():
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            weak_secrets.append(line)
                
                self.logger.info("Weak secrets wordlist loaded", 
                               path=str(wordlist_path),
                               secrets_count=len(weak_secrets))
            else:
                self.logger.warning("Weak secrets wordlist not found", path=str(wordlist_path))
                # Add some default weak secrets
                weak_secrets = [
                    'secret', 'password', '123456', 'admin', 'test', 'key',
                    'jwt', 'token', 'your-256-bit-secret', 'your-secret-key'
                ]
        
        except Exception as e:
            self.logger.error("Failed to load weak secrets wordlist", error=str(e))
            weak_secrets = ['secret', 'password', '123456']
        
        return weak_secrets

    def _is_weak_algorithm(self, algorithm: Optional[str],
                           recovered_secret: Optional[str] = None) -> bool:
        """Context-aware weak-algorithm classification (Requirements 9.1, 9.2).

        An algorithm is classified as weak ONLY when:
          * it is ``none`` (no signature verification), or
          * it is an HMAC algorithm (HS*) demonstrated to use a recovered weak
            secret (``recovered_secret`` is provided).

        HS256/RS256 (and other strong algorithms) are never labeled inherently
        weak in the absence of a demonstrated weakness.

        Args:
            algorithm: The JWT ``alg`` value to classify
            recovered_secret: A recovered weak HMAC secret, when one was
                demonstrated for the token's algorithm

        Returns:
            True when the algorithm is weak in context, False otherwise.
        """
        if not algorithm:
            return False
        alg = str(algorithm).lower()
        if alg == 'none':
            return True
        if alg.startswith('hs') and recovered_secret:
            return True
        return False

    async def _test_anonymous_access(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test endpoints accessible without authentication (Requirement 7)

        Detection is evidence-based: for each endpoint the anonymous response is
        compared against an authenticated response obtained with a valid
        Auth_Context for the same endpoint (Requirement 7.1). An endpoint is
        classified as not requiring authentication only when the anonymous
        response exposes protected data AND (when an authenticated baseline is
        available) the two responses are equivalent (Requirement 7.3). Severity
        is derived from the exposed data and endpoint sensitivity rather than the
        presence of a single keyword (Requirement 7.2), and the comparison
        evidence is embedded in the finding (Requirement 7.4).

        Args:
            endpoints: List of endpoints to test

        Returns:
            List of findings for anonymous access vulnerabilities
        """
        findings = []
        self.logger.info("Testing anonymous access to endpoints", count=len(endpoints))

        # A valid Auth_Context used to obtain an authenticated baseline response
        # for comparison. May be None when no authenticated context is supplied.
        valid_context = self._select_valid_auth_context()

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'

            # Anonymous access testing is a read-only comparison probe. In Safe
            # Mode an endpoint's declared State_Changing_Method must never be
            # issued, so downgrade the probe to GET (Requirements 21.2, 21.3).
            method = self.safe_read_method(method, "anonymous_access")

            try:
                # Anonymous request: explicitly clear any auth context.
                self.http_client.current_auth_context = None
                anon_response = await self.http_client.request(method, endpoint_url)
            except Exception as e:
                self.logger.debug("Anonymous access test failed",
                                  endpoint=endpoint_url, method=method, error=str(e))
                continue

            # Skip when the anonymous response is not a successful, data-bearing
            # response (auth errors, empty bodies, etc.).
            if not self._is_endpoint_accessible_anonymously(anon_response):
                continue

            has_protected, protected_fields = self._response_contains_protected_data(anon_response)
            if not has_protected:
                # Without protected data we cannot conclude an authorization
                # weakness (Requirement 7.3).
                self.logger.debug("Anonymous response exposed no protected data; not reported",
                                  endpoint=endpoint_url)
                continue

            # Obtain an authenticated baseline for the same endpoint and compare.
            auth_response = None
            equivalent: Optional[bool] = None
            if valid_context is not None:
                try:
                    self.http_client.set_auth_context(valid_context)
                    auth_response = await self.http_client.request(method, endpoint_url)
                    equivalent = self._anon_auth_equivalent(anon_response, auth_response)
                except Exception as e:
                    self.logger.debug("Authenticated baseline request failed",
                                      endpoint=endpoint_url, error=str(e))
                    auth_response = None
                finally:
                    self.http_client.current_auth_context = None

            # Classify "does not require auth" only when protected data is present
            # AND (when a baseline exists) the responses are equivalent.
            if auth_response is not None and not equivalent:
                self.logger.debug("Anonymous and authenticated responses differ; not reported",
                                  endpoint=endpoint_url)
                continue

            severity = self._classify_anonymous_access_severity(
                endpoint_url, anon_response, protected_fields
            )

            evidence = self._build_anonymous_access_evidence(
                anon_response, auth_response, equivalent, protected_fields
            )

            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_ANONYMOUS_ACCESS',
                owasp_category='API2',
                severity=severity,
                endpoint=endpoint_url,
                method=method,
                status_code=anon_response.status_code,
                response_size=len(anon_response.content),
                response_time=anon_response.elapsed,
                evidence=evidence,
                recommendation="Implement proper authentication checks for all protected endpoints. "
                             "Ensure sensitive operations require valid authentication tokens.",
                response_snippet=anon_response.text[:500] if anon_response.text else None
            )
            findings.append(finding)

            self.logger.warning("Anonymous access detected",
                                endpoint=endpoint_url,
                                method=method,
                                status_code=anon_response.status_code,
                                severity=severity.value,
                                protected_fields=protected_fields)

        return findings

    def _select_valid_auth_context(self) -> Optional[AuthContext]:
        """Return a valid Auth_Context to use as an authenticated baseline.

        Picks the first context carrying a non-empty token. Returns None when no
        authenticated context is available, in which case anonymous detection
        falls back to protected-data presence alone.
        """
        for ctx in self.auth_contexts:
            if getattr(ctx, 'token', None):
                return ctx
        return None

    def _response_contains_protected_data(self, response: Response) -> Tuple[bool, List[str]]:
        """Detect protected/personal data in a response body (Requirement 7.3).

        Parses the JSON body and collects the recognized protected/identifying
        field names it exposes (searched recursively). Returns
        ``(has_protected, field_names)``. Non-JSON or unparseable bodies degrade
        to ``(False, [])`` rather than raising.
        """
        if not response or not getattr(response, 'text', None):
            return (False, [])

        try:
            body = json.loads(response.text)
        except (ValueError, TypeError):
            return (False, [])

        found: Set[str] = set()

        def _walk(node: Any, depth: int = 0) -> None:
            if depth > 6:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(key, str) and key.lower() in self.PROTECTED_DATA_FIELDS:
                        found.add(key.lower())
                    _walk(value, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    _walk(item, depth + 1)

        _walk(body)
        return (len(found) > 0, sorted(found))

    def _anon_auth_equivalent(self, anon_response: Response, auth_response: Response) -> bool:
        """Decide whether anonymous and authenticated responses are equivalent.

        Equivalence requires matching status classes AND either an identity
        overlap (same Identifying_Field value) or identical bodies. Size/word
        similarity is never used (Requirement 7.1).
        """
        if anon_response is None or auth_response is None:
            return False
        if (anon_response.status_code // 100) != (auth_response.status_code // 100):
            return False
        same, _field, _value = responses_identify_same_object(anon_response, auth_response)
        if same:
            return True
        return anon_response.text == auth_response.text

    def _build_anonymous_access_evidence(self, anon_response: Response,
                                         auth_response: Optional[Response],
                                         equivalent: Optional[bool],
                                         protected_fields: List[str]) -> str:
        """Build the embedded comparison evidence for an AUTH_ANONYMOUS_ACCESS
        finding (Requirement 7.4)."""
        parts = [
            "Endpoint returns protected data without authentication.",
            f"Anonymous status: {anon_response.status_code}, "
            f"size: {len(anon_response.content)} bytes.",
            f"Protected fields exposed: {', '.join(protected_fields)}.",
        ]
        if auth_response is not None:
            parts.append(
                f"Authenticated status: {auth_response.status_code}; "
                f"anonymous vs authenticated responses equivalent: {bool(equivalent)}."
            )
        else:
            parts.append("No authenticated baseline available; "
                         "classification based on protected-data exposure.")
        return " ".join(parts)
    
    def _is_endpoint_accessible_anonymously(self, response: Response) -> bool:
        """
        Determine if an endpoint is accessible without authentication
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            True if endpoint appears accessible anonymously
        """
        # Consider accessible if:
        # - Status code is 2xx (success)
        # - Status code is 3xx (redirect, but not auth-related)
        # - Response has substantial content (not just error message)
        
        if response.status_code == 0:  # Request failed
            return False
        
        # Definitely not accessible if auth-related error codes
        if response.status_code in [401, 403]:
            return False
        
        # Success codes indicate accessibility
        if 200 <= response.status_code < 300:
            # Additional check: response should have meaningful content
            if len(response.content) > 100:  # More than just error message
                return True
            
            # Check if response looks like actual data vs error message
            if response.text:
                auth_error_indicators = [
                    'unauthorized', 'forbidden', 'authentication required',
                    'access denied', 'login required', 'token required',
                    'invalid token', 'missing token', 'expired token'
                ]
                response_lower = response.text.lower()
                
                # If response contains auth error indicators, not accessible
                if any(indicator in response_lower for indicator in auth_error_indicators):
                    return False
                
                # If response contains data indicators, likely accessible
                data_indicators = [
                    'data', 'result', 'response', 'success', 'items',
                    'users', 'accounts', 'orders', 'products', 'api'
                ]
                if any(indicator in response_lower for indicator in data_indicators):
                    return True
        
        # Redirects might indicate accessibility (but not auth redirects)
        if 300 <= response.status_code < 400:
            location = response.headers.get('location', '').lower()
            if 'login' not in location and 'auth' not in location:
                return True
        
        return False
    
    def _classify_anonymous_access_severity(self, endpoint: str, response: Response,
                                            protected_fields: Optional[List[str]] = None) -> Severity:
        """
        Classify severity of anonymous access from response evidence and
        endpoint sensitivity (Requirement 7.2).

        Severity is driven by the kind of exposed data (credential-grade fields
        escalate to CRITICAL) and the sensitivity of the endpoint, rather than
        the mere presence of a single keyword such as ``email``.

        Args:
            endpoint: Endpoint URL
            response: HTTP response
            protected_fields: Recognized protected/personal field names found in
                the response body (lowercased)

        Returns:
            Severity level
        """
        protected_fields = protected_fields or []
        exposed = set(protected_fields)
        endpoint_lower = endpoint.lower()

        # Credential-grade data exposed anonymously is always CRITICAL.
        if exposed & self.CREDENTIAL_DATA_FIELDS:
            return Severity.CRITICAL

        # Sensitive endpoints (admin/management/user/account/payment data).
        critical_patterns = [
            '/admin', '/management', '/dashboard', '/config',
            '/users', '/accounts', '/orders', '/payments',
            '/api/admin', '/api/management', '/api/users'
        ]
        if any(pattern in endpoint_lower for pattern in critical_patterns):
            return Severity.CRITICAL

        # API endpoints exposing personal data to anonymous callers are HIGH.
        high_patterns = ['/api/', '/v1/', '/v2/', '/rest/', 'profile', 'settings', 'data']
        if any(pattern in endpoint_lower for pattern in high_patterns) and exposed:
            return Severity.HIGH

        # Any other endpoint exposing protected data anonymously is at least
        # MEDIUM.
        return Severity.MEDIUM
    
    async def _test_jwt_vulnerabilities(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test JWT vulnerabilities (Requirements 2.1, 2.4)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for JWT vulnerabilities
        """
        findings = []
        self.logger.info("Testing JWT vulnerabilities")
        
        # Collect JWT tokens from auth contexts
        jwt_tokens = []
        for auth_context in self.auth_contexts:
            if auth_context.type in [AuthType.JWT, AuthType.BEARER]:
                if auth_context.token and auth_context.token not in self.tested_tokens:
                    jwt_token = self._parse_jwt_token(auth_context.token)
                    if jwt_token:
                        jwt_tokens.append((auth_context, jwt_token))
                        self.tested_tokens.add(auth_context.token)
        
        if not jwt_tokens:
            self.logger.info("No JWT tokens found in auth contexts")
            return findings
        
        # Test each JWT token for vulnerabilities
        for auth_context, jwt_token in jwt_tokens:
            # Test 1: Weak algorithm detection
            algorithm_findings = await self._test_jwt_algorithm_vulnerabilities(
                auth_context, jwt_token, endpoints
            )
            findings.extend(algorithm_findings)
            
            # Test 2: Weak secret detection
            if jwt_token.algorithm.startswith('HS'):  # HMAC algorithms
                secret_findings = await self._test_jwt_weak_secrets(
                    auth_context, jwt_token, endpoints
                )
                findings.extend(secret_findings)
            
            # Test 3: Algorithm confusion attack
            confusion_findings = await self._test_jwt_algorithm_confusion(
                auth_context, jwt_token, endpoints
            )
            findings.extend(confusion_findings)
        
        return findings
    
    def _parse_jwt_token(self, token: str) -> Optional[JWTToken]:
        """
        Parse JWT token into components
        
        Args:
            token: JWT token string
            
        Returns:
            JWTToken object or None if parsing fails
        """
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            # JWT should have 3 parts separated by dots
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature = parts
            
            # Decode header and payload (add padding if needed)
            def decode_base64url(data):
                # Add padding if needed
                padding = 4 - (len(data) % 4)
                if padding != 4:
                    data += '=' * padding
                return base64.urlsafe_b64decode(data)
            
            header_json = decode_base64url(header_b64).decode('utf-8')
            payload_json = decode_base64url(payload_b64).decode('utf-8')
            
            header = json.loads(header_json)
            payload = json.loads(payload_json)
            
            algorithm = header.get('alg', 'unknown')
            
            jwt_token = JWTToken(
                raw_token=token,
                header=header,
                payload=payload,
                signature=signature,
                algorithm=algorithm
            )
            
            self.logger.debug("JWT token parsed successfully",
                            algorithm=algorithm,
                            header_keys=list(header.keys()),
                            payload_keys=list(payload.keys()))
            
            return jwt_token
            
        except Exception as e:
            self.logger.debug("Failed to parse JWT token", error=str(e))
            return None
    
    async def _test_jwt_algorithm_vulnerabilities(self, auth_context: AuthContext, 
                                                jwt_token: JWTToken, 
                                                endpoints: List[Any]) -> List[Finding]:
        """Test JWT algorithm vulnerabilities"""
        findings = []
        
        # Test 1: 'none' algorithm vulnerability
        if jwt_token.algorithm.lower() == 'none':
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='JWT_NONE_ALGORITHM',
                owasp_category='API2',
                severity=Severity.CRITICAL,
                endpoint='JWT_TOKEN_ANALYSIS',
                method='ANALYSIS',
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=f"JWT token uses 'none' algorithm which bypasses signature verification. "
                        f"Token header: {json.dumps(jwt_token.header)}",
                recommendation="Never use 'none' algorithm for JWT tokens in production. "
                             "Use strong algorithms like RS256 or HS256 with proper secrets.",
                payload=auth_context.token[:50] + "..." if len(auth_context.token) > 50 else auth_context.token
            )
            findings.append(finding)
            
            self.logger.warning("JWT 'none' algorithm detected",
                              auth_context=auth_context.name)
        
        # Test 2: Test if 'none' algorithm is accepted by modifying token
        if jwt_token.algorithm != 'none':
            none_findings = await self._test_none_algorithm_acceptance(
                auth_context, jwt_token, endpoints
            )
            findings.extend(none_findings)
        
        return findings
    
    async def _test_none_algorithm_acceptance(self, auth_context: AuthContext,
                                            jwt_token: JWTToken,
                                            endpoints: List[Any]) -> List[Finding]:
        """Test if endpoints accept JWT tokens with 'none' algorithm"""
        findings = []
        
        try:
            # Create a modified token with 'none' algorithm
            modified_header = jwt_token.header.copy()
            modified_header['alg'] = 'none'
            
            # Encode modified header
            header_json = json.dumps(modified_header, separators=(',', ':'))
            header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
            
            # Keep original payload
            payload_json = json.dumps(jwt_token.payload, separators=(',', ':'))
            payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
            
            # Create token with no signature (empty signature for 'none' algorithm)
            modified_token = f"{header_b64}.{payload_b64}."
            
            # Test with a few endpoints
            test_endpoints = endpoints[:5] if len(endpoints) > 5 else endpoints
            
            for endpoint in test_endpoints:
                endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
                method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
                # Safe mode: replaying a state-changing method is forbidden; the
                # 'none' algorithm test is a read probe, so downgrade to GET
                # (Requirements 21.2, 21.3).
                method = self.safe_read_method(method, "jwt_none_algorithm")

                # Create modified auth context
                modified_auth = AuthContext(
                    name=f"{auth_context.name}_none_test",
                    type=auth_context.type,
                    token=modified_token,
                    privilege_level=auth_context.privilege_level
                )
                
                self.http_client.set_auth_context(modified_auth)
                
                try:
                    response = await self.http_client.request(method, endpoint_url)
                    
                    # If request succeeds with 'none' algorithm, it's a vulnerability
                    if response.is_success:
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            scan_id='',
                            category='JWT_NONE_ALGORITHM_ACCEPTED',
                            owasp_category='API2',
                            severity=Severity.CRITICAL,
                            endpoint=endpoint_url,
                            method=method,
                            status_code=response.status_code,
                            response_size=len(response.content),
                            response_time=response.elapsed,
                            evidence=f"Endpoint accepts JWT tokens with 'none' algorithm, "
                                    f"bypassing signature verification. Original algorithm: {jwt_token.algorithm}",
                            recommendation="Reject JWT tokens with 'none' algorithm. "
                                         "Implement proper algorithm validation.",
                            payload=modified_token[:100] + "..." if len(modified_token) > 100 else modified_token
                        )
                        findings.append(finding)
                        
                        self.logger.warning("JWT 'none' algorithm accepted",
                                          endpoint=endpoint_url,
                                          original_algorithm=jwt_token.algorithm)
                        break  # Found vulnerability, no need to test more endpoints
                
                except Exception as e:
                    self.logger.debug("None algorithm test failed",
                                    endpoint=endpoint_url,
                                    error=str(e))
        
        except Exception as e:
            self.logger.error("Failed to test 'none' algorithm acceptance", error=str(e))
        
        return findings
    
    async def _test_jwt_weak_secrets(self, auth_context: AuthContext,
                                   jwt_token: JWTToken,
                                   endpoints: List[Any]) -> List[Finding]:
        """Test JWT tokens for weak secrets (Requirement 2.4)"""
        findings = []
        
        if not jwt_token.algorithm.startswith('HS'):
            return findings  # Only test HMAC algorithms
        
        self.logger.info("Testing JWT weak secrets", algorithm=jwt_token.algorithm)
        
        # Extract token parts for signature verification
        token_parts = jwt_token.raw_token.split('.')
        if len(token_parts) != 3:
            return findings
        
        header_payload = f"{token_parts[0]}.{token_parts[1]}"
        original_signature = token_parts[2]
        
        # Test each weak secret
        for secret in self.weak_secrets:
            try:
                # Generate signature with weak secret
                if jwt_token.algorithm == 'HS256':
                    signature = hmac.new(
                        secret.encode(),
                        header_payload.encode(),
                        hashlib.sha256
                    ).digest()
                elif jwt_token.algorithm == 'HS384':
                    signature = hmac.new(
                        secret.encode(),
                        header_payload.encode(),
                        hashlib.sha384
                    ).digest()
                elif jwt_token.algorithm == 'HS512':
                    signature = hmac.new(
                        secret.encode(),
                        header_payload.encode(),
                        hashlib.sha512
                    ).digest()
                else:
                    continue
                
                # Encode signature
                signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                
                # Check if signatures match
                if signature_b64 == original_signature:
                    # Record the recovered secret so it can be reused as a known
                    # signing key for the validly-signed-but-expired token test
                    # (Requirement 8.1) and to demonstrate a weak HMAC algorithm
                    # (Requirement 9.1).
                    self._recovered_secret = secret

                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='JWT_WEAK_SECRET',
                        owasp_category='API2',
                        severity=Severity.HIGH,
                        endpoint='JWT_TOKEN_ANALYSIS',
                        method='ANALYSIS',
                        status_code=200,
                        response_size=0,
                        response_time=0.0,
                        evidence=f"JWT token signed with weak secret: '{secret}'. "
                                f"Algorithm: {jwt_token.algorithm}. "
                                f"This allows token forgery and privilege escalation.",
                        recommendation="Use strong, randomly generated secrets for JWT signing. "
                                     "Secrets should be at least 256 bits for HS256.",
                        payload=f"Weak secret: {secret}"
                    )
                    findings.append(finding)
                    
                    self.logger.warning("JWT weak secret detected",
                                      secret=secret,
                                      algorithm=jwt_token.algorithm,
                                      auth_context=auth_context.name)
                    break  # Found weak secret, no need to test more
            
            except Exception as e:
                self.logger.debug("Weak secret test failed",
                                secret=secret,
                                error=str(e))
        
        return findings
    
    async def _resolve_public_key_bytes(self) -> Optional[bytes]:
        """Resolve the server's RSA public-key bytes for algorithm confusion.

        Key sourcing precedence (Requirements 6.1, 6.2):
          1. Operator-supplied ``AuthTestingConfig.public_key_material`` (a PEM
             file path or inline PEM/DER/string material).
          2. A JWKS endpoint (``AuthTestingConfig.jwks_url``) fetched through the
             shared ``HTTPRequestEngine``; the RSA JWK (``n``/``e``) is converted
             to PEM public-key bytes.

        Returns the raw public-key bytes to be used as the HMAC key, or ``None``
        when no public key is available (Requirement 6.3). The result is cached
        so resolution runs at most once. Literal placeholder strings are never
        returned (Requirement 6.4).
        """
        if self._public_key_bytes is not _UNRESOLVED:
            return self._public_key_bytes

        resolved: Optional[bytes] = None

        material = getattr(self.config, 'public_key_material', None)
        if material:
            resolved = self._load_public_key_material(material)
            if resolved:
                self.logger.debug("Resolved public key from operator-supplied material")

        if resolved is None:
            jwks_url = getattr(self.config, 'jwks_url', None)
            if jwks_url:
                resolved = await self._fetch_jwks_public_key(jwks_url)
                if resolved:
                    self.logger.debug("Resolved public key from JWKS", jwks_url=jwks_url)

        self._public_key_bytes = resolved
        return resolved

    def _load_public_key_material(self, material: str) -> Optional[bytes]:
        """Load operator-supplied public-key material into raw bytes.

        ``material`` may be a filesystem path to a PEM/DER file or inline
        PEM/string material. Returns the raw bytes used as the HMAC key, or
        ``None`` when the material is empty/unreadable.
        """
        try:
            path = Path(material)
            if path.exists() and path.is_file():
                return path.read_bytes()
        except (OSError, ValueError):
            pass

        if material and material.strip():
            return material.encode('utf-8')
        return None

    async def _fetch_jwks_public_key(self, jwks_url: str) -> Optional[bytes]:
        """Fetch a JWKS and convert its first RSA key to PEM public-key bytes.

        The JWKS is fetched through the shared ``HTTPRequestEngine`` (a safe GET)
        so it inherits rate-limiting/proxy/TLS controls (Requirements 6.2, 17).
        Returns ``None`` when the JWKS cannot be fetched or contains no usable
        RSA key.
        """
        try:
            # JWKS retrieval is unauthenticated and read-only.
            self.http_client.current_auth_context = None
            response = await self.http_client.request('GET', jwks_url)
            if not response or not getattr(response, 'text', None):
                return None

            data = json.loads(response.text)
            keys = None
            if isinstance(data, dict):
                if isinstance(data.get('keys'), list):
                    keys = data['keys']
                elif 'n' in data and 'e' in data:
                    keys = [data]

            if not keys:
                return None

            for jwk in keys:
                if not isinstance(jwk, dict):
                    continue
                if str(jwk.get('kty', 'RSA')).upper() != 'RSA':
                    continue
                n_b64 = jwk.get('n')
                e_b64 = jwk.get('e')
                if not n_b64 or not e_b64:
                    continue
                pem = self._jwk_rsa_to_pem(n_b64, e_b64)
                if pem:
                    return pem
        except Exception as e:
            self.logger.debug("Failed to fetch/parse JWKS public key",
                              jwks_url=jwks_url, error=str(e))
        return None

    def _jwk_rsa_to_pem(self, n_b64: str, e_b64: str) -> Optional[bytes]:
        """Convert an RSA JWK (base64url ``n``/``e``) to PEM public-key bytes."""
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization

            n = int.from_bytes(jwt_utils.base64url_decode(n_b64), 'big')
            e = int.from_bytes(jwt_utils.base64url_decode(e_b64), 'big')
            public_key = RSAPublicNumbers(e, n).public_key()
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as e:
            self.logger.debug("Failed to convert RSA JWK to PEM", error=str(e))
            return None

    async def _test_jwt_algorithm_confusion(self, auth_context: AuthContext,
                                          jwt_token: JWTToken,
                                          endpoints: List[Any]) -> List[Finding]:
        """Test JWT algorithm confusion attack (RS256 -> HS256).

        HMAC-signs the HS256-rewritten token using the server's REAL public-key
        bytes resolved via ``_resolve_public_key_bytes`` (Requirements 6.1, 6.2).
        When no public key is available the test is skipped and logged
        (Requirement 6.3); literal placeholder strings are never used as the
        HMAC key (Requirement 6.4).
        """
        findings = []

        if jwt_token.algorithm != 'RS256':
            return findings  # Only test RS256 tokens

        self.logger.info("Testing JWT algorithm confusion attack")

        # Resolve the real public-key bytes; skip + log when unavailable.
        public_key_bytes = await self._resolve_public_key_bytes()
        if not public_key_bytes:
            self.logger.info(
                "Skipping algorithm-confusion test for lack of a public key",
                auth_context=auth_context.name
            )
            return findings

        try:
            # Create modified token with HS256 algorithm.
            modified_header = jwt_token.header.copy()
            modified_header['alg'] = 'HS256'

            header_json = json.dumps(modified_header, separators=(',', ':'))
            header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')

            payload_json = json.dumps(jwt_token.payload, separators=(',', ':'))
            payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')

            header_payload = f"{header_b64}.{payload_b64}"

            # HMAC-sign using the REAL public-key bytes as the key (the essence
            # of the RS256->HS256 confusion attack).
            signature = hmac.new(
                public_key_bytes,
                header_payload.encode(),
                hashlib.sha256
            ).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            confused_token = f"{header_payload}.{signature_b64}"

            if endpoints:
                test_endpoint = endpoints[0]
                endpoint_url = test_endpoint.url if hasattr(test_endpoint, 'url') else str(test_endpoint)
                method = test_endpoint.method if hasattr(test_endpoint, 'method') else 'GET'

                confused_auth = AuthContext(
                    name=f"{auth_context.name}_confused",
                    type=auth_context.type,
                    token=confused_token,
                    privilege_level=auth_context.privilege_level
                )

                # Safe mode: the algorithm-confusion probe is a read; never
                # replay a state-changing method (Requirements 21.2, 21.3).
                method = self.safe_read_method(method, "jwt_algorithm_confusion")

                self.http_client.set_auth_context(confused_auth)
                response = await self.http_client.request(method, endpoint_url)

                # If the server accepts the HS256-resigned token, the algorithm
                # confusion vulnerability is confirmed.
                if response.is_success:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='JWT_ALGORITHM_CONFUSION',
                        owasp_category='API2',
                        severity=Severity.CRITICAL,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=response.status_code,
                        response_size=len(response.content),
                        response_time=response.elapsed,
                        evidence="JWT algorithm confusion attack successful. "
                                "RS256 token accepted as HS256 signed with the server's "
                                "real public key bytes as the HMAC secret.",
                        recommendation="Implement strict algorithm validation. "
                                     "Never allow algorithm switching in JWT verification.",
                        payload=confused_token[:100] + "..." if len(confused_token) > 100 else confused_token
                    )
                    findings.append(finding)

                    self.logger.warning("JWT algorithm confusion detected",
                                      endpoint=endpoint_url)

        except Exception as e:
            self.logger.error("Failed to test algorithm confusion", error=str(e))

        return findings
    
    async def _test_token_expiration(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test token expiration validation (Requirement 2.2)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for token expiration issues
        """
        findings = []
        self.logger.info("Testing token expiration validation")
        
        # Test each auth context for expiration issues
        for auth_context in self.auth_contexts:
            if auth_context.type in [AuthType.JWT, AuthType.BEARER]:
                jwt_token = self._parse_jwt_token(auth_context.token)
                if jwt_token and 'exp' in jwt_token.payload:
                    exp_findings = await self._test_jwt_expiration(
                        auth_context, jwt_token, endpoints
                    )
                    findings.extend(exp_findings)
                elif jwt_token and 'exp' not in jwt_token.payload:
                    # Token without expiration claim
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='JWT_NO_EXPIRATION',
                        owasp_category='API2',
                        severity=Severity.HIGH,
                        endpoint='JWT_TOKEN_ANALYSIS',
                        method='ANALYSIS',
                        status_code=200,
                        response_size=0,
                        response_time=0.0,
                        evidence=f"JWT token does not contain expiration claim (exp). "
                                f"Token payload: {json.dumps(jwt_token.payload)}",
                        recommendation="Include expiration claim (exp) in all JWT tokens. "
                                     "Implement proper token lifecycle management.",
                        payload=auth_context.token[:50] + "..." if len(auth_context.token) > 50 else auth_context.token
                    )
                    findings.append(finding)
                    
                    self.logger.warning("JWT token without expiration",
                                      auth_context=auth_context.name)
        
        return findings
    
    async def _test_jwt_expiration(self, auth_context: AuthContext,
                                 jwt_token: JWTToken,
                                 endpoints: List[Any]) -> List[Finding]:
        """Test JWT token expiration validation"""
        findings = []
        
        try:
            exp_timestamp = jwt_token.payload.get('exp')
            if not exp_timestamp:
                return findings
            
            current_timestamp = int(time.time())
            
            # Check if token is already expired
            if exp_timestamp < current_timestamp:
                # Test if expired token is still accepted
                expired_findings = await self._test_expired_token_acceptance(
                    auth_context, jwt_token, endpoints
                )
                findings.extend(expired_findings)
            else:
                # Create an expired version of the token
                expired_findings = await self._test_with_expired_token(
                    auth_context, jwt_token, endpoints
                )
                findings.extend(expired_findings)
        
        except Exception as e:
            self.logger.error("JWT expiration test failed", error=str(e))
        
        return findings
    
    async def _test_expired_token_acceptance(self, auth_context: AuthContext,
                                           jwt_token: JWTToken,
                                           endpoints: List[Any]) -> List[Finding]:
        """Test if expired tokens are still accepted"""
        findings = []
        
        # Test with a few endpoints
        test_endpoints = endpoints[:3] if len(endpoints) > 3 else endpoints
        
        self.http_client.set_auth_context(auth_context)
        
        for endpoint in test_endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
            # Safe mode: expired-token acceptance is a read probe; never replay
            # a state-changing method (Requirements 21.2, 21.3).
            method = self.safe_read_method(method, "jwt_expired_token_acceptance")

            try:
                response = await self.http_client.request(method, endpoint_url)
                
                # If expired token is accepted, it's a vulnerability
                if response.is_success:
                    exp_timestamp = jwt_token.payload.get('exp')
                    current_timestamp = int(time.time())
                    expired_duration = current_timestamp - exp_timestamp
                    
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='JWT_EXPIRED_TOKEN_ACCEPTED',
                        owasp_category='API2',
                        severity=Severity.HIGH,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=response.status_code,
                        response_size=len(response.content),
                        response_time=response.elapsed,
                        evidence=f"Expired JWT token accepted by endpoint. "
                                f"Token expired {expired_duration} seconds ago. "
                                f"Expiration timestamp: {exp_timestamp}, Current: {current_timestamp}",
                        recommendation="Implement proper token expiration validation. "
                                     "Reject all expired tokens immediately.",
                        payload=auth_context.token[:50] + "..." if len(auth_context.token) > 50 else auth_context.token
                    )
                    findings.append(finding)
                    
                    self.logger.warning("Expired JWT token accepted",
                                      endpoint=endpoint_url,
                                      expired_duration=expired_duration)
                    break  # Found issue, no need to test more endpoints
            
            except Exception as e:
                self.logger.debug("Expired token test failed",
                                endpoint=endpoint_url,
                                error=str(e))
        
        return findings
    
    def _get_signing_secret(self) -> Optional[str]:
        """Return a known HMAC signing secret, or None when none is known.

        Precedence (Requirement 8.1):
          1. Operator-supplied ``AuthTestingConfig.signing_secret``.
          2. A weak secret recovered by ``_test_jwt_weak_secrets``.
        """
        secret = getattr(self.config, 'signing_secret', None)
        if secret:
            return secret
        if self._recovered_secret:
            return self._recovered_secret
        return None

    async def _test_with_expired_token(self, auth_context: AuthContext,
                                     jwt_token: JWTToken,
                                     endpoints: List[Any]) -> List[Finding]:
        """Construct a validly-signed-but-expired token and test acceptance.

        A token with a VALID HMAC signature and an ``exp`` claim in the past is
        built using a known signing secret (Requirements 8.1, 8.5) via
        ``jwt_utils.encode_jwt``. If the server accepts it, a
        ``JWT_EXPIRED_TOKEN_ACCEPTED`` finding is reported (Requirement 8.2).
        When no signing key is known the test is skipped and logged
        (Requirement 8.4). The finding-emission path is NOT wrapped in a
        swallowing ``except`` so a reporting failure aborts the test rather than
        silently losing a finding (Requirement 8.3).
        """
        findings = []

        secret = self._get_signing_secret()
        if not secret:
            self.logger.info(
                "Skipping expiration test: no signing key known to construct a "
                "validly-signed token",
                auth_context=auth_context.name
            )
            return findings

        # Build a validly-signed HS256 token whose exp is in the past. encode_jwt
        # signs with HMAC-SHA256, so the declared algorithm is forced to HS256 to
        # keep the signature genuinely valid (distinguishing it from a
        # broken-signature token - Requirement 8.5).
        header = {k: v for k, v in jwt_token.header.items()}
        header['alg'] = 'HS256'
        header.setdefault('typ', 'JWT')

        payload = jwt_token.payload.copy()
        payload['exp'] = int(time.time()) - 3600  # Expired 1 hour ago

        expired_token = jwt_utils.encode_jwt(header, payload, secret)

        if not endpoints:
            return findings

        test_endpoint = endpoints[0]
        endpoint_url = test_endpoint.url if hasattr(test_endpoint, 'url') else str(test_endpoint)
        method = test_endpoint.method if hasattr(test_endpoint, 'method') else 'GET'
        # Safe mode: validly-signed expired token check is a read probe; never
        # replay a state-changing method (Requirements 21.2, 21.3).
        method = self.safe_read_method(method, "jwt_validly_signed_expired")

        expired_auth = AuthContext(
            name=f"{auth_context.name}_validly_signed_expired",
            type=auth_context.type,
            token=expired_token,
            privilege_level=auth_context.privilege_level
        )
        self.http_client.set_auth_context(expired_auth)

        # Network errors are tolerated (logged) - they do not constitute a lost
        # finding. The finding-emission below, however, is intentionally NOT
        # guarded so any reporting failure propagates and aborts the test
        # (Requirement 8.3).
        try:
            response = await self.http_client.request(method, endpoint_url)
        except Exception as e:
            self.logger.debug("Validly-signed expired token request failed",
                              endpoint=endpoint_url, error=str(e))
            return findings

        if response.is_success:
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='JWT_EXPIRED_TOKEN_ACCEPTED',
                owasp_category='API2',
                severity=Severity.HIGH,
                endpoint=endpoint_url,
                method=method,
                status_code=response.status_code,
                response_size=len(response.content),
                response_time=response.elapsed,
                evidence="Validly-signed JWT with an expired 'exp' claim was accepted. "
                        "The token signature is valid (signed with a known secret) and the "
                        "expiration is in the past, indicating missing expiration validation.",
                recommendation="Implement proper token expiration validation. "
                             "Reject all expired tokens immediately.",
                payload=expired_token[:100] + "..." if len(expired_token) > 100 else expired_token
            )
            findings.append(finding)

            self.logger.warning("Validly-signed expired JWT accepted",
                              endpoint=endpoint_url,
                              auth_context=auth_context.name)

        return findings
    
    async def _test_logout_invalidation(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test logout token invalidation (Requirement 2.3)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for logout invalidation issues
        """
        findings = []
        self.logger.info("Testing logout token invalidation")

        # Preserve the configured short-circuit as an additional skip condition
        # regardless of Safe Mode (Requirement 9.5).
        if not getattr(self.config, 'test_logout_invalidation', True):
            self.logger.info("Skipping logout-invalidation test (disabled by configuration)")
            return findings

        # The logout-invalidation test issues a State_Changing_Method (logout is
        # typically POST) and is therefore skipped under Safe Mode
        # (Requirements 9.3, 21.2). When Safe Mode is off it runs and can report
        # JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT (Requirement 9.4).
        if self.skip_if_state_changing('POST', 'logout_invalidation'):
            return findings

        # Look for logout endpoints
        logout_endpoints = []
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            if self._is_logout_endpoint(endpoint_url):
                logout_endpoints.append(endpoint)
        
        if not logout_endpoints:
            self.logger.info("No logout endpoints found for invalidation testing")
            return findings
        
        # Test each auth context
        for auth_context in self.auth_contexts:
            if auth_context.type in [AuthType.JWT, AuthType.BEARER]:
                invalidation_findings = await self._test_token_invalidation_after_logout(
                    auth_context, logout_endpoints, endpoints
                )
                findings.extend(invalidation_findings)
        
        return findings
    
    def _is_logout_endpoint(self, endpoint_url: str) -> bool:
        """Check if endpoint is a logout endpoint"""
        logout_patterns = [
            '/logout', '/signout', '/sign-out', '/logoff',
            '/api/logout', '/api/signout', '/api/auth/logout',
            '/auth/logout', '/session/logout', '/user/logout'
        ]
        
        endpoint_lower = endpoint_url.lower()
        return any(pattern in endpoint_lower for pattern in logout_patterns)
    
    async def _test_token_invalidation_after_logout(self, auth_context: AuthContext,
                                                   logout_endpoints: List[Any],
                                                   all_endpoints: List[Any]) -> List[Finding]:
        """Test if tokens remain valid after logout"""
        findings = []
        
        # Set auth context
        self.http_client.set_auth_context(auth_context)
        
        # Try to logout using each logout endpoint
        for logout_endpoint in logout_endpoints:
            logout_url = logout_endpoint.url if hasattr(logout_endpoint, 'url') else str(logout_endpoint)
            logout_method = logout_endpoint.method if hasattr(logout_endpoint, 'method') else 'POST'
            
            try:
                # Perform logout
                logout_response = await self.http_client.request(logout_method, logout_url)
                
                # If logout appears successful, test if token is still valid
                if logout_response.is_success or logout_response.status_code in [200, 204, 302]:
                    # Test token validity after logout
                    test_endpoints = all_endpoints[:3] if len(all_endpoints) > 3 else all_endpoints
                    
                    for test_endpoint in test_endpoints:
                        test_url = test_endpoint.url if hasattr(test_endpoint, 'url') else str(test_endpoint)
                        test_method = test_endpoint.method if hasattr(test_endpoint, 'method') else 'GET'
                        
                        # Skip the logout endpoint itself
                        if test_url == logout_url:
                            continue
                        
                        try:
                            # Use same token after logout
                            test_response = await self.http_client.request(test_method, test_url)
                            
                            # If token still works after logout, it's a vulnerability
                            if test_response.is_success:
                                finding = Finding(
                                    id=str(uuid.uuid4()),
                                    scan_id='',
                                    category='JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT',
                                    owasp_category='API2',
                                    severity=Severity.HIGH,
                                    endpoint=test_url,
                                    method=test_method,
                                    status_code=test_response.status_code,
                                    response_size=len(test_response.content),
                                    response_time=test_response.elapsed,
                                    evidence=f"Token remains valid after logout. "
                                            f"Logout endpoint: {logout_url} (status: {logout_response.status_code}). "
                                            f"Token still grants access to: {test_url}",
                                    recommendation="Implement proper token invalidation on logout. "
                                                 "Maintain a blacklist of invalidated tokens or use short-lived tokens with refresh mechanism.",
                                    payload=f"Logout endpoint: {logout_url}"
                                )
                                findings.append(finding)
                                
                                self.logger.warning("Token not invalidated after logout",
                                                  logout_endpoint=logout_url,
                                                  test_endpoint=test_url,
                                                  auth_context=auth_context.name)
                                break  # Found issue, no need to test more endpoints
                        
                        except Exception as e:
                            self.logger.debug("Post-logout token test failed",
                                            test_endpoint=test_url,
                                            error=str(e))
            
            except Exception as e:
                self.logger.debug("Logout test failed",
                                logout_endpoint=logout_url,
                                error=str(e))
        
        return findings