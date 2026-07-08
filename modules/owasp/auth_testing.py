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
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from utils.safe_mode import SafeModeGuard, SAFE_METHODS, STATE_CHANGING_METHODS
from utils.authz_baseline import (
    extract_identifying_fields,
    responses_identify_same_object,
    responses_equivalent,
    NegativeControlMixin,
    NegativeControlBaseline,
)
from utils import jwt_utils
from utils.jwt_attack_response_analyzer import JWTAttackResponseAnalyzer
from utils.jwt_attack_models import (
    AttackType,
    BaselineResponse,
    RequestDetails,
    ResponseDetails,
)
from core.config import AuthTestingConfig, AuthContext, AuthType, Severity
from utils.typed_payload import apply_actor_profile
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


@dataclass
class OAuthFlowInputs:
    """Operator-supplied inputs describing an OAuth/OpenID authorization flow (Req 41).

    ``authorize_url`` is the authorization endpoint under test.
    ``registered_redirect_uri`` is the legitimate redirect URI the client
    registered. ``attacker_redirect_uri`` is an attacker-controlled or
    unregistered redirect URI used to probe redirect_uri validation (Reqs 41.1,
    41.2). ``foreign_aud_token`` is an optional access token issued for a
    *different* application, used to probe audience-claim validation (Req 41.3);
    when ``None`` the audience-confusion sub-probe is skipped. ``state_present``
    indicates whether the authorization request carries a ``state`` parameter;
    when ``False`` the missing-state sub-probe reports a finding (Req 41.4).
    """
    authorize_url: str
    registered_redirect_uri: str
    attacker_redirect_uri: str
    foreign_aud_token: Optional[str] = None
    state_present: bool = True


class AuthenticationTestingModule(OWASPModule, SafeModeGuard, NegativeControlMixin):
    """
    Authentication Testing Module for detecting Broken Authentication
    
    This module implements comprehensive testing for OWASP API Security Top 10 #2:
    - Analyzes JWT vulnerabilities (weak algorithms, algorithm confusion)
    - Tests token expiration validation
    - Detects tokens valid after logout
    - Verifies weak secrets in JWT against wordlist
    - Detects endpoints accessible without authentication
    """
    
    # Algorithms that are inherently weak regardless of context. Only 'none'    # qualifies: it bypasses signature verification entirely. HS256/RS256 are
    # NOT inherently weak and are labeled weak only when a weakness is
    # demonstrated (e.g. a recovered HMAC secret) - see ``_is_weak_algorithm``
    # (Requirements 9.1, 9.2).
    WEAK_ALGORITHMS = ['none']

    # Credential-bearing query-parameter names probed by the secret-in-URL test
    # (Requirement 38.1). A VALID authentication secret is placed into each of
    # these parameters in turn and the endpoint is observed for whether the
    # URL-borne secret is accepted as valid authentication (Requirement 38.2).
    SECRET_URL_PARAM_NAMES = [
        'access_token', 'token', 'api_key', 'apikey', 'auth',
        'auth_token', 'jwt', 'session', 'sessionid', 'key', 'secret',
    ]

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
    
    # Unauthorized_Endpoint_Assertion classification for this module (Req 55.2,
    # 56.2): the Auth module emits within API2.
    UNAUTHORIZED_ASSERTION_CATEGORY = "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS"
    UNAUTHORIZED_ASSERTION_OWASP = "API2"

    def __init__(self, config: AuthTestingConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext], spec_schema=None):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="auth_testing")

        # Optional merged Spec_Schema threaded from the ``full`` command's
        # ``--openapi`` / ``--postman`` sources (Requirements 49.2, 49.5). It is
        # additive and defaults to ``None``; every consumer guards on
        # ``if self.spec_schema is not None`` so the no-spec path is unchanged
        # (Requirements 49.3, 54.3).
        self.spec_schema = spec_schema

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

        # Lazily-created BOLA redactor used to reuse the shared ``redact_secrets``
        # helper for secret-in-URL / MFA evidence (Requirements 38.3). It is
        # never recreated here - the exact BOLA implementation is reused.
        self._secret_redactor: Any = None

        # Lazily-created BOLA instance used to reuse the shared identifier
        # predictability analyzer for reset-token classification (Reqs 40.1,
        # 40.2). The analyzer is a pure function of its arguments, so a BOLA
        # instance built via ``__new__`` (no config/HTTP client) is sufficient;
        # the exact analyzer implementation is reused, never recreated.
        self._predictability_analyzer: Any = None

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

            # Step 5: Declarative Unauthorized_Endpoint_Assertions (Req 55). Only
            # runs when an auth context carries operator-declared patterns;
            # otherwise the module behaves exactly as before (Req 55.5).
            assertion_findings = await self._run_unauthorized_assertions(endpoints)
            findings.extend(assertion_findings)
            self.logger.debug("Unauthorized-endpoint assertion evaluation completed",
                              findings=len(assertion_findings))

            # Step 6: Advanced auth attack probes (Levels 2, 3 & Expert).
            # Gated by allow_aggressive + Safe_Mode; no-op when either gate is
            # closed. Runs OTP brute-force, OTP race, IP-header bypass, password
            # spraying, and timing/Content-Length oracle probes.
            advanced_findings = await self._run_advanced_auth_probes(endpoints)
            findings.extend(advanced_findings)
            self.logger.debug("Advanced auth probes completed",
                              findings=len(advanced_findings))

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
                    params, _ = apply_actor_profile(valid_context, endpoint_url)
                    request_kwargs = {'params': params} if params else {}
                    auth_response = await self.http_client.request(method, endpoint_url, **request_kwargs)
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

    @staticmethod
    def _response_to_details(response) -> ResponseDetails:
        """Adapt an ``HTTPRequestEngine`` Response into ``ResponseDetails``.

        Mirrors the adapter used by ``JWTAttackEngine`` so the shared
        ``JWTAttackResponseAnalyzer`` (the single success detector, Requirement
        19.1) can compare the attack response against the baseline.
        """
        content = getattr(response, 'content', b'') or b''
        return ResponseDetails(
            status_code=getattr(response, 'status_code', 0),
            headers=dict(getattr(response, 'headers', {}) or {}),
            body=getattr(response, 'text', '') or '',
            response_time=getattr(response, 'elapsed', 0.0) or 0.0,
            content_length=len(content),
        )

    async def _build_algorithm_confusion_analyzer(
        self, sign_fn, endpoint_url: str, method: str,
        auth_context: AuthContext
    ) -> Optional[JWTAttackResponseAnalyzer]:
        """Establish a negative-control baseline for the algorithm-confusion test.

        The baseline is an HS256 token whose signature is computed with a key
        that is NOT derived from the server's public key. A correctly-validating
        server rejects it, so acceptance of a public-key-derived variant is a
        genuine algorithm-confusion bypass rather than an endpoint that accepts
        any input. Success for each variant is then confirmed through the
        ``JWTAttackResponseAnalyzer`` baseline comparison (Requirements 60.4, 19)
        rather than by key-format submission alone.

        Returns ``None`` when the baseline request cannot be issued.
        """
        invalid_key = b"apileaks-algorithm-confusion-negative-control-key"
        baseline_token = sign_fn(invalid_key)
        baseline_auth = AuthContext(
            name=f"{auth_context.name}_confusion_baseline",
            type=auth_context.type,
            token=baseline_token,
            privilege_level=auth_context.privilege_level,
        )
        self.http_client.set_auth_context(baseline_auth)
        try:
            baseline_response = await self.http_client.request(method, endpoint_url)
        except Exception as e:
            self.logger.debug("Algorithm-confusion baseline request failed",
                              endpoint=endpoint_url, error=str(e))
            return None
        finally:
            self.http_client.current_auth_context = None

        baseline = BaselineResponse(
            request_details=RequestDetails(url=endpoint_url, method=method, headers={}),
            response_details=self._response_to_details(baseline_response),
        )
        return JWTAttackResponseAnalyzer(baseline)

    async def _test_jwt_algorithm_confusion(self, auth_context: AuthContext,
                                          jwt_token: JWTToken,
                                          endpoints: List[Any]) -> List[Finding]:
        """Test JWT algorithm confusion attack (RS256 -> HS256).

        Iterates over every public-key representation produced by
        ``jwt_utils._public_key_variants`` (PEM with/without a trailing newline,
        DER, and the certificate-derived ``x5c`` bytes) and HMAC-signs the
        UNCHANGED ``header.payload`` with each variant's bytes as the HMAC key,
        varying only the signing key and the ``alg`` header while preserving the
        header and payload segments (Requirements 60.1, 60.2). Each candidate is
        issued through the shared ``HTTPRequestEngine`` and success is confirmed
        through the ``JWTAttackResponseAnalyzer`` baseline comparison
        (Requirements 60.4, 19) rather than by key-format submission alone.

        The server's real public-key bytes are resolved via
        ``_resolve_public_key_bytes`` (Requirements 6.1, 6.2); when no public key
        is available the test is skipped and logged (Requirement 6.3) and literal
        placeholder strings are never used as the HMAC key (Requirement 6.4).
        When any representation produces an accepted token, a
        ``JWT_ALGORITHM_CONFUSION`` finding (OWASP ``API2``) is reported whose
        evidence names the accepted key representation (Requirement 60.3).
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

        if not endpoints:
            return findings

        # Enumerate every derivable public-key representation to attempt as the
        # HMAC key (Requirement 60.1). Representations that cannot be produced
        # from the material are omitted, never raised.
        variants = jwt_utils._public_key_variants(public_key_bytes)
        if not variants:
            self.logger.info(
                "No public-key representation derivable; skipping algorithm-confusion",
                auth_context=auth_context.name
            )
            return findings

        # Build the UNCHANGED header.payload once (alg -> HS256). It is preserved
        # across every representation; only the signing key varies
        # (Requirement 60.2).
        modified_header = jwt_token.header.copy()
        modified_header['alg'] = 'HS256'

        header_json = json.dumps(modified_header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')

        payload_json = json.dumps(jwt_token.payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')

        header_payload = f"{header_b64}.{payload_b64}"

        def _sign(key_bytes: bytes) -> str:
            signature = hmac.new(key_bytes, header_payload.encode(), hashlib.sha256).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            return f"{header_payload}.{signature_b64}"

        test_endpoint = endpoints[0]
        endpoint_url = test_endpoint.url if hasattr(test_endpoint, 'url') else str(test_endpoint)
        method = test_endpoint.method if hasattr(test_endpoint, 'method') else 'GET'

        # Safe mode: the algorithm-confusion probe is a read; never replay a
        # state-changing method (Requirements 21.2, 21.3).
        method = self.safe_read_method(method, "jwt_algorithm_confusion")

        # Establish the negative-control baseline + analyzer (Requirements 60.4, 19).
        analyzer = await self._build_algorithm_confusion_analyzer(
            _sign, endpoint_url, method, auth_context
        )
        if analyzer is None:
            return findings

        try:
            for representation_name, key_bytes in variants:
                # HMAC-sign the unchanged header.payload with this representation's
                # bytes as the key (Requirements 60.1, 60.2).
                confused_token = _sign(key_bytes)

                confused_auth = AuthContext(
                    name=f"{auth_context.name}_confused_{representation_name}",
                    type=auth_context.type,
                    token=confused_token,
                    privilege_level=auth_context.privilege_level
                )

                self.http_client.set_auth_context(confused_auth)
                try:
                    response = await self.http_client.request(method, endpoint_url)
                except Exception as e:
                    self.logger.debug("Algorithm-confusion variant request failed",
                                      representation=representation_name, error=str(e))
                    continue
                finally:
                    self.http_client.current_auth_context = None

                # Confirm success through the analyzer baseline comparison rather
                # than key-format submission alone (Requirements 60.4, 19).
                assessment = analyzer.analyze_attack_response(
                    self._response_to_details(response), AttackType.ALG_NONE
                )
                if not assessment.is_vulnerable:
                    continue

                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_id='',
                    category='JWT_ALGORITHM_CONFUSION',
                    owasp_category='API2',
                    severity=Severity.CRITICAL,
                    endpoint=endpoint_url,
                    method=method,
                    status_code=response.status_code,
                    response_size=len(getattr(response, 'content', b'') or b''),
                    response_time=getattr(response, 'elapsed', 0.0) or 0.0,
                    evidence=(
                        "JWT algorithm confusion attack successful. The RS256 token "
                        "was accepted as an HS256 token signed with the server's real "
                        f"public key in the '{representation_name}' representation as the "
                        "HMAC secret. Confirmed through response-analyzer baseline "
                        f"comparison (confidence {assessment.confidence_score}). "
                        f"Accepted key representation: {representation_name}."
                    ),
                    recommendation="Implement strict algorithm validation. "
                                 "Never allow algorithm switching in JWT verification.",
                    payload=confused_token[:100] + "..." if len(confused_token) > 100 else confused_token
                )
                findings.append(finding)

                self.logger.warning("JWT algorithm confusion detected",
                                    endpoint=endpoint_url,
                                    representation=representation_name)
                # One confirmed representation is sufficient to prove the flaw.
                break

        except Exception as e:
            self.logger.error("Failed to test algorithm confusion", error=str(e))
        finally:
            self.http_client.current_auth_context = None

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
            params, _ = apply_actor_profile(auth_context, endpoint_url)
            request_kwargs = {'params': params} if params else {}
            response = await self.http_client.request(method, endpoint_url, **request_kwargs)
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

    # ------------------------------------------------------------------
    # Aggressive gate + anti-automation / rate-limiting detection
    # (Requirements 37.1-37.6, 46.1, 46.4)
    # ------------------------------------------------------------------

    def _aggressive_allowed(self) -> bool:
        """Return True only when an aggressive auth probe may be issued.

        The auth-side analogue of BOLA's ``_destructive_allowed()``. A high-volume
        probe such as the anti-automation login burst or the token-revocation race
        is permitted only when BOTH Safe_Mode is disabled AND the Aggressive_Opt_In
        (``config.allow_aggressive``) is present (Requirements 37.1, 46.2, 46.3).
        The gate is fail-closed: aggressive probing is disabled by default because
        ``config.allow_aggressive`` defaults to ``False`` (Requirement 46.1).
        """
        return (not self.safe_mode) and bool(
            getattr(self.config, "allow_aggressive", False)
        )

    def _reset_request_allowed(self) -> bool:
        """State-changing password-reset gate (Safe_Mode off AND Destructive_Opt_In).

        Distinct from :meth:`_aggressive_allowed` so a state-changing reset request
        can be authorized independently of the burst/race probes. Returns True only
        when Safe_Mode is disabled AND ``config.allow_destructive`` is set; it is
        fail-closed because ``config.allow_destructive`` defaults to ``False``.
        """
        return (not self.safe_mode) and bool(
            getattr(self.config, "allow_destructive", False)
        )

    def _build_login_burst(self, login_endpoint: str, attempts: int) -> List[Request]:
        """Build at most ``attempts`` login requests for the anti-automation probe.

        Every request targets the same login endpoint using ONE benign username
        (``config.benign_username``) with varied passwords only, so a real account
        is never exhaustively guessed or locked out (Requirement 37.4). The number
        of requests never exceeds ``attempts`` - ``len(result) <= attempts`` is an
        invariant of this builder (Requirements 37.2, 46.4).

        When no benign username is configured a fixed non-personal placeholder is
        used so the burst still targets a single, non-real account.
        """
        count = max(0, int(attempts))
        username = self.config.benign_username or "apileaks_benign_probe"
        requests: List[Request] = []
        for i in range(count):
            # Vary only the password; the username is held constant across the
            # entire burst (Requirement 37.4).
            password = f"AntiAutomationProbe-{i}-Pw!"
            requests.append(Request(
                method="POST",
                url=login_endpoint,
                json={"username": username, "password": password},
            ))
        return requests

    def _classify_throttling(self, responses: List[Response]) -> Dict[str, Any]:
        """Pure classifier for throttling / anti-automation signals.

        Returns ``{"throttled": bool, "evidence": {...}}``. The responses are
        classified as throttled when ANY of the following signals is present
        (Requirements 37.5, 37.6):

        * an HTTP 429 (Too Many Requests) response;
        * an Account_Lockout response - HTTP 403/423 whose body carries a lockout
          signal (e.g. "account locked", "too many attempts", "try again later");
        * an increasing-delay latency trend across the observed responses (a
          non-decreasing latency sequence whose final latency exceeds the first),
          indicating deliberate server-side slow-down.

        The evidence records the concrete signals and per-response status codes and
        latencies so the caller can embed the observed/absent throttling responses
        in a finding (Requirement 37.7).
        """
        status_codes = [r.status_code for r in responses]
        latencies = [float(getattr(r, "elapsed", 0.0) or 0.0) for r in responses]

        has_429 = any(code == 429 for code in status_codes)

        lockout_signals = [
            "account locked", "account has been locked", "account is locked",
            "locked out", "lockout", "too many attempts", "too many requests",
            "too many failed", "try again later", "rate limit", "rate-limit",
            "temporarily locked", "temporarily blocked", "throttled",
        ]

        def _is_lockout(resp: Response) -> bool:
            if resp.status_code not in (403, 423):
                return False
            text = (getattr(resp, "text", "") or "").lower()
            return any(signal in text for signal in lockout_signals)

        has_lockout = any(_is_lockout(r) for r in responses)

        # Increasing-delay trend: at least three samples, a non-decreasing latency
        # sequence, and a final latency strictly greater than the first.
        increasing_delay = False
        if len(latencies) >= 3:
            non_decreasing = all(
                latencies[i] <= latencies[i + 1] for i in range(len(latencies) - 1)
            )
            increasing_delay = non_decreasing and latencies[-1] > latencies[0]

        throttled = has_429 or has_lockout or increasing_delay

        evidence = {
            "throttled": throttled,
            "signals": {
                "http_429": has_429,
                "account_lockout": has_lockout,
                "increasing_delay": increasing_delay,
            },
            "status_codes": status_codes,
            "latencies": latencies,
            "responses_observed": len(responses),
        }
        return {"throttled": throttled, "evidence": evidence}

    async def _test_rate_limiting(self, login_endpoint: str) -> List[Finding]:
        """Anti-automation / rate-limiting probe (Requirement 37).

        Gated by :meth:`_aggressive_allowed`. When aggressive probing is not
        permitted (opt-in absent or Safe_Mode on) the probe is skipped with an
        info-level log and returns no findings (Requirements 37.8, 46). When it is
        permitted, the probe logs the probe type and request count (Requirement
        46.5), then issues a BOUNDED burst (at most ``config.rate_limit_attempts``
        attempts, Requirement 37.2) through the shared ``HTTPRequestEngine`` so the
        operator rate limit is honored (Requirement 37.3), using a single benign
        username with varied passwords (Requirement 37.4).

        The executor stops early on the first throttling signal, so the issued
        request count never exceeds the configured bound (Requirements 37.2, 46.4).
        When NO throttling is observed the probe reports both ``AUTH_NO_RATE_LIMITING``
        (Requirement 37.5) and ``AUTH_CREDENTIAL_STUFFING_EXPOSURE`` (Requirement
        37.6), each mapped to OWASP API2, embedding the number of attempts issued and
        the observed/absent throttling responses as evidence (Requirement 37.7).
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping aggressive auth probe",
                             probe="rate_limiting",
                             reason="opt-in absent or safe mode")
            return findings

        attempts = max(0, int(getattr(self.config, "rate_limit_attempts", 0)))
        self.logger.info("Issuing aggressive auth probe",
                         probe="rate_limiting",
                         endpoint=login_endpoint,
                         requests=attempts)

        burst = self._build_login_burst(login_endpoint, attempts)

        responses: List[Response] = []
        for request in burst:
            try:
                response = await self.http_client.request(
                    request.method,
                    request.url,
                    json=request.json,
                    headers=request.headers,
                )
            except Exception as e:
                self.logger.debug("Login burst request failed",
                                  endpoint=login_endpoint, error=str(e))
                continue

            responses.append(response)

            # Stop early on the first unambiguous throttling signal (429 or an
            # account-lockout response) so the issued count never exceeds the
            # bound and a real endpoint is not hammered once it starts pushing
            # back (Requirements 37.2, 46.4).
            interim = self._classify_throttling(responses)
            interim_signals = interim["evidence"]["signals"]
            if interim_signals["http_429"] or interim_signals["account_lockout"]:
                break

        if not responses:
            self.logger.info("Rate-limiting probe issued no observable responses",
                             endpoint=login_endpoint)
            return findings

        classification = self._classify_throttling(responses)
        attempts_issued = len(responses)

        if classification["throttled"]:
            self.logger.info("Throttling observed; no rate-limiting finding reported",
                             endpoint=login_endpoint,
                             attempts_issued=attempts_issued,
                             signals=classification["evidence"]["signals"])
            return findings

        evidence_detail = (
            f"No throttling observed after {attempts_issued} authentication "
            f"attempt(s) against {login_endpoint} using a single benign username "
            f"with varied passwords. Observed status codes: "
            f"{classification['evidence']['status_codes']}. Throttling signals: "
            f"{classification['evidence']['signals']}."
        )

        last_response = responses[-1]

        no_rate_limit_finding = Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_NO_RATE_LIMITING',
            owasp_category='API2',
            severity=Severity.MEDIUM,
            endpoint=login_endpoint,
            method='POST',
            status_code=last_response.status_code,
            response_size=len(last_response.content),
            response_time=last_response.elapsed,
            evidence=(
                "Authentication endpoint does not enforce rate limiting. "
                + evidence_detail
            ),
            recommendation="Enforce rate limiting and progressive delays or account "
                           "lockout on repeated failed authentication attempts to "
                           "prevent automated abuse.",
        )
        findings.append(no_rate_limit_finding)

        stuffing_finding = Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_CREDENTIAL_STUFFING_EXPOSURE',
            owasp_category='API2',
            severity=Severity.HIGH,
            endpoint=login_endpoint,
            method='POST',
            status_code=last_response.status_code,
            response_size=len(last_response.content),
            response_time=last_response.elapsed,
            evidence=(
                "Absence of rate limiting exposes the authentication endpoint to "
                "credential-stuffing attacks. " + evidence_detail
            ),
            recommendation="Add anti-automation controls (rate limiting, CAPTCHA, "
                           "device/IP reputation, MFA) so the endpoint cannot be used "
                           "for high-volume credential-stuffing.",
        )
        findings.append(stuffing_finding)

        self.logger.warning("No rate limiting detected on authentication endpoint",
                            endpoint=login_endpoint,
                            attempts_issued=attempts_issued)

        return findings

    # ------------------------------------------------------------------
    # Token-revocation race (Requirement 42). Aggressive concurrency probe
    # gated by ``_aggressive_allowed`` (opt-in present AND Safe_Mode off) and
    # bounded by ``config.revocation_race_requests``. Reuses the shared
    # ``HTTPRequestEngine`` and the ``FindingsCollector`` finding schema - none
    # of these are recreated. Bounding/gating is also covered by Property 26
    # (Task 25.3, ``tests/test_auth_aggressive_gating_properties.py``).
    # ------------------------------------------------------------------

    async def _issue_revocation_logout(self, token: str, logout_endpoint: str) -> Response:
        """Issue the logout / token-revocation request bearing ``token``.

        Uses the shared ``HTTPRequestEngine`` so the operator rate limit, proxy,
        UA rotation and TLS controls apply. Kept as a small coroutine factory so
        it can be scheduled concurrently with the protected requests via
        ``asyncio.gather`` (Requirement 42.1).
        """
        return await self.http_client.request(
            "POST",
            logout_endpoint,
            headers={"Authorization": f"Bearer {token}"},
        )

    async def _issue_revocation_protected(self, token: str,
                                          protected_endpoint: str) -> Response:
        """Issue one protected-resource request bearing ``token`` (read-only GET).

        Raced concurrently against the logout to observe whether the token is
        still honored after revocation is issued (Requirement 42.1).
        """
        return await self.http_client.request(
            "GET",
            protected_endpoint,
            headers={"Authorization": f"Bearer {token}"},
        )

    async def _test_revocation_race(self, token: str, logout_endpoint: str,
                                    protected_endpoint: str) -> List[Finding]:
        """Token-revocation race probe (Requirement 42).

        Gated by :meth:`_aggressive_allowed` - the probe runs only when BOTH the
        Aggressive_Opt_In is present AND Safe_Mode is disabled; otherwise it is
        skipped with an info-level log and returns no findings (Requirements
        42.1, 42.5, 46.1-46.3). When permitted, it issues a BOUNDED concurrent
        batch through the shared ``HTTPRequestEngine`` via ``asyncio.gather``:
        one logout/revocation request plus a set of protected-resource requests
        that race against it. The total number of requests issued never exceeds
        ``config.revocation_race_requests`` (one slot is reserved for the logout,
        the remainder race as concurrent protected requests), so the operator
        bound is honored (Requirements 42.2, 46.4). Bounding/gating is also
        proven by Property 26 (Task 25.3).

        When a protected request is accepted (HTTP 2xx) after the logout /
        revocation is issued under concurrency, the token is still honored after
        revocation and an ``AUTH_TOKEN_REVOCATION_RACE`` finding is reported
        (OWASP API2, Requirement 42.3). The finding embeds the concurrent-request
        evidence showing post-logout acceptance (Requirement 42.4).
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping aggressive auth probe",
                             probe="revocation_race",
                             reason="opt-in absent or safe mode")
            return findings

        if not token:
            self.logger.debug("Revocation-race probe skipped; no token supplied",
                              logout_endpoint=logout_endpoint,
                              protected_endpoint=protected_endpoint)
            return findings

        # Bound the concurrency by the operator-configured request count. One
        # request slot is reserved for the logout/revocation; the remainder race
        # as concurrent protected requests. total issued == budget <= bound.
        budget = max(0, int(getattr(self.config, "revocation_race_requests", 0)))
        num_protected = budget - 1
        if num_protected < 1:
            self.logger.info("Revocation-race probe skipped; configured bound too small",
                             logout_endpoint=logout_endpoint,
                             protected_endpoint=protected_endpoint,
                             revocation_race_requests=budget)
            return findings

        self.logger.info("Issuing aggressive auth probe",
                         probe="revocation_race",
                         logout_endpoint=logout_endpoint,
                         protected_endpoint=protected_endpoint,
                         requests=budget)

        # Schedule the logout and the protected requests to run CONCURRENTLY so
        # the protected requests race against the revocation (Requirement 42.1).
        coros = [self._issue_revocation_logout(token, logout_endpoint)]
        coros.extend(
            self._issue_revocation_protected(token, protected_endpoint)
            for _ in range(num_protected)
        )
        results = await asyncio.gather(*coros, return_exceptions=True)

        logout_result = results[0]
        protected_results = results[1:]

        logout_response = logout_result if isinstance(logout_result, Response) else None
        logout_status = logout_response.status_code if logout_response else None
        # The logout must have been accepted (2xx/3xx) for post-revocation
        # acceptance of the token to be meaningful.
        logout_issued = logout_response is not None and 200 <= logout_response.status_code < 400

        accepted: List[Response] = []
        protected_statuses: List[Optional[int]] = []
        for r in protected_results:
            if isinstance(r, Response):
                protected_statuses.append(r.status_code)
                if 200 <= r.status_code < 300:
                    accepted.append(r)
            else:
                protected_statuses.append(None)
                self.logger.debug("Revocation-race protected request failed",
                                  protected_endpoint=protected_endpoint,
                                  error=str(r))

        if not logout_issued:
            self.logger.info("Revocation-race probe: logout not issued/accepted; no finding",
                             logout_endpoint=logout_endpoint,
                             logout_status=logout_status)
            return findings

        if not accepted:
            self.logger.info("Revocation-race probe: token not accepted after logout",
                             protected_endpoint=protected_endpoint,
                             logout_status=logout_status,
                             protected_statuses=protected_statuses)
            return findings

        accepted_response = accepted[-1]
        evidence = (
            f"Under a bounded concurrent batch of {budget} request(s), a logout / "
            f"token-revocation request to {logout_endpoint} was issued (status "
            f"{logout_status}) while {num_protected} protected request(s) to "
            f"{protected_endpoint} raced against it. {len(accepted)} protected "
            f"request(s) were still accepted (HTTP 2xx) after revocation was "
            f"issued, showing the token remained usable during the revocation "
            f"window. Protected-request statuses: {protected_statuses}. The token "
            f"is consumed before being marked revoked (a token-revocation race)."
        )

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_TOKEN_REVOCATION_RACE',
            owasp_category='API2',
            severity=Severity.HIGH,
            endpoint=protected_endpoint,
            method='GET',
            status_code=accepted_response.status_code,
            response_size=len(accepted_response.content),
            response_time=accepted_response.elapsed,
            evidence=evidence,
            recommendation="Revoke tokens atomically with respect to concurrent "
                           "requests. Mark the token/session revoked before releasing "
                           "the logout response, and re-check revocation state at the "
                           "point of use (e.g. via a shared, strongly-consistent token "
                           "denylist) so a token cannot be honored after logout under "
                           "concurrency.",
        )
        findings.append(finding)

        self.logger.warning("Token honored after logout under concurrency (revocation race)",
                            logout_endpoint=logout_endpoint,
                            protected_endpoint=protected_endpoint,
                            logout_status=logout_status,
                            accepted_after_logout=len(accepted))

        return findings

    # ------------------------------------------------------------------
    # Insecure credential transport (Requirement 38) + MFA bypass
    # (Requirement 39). Both probes are read-only GETs and therefore
    # Safe_Mode compatible; access decisions are negative-control calibrated
    # via the shared ``NegativeControlMixin`` so a non-discriminating endpoint
    # cannot yield a false positive.
    # ------------------------------------------------------------------

    def _redact_secret(self, text: str, secret: Optional[str] = None) -> str:
        """Redact credential values in evidence before it is stored.

        Reuses the BOLA module's ``redact_secrets`` (Requirement 38.3, 33.3)
        rather than recreating a redactor: a BOLA instance is created via
        ``__new__`` (so no config/HTTP client is required) purely to invoke the
        shared, self-contained redaction logic. When the concrete ``secret``
        value is known it is additionally replaced with the redaction marker so
        it is never echoed even if it does not match a credential-shaped
        pattern.
        """
        if not text:
            return text

        redacted = text
        if secret:
            redacted = redacted.replace(secret, "<redacted>")

        redactor = self._secret_redactor
        if redactor is None:
            from .bola_testing import BOLATestingModule
            redactor = BOLATestingModule.__new__(BOLATestingModule)
            self._secret_redactor = redactor

        try:
            return redactor.redact_secrets(redacted)
        except Exception:
            # Redaction must never break evidence emission; fall back to the
            # explicitly-redacted text.
            return redacted

    def _build_secret_in_url(self, endpoint: str, param_name: str, secret: str) -> str:
        """Place ``secret`` into the named query parameter of ``endpoint``.

        Reuses the same urlparse/urlencode discipline as the BOLA identifier
        substitution helper: the target query parameter is set to ``secret``
        while every other path segment and query parameter is preserved
        unchanged.
        """
        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [secret]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def _test_secret_in_url(self, endpoint: str,
                                  auth_context: AuthContext) -> List[Finding]:
        """Test whether a VALID secret carried in the URL is accepted (Req 38).

        A valid authentication secret (``auth_context.token``) is placed into
        each candidate credential query parameter in turn and the endpoint is
        requested WITHOUT the normal Authorization header, so any access granted
        is attributable solely to the URL-borne secret (Requirement 38.1). Each
        probe is negative-control calibrated: a baseline is captured with a
        known-invalid secret in the same parameter (Requirement 3). When the
        baseline is non-discriminating (the endpoint answers success for any
        input) the probe is suppressed and logged. When the valid secret grants
        access that the invalid secret does not, an AUTH_SECRET_IN_URL finding
        is reported (API2, Requirement 38.2) whose evidence names the offending
        parameter and the leakage surfaces (server logs, Referer header, browser
        history) with the secret value redacted (Requirement 38.3). The test is
        runtime-only and performs no OSINT or external secret-harvesting
        (Requirement 38.4).
        """
        findings: List[Finding] = []

        secret = getattr(auth_context, 'token', None)
        if not secret:
            self.logger.debug("Secret-in-URL test skipped; no secret in auth context",
                              endpoint=endpoint,
                              auth_context=getattr(auth_context, 'name', None))
            return findings

        for param_name in self.SECRET_URL_PARAM_NAMES:
            invalid_secret = f"apileaks-invalid-secret-{uuid.uuid4().hex}"

            # Negative control: an invalid secret in the SAME parameter, issued
            # with no Authorization header so only the URL value is in play.
            self.http_client.current_auth_context = None
            try:
                baseline = await self.build_negative_control(
                    endpoint,
                    auth_context=None,
                    invalid_id=invalid_secret,
                    substitute=lambda inv: self._build_secret_in_url(endpoint, param_name, inv),
                )
            except Exception as e:
                self.logger.debug("Secret-in-URL negative control failed",
                                  endpoint=endpoint, param=param_name, error=str(e))
                continue

            if baseline.non_discriminating:
                self.logger.info("Secret-in-URL probe suppressed; endpoint non-discriminating",
                                 endpoint=endpoint, param=param_name,
                                 status_code=baseline.status_code)
                continue

            # Probe with the VALID secret in the URL, again with no auth header.
            self.http_client.current_auth_context = None
            probe_url = self._build_secret_in_url(endpoint, param_name, secret)
            try:
                probe_response = await self.http_client.request("GET", probe_url)
            except Exception as e:
                self.logger.debug("Secret-in-URL probe request failed",
                                  endpoint=endpoint, param=param_name, error=str(e))
                continue

            # Accepted only when the response indicates access AND is distinct
            # from the invalid-secret baseline (negative-control calibrated).
            if not (200 <= probe_response.status_code < 300):
                continue
            if responses_equivalent(probe_response, baseline):
                self.logger.debug("URL secret not accepted; equivalent to negative control",
                                  endpoint=endpoint, param=param_name)
                continue

            evidence = (
                f"A valid authentication secret placed in the URL query parameter "
                f"'{param_name}' was accepted as valid authentication (status "
                f"{probe_response.status_code}) without an Authorization header, "
                f"while an invalid secret in the same parameter was rejected "
                f"(negative-control status {baseline.status_code}). Probe URL: "
                f"{probe_url}. Secrets carried in the URL leak through server "
                f"access logs, the Referer header sent to third parties, and "
                f"browser history."
            )
            evidence = self._redact_secret(evidence, secret)

            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_SECRET_IN_URL',
                owasp_category='API2',
                severity=Severity.HIGH,
                endpoint=endpoint,
                method='GET',
                status_code=probe_response.status_code,
                response_size=len(probe_response.content),
                response_time=probe_response.elapsed,
                evidence=evidence,
                recommendation="Never transmit authentication secrets in the URL query "
                               "string. Carry credentials in the Authorization header or a "
                               "secure, HttpOnly cookie so they are not exposed via logs, "
                               "the Referer header, or browser history.",
            )
            findings.append(finding)

            self.logger.warning("Secret accepted in URL query parameter",
                                endpoint=endpoint,
                                param=param_name,
                                status_code=probe_response.status_code)

        return findings

    async def _test_mfa_bypass(self, provisional_token: str,
                               protected_endpoint: str) -> List[Finding]:
        """Test whether a pre-MFA Provisional_Token grants access (Req 39).

        The operator-supplied Provisional_Token (issued before MFA completion)
        is submitted to a protected endpoint and access is observed
        (Requirement 39.1). The decision is negative-control calibrated against a
        baseline captured with a known-invalid token under the same conditions
        (Requirement 39.4, reusing Req 3 infra): when the baseline is
        non-discriminating the probe is suppressed and logged. When the
        provisional token genuinely grants access that the invalid token does
        not, an AUTH_MFA_BYPASS finding is reported (API2, Requirement 39.2)
        including the evidence that access was granted (Requirement 39.3). When
        no multi-step flow inputs are supplied the test is skipped and the
        omission is logged (Requirement 39.5).
        """
        findings: List[Finding] = []

        if not provisional_token or not protected_endpoint:
            self.logger.info("MFA-bypass test skipped for lack of multi-step flow inputs",
                             has_provisional_token=bool(provisional_token),
                             has_protected_endpoint=bool(protected_endpoint))
            return findings

        # Negative control: request the protected endpoint with a known-invalid
        # token under the same conditions the provisional token will use.
        invalid_ctx = AuthContext(
            name="mfa_negative_control",
            type=AuthType.BEARER,
            token=f"apileaks-invalid-token-{uuid.uuid4().hex}",
            privilege_level=0,
        )
        try:
            baseline = await self.build_negative_control(
                protected_endpoint,
                auth_context=invalid_ctx,
            )
        except Exception as e:
            self.logger.debug("MFA-bypass negative control failed",
                              endpoint=protected_endpoint, error=str(e))
            return findings
        finally:
            self.http_client.current_auth_context = None

        if baseline.non_discriminating:
            self.logger.info("MFA-bypass probe suppressed; endpoint non-discriminating",
                             endpoint=protected_endpoint,
                             status_code=baseline.status_code)
            return findings

        # Probe with the operator-supplied Provisional_Token.
        provisional_ctx = AuthContext(
            name="mfa_provisional",
            type=AuthType.BEARER,
            token=provisional_token,
            privilege_level=0,
        )
        try:
            self.http_client.set_auth_context(provisional_ctx)
            probe_response = await self.http_client.request("GET", protected_endpoint)
        except Exception as e:
            self.logger.debug("MFA-bypass probe request failed",
                              endpoint=protected_endpoint, error=str(e))
            return findings
        finally:
            self.http_client.current_auth_context = None

        # Bypass only when the provisional token yields access AND that access is
        # distinct from the invalid-token baseline (negative-control calibrated).
        if not (200 <= probe_response.status_code < 300):
            self.logger.debug("Provisional token did not grant access",
                              endpoint=protected_endpoint,
                              status_code=probe_response.status_code)
            return findings
        if responses_equivalent(probe_response, baseline):
            self.logger.debug("Provisional token access equivalent to negative control",
                              endpoint=protected_endpoint)
            return findings

        evidence = (
            f"A Provisional_Token issued before MFA completion granted access to "
            f"the protected endpoint {protected_endpoint} (status "
            f"{probe_response.status_code}), while a known-invalid token was "
            f"rejected (negative-control status {baseline.status_code}). This "
            f"demonstrates the endpoint does not enforce MFA state, allowing an "
            f"authentication step to be bypassed. Provisional token: "
            f"{provisional_token}."
        )
        evidence = self._redact_secret(evidence, provisional_token)

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_MFA_BYPASS',
            owasp_category='API2',
            severity=Severity.CRITICAL,
            endpoint=protected_endpoint,
            method='GET',
            status_code=probe_response.status_code,
            response_size=len(probe_response.content),
            response_time=probe_response.elapsed,
            evidence=evidence,
            recommendation="Enforce MFA completion server-side before granting access to "
                           "protected resources. A pre-MFA Provisional_Token must not be "
                           "accepted for any resource that requires full authentication.",
        )
        findings.append(finding)

        self.logger.warning("MFA bypass detected via provisional token",
                            endpoint=protected_endpoint,
                            status_code=probe_response.status_code)

        return findings

    # ------------------------------------------------------------------
    # Predictable password-reset token detection (Requirement 40)
    # ------------------------------------------------------------------

    def _get_predictability_analyzer(self) -> Any:
        """Return the shared BOLA identifier-predictability analyzer (Req 40.2).

        The analyzer (``analyze_identifier_predictability`` on
        ``BOLATestingModule``) is a pure function of its arguments, so a BOLA
        instance created via ``__new__`` - with no config or HTTP client - is
        sufficient to invoke it. The exact BOLA implementation is REUSED here
        rather than recreated, so reset-token classification and BOLA identifier
        classification share one source of truth.
        """
        analyzer = self._predictability_analyzer
        if analyzer is None:
            from .bola_testing import BOLATestingModule
            analyzer = BOLATestingModule.__new__(BOLATestingModule)
            self._predictability_analyzer = analyzer
        return analyzer

    async def _test_reset_token_predictability(
        self,
        observed_tokens: List[str],
        known_inputs: Optional[List[str]] = None,
    ) -> List[Finding]:
        """Detect predictable Password_Reset_Tokens (Requirement 40).

        Analyzes the observed Password_Reset_Tokens for predictability
        (Requirement 40.1) by REUSING the shared identifier-predictability
        analyzer (Requirement 40.2). When a token is classified predictable
        (timestamp-based, sequential, or hash-of-known-input such as
        ``MD5(email)``) an ``AUTH_PREDICTABLE_RESET_TOKEN`` finding is reported
        with OWASP_Category API2 including the predictability assessment
        (Requirement 40.3). Random high-entropy tokens (including UUIDv4) are
        classified not predictable and raise no finding.

        Analyzing supplied tokens is READ-ONLY and always permitted. Any
        state-changing password-reset request used to OBSERVE tokens must be
        authorized through :meth:`_reset_request_allowed` (Safe_Mode OFF AND the
        Destructive_Opt_In, Requirement 40.4); while Safe_Mode is enabled such a
        request is NOT issued and the skip is logged (Requirement 40.5). This
        method never issues a state-changing reset request itself - it consumes
        operator-supplied observed tokens - so it is safe under Safe_Mode.
        """
        findings: List[Finding] = []

        tokens = [str(t) for t in (observed_tokens or []) if t is not None and str(t) != '']
        if not tokens:
            # Observing reset tokens live would require a state-changing reset
            # request. Note the Safe_Mode / Destructive_Opt_In posture governing
            # any such observation (Reqs 40.4, 40.5); no request is issued here.
            if self.safe_mode:
                self.logger.info(
                    "Reset-token predictability test skipped; no observed tokens "
                    "and Safe_Mode is enabled so a state-changing reset request "
                    "to observe tokens was not issued",
                    safe_mode=True,
                )
            elif not self._reset_request_allowed():
                self.logger.info(
                    "Reset-token predictability test skipped; no observed tokens "
                    "and the Destructive_Opt_In required to issue a state-changing "
                    "reset request is absent",
                    reset_request_allowed=False,
                )
            else:
                self.logger.info(
                    "Reset-token predictability test skipped for lack of observed "
                    "Password_Reset_Tokens",
                )
            return findings

        analyzer = self._get_predictability_analyzer()
        cleaned_known = (
            [str(k) for k in known_inputs if k is not None and str(k) != '']
            if known_inputs
            else None
        )

        for token in tokens:
            try:
                assessment = analyzer.analyze_identifier_predictability(
                    [token], known_inputs=cleaned_known
                )
            except Exception as e:
                self.logger.debug("Reset-token predictability analysis failed",
                                  error=str(e))
                continue

            if not assessment.predictable:
                self.logger.debug("Reset token classified as not predictable",
                                  scheme=assessment.scheme)
                continue

            evidence = (
                f"An observed Password_Reset_Token was classified as predictable "
                f"(scheme '{assessment.scheme}'). {assessment.rationale} A "
                f"predictable reset token lets an attacker forge or guess a valid "
                f"token and take over an account through the recovery flow."
            )

            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_PREDICTABLE_RESET_TOKEN',
                owasp_category='API2',
                severity=Severity.HIGH,
                endpoint='',
                method='',
                status_code=0,
                response_size=0,
                response_time=0.0,
                evidence=evidence,
                recommendation="Generate password-reset tokens from a cryptographically "
                               "secure random source with sufficient entropy (e.g. 128+ "
                               "bits). Never derive a token from a timestamp, a sequential "
                               "counter, or a hash of a known value such as the account "
                               "email address.",
            )
            findings.append(finding)

            self.logger.warning("Predictable password-reset token detected",
                                scheme=assessment.scheme)

        return findings

    # ------------------------------------------------------------------
    # OAuth / OpenID flow abuse detection (Requirement 41)
    # ------------------------------------------------------------------

    def _coerce_oauth_inputs(self, oauth_inputs: Any) -> Optional[OAuthFlowInputs]:
        """Normalize operator-supplied OAuth inputs into an ``OAuthFlowInputs``.

        Accepts an :class:`OAuthFlowInputs` directly, or a mapping (as carried by
        ``config.oauth_flow_inputs``) whose keys mirror the dataclass fields.
        Returns ``None`` when the inputs are missing or lack the mandatory
        ``authorize_url`` so the caller can skip and log (Requirement 41.6).
        """
        if oauth_inputs is None:
            return None
        if isinstance(oauth_inputs, OAuthFlowInputs):
            return oauth_inputs if oauth_inputs.authorize_url else None
        if isinstance(oauth_inputs, dict):
            if not oauth_inputs:
                return None
            authorize_url = oauth_inputs.get('authorize_url')
            if not authorize_url:
                return None
            return OAuthFlowInputs(
                authorize_url=authorize_url,
                registered_redirect_uri=oauth_inputs.get('registered_redirect_uri', ''),
                attacker_redirect_uri=oauth_inputs.get('attacker_redirect_uri', ''),
                foreign_aud_token=oauth_inputs.get('foreign_aud_token'),
                state_present=bool(oauth_inputs.get('state_present', True)),
            )
        return None

    def _build_redirect_uri_probe(self, authorize_url: str,
                                  attacker_redirect_uri: str) -> str:
        """Build an authorization URL whose ``redirect_uri`` is attacker-controlled.

        The ``redirect_uri`` query parameter is set to the attacker-controlled or
        unregistered value while every other path segment and query parameter of
        the authorization endpoint is preserved (Requirement 41.1), reusing the
        same urlparse/urlencode discipline as the other auth probes.
        """
        parsed = urlparse(authorize_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs['redirect_uri'] = [attacker_redirect_uri]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def _build_redirect_uri_finding(
        self, oauth_inputs: OAuthFlowInputs
    ) -> Optional[Finding]:
        """redirect_uri manipulation sub-probe (Reqs 41.1, 41.2, 41.5).

        Submits an attacker-controlled/unregistered Redirect_URI to the
        authorization endpoint and observes whether the server accepts it. The
        server is considered to accept the attacker redirect when it responds
        successfully (2xx) or issues a redirect (3xx) whose ``Location`` points
        at the attacker redirect URI rather than rejecting the request. On
        acceptance an ``AUTH_OAUTH_REDIRECT_URI`` finding (API2) is returned with
        the accepted Redirect_URI as supporting evidence (Req 41.5).
        """
        if not oauth_inputs.attacker_redirect_uri:
            self.logger.info("OAuth redirect_uri sub-probe skipped; no attacker "
                             "redirect URI supplied")
            return None

        probe_url = self._build_redirect_uri_probe(
            oauth_inputs.authorize_url, oauth_inputs.attacker_redirect_uri
        )
        self.http_client.current_auth_context = None
        try:
            response = await self.http_client.request("GET", probe_url)
        except Exception as e:
            self.logger.debug("OAuth redirect_uri probe request failed",
                              error=str(e))
            return None

        location = ''
        try:
            headers = response.headers or {}
            location = headers.get('Location') or headers.get('location') or ''
        except Exception:
            location = ''

        accepted = False
        if response.is_success:
            accepted = True
        elif response.is_redirect and oauth_inputs.attacker_redirect_uri in location:
            accepted = True

        if not accepted:
            self.logger.debug("Attacker redirect_uri rejected by authorization server",
                              status_code=response.status_code)
            return None

        evidence = (
            f"The authorization server accepted an attacker-controlled or "
            f"unregistered Redirect_URI '{oauth_inputs.attacker_redirect_uri}' "
            f"(status {response.status_code}"
            f"{f', Location: {location}' if location else ''}). The registered "
            f"redirect URI was '{oauth_inputs.registered_redirect_uri}'. Probe "
            f"URL: {probe_url}. An authorization server that fails to strictly "
            f"validate redirect_uri against the registered value allows an "
            f"attacker to capture the authorization code or token."
        )

        self.logger.warning("OAuth redirect_uri manipulation accepted",
                            status_code=response.status_code)

        return Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_OAUTH_REDIRECT_URI',
            owasp_category='API2',
            severity=Severity.HIGH,
            endpoint=oauth_inputs.authorize_url,
            method='GET',
            status_code=response.status_code,
            response_size=len(response.content),
            response_time=response.elapsed,
            evidence=evidence,
            recommendation="Strictly validate the redirect_uri against the exact set of "
                           "redirect URIs registered for the client, using an exact match "
                           "(no prefix or substring matching). Reject any authorization "
                           "request whose redirect_uri is not pre-registered.",
        )

    async def _check_audience_confusion(
        self, oauth_inputs: OAuthFlowInputs
    ) -> Optional[Finding]:
        """Audience-confusion sub-probe (Reqs 41.3, 41.5).

        Presents a token issued for one application (``foreign_aud_token``) to a
        different application (the authorization endpoint host) and observes
        whether it is accepted. When the foreign-audience token is accepted
        (2xx) the ``aud`` claim is not being validated, so an
        ``AUTH_TOKEN_AUDIENCE_CONFUSION`` finding (API2) is returned including the
        Token_Substitution outcome as evidence (Req 41.5). Skipped when no
        foreign-audience token is supplied.
        """
        if not oauth_inputs.foreign_aud_token:
            self.logger.info("OAuth audience-confusion sub-probe skipped; no "
                             "foreign-audience token supplied")
            return None

        foreign_ctx = AuthContext(
            name="oauth_foreign_aud",
            type=AuthType.BEARER,
            token=oauth_inputs.foreign_aud_token,
            privilege_level=0,
        )
        try:
            self.http_client.set_auth_context(foreign_ctx)
            response = await self.http_client.request("GET", oauth_inputs.authorize_url)
        except Exception as e:
            self.logger.debug("OAuth audience-confusion probe request failed",
                              error=str(e))
            return None
        finally:
            self.http_client.current_auth_context = None

        if not response.is_success:
            self.logger.debug("Foreign-audience token rejected",
                              status_code=response.status_code)
            return None

        evidence = (
            f"A token issued for a different application (a foreign Audience_Claim) "
            f"was accepted at {oauth_inputs.authorize_url} (status "
            f"{response.status_code}). The Token_Substitution succeeded, "
            f"demonstrating the application does not validate the 'aud' claim and "
            f"accepts tokens minted for another audience."
        )
        evidence = self._redact_secret(evidence, oauth_inputs.foreign_aud_token)

        self.logger.warning("OAuth token audience confusion detected",
                            status_code=response.status_code)

        return Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_TOKEN_AUDIENCE_CONFUSION',
            owasp_category='API2',
            severity=Severity.HIGH,
            endpoint=oauth_inputs.authorize_url,
            method='GET',
            status_code=response.status_code,
            response_size=len(response.content),
            response_time=response.elapsed,
            evidence=evidence,
            recommendation="Validate the 'aud' (audience) claim on every token and reject "
                           "any token whose audience does not match this application. Do "
                           "not accept tokens minted for a different application or client.",
        )

    def _check_missing_state(
        self, oauth_inputs: OAuthFlowInputs
    ) -> Optional[Finding]:
        """Missing-state sub-probe (Reqs 41.4, 41.5).

        Detects an authorization request that omits or ignores the ``state``
        parameter. The state is considered absent when the operator marks
        ``state_present=False`` or when the authorization URL carries no
        ``state`` query parameter. When absent, an ``AUTH_OAUTH_MISSING_STATE``
        finding (API2) is returned recording the absent state as evidence
        (Req 41.5). This check is read-only (no request issued).
        """
        parsed = urlparse(oauth_inputs.authorize_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        url_has_state = bool(qs.get('state') and any(v for v in qs.get('state', [])))

        # State is present only when the operator confirms it AND the URL carries
        # a non-empty state parameter.
        if oauth_inputs.state_present and url_has_state:
            self.logger.debug("OAuth authorization request carries a state parameter")
            return None

        reasons = []
        if not oauth_inputs.state_present:
            reasons.append("the flow was reported as omitting/ignoring the state parameter")
        if not url_has_state:
            reasons.append("the authorization URL carries no non-empty 'state' query parameter")
        reason_text = " and ".join(reasons) if reasons else "the state parameter is absent"

        evidence = (
            f"The OAuth authorization request at {oauth_inputs.authorize_url} does "
            f"not use a state parameter: {reason_text}. Without a state parameter "
            f"bound to the user session, the flow is vulnerable to CSRF / "
            f"authorization-code injection."
        )

        self.logger.warning("OAuth authorization flow missing state parameter")

        return Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_OAUTH_MISSING_STATE',
            owasp_category='API2',
            severity=Severity.MEDIUM,
            endpoint=oauth_inputs.authorize_url,
            method='GET',
            status_code=0,
            response_size=0,
            response_time=0.0,
            evidence=evidence,
            recommendation="Include an unguessable, session-bound 'state' parameter in every "
                           "OAuth authorization request and verify it on the redirect to "
                           "prevent CSRF and authorization-code injection.",
        )

    async def _test_oauth_flow(self, oauth_inputs: Any) -> List[Finding]:
        """OAuth / OpenID flow abuse detection (Requirement 41).

        Runs three sub-probes against an operator-supplied OAuth_Flow:

        * redirect_uri manipulation - submit an attacker-controlled/unregistered
          Redirect_URI and report ``AUTH_OAUTH_REDIRECT_URI`` (API2) when the
          authorization server accepts it (Reqs 41.1, 41.2);
        * audience confusion - present a token issued for one application to a
          different application and report ``AUTH_TOKEN_AUDIENCE_CONFUSION``
          (API2) when it is accepted because the ``aud`` claim is not validated
          (Req 41.3);
        * missing state - detect an authorization request that omits or ignores
          the ``state`` parameter and report ``AUTH_OAUTH_MISSING_STATE`` (API2)
          (Req 41.4).

        Each finding includes its supporting evidence - the accepted
        Redirect_URI, the Token_Substitution outcome, or the absent state
        parameter (Req 41.5). When no OAuth_Flow inputs are supplied the test is
        skipped and the omission is logged (Req 41.6).
        """
        findings: List[Finding] = []

        inputs = self._coerce_oauth_inputs(oauth_inputs)
        if inputs is None:
            self.logger.info("OAuth flow test skipped for lack of OAuth_Flow inputs")
            return findings

        redirect_finding = await self._build_redirect_uri_finding(inputs)
        if redirect_finding is not None:
            findings.append(redirect_finding)

        audience_finding = await self._check_audience_confusion(inputs)
        if audience_finding is not None:
            findings.append(audience_finding)

        state_finding = self._check_missing_state(inputs)
        if state_finding is not None:
            findings.append(state_finding)

        return findings

    # ==================================================================
    # NIVEL 2 – OTP / MFA Brute-Force (Flujo Secuencial)
    # Detecta ausencia de rate limiting o lockout en endpoints OTP.
    # Requiere: allow_aggressive + otp_endpoint + otp_session_token
    # Finding: AUTH_OTP_NO_RATE_LIMITING (HIGH), AUTH_OTP_BRUTEFORCE_SUCCESS (CRITICAL)
    # ==================================================================

    def _generate_otp_codes(self, digits: int) -> List[str]:
        """Generate all possible OTP codes for ``digits``-digit space (0…10^digits-1)."""
        total = 10 ** digits
        return [str(i).zfill(digits) for i in range(total)]

    async def _test_otp_brute_force(self) -> List[Finding]:
        """Sequential OTP / MFA brute-force probe (Level 2, CWE-307).

        Iterates through the full OTP code space for the configured digit count
        (default: 6 digits = 1,000,000 combinations; typically a 4-digit OTP is
        probed: 10,000 combinations). The probe stops on the FIRST throttling
        signal (429 / 403-lockout) or on discovering a successful OTP. A bounded
        maximum of ``rate_limit_attempts`` (default 10) is used when the full
        space is larger than that bound, so the probe stays safe even against a
        real OTP space.

        Gated by ``_aggressive_allowed()`` (opt-in AND Safe_Mode off). Requires
        ``config.otp_endpoint`` and ``config.otp_session_token``; skipped when
        either is absent.

        Findings emitted:
        - ``AUTH_OTP_NO_RATE_LIMITING`` (HIGH): no throttling observed after the
          configured number of attempts.
        - ``AUTH_OTP_BRUTEFORCE_SUCCESS`` (CRITICAL): a specific OTP code was
          accepted (server returned 2xx).
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping OTP brute-force probe",
                             reason="opt-in absent or safe mode")
            return findings

        otp_endpoint = getattr(self.config, "otp_endpoint", None)
        session_token = getattr(self.config, "otp_session_token", None)
        if not otp_endpoint:
            self.logger.info("OTP brute-force probe skipped; no otp_endpoint configured")
            return findings
        if not session_token:
            self.logger.info("OTP brute-force probe skipped; no otp_session_token configured")
            return findings

        digits = max(4, int(getattr(self.config, "otp_digits", 6)))
        otp_field = getattr(self.config, "otp_field", "otp")
        session_field = getattr(self.config, "otp_session_field", "session_token")
        max_attempts = max(1, int(getattr(self.config, "rate_limit_attempts", 10)))

        codes = self._generate_otp_codes(digits)
        probe_codes = codes[:max_attempts]

        self.logger.info("Starting OTP brute-force probe",
                         endpoint=otp_endpoint,
                         digits=digits,
                         max_attempts=len(probe_codes))

        responses: List[Response] = []
        successful_code: Optional[str] = None

        for code in probe_codes:
            try:
                resp = await self.http_client.request(
                    "POST", otp_endpoint,
                    json={otp_field: code, session_field: session_token},
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:
                self.logger.debug("OTP probe request failed", code=code, error=str(e))
                continue

            responses.append(resp)

            if resp.is_success:
                successful_code = code
                break

            classification = self._classify_throttling(responses)
            signals = classification["evidence"]["signals"]
            if signals["http_429"] or signals["account_lockout"]:
                self.logger.info("OTP endpoint throttled; stopping probe",
                                 code=code, status=resp.status_code)
                break

        if not responses:
            return findings

        if successful_code is not None:
            last = responses[-1]
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_OTP_BRUTEFORCE_SUCCESS',
                owasp_category='API2',
                severity=Severity.CRITICAL,
                endpoint=otp_endpoint,
                method='POST',
                status_code=last.status_code,
                response_size=len(last.content),
                response_time=last.elapsed,
                evidence=(
                    f"OTP code '{successful_code}' was accepted by the endpoint "
                    f"after sequential enumeration. No lockout or rate limiting was "
                    f"triggered after {len(responses)} attempt(s). The "
                    f"{digits}-digit OTP space ({10**digits:,} combinations) is "
                    f"trivially exhausted without protection."
                ),
                recommendation=(
                    "Destroy the OTP code after 3 failed attempts and invalidate "
                    "the session. Enforce a hard rate limit (e.g. 3 req/min) on the "
                    "OTP verification endpoint independently of the main login endpoint."
                ),
                payload=f"{otp_field}={successful_code}",
            ))
            self.logger.warning("OTP brute-force successful",
                                endpoint=otp_endpoint, code=successful_code)
            return findings

        classification = self._classify_throttling(responses)
        if not classification["throttled"]:
            last = responses[-1]
            status_codes = classification["evidence"]["status_codes"]
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_OTP_NO_RATE_LIMITING',
                owasp_category='API2',
                severity=Severity.HIGH,
                endpoint=otp_endpoint,
                method='POST',
                status_code=last.status_code,
                response_size=len(last.content),
                response_time=last.elapsed,
                evidence=(
                    f"The OTP verification endpoint did not throttle or lock the "
                    f"session after {len(responses)} sequential attempt(s). "
                    f"Observed status codes: {status_codes}. A {digits}-digit OTP "
                    f"space ({10**digits:,} combinations) can be exhausted before "
                    f"a typical OTP expiry window."
                ),
                recommendation=(
                    "Apply strict rate limiting (≤3 attempts) AND session invalidation "
                    "on the OTP endpoint. Do NOT rely solely on rate limiting the main "
                    "login endpoint."
                ),
            ))
            self.logger.warning("OTP endpoint lacks rate limiting",
                                endpoint=otp_endpoint, attempts=len(responses))

        return findings

    # ==================================================================
    # NIVEL EXPERTO – OTP Race Condition (Bypass por concurrencia)
    # Envía N peticiones OTP idénticas en paralelo para ganarle al
    # contador atómico de la base de datos antes de que registre el
    # primer intento fallido.
    # Gated por _aggressive_allowed(). Requiere otp_endpoint + otp_session_token.
    # Finding: AUTH_OTP_RACE_CONDITION (CRITICAL)
    # ==================================================================

    async def _test_otp_race_condition(self) -> List[Finding]:
        """OTP race-condition probe (Expert Level, CWE-307 + race hazard).

        Sends ``otp_race_concurrency`` (default 50) identical OTP requests for
        a single fixed code at EXACTLY the same moment via ``asyncio.gather``.
        If the server processes them before the first write increments the
        failed-attempt counter, multiple requests pass the limit check and a
        subset are accepted.

        A single accepted response proves that the counter check is non-atomic
        (TOCTOU). An ``AUTH_OTP_RACE_CONDITION`` (CRITICAL) finding is emitted.
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping OTP race-condition probe",
                             reason="opt-in absent or safe mode")
            return findings

        otp_endpoint = getattr(self.config, "otp_endpoint", None)
        session_token = getattr(self.config, "otp_session_token", None)
        if not otp_endpoint or not session_token:
            self.logger.info("OTP race-condition probe skipped; missing otp_endpoint or token")
            return findings

        digits = max(4, int(getattr(self.config, "otp_digits", 6)))
        otp_field = getattr(self.config, "otp_field", "otp")
        session_field = getattr(self.config, "otp_session_field", "session_token")
        concurrency = max(2, int(getattr(self.config, "otp_race_concurrency", 50)))

        # Use a fixed candidate code (e.g. "000000"). The goal is not to guess
        # the right code but to confirm whether the counter is atomic.
        probe_code = "0" * digits

        self.logger.info("Starting OTP race-condition probe",
                         endpoint=otp_endpoint,
                         concurrency=concurrency,
                         probe_code=probe_code)

        async def _send_one() -> Response:
            return await self.http_client.request(
                "POST", otp_endpoint,
                json={otp_field: probe_code, session_field: session_token},
                headers={"Content-Type": "application/json"},
            )

        try:
            race_responses = await asyncio.gather(
                *[_send_one() for _ in range(concurrency)],
                return_exceptions=True,
            )
        except Exception as e:
            self.logger.error("OTP race-condition gather failed", error=str(e))
            return findings

        valid_responses = [r for r in race_responses if isinstance(r, Response)]
        accepted = [r for r in valid_responses if r.is_success]
        status_codes = [r.status_code for r in valid_responses]

        if not accepted:
            self.logger.info("OTP race-condition probe: no accepted responses",
                             concurrency=concurrency, status_codes=status_codes)
            return findings

        first_accepted = accepted[0]
        findings.append(Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_OTP_RACE_CONDITION',
            owasp_category='API2',
            severity=Severity.CRITICAL,
            endpoint=otp_endpoint,
            method='POST',
            status_code=first_accepted.status_code,
            response_size=len(first_accepted.content),
            response_time=first_accepted.elapsed,
            evidence=(
                f"OTP race condition confirmed: {len(accepted)} of {len(valid_responses)} "
                f"concurrent requests for OTP code '{probe_code}' were accepted (HTTP "
                f"{first_accepted.status_code}). The attempt counter is non-atomic "
                f"(TOCTOU): multiple threads read 'counter=0' before any write "
                f"committed. All {concurrency} requests were dispatched simultaneously "
                f"via asyncio.gather. Status codes observed: {status_codes}."
            ),
            recommendation=(
                "Use a database-level atomic increment (e.g. UPDATE … SET attempts = "
                "attempts + 1 WHERE attempts < 3 RETURNING id) or a distributed lock "
                "(Redis INCR + TTL) so concurrent requests see the same counter state. "
                "Do not use read-then-write patterns for attempt counting."
            ),
            payload=f"concurrency={concurrency}, {otp_field}={probe_code}",
        ))
        self.logger.warning("OTP race condition detected",
                            endpoint=otp_endpoint,
                            accepted=len(accepted),
                            total=len(valid_responses))

        return findings

    # ==================================================================
    # NIVEL 3 AVANZADO – IP Rotation via HTTP Header Injection
    # Detecta si el rate limiting se basa en cabeceras manipulables
    # (X-Forwarded-For, X-Real-IP, etc.) en lugar de la IP real.
    # Finding: AUTH_RATE_LIMIT_IP_BYPASS (HIGH)
    # ==================================================================

    # Standard IP-origin-override headers ordered by prevalence. Rotating these
    # simulates each request appearing to come from a distinct client to a
    # poorly-configured WAF / API Gateway that trusts them blindly.
    _IP_SPOOF_HEADERS: List[str] = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
        "Forwarded",
        "X-Cluster-Client-IP",
    ]

    def _build_ip_spoof_header(self, header_name: str, index: int) -> Dict[str, str]:
        """Return a headers dict spoofing ``header_name`` with a unique internal IP."""
        # Use RFC-5737 documentation addresses (192.0.2.x) to avoid hitting real IPs.
        ip = f"192.0.2.{(index % 254) + 1}"
        if header_name == "Forwarded":
            return {header_name: f"for={ip};proto=https"}
        return {header_name: ip}

    async def _test_ip_header_rate_limit_bypass(self, login_endpoint: str) -> List[Finding]:
        """IP-header rate-limit bypass probe (Level 3, Requirement 37-advanced).

        After confirming that the endpoint has some form of rate limiting (or
        regardless, per ``allow_aggressive``), issues a second burst in which
        each request injects a DIFFERENT value in each of the common IP-origin
        headers. If the burst succeeds (no 429/lockout) while an un-spoofed
        burst would be blocked, the rate limiting is cosmetic and header-based.

        Gated by ``_aggressive_allowed()``. The burst size is bounded by
        ``ip_rotation_burst`` (default 15). Requires ``allow_aggressive``.

        Finding: ``AUTH_RATE_LIMIT_IP_BYPASS`` (HIGH) when spoofed requests
        are NOT throttled after the configured burst size, mapped to API2.
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping IP-header rate-limit bypass probe",
                             reason="opt-in absent or safe mode")
            return findings

        username = getattr(self.config, "benign_username", None) or "apileaks_benign_probe"
        username_field = getattr(self.config, "login_username_field", "username")
        password_field = getattr(self.config, "login_password_field", "password")
        burst_size = max(1, int(getattr(self.config, "ip_rotation_burst", 15)))

        extra_headers_names = list(getattr(self.config, "extra_ip_headers", []) or [])
        all_header_names = self._IP_SPOOF_HEADERS + extra_headers_names

        responses_by_header: Dict[str, List[Response]] = {}

        for header_name in all_header_names:
            spoofed_responses: List[Response] = []
            for i in range(burst_size):
                spoof_headers = self._build_ip_spoof_header(header_name, i)
                spoof_headers["Content-Type"] = "application/json"
                try:
                    resp = await self.http_client.request(
                        "POST", login_endpoint,
                        json={username_field: username,
                              password_field: f"IpRotationProbe-{i}!"},
                        headers=spoof_headers,
                    )
                except Exception as e:
                    self.logger.debug("IP-spoof probe request failed",
                                      header=header_name, error=str(e))
                    continue

                spoofed_responses.append(resp)
                classification = self._classify_throttling(spoofed_responses)
                signals = classification["evidence"]["signals"]
                if signals["http_429"] or signals["account_lockout"]:
                    # Header rotation did not help – endpoint throttled anyway.
                    break

            if spoofed_responses:
                responses_by_header[header_name] = spoofed_responses

        # Identify headers for which the full burst completed without throttling.
        bypassed_headers = []
        for hdr, resps in responses_by_header.items():
            cls = self._classify_throttling(resps)
            if not cls["throttled"] and len(resps) >= burst_size:
                bypassed_headers.append(hdr)

        if not bypassed_headers:
            self.logger.info("IP-header rotation did not bypass rate limiting",
                             login_endpoint=login_endpoint)
            return findings

        status_sample = [
            r.status_code
            for r in responses_by_header[bypassed_headers[0]]
        ]
        findings.append(Finding(
            id=str(uuid.uuid4()),
            scan_id='',
            category='AUTH_RATE_LIMIT_IP_BYPASS',
            owasp_category='API2',
            severity=Severity.HIGH,
            endpoint=login_endpoint,
            method='POST',
            status_code=status_sample[-1] if status_sample else 0,
            response_size=0,
            response_time=0.0,
            evidence=(
                f"Rate limiting was bypassed by rotating the following IP-origin "
                f"HTTP headers: {bypassed_headers}. A burst of {burst_size} "
                f"requests completed with no 429 / account-lockout response when "
                f"each request carried a different spoofed IP in these headers. "
                f"Status codes observed: {status_sample}. The rate-limit counter "
                f"trusts the client-supplied header instead of the connection's "
                f"real IP address."
            ),
            recommendation=(
                "Base rate limiting on the TCP layer's real remote IP address, "
                "NOT on X-Forwarded-For or similar client-supplied headers. If "
                "you MUST trust a proxy header, allowlist only known upstream "
                "proxy IPs and reject or ignore the header from any other source."
            ),
            payload=f"bypassed_headers={bypassed_headers}",
        ))
        self.logger.warning("IP-header rate-limit bypass confirmed",
                            endpoint=login_endpoint,
                            headers=bypassed_headers)

        return findings

    # ==================================================================
    # NIVEL 3 AVANZADO – Password Spraying (1 password × N users)
    # Evade el lockout por cuenta porque cada cuenta solo recibe 1 intento.
    # Requiere: allow_aggressive + users_wordlist + spray_password + login_endpoint
    # Finding: AUTH_PASSWORD_SPRAY_NO_DETECTION (HIGH)
    #          AUTH_PASSWORD_SPRAY_VALID_CREDENTIAL (CRITICAL)
    # ==================================================================

    def _load_users_wordlist(self) -> List[str]:
        """Load a newline-separated users/emails wordlist from ``config.users_wordlist``."""
        path_str = getattr(self.config, "users_wordlist", None)
        if not path_str:
            return []
        path = Path(path_str)
        if not path.exists():
            self.logger.warning("Users wordlist not found", path=str(path))
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            users = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            self.logger.info("Users wordlist loaded", count=len(users), path=str(path))
            return users
        except OSError as e:
            self.logger.error("Failed to read users wordlist", error=str(e))
            return []

    async def _test_password_spraying(self, login_endpoint: str) -> List[Finding]:
        """Password-spraying probe (Level 3 Advanced).

        Tries ONE fixed password (``config.spray_password``) against UP TO
        ``spray_batch_size`` (default 50) usernames loaded from
        ``config.users_wordlist``. Because each account receives at most ONE
        attempt the per-account lockout counter is never incremented enough to
        trigger a lockout, evading threshold-based account-level protection.

        The probe reports:
        - ``AUTH_PASSWORD_SPRAY_VALID_CREDENTIAL`` (CRITICAL) when a 2xx
          response is observed for a specific username (valid credential found).
        - ``AUTH_PASSWORD_SPRAY_NO_DETECTION`` (HIGH) when the full batch
          completes without any throttling or rate-limit signal, meaning the API
          cannot detect the spray pattern.

        Gated by ``_aggressive_allowed()``. Requires ``spray_password``,
        ``users_wordlist``, and a resolved ``login_endpoint``.
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping password-spray probe",
                             reason="opt-in absent or safe mode")
            return findings

        spray_password = getattr(self.config, "spray_password", None)
        if not spray_password:
            self.logger.info("Password-spray probe skipped; no spray_password configured")
            return findings

        users = self._load_users_wordlist()
        if not users:
            self.logger.info("Password-spray probe skipped; no users loaded from wordlist")
            return findings

        username_field = getattr(self.config, "login_username_field", "username")
        password_field = getattr(self.config, "login_password_field", "password")
        batch_size = max(1, int(getattr(self.config, "spray_batch_size", 50)))
        batch = users[:batch_size]

        self.logger.info("Starting password-spray probe",
                         endpoint=login_endpoint,
                         users=len(batch),
                         password="<redacted>")

        responses: List[Response] = []
        valid_username: Optional[str] = None

        for username in batch:
            try:
                resp = await self.http_client.request(
                    "POST", login_endpoint,
                    json={username_field: username, password_field: spray_password},
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:
                self.logger.debug("Spray probe request failed",
                                  username=username, error=str(e))
                continue

            responses.append(resp)

            if resp.is_success:
                valid_username = username
                break

            # Early stop only on global throttling (not per-account, since that
            # is exactly what spraying is designed to evade).
            cls = self._classify_throttling(responses)
            signals = cls["evidence"]["signals"]
            if signals["http_429"]:
                self.logger.info("Global rate limit hit during password spray",
                                 username=username)
                break

        if not responses:
            return findings

        if valid_username is not None:
            last = responses[-1]
            evidence = (
                f"Password-spray attack found a valid credential: username "
                f"'{valid_username}' accepted the sprayed password after "
                f"{len(responses)} attempt(s) across distinct accounts. No "
                f"per-account lockout was triggered."
            )
            evidence = self._redact_secret(evidence, spray_password)
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_PASSWORD_SPRAY_VALID_CREDENTIAL',
                owasp_category='API2',
                severity=Severity.CRITICAL,
                endpoint=login_endpoint,
                method='POST',
                status_code=last.status_code,
                response_size=len(last.content),
                response_time=last.elapsed,
                evidence=evidence,
                recommendation=(
                    "Enforce MFA for all accounts. Implement global rate limiting "
                    "across all usernames (not just per-account). Consider "
                    "behavioral anomaly detection for distributed credential attacks."
                ),
                payload=f"{username_field}={valid_username}",
            ))
            self.logger.warning("Password spray found valid credential",
                                endpoint=login_endpoint, username=valid_username)
            return findings

        cls = self._classify_throttling(responses)
        if not cls["throttled"]:
            last = responses[-1]
            status_codes = cls["evidence"]["status_codes"]
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_PASSWORD_SPRAY_NO_DETECTION',
                owasp_category='API2',
                severity=Severity.HIGH,
                endpoint=login_endpoint,
                method='POST',
                status_code=last.status_code,
                response_size=len(last.content),
                response_time=last.elapsed,
                evidence=(
                    f"A password-spray pattern ({len(responses)} requests across "
                    f"distinct accounts, one attempt each) completed without "
                    f"triggering any global rate limit or anomaly detection. "
                    f"Status codes: {status_codes}. Per-account lockout is "
                    f"ineffective against this technique."
                ),
                recommendation=(
                    "Implement global rate limiting keyed on the originating IP "
                    "(not per-account). Deploy behavioral anomaly detection that "
                    "flags many different accounts attempted from one source in a "
                    "short window. Enforce MFA."
                ),
            ))
            self.logger.warning("Password spray not detected by API",
                                endpoint=login_endpoint, attempts=len(responses))

        return findings

    # ==================================================================
    # NIVEL EXPERTO – Timing Oracle Attack
    # Mide diferencias de tiempo de respuesta (y Content-Length) para
    # distinguir usuarios válidos de inválidos → enumeración de cuentas.
    # Finding: AUTH_TIMING_ORACLE (MEDIUM/HIGH)
    #          AUTH_USERNAME_ENUMERATION_CONTENT_LENGTH (MEDIUM)
    # ==================================================================

    def _compute_timing_stats(self, samples: List[float]) -> Dict[str, float]:
        """Compute mean and standard deviation of a list of response times."""
        if not samples:
            return {"mean": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0}
        n = len(samples)
        mean = sum(samples) / n
        variance = sum((x - mean) ** 2 for x in samples) / n
        return {
            "mean": mean,
            "stddev": variance ** 0.5,
            "min": min(samples),
            "max": max(samples),
        }

    async def _collect_timing_samples(
        self,
        endpoint: str,
        username: str,
        password: str,
        n_samples: int,
        username_field: str,
        password_field: str,
    ) -> Tuple[List[float], List[int]]:
        """Collect ``n_samples`` response times and Content-Lengths for one credential pair."""
        times: List[float] = []
        sizes: List[int] = []
        for _ in range(n_samples):
            try:
                t0 = time.monotonic()
                resp = await self.http_client.request(
                    "POST", endpoint,
                    json={username_field: username, password_field: password},
                    headers={"Content-Type": "application/json"},
                )
                elapsed = time.monotonic() - t0
                times.append(elapsed)
                sizes.append(len(resp.content))
            except Exception:
                continue
        return times, sizes

    async def _test_timing_oracle(self, login_endpoint: str) -> List[Finding]:
        """Timing-attack / username-enumeration probe (Expert Level).

        Measures the MEAN response time for:
        - A known-benign (possibly valid) username with a wrong password.
        - A likely-invalid username (random UUID) with the same wrong password.

        A statistically significant timing difference (> ``timing_threshold``
        seconds, default 50ms) between the two populations indicates that the
        server performs more work for valid usernames (e.g. password hashing
        only when the account exists), leaking user existence.

        A Content-Length difference in the responses is reported separately as
        ``AUTH_USERNAME_ENUMERATION_CONTENT_LENGTH`` (MEDIUM) because differing
        body sizes alone reveal account existence even without timing data.

        Findings:
        - ``AUTH_TIMING_ORACLE`` (HIGH if delta > 2×threshold, else MEDIUM).
        - ``AUTH_USERNAME_ENUMERATION_CONTENT_LENGTH`` (MEDIUM) when Content-
          Length differs for valid vs invalid username responses.

        Requires ``benign_username`` (or falls back to a fixed placeholder).
        Gated by ``allow_aggressive``.
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Skipping timing-oracle probe",
                             reason="opt-in absent or safe mode")
            return findings

        username_field = getattr(self.config, "login_username_field", "username")
        password_field = getattr(self.config, "login_password_field", "password")
        n_samples = max(3, int(getattr(self.config, "timing_samples", 10)))
        threshold = float(getattr(self.config, "timing_threshold", 0.05))

        # Use the benign username (plausibly valid account) vs a UUID placeholder.
        benign = getattr(self.config, "benign_username", None) or "apileaks_benign_probe"
        invalid = f"nonexistent-{uuid.uuid4().hex[:12]}@apileaks.invalid"
        wrong_password = f"WrongPw-{uuid.uuid4().hex[:8]}!"

        self.logger.info("Collecting timing samples",
                         endpoint=login_endpoint,
                         samples=n_samples,
                         benign_user=benign,
                         invalid_user=invalid)

        benign_times, benign_sizes = await self._collect_timing_samples(
            login_endpoint, benign, wrong_password, n_samples,
            username_field, password_field,
        )
        invalid_times, invalid_sizes = await self._collect_timing_samples(
            login_endpoint, invalid, wrong_password, n_samples,
            username_field, password_field,
        )

        if not benign_times or not invalid_times:
            self.logger.info("Timing oracle probe: insufficient samples collected")
            return findings

        benign_stats = self._compute_timing_stats(benign_times)
        invalid_stats = self._compute_timing_stats(invalid_times)
        delta = abs(benign_stats["mean"] - invalid_stats["mean"])

        self.logger.info("Timing oracle stats",
                         benign_mean=round(benign_stats["mean"], 4),
                         invalid_mean=round(invalid_stats["mean"], 4),
                         delta=round(delta, 4),
                         threshold=threshold)

        if delta >= threshold:
            severity = Severity.HIGH if delta >= 2 * threshold else Severity.MEDIUM
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id='',
                category='AUTH_TIMING_ORACLE',
                owasp_category='API2',
                severity=severity,
                endpoint=login_endpoint,
                method='POST',
                status_code=0,
                response_size=0,
                response_time=delta,
                evidence=(
                    f"Timing difference of {delta:.4f}s (>{threshold}s threshold) "
                    f"detected between valid-user responses "
                    f"(mean={benign_stats['mean']:.4f}s, "
                    f"stddev={benign_stats['stddev']:.4f}s, n={len(benign_times)}) "
                    f"and invalid-user responses "
                    f"(mean={invalid_stats['mean']:.4f}s, "
                    f"stddev={invalid_stats['stddev']:.4f}s, n={len(invalid_times)}). "
                    f"The server likely performs additional work (e.g. bcrypt hashing) "
                    f"only when the account exists, enabling username enumeration."
                ),
                recommendation=(
                    "Use constant-time password comparison for ALL usernames, including "
                    "non-existent ones (e.g. hash a dummy password to preserve timing "
                    "parity). Return the same generic error message and response body "
                    "for both invalid-username and wrong-password scenarios."
                ),
            ))
            self.logger.warning("Timing oracle detected",
                                endpoint=login_endpoint, delta=round(delta, 4))

        # Content-Length oracle: same logic, different signal.
        if benign_sizes and invalid_sizes:
            avg_benign_size = sum(benign_sizes) / len(benign_sizes)
            avg_invalid_size = sum(invalid_sizes) / len(invalid_sizes)
            size_delta = abs(avg_benign_size - avg_invalid_size)
            if size_delta >= 5:  # >5-byte difference is meaningful
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    scan_id='',
                    category='AUTH_USERNAME_ENUMERATION_CONTENT_LENGTH',
                    owasp_category='API2',
                    severity=Severity.MEDIUM,
                    endpoint=login_endpoint,
                    method='POST',
                    status_code=0,
                    response_size=int(size_delta),
                    response_time=0.0,
                    evidence=(
                        f"Response Content-Length differs by {size_delta:.1f} bytes "
                        f"between a valid-username request (avg {avg_benign_size:.1f}B) "
                        f"and an invalid-username request (avg {avg_invalid_size:.1f}B). "
                        f"Body-size variations leak account existence independently of "
                        f"timing differences."
                    ),
                    recommendation=(
                        "Return a single generic error message with the same body "
                        "structure (and padding if necessary) for both 'user not found' "
                        "and 'wrong password' scenarios."
                    ),
                ))
                self.logger.warning("Content-Length username enumeration detected",
                                    endpoint=login_endpoint,
                                    size_delta=round(size_delta, 1))

        return findings

    # ==================================================================
    # Orquestador de probes avanzados (Niveles 2, 3 y Experto)
    # Se invoca desde execute_tests cuando allow_aggressive es True.
    # Detecta automáticamente endpoints de login/OTP del conjunto
    # descubierto y ejecuta los nuevos probes.
    # ==================================================================

    # URL path fragments that identify login/authentication endpoints.
    _LOGIN_PATH_PATTERNS: List[str] = [
        "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
        "/api/login", "/api/signin", "/api/v1/auth/login",
        "/api/v1/users/signin", "/api/v1/login", "/api/v2/auth/login",
        "/api/auth/token", "/token", "/api/token", "/oauth/token",
        "/session", "/api/session",
    ]

    def _detect_login_endpoints(self, endpoints: List[Any]) -> List[str]:
        """Return discovered endpoint URLs that look like login/auth endpoints."""
        login_urls: List[str] = []
        for ep in endpoints:
            url = ep.url if hasattr(ep, "url") else str(ep)
            method = (ep.method if hasattr(ep, "method") else "GET").upper()
            if method not in ("POST", "PUT"):
                continue
            url_lower = url.lower()
            if any(pat in url_lower for pat in self._LOGIN_PATH_PATTERNS):
                login_urls.append(url)
        return login_urls

    async def _run_advanced_auth_probes(self, endpoints: List[Any]) -> List[Finding]:
        """Orchestrate Level 2/3/Expert auth probes against discovered endpoints.

        This method is the single integration point for all new attack techniques.
        It is called from ``execute_tests`` ONLY when ``allow_aggressive`` is set
        AND Safe_Mode is off (the ``_aggressive_allowed`` gate is re-checked inside
        each sub-probe for defence-in-depth; this call skips the work entirely if
        neither condition is met, saving the endpoint-scan overhead).

        Sub-probes executed (in order):
        1. OTP sequential brute-force (Level 2).
        2. OTP race condition (Expert).
        3. Rate-limiting / anti-automation detection on login endpoints (Req 37).
        4. IP-header rate-limit bypass (Level 3).
        5. Password spraying (Level 3).
        6. Timing / Content-Length oracle (Expert).
        7. Secret-in-URL credential leakage (Req 38) — per endpoint × auth context.
        8. MFA bypass with provisional token (Req 39) — when inputs configured.
        9. Password-reset token predictability analysis (Req 40) — when samples supplied.
        10. OAuth / OpenID flow abuse (Req 41) — when flow inputs configured.
        """
        findings: List[Finding] = []

        if not self._aggressive_allowed():
            self.logger.info("Advanced auth probes skipped",
                             reason="opt-in absent or safe mode")
            return findings

        # -- OTP probes (endpoint comes from config) -----------------------
        otp_findings = await self._test_otp_brute_force()
        findings.extend(otp_findings)
        self.logger.debug("OTP brute-force probe completed",
                          findings=len(otp_findings))

        otp_race_findings = await self._test_otp_race_condition()
        findings.extend(otp_race_findings)
        self.logger.debug("OTP race-condition probe completed",
                          findings=len(otp_race_findings))

        # -- Login-endpoint probes (auto-detected from discovered set) ------
        login_endpoints = self._detect_login_endpoints(endpoints)
        if not login_endpoints:
            self.logger.info("No login endpoints detected; skipping login-based probes")
        else:
            for login_url in login_endpoints:
                # Req 37: anti-automation / rate-limiting burst
                rate_findings = await self._test_rate_limiting(login_url)
                findings.extend(rate_findings)

                # Req 37 (Level 3): IP-header rotation bypass
                ip_findings = await self._test_ip_header_rate_limit_bypass(login_url)
                findings.extend(ip_findings)

                # Req 37 (Level 3): password spraying (1 password × N users)
                spray_findings = await self._test_password_spraying(login_url)
                findings.extend(spray_findings)

                # Expert: timing / Content-Length oracle (username enumeration)
                timing_findings = await self._test_timing_oracle(login_url)
                findings.extend(timing_findings)

            self.logger.debug("Login-endpoint probes completed",
                              login_endpoints=len(login_endpoints))

        # -- Per-endpoint × auth-context probes ----------------------------
        # Req 38: secret-in-URL (credential leakage via query parameters).
        # Runs for every discovered endpoint against every configured auth context
        # that carries a non-empty token — gating is inside the method itself.
        valid_auth_contexts = [
            ctx for ctx in self.auth_contexts
            if getattr(ctx, 'token', None)
        ]
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            for auth_ctx in valid_auth_contexts:
                secret_url_findings = await self._test_secret_in_url(
                    endpoint_url, auth_ctx
                )
                findings.extend(secret_url_findings)

        if valid_auth_contexts:
            self.logger.debug("Secret-in-URL probes completed",
                              endpoints=len(endpoints),
                              auth_contexts=len(valid_auth_contexts))

        # -- Config-input-driven probes (only run when operator supplies inputs) --
        # Req 39: MFA bypass with a provisional (pre-MFA) token.
        mfa_inputs = getattr(self.config, 'mfa_flow_inputs', None) or {}
        provisional_token = mfa_inputs.get('provisional_token', '')
        protected_endpoint = mfa_inputs.get('protected_endpoint', '')
        mfa_findings = await self._test_mfa_bypass(provisional_token, protected_endpoint)
        findings.extend(mfa_findings)
        self.logger.debug("MFA-bypass probe completed", findings=len(mfa_findings))

        # Req 40: password-reset token predictability analysis.
        reset_token_samples = getattr(self.config, 'reset_token_samples', None) or []
        reset_known_inputs = getattr(self.config, 'reset_token_known_inputs', None)
        reset_findings = await self._test_reset_token_predictability(
            reset_token_samples, reset_known_inputs
        )
        findings.extend(reset_findings)
        self.logger.debug("Reset-token predictability probe completed",
                          findings=len(reset_findings))

        # Req 41: OAuth / OpenID flow abuse (redirect_uri, audience confusion,
        # missing state).
        oauth_inputs = getattr(self.config, 'oauth_flow_inputs', None)
        oauth_findings = await self._test_oauth_flow(oauth_inputs)
        findings.extend(oauth_findings)
        self.logger.debug("OAuth-flow probe completed", findings=len(oauth_findings))

        self.logger.debug("Advanced auth probes completed",
                          login_endpoints=len(login_endpoints) if login_endpoints else 0,
                          findings=len(findings))

        return findings
