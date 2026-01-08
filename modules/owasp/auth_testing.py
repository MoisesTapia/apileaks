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
from core.config import AuthTestingConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


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


class AuthenticationTestingModule(OWASPModule):
    """
    Authentication Testing Module for detecting Broken Authentication
    
    This module implements comprehensive testing for OWASP API Security Top 10 #2:
    - Analyzes JWT vulnerabilities (weak algorithms, algorithm confusion)
    - Tests token expiration validation
    - Detects tokens valid after logout
    - Verifies weak secrets in JWT against wordlist
    - Detects endpoints accessible without authentication
    """
    
    # Weak JWT algorithms that should be flagged
    WEAK_ALGORITHMS = [
        'none',  # No signature
        'HS256',  # When used with weak secrets
        'RS256'   # When confused with HS256
    ]
    
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
        
        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        
        # Load weak secrets wordlist
        self.weak_secrets = self._load_weak_secrets_wordlist()
        
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
            
            # Step 4: Test logout token invalidation
            if self.config.test_logout_invalidation:
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
    
    async def _test_anonymous_access(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test endpoints accessible without authentication (Requirement 2.5)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings for anonymous access vulnerabilities
        """
        findings = []
        self.logger.info("Testing anonymous access to endpoints", count=len(endpoints))
        
        # Clear any authentication context for anonymous testing
        self.http_client.current_auth_context = None
        
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
            
            try:
                # Test access without authentication
                response = await self.http_client.request(method, endpoint_url)
                
                # Check if endpoint is accessible without authentication
                if self._is_endpoint_accessible_anonymously(response):
                    # Determine if this is a critical finding based on endpoint characteristics
                    severity = self._classify_anonymous_access_severity(endpoint_url, response)
                    
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id='',
                        category='AUTH_ANONYMOUS_ACCESS',
                        owasp_category='API2',
                        severity=severity,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=response.status_code,
                        response_size=len(response.content),
                        response_time=response.elapsed,
                        evidence=f"Endpoint accessible without authentication. "
                                f"Status: {response.status_code}, Size: {len(response.content)} bytes. "
                                f"Response indicates successful access to protected resource.",
                        recommendation="Implement proper authentication checks for all protected endpoints. "
                                     "Ensure sensitive operations require valid authentication tokens.",
                        response_snippet=response.text[:500] if response.text else None
                    )
                    findings.append(finding)
                    
                    self.logger.warning("Anonymous access detected",
                                      endpoint=endpoint_url,
                                      method=method,
                                      status_code=response.status_code,
                                      severity=severity.value)
            
            except Exception as e:
                self.logger.debug("Anonymous access test failed",
                                endpoint=endpoint_url,
                                method=method,
                                error=str(e))
        
        return findings
    
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
    
    def _classify_anonymous_access_severity(self, endpoint: str, response: Response) -> Severity:
        """
        Classify severity of anonymous access based on endpoint characteristics
        
        Args:
            endpoint: Endpoint URL
            response: HTTP response
            
        Returns:
            Severity level
        """
        endpoint_lower = endpoint.lower()
        
        # Critical: Admin, management, or sensitive endpoints
        critical_patterns = [
            '/admin', '/management', '/dashboard', '/config',
            '/users', '/accounts', '/orders', '/payments',
            '/api/admin', '/api/management', '/api/users'
        ]
        
        if any(pattern in endpoint_lower for pattern in critical_patterns):
            return Severity.CRITICAL
        
        # High: API endpoints with data
        high_patterns = [
            '/api/', '/v1/', '/v2/', '/rest/',
            'profile', 'settings', 'data'
        ]
        
        if any(pattern in endpoint_lower for pattern in high_patterns):
            # Check response content for sensitive data
            if response.text and len(response.text) > 200:
                sensitive_indicators = [
                    'password', 'token', 'secret', 'key', 'email',
                    'phone', 'address', 'ssn', 'credit'
                ]
                response_lower = response.text.lower()
                if any(indicator in response_lower for indicator in sensitive_indicators):
                    return Severity.CRITICAL
                return Severity.HIGH
        
        # Medium: Other endpoints that should require auth
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
    
    async def _test_jwt_algorithm_confusion(self, auth_context: AuthContext,
                                          jwt_token: JWTToken,
                                          endpoints: List[Any]) -> List[Finding]:
        """Test JWT algorithm confusion attack (RS256 -> HS256)"""
        findings = []
        
        if jwt_token.algorithm != 'RS256':
            return findings  # Only test RS256 tokens
        
        self.logger.info("Testing JWT algorithm confusion attack")
        
        try:
            # Create modified token with HS256 algorithm
            modified_header = jwt_token.header.copy()
            modified_header['alg'] = 'HS256'
            
            # Encode modified header
            header_json = json.dumps(modified_header, separators=(',', ':'))
            header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
            
            # Keep original payload
            payload_json = json.dumps(jwt_token.payload, separators=(',', ':'))
            payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
            
            header_payload = f"{header_b64}.{payload_b64}"
            
            # Try common public key patterns as HMAC secrets
            public_key_patterns = [
                "-----BEGIN PUBLIC KEY-----",
                "-----BEGIN RSA PUBLIC KEY-----",
                "-----BEGIN CERTIFICATE-----",
                "public_key",
                "rsa_public_key",
                "cert"
            ]
            
            for pattern in public_key_patterns:
                try:
                    # Generate HMAC signature using public key pattern as secret
                    signature = hmac.new(
                        pattern.encode(),
                        header_payload.encode(),
                        hashlib.sha256
                    ).digest()
                    
                    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                    confused_token = f"{header_payload}.{signature_b64}"
                    
                    # Test with a sample endpoint
                    if endpoints:
                        test_endpoint = endpoints[0]
                        endpoint_url = test_endpoint.url if hasattr(test_endpoint, 'url') else str(test_endpoint)
                        method = test_endpoint.method if hasattr(test_endpoint, 'method') else 'GET'
                        
                        # Create modified auth context
                        confused_auth = AuthContext(
                            name=f"{auth_context.name}_confused",
                            type=auth_context.type,
                            token=confused_token,
                            privilege_level=auth_context.privilege_level
                        )
                        
                        self.http_client.set_auth_context(confused_auth)
                        response = await self.http_client.request(method, endpoint_url)
                        
                        # If request succeeds, algorithm confusion is possible
                        if response.is_success:
                            finding = Finding(
                                id=str(uuid.uuid4()),
                                scan_id='',
                                category='JWT_ALGORITHM_CONFUSION',
                                owasp_category='API2',
                                severity=Severity.HIGH,
                                endpoint=endpoint_url,
                                method=method,
                                status_code=response.status_code,
                                response_size=len(response.content),
                                response_time=response.elapsed,
                                evidence=f"JWT algorithm confusion attack successful. "
                                        f"RS256 token accepted as HS256 with public key as secret. "
                                        f"Pattern used: {pattern}",
                                recommendation="Implement strict algorithm validation. "
                                             "Never allow algorithm switching in JWT verification.",
                                payload=confused_token[:100] + "..." if len(confused_token) > 100 else confused_token
                            )
                            findings.append(finding)
                            
                            self.logger.warning("JWT algorithm confusion detected",
                                              endpoint=endpoint_url,
                                              pattern=pattern)
                            break
                
                except Exception as e:
                    self.logger.debug("Algorithm confusion test failed",
                                    pattern=pattern,
                                    error=str(e))
        
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
    
    async def _test_with_expired_token(self, auth_context: AuthContext,
                                     jwt_token: JWTToken,
                                     endpoints: List[Any]) -> List[Finding]:
        """Create and test with artificially expired token"""
        findings = []
        
        try:
            # Create expired token by modifying expiration time
            modified_payload = jwt_token.payload.copy()
            modified_payload['exp'] = int(time.time()) - 3600  # Expired 1 hour ago
            
            # For this test, we'll create a token with modified expiration
            # Note: This won't have a valid signature, but we're testing if the server validates expiration
            
            # Encode modified payload
            payload_json = json.dumps(modified_payload, separators=(',', ':'))
            payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
            
            # Keep original header and signature (signature will be invalid, but that's expected)
            token_parts = jwt_token.raw_token.split('.')
            expired_token = f"{token_parts[0]}.{payload_b64}.{token_parts[2]}"
            
            # Create modified auth context
            expired_auth = AuthContext(
                name=f"{auth_context.name}_expired",
                type=auth_context.type,
                token=expired_token,
                privilege_level=auth_context.privilege_level
            )
            
            self.http_client.set_auth_context(expired_auth)
            
            # Test with one endpoint
            if endpoints:
                test_endpoint = endpoints[0]
                endpoint_url = test_endpoint.url if hasattr(test_endpoint, 'url') else str(test_endpoint)
                method = test_endpoint.method if hasattr(test_endpoint, 'method') else 'GET'
                
                try:
                    response = await self.http_client.request(method, endpoint_url)
                    
                    # If modified expired token is accepted (ignoring signature validation),
                    # it suggests weak expiration validation
                    if response.is_success:
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            scan_id='',
                            category='JWT_WEAK_EXPIRATION_VALIDATION',
                            owasp_category='API2',
                            severity=Severity.MEDIUM,
                            endpoint=endpoint_url,
                            method=method,
                            status_code=response.status_code,
                            response_size=len(response.content),
                            response_time=response.elapsed,
                            evidence=f"Token with modified expiration time accepted. "
                                    f"This may indicate weak expiration validation or signature verification issues.",
                            recommendation="Implement proper JWT validation including signature verification "
                                         "and expiration time validation.",
                            payload=expired_token[:100] + "..." if len(expired_token) > 100 else expired_token
                        )
                        findings.append(finding)
                
                except Exception as e:
                    self.logger.debug("Expired token creation test failed",
                                    endpoint=endpoint_url,
                                    error=str(e))
        
        except Exception as e:
            self.logger.error("Failed to test with expired token", error=str(e))
        
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