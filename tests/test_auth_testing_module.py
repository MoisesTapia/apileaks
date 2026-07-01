"""
Tests for Authentication Testing Module
"""

import pytest
import asyncio
import json
import base64
import hmac
import hashlib
import time
from unittest.mock import Mock, AsyncMock, patch, mock_open
from dataclasses import dataclass

from modules.owasp.auth_testing import AuthenticationTestingModule, JWTToken
from utils.http_client import HTTPRequestEngine, Response
from core.config import AuthTestingConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


class TestAuthenticationTestingModule:
    """Test cases for Authentication Testing Module"""
    
    @pytest.fixture
    def auth_config(self):
        """Create authentication testing configuration"""
        return AuthTestingConfig(
            enabled=True,
            jwt_testing=True,
            weak_secrets_wordlist="wordlists/jwt_secrets.txt",
            test_logout_invalidation=True
        )
    
    @pytest.fixture
    def auth_contexts(self):
        """Create auth contexts for testing"""
        # Create a valid JWT token for testing
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # Expires in 1 hour
            "role": "user"
        }
        
        # Create JWT token with weak secret
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Sign with weak secret "secret"
        signature = hmac.new(
            b"secret",
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        # Create expired JWT token
        expired_payload = payload.copy()
        expired_payload["exp"] = int(time.time()) - 3600  # Expired 1 hour ago
        
        expired_payload_b64 = base64.urlsafe_b64encode(json.dumps(expired_payload).encode()).decode().rstrip('=')
        expired_signature = hmac.new(
            b"secret",
            f"{header_b64}.{expired_payload_b64}".encode(),
            hashlib.sha256
        ).digest()
        expired_signature_b64 = base64.urlsafe_b64encode(expired_signature).decode().rstrip('=')
        
        expired_jwt_token = f"{header_b64}.{expired_payload_b64}.{expired_signature_b64}"
        
        # Create JWT with 'none' algorithm
        none_header = {"alg": "none", "typ": "JWT"}
        none_header_b64 = base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip('=')
        none_jwt_token = f"{none_header_b64}.{payload_b64}."
        
        return [
            AuthContext(
                name="user_jwt",
                type=AuthType.JWT,
                token=jwt_token,
                privilege_level=1
            ),
            AuthContext(
                name="expired_user",
                type=AuthType.JWT,
                token=expired_jwt_token,
                privilege_level=1
            ),
            AuthContext(
                name="none_algorithm_user",
                type=AuthType.JWT,
                token=none_jwt_token,
                privilege_level=1
            ),
            AuthContext(
                name="bearer_user",
                type=AuthType.BEARER,
                token="bearer_token_123",
                privilege_level=1
            )
        ]
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        client.current_auth_context = None
        return client
    
    @pytest.fixture
    def mock_wordlist(self):
        """Mock weak secrets wordlist"""
        wordlist_content = """# JWT weak secrets
secret
password
123456
admin
test
key
jwt
token
your-256-bit-secret
"""
        return wordlist_content
    
    @pytest.fixture
    def auth_module(self, auth_config, auth_contexts, mock_http_client, mock_wordlist):
        """Create authentication testing module"""
        with patch("builtins.open", mock_open(read_data=mock_wordlist)):
            with patch("pathlib.Path.exists", return_value=True):
                return AuthenticationTestingModule(auth_config, mock_http_client, auth_contexts)

    @pytest.fixture
    def make_auth_module(self, auth_contexts, mock_http_client, mock_wordlist):
        """Factory to build a module with a custom AuthTestingConfig."""
        def _make(config, contexts=None):
            with patch("builtins.open", mock_open(read_data=mock_wordlist)):
                with patch("pathlib.Path.exists", return_value=True):
                    return AuthenticationTestingModule(
                        config, mock_http_client,
                        contexts if contexts is not None else auth_contexts
                    )
        return _make
    
    def test_module_initialization(self, auth_module, auth_contexts):
        """Test authentication module initialization"""
        assert auth_module.get_module_name() == "auth_testing"
        assert len(auth_module.auth_contexts) == len(auth_contexts)
        assert len(auth_module.weak_secrets) > 0
        assert "secret" in auth_module.weak_secrets
    
    def test_parse_jwt_token_valid(self, auth_module):
        """Test JWT token parsing with valid token"""
        # Create a simple JWT token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user123", "exp": int(time.time()) + 3600}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = "fake_signature"
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        jwt_token = auth_module._parse_jwt_token(token)
        
        assert jwt_token is not None
        assert jwt_token.algorithm == "HS256"
        assert jwt_token.header["alg"] == "HS256"
        assert jwt_token.payload["sub"] == "user123"
        assert jwt_token.signature == signature_b64
    
    def test_parse_jwt_token_with_bearer_prefix(self, auth_module):
        """Test JWT token parsing with Bearer prefix"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user123"}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = "fake_signature"
        
        token = f"Bearer {header_b64}.{payload_b64}.{signature_b64}"
        
        jwt_token = auth_module._parse_jwt_token(token)
        
        assert jwt_token is not None
        assert jwt_token.algorithm == "HS256"
    
    def test_parse_jwt_token_invalid(self, auth_module):
        """Test JWT token parsing with invalid token"""
        invalid_tokens = [
            "invalid.token",  # Only 2 parts
            "invalid",  # Single part
            "invalid.token.signature.extra",  # Too many parts
            "not_base64.not_base64.not_base64"  # Invalid base64
        ]
        
        for token in invalid_tokens:
            jwt_token = auth_module._parse_jwt_token(token)
            assert jwt_token is None
    
    def test_is_endpoint_accessible_anonymously(self, auth_module):
        """Test anonymous endpoint accessibility detection"""
        # Accessible response
        accessible_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"data": "some content", "users": [{"id": 1, "name": "John"}]}',
            text='{"data": "some content", "users": [{"id": 1, "name": "John"}]}',
            url="https://api.example.com/data",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Unauthorized response
        unauthorized_response = Response(
            status_code=401,
            headers={"content-type": "application/json"},
            content=b'{"error": "unauthorized"}',
            text='{"error": "unauthorized"}',
            url="https://api.example.com/protected",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Forbidden response
        forbidden_response = Response(
            status_code=403,
            headers={"content-type": "application/json"},
            content=b'{"error": "forbidden"}',
            text='{"error": "forbidden"}',
            url="https://api.example.com/admin",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Success but with auth error message
        auth_error_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"error": "authentication required"}',
            text='{"error": "authentication required"}',
            url="https://api.example.com/secure",
            elapsed=0.1,
            request_method="GET"
        )
        
        assert auth_module._is_endpoint_accessible_anonymously(accessible_response) == True
        assert auth_module._is_endpoint_accessible_anonymously(unauthorized_response) == False
        assert auth_module._is_endpoint_accessible_anonymously(forbidden_response) == False
        assert auth_module._is_endpoint_accessible_anonymously(auth_error_response) == False
    
    def test_classify_anonymous_access_severity(self, auth_module):
        """Test evidence-based anonymous access severity classification (Req 7.2).

        Severity is driven by the kind of exposed data (credential-grade fields
        escalate to CRITICAL) and endpoint sensitivity, NOT the presence of a
        single keyword such as ``email``.
        """
        resp = Response(
            status_code=200, headers={}, content=b'{}', text='{}',
            url="", elapsed=0.1, request_method="GET"
        )

        # Credential-grade data exposed anonymously => CRITICAL even on an
        # otherwise-benign endpoint.
        assert auth_module._classify_anonymous_access_severity(
            "https://api.example.com/public/info", resp, ["password"]
        ) == Severity.CRITICAL
        assert auth_module._classify_anonymous_access_severity(
            "https://api.example.com/v1/items", resp, ["token"]
        ) == Severity.CRITICAL

        # Sensitive endpoints (admin/users/etc.) => CRITICAL.
        for endpoint in [
            "https://api.example.com/admin/settings",
            "https://api.example.com/management/config",
            "https://api.example.com/users",
            "https://api.example.com/api/users",
        ]:
            assert auth_module._classify_anonymous_access_severity(
                endpoint, resp, ["email"]
            ) == Severity.CRITICAL

        # API endpoints exposing personal (non-credential) data => HIGH.
        for endpoint in [
            "https://api.example.com/api/profile",
            "https://api.example.com/v1/info",
            "https://api.example.com/rest/catalog",
        ]:
            assert auth_module._classify_anonymous_access_severity(
                endpoint, resp, ["email"]
            ) == Severity.HIGH

        # Other endpoints exposing protected data => MEDIUM.
        assert auth_module._classify_anonymous_access_severity(
            "https://example.com/home", resp, ["email"]
        ) == Severity.MEDIUM

        # A single 'email' keyword on a benign endpoint must NOT escalate to
        # CRITICAL (the corrected behavior).
        severity = auth_module._classify_anonymous_access_severity(
            "https://example.com/home", resp, ["email"]
        )
        assert severity != Severity.CRITICAL

        # No protected fields => MEDIUM (lowest anonymous-access classification).
        assert auth_module._classify_anonymous_access_severity(
            "https://example.com/home", resp, []
        ) == Severity.MEDIUM
    
    def test_is_logout_endpoint(self, auth_module):
        """Test logout endpoint detection"""
        logout_endpoints = [
            "https://api.example.com/logout",
            "https://api.example.com/signout",
            "https://api.example.com/api/logout",
            "https://api.example.com/auth/logout",
            "https://api.example.com/user/logout"
        ]
        
        non_logout_endpoints = [
            "https://api.example.com/login",
            "https://api.example.com/users",
            "https://api.example.com/data"
        ]
        
        for endpoint in logout_endpoints:
            assert auth_module._is_logout_endpoint(endpoint) == True
        
        for endpoint in non_logout_endpoints:
            assert auth_module._is_logout_endpoint(endpoint) == False
    
    @pytest.mark.asyncio
    async def test_anonymous_access_detection(self, auth_module, mock_http_client):
        """Test anonymous access detection"""
        endpoints = [
            MockEndpoint("https://api.example.com/users"),
            MockEndpoint("https://api.example.com/admin/config")
        ]
        
        # Mock accessible response (vulnerability)
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"users": [{"id": 1, "name": "John", "email": "john@example.com"}]}',
            text='{"users": [{"id": 1, "name": "John", "email": "john@example.com"}]}',
            url="https://api.example.com/users",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await auth_module._test_anonymous_access(endpoints)
        
        assert len(findings) == 2  # Both endpoints accessible
        for finding in findings:
            assert finding.category == "AUTH_ANONYMOUS_ACCESS"
            assert finding.owasp_category == "API2"
            assert finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_jwt_algorithm_vulnerabilities_none_algorithm(self, auth_module, mock_http_client):
        """Test JWT 'none' algorithm vulnerability detection"""
        # Get the auth context with 'none' algorithm
        none_auth_context = None
        for ctx in auth_module.auth_contexts:
            if ctx.name == "none_algorithm_user":
                none_auth_context = ctx
                break
        
        assert none_auth_context is not None
        
        jwt_token = auth_module._parse_jwt_token(none_auth_context.token)
        assert jwt_token is not None
        assert jwt_token.algorithm == "none"
        
        endpoints = [MockEndpoint("https://api.example.com/test")]
        
        findings = await auth_module._test_jwt_algorithm_vulnerabilities(
            none_auth_context, jwt_token, endpoints
        )
        
        # Should detect 'none' algorithm vulnerability
        none_findings = [f for f in findings if f.category == "JWT_NONE_ALGORITHM"]
        assert len(none_findings) == 1
        assert none_findings[0].severity == Severity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_jwt_weak_secret_detection(self, auth_module, mock_http_client):
        """Test JWT weak secret detection"""
        # Get the JWT auth context (signed with "secret")
        jwt_auth_context = None
        for ctx in auth_module.auth_contexts:
            if ctx.name == "user_jwt":
                jwt_auth_context = ctx
                break
        
        assert jwt_auth_context is not None
        
        jwt_token = auth_module._parse_jwt_token(jwt_auth_context.token)
        assert jwt_token is not None
        assert jwt_token.algorithm == "HS256"
        
        endpoints = [MockEndpoint("https://api.example.com/test")]
        
        findings = await auth_module._test_jwt_weak_secrets(
            jwt_auth_context, jwt_token, endpoints
        )
        
        # Should detect weak secret "secret"
        assert len(findings) == 1
        assert findings[0].category == "JWT_WEAK_SECRET"
        assert findings[0].severity == Severity.HIGH
        assert "secret" in findings[0].evidence
    
    @pytest.mark.asyncio
    async def test_token_expiration_no_exp_claim(self, auth_module, mock_http_client):
        """Test token without expiration claim"""
        # Create token without exp claim
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user123", "iat": int(time.time())}  # No exp claim
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = "fake_signature"
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        no_exp_context = AuthContext(
            name="no_exp_user",
            type=AuthType.JWT,
            token=token,
            privilege_level=1
        )
        
        # Temporarily add to auth contexts
        auth_module.auth_contexts.append(no_exp_context)
        
        endpoints = [MockEndpoint("https://api.example.com/test")]
        
        findings = await auth_module._test_token_expiration(endpoints)
        
        # Should detect missing expiration
        no_exp_findings = [f for f in findings if f.category == "JWT_NO_EXPIRATION"]
        assert len(no_exp_findings) == 1
        assert no_exp_findings[0].severity == Severity.HIGH
    
    @pytest.mark.asyncio
    async def test_expired_token_acceptance(self, auth_module, mock_http_client):
        """Test expired token acceptance"""
        # Get the expired token auth context
        expired_auth_context = None
        for ctx in auth_module.auth_contexts:
            if ctx.name == "expired_user":
                expired_auth_context = ctx
                break
        
        assert expired_auth_context is not None
        
        jwt_token = auth_module._parse_jwt_token(expired_auth_context.token)
        assert jwt_token is not None
        assert jwt_token.payload["exp"] < int(time.time())  # Should be expired
        
        endpoints = [MockEndpoint("https://api.example.com/test")]
        
        # Mock successful response (vulnerability - expired token accepted)
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"data": "success"}',
            text='{"data": "success"}',
            url="https://api.example.com/test",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await auth_module._test_expired_token_acceptance(
            expired_auth_context, jwt_token, endpoints
        )
        
        # Should detect expired token acceptance
        assert len(findings) == 1
        assert findings[0].category == "JWT_EXPIRED_TOKEN_ACCEPTED"
        assert findings[0].severity == Severity.HIGH
    
    @pytest.mark.asyncio
    async def test_logout_invalidation(self, auth_module, mock_http_client):
        """Test logout token invalidation"""
        endpoints = [
            MockEndpoint("https://api.example.com/logout", "POST"),
            MockEndpoint("https://api.example.com/users", "GET"),
            MockEndpoint("https://api.example.com/profile", "GET")
        ]
        
        # Mock successful logout
        logout_response = Response(
            status_code=200,
            headers={},
            content=b'{"message": "logged out"}',
            text='{"message": "logged out"}',
            url="https://api.example.com/logout",
            elapsed=0.1,
            request_method="POST"
        )
        
        # Mock successful access after logout (vulnerability)
        access_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"user": {"id": 123, "name": "John"}}',
            text='{"user": {"id": 123, "name": "John"}}',
            url="https://api.example.com/users",
            elapsed=0.1,
            request_method="GET"
        )
        
        def mock_request_side_effect(method, url):
            if "logout" in url:
                return logout_response
            else:
                return access_response
        
        mock_http_client.request.side_effect = mock_request_side_effect
        
        # Get JWT auth context
        jwt_auth_context = None
        for ctx in auth_module.auth_contexts:
            if ctx.name == "user_jwt":
                jwt_auth_context = ctx
                break
        
        assert jwt_auth_context is not None
        
        logout_endpoints = [endpoints[0]]  # Just the logout endpoint
        all_endpoints = endpoints
        
        findings = await auth_module._test_token_invalidation_after_logout(
            jwt_auth_context, logout_endpoints, all_endpoints
        )
        
        # Should detect token not invalidated after logout
        assert len(findings) == 1
        assert findings[0].category == "JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT"
        assert findings[0].severity == Severity.HIGH
    
    @pytest.mark.asyncio
    async def test_none_algorithm_acceptance(self, auth_module, mock_http_client):
        """Test if endpoints accept 'none' algorithm tokens"""
        # Get a normal JWT context
        jwt_auth_context = None
        for ctx in auth_module.auth_contexts:
            if ctx.name == "user_jwt":
                jwt_auth_context = ctx
                break
        
        assert jwt_auth_context is not None
        
        jwt_token = auth_module._parse_jwt_token(jwt_auth_context.token)
        assert jwt_token is not None
        assert jwt_token.algorithm == "HS256"
        
        endpoints = [MockEndpoint("https://api.example.com/test")]
        
        # Mock successful response (vulnerability - 'none' algorithm accepted)
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"data": "success"}',
            text='{"data": "success"}',
            url="https://api.example.com/test",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await auth_module._test_none_algorithm_acceptance(
            jwt_auth_context, jwt_token, endpoints
        )
        
        # Should detect 'none' algorithm acceptance
        assert len(findings) == 1
        assert findings[0].category == "JWT_NONE_ALGORITHM_ACCEPTED"
        assert findings[0].severity == Severity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_execute_tests_integration(self, auth_module, mock_http_client):
        """Test full authentication testing execution"""
        endpoints = [
            MockEndpoint("https://api.example.com/users"),
            MockEndpoint("https://api.example.com/admin"),
            MockEndpoint("https://api.example.com/logout", "POST")
        ]
        
        # Mock accessible response for anonymous access. Includes protected data
        # (a 'users' collection with email/id) so the corrected, evidence-based
        # anonymous-access detection reports it (Requirement 7.3).
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"users": [{"id": 1, "email": "john@example.com", "role": "user"}]}',
            text='{"users": [{"id": 1, "email": "john@example.com", "role": "user"}]}',
            url="https://api.example.com/users",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await auth_module.execute_tests(endpoints)
        
        # Should return list of findings
        assert isinstance(findings, list)
        
        # Check that we have various types of findings
        categories = [f.category for f in findings]
        
        # Should have anonymous access findings
        assert any("AUTH_ANONYMOUS_ACCESS" in cat for cat in categories)
        
        # Should have JWT-related findings (weak secret, none algorithm, etc.)
        jwt_categories = [cat for cat in categories if "JWT" in cat]
        assert len(jwt_categories) > 0
        
        # All findings should have required attributes
        for finding in findings:
            assert hasattr(finding, 'category')
            assert hasattr(finding, 'severity')
            assert hasattr(finding, 'owasp_category')
            assert finding.owasp_category == "API2"  # All auth findings should be API2


    # ------------------------------------------------------------------
    # Task 6.1 - Algorithm-confusion key sourcing (Requirements 6.1-6.4)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_resolve_public_key_prefers_operator_material(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Operator-supplied public_key_material takes precedence over JWKS (Req 6.1)."""
        auth_config.public_key_material = (
            "-----BEGIN PUBLIC KEY-----\nMIIBmaterial\n-----END PUBLIC KEY-----"
        )
        auth_config.jwks_url = "https://api.example.com/.well-known/jwks.json"
        module = make_auth_module(auth_config)

        key_bytes = await module._resolve_public_key_bytes()

        assert key_bytes == auth_config.public_key_material.encode("utf-8")
        # JWKS must NOT be fetched when material is supplied.
        mock_http_client.request.assert_not_called()
        # Never a literal placeholder.
        assert key_bytes != b"public_key"
        assert b"BEGIN PUBLIC KEY" in key_bytes

    @pytest.mark.asyncio
    async def test_resolve_public_key_from_jwks(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """JWKS RSA key (n/e) is fetched and converted to PEM bytes (Req 6.2)."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = private_key.public_key().public_numbers()

        def int_to_b64(value):
            length = (value.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode().rstrip("=")

        jwks = {"keys": [{
            "kty": "RSA",
            "n": int_to_b64(public_numbers.n),
            "e": int_to_b64(public_numbers.e),
        }]}
        jwks_text = json.dumps(jwks)

        jwks_response = Response(
            status_code=200, headers={"content-type": "application/json"},
            content=jwks_text.encode(), text=jwks_text,
            url="https://api.example.com/jwks.json", elapsed=0.1, request_method="GET"
        )
        mock_http_client.request.return_value = jwks_response

        auth_config.public_key_material = None
        auth_config.jwks_url = "https://api.example.com/jwks.json"
        module = make_auth_module(auth_config)

        key_bytes = await module._resolve_public_key_bytes()

        assert key_bytes is not None
        # The PEM converts back to the same public key numbers.
        recovered = load_pem_public_key(key_bytes).public_numbers()
        assert recovered.n == public_numbers.n
        assert recovered.e == public_numbers.e

    @pytest.mark.asyncio
    async def test_algorithm_confusion_skipped_without_public_key(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """No public key available => algorithm-confusion test is skipped (Req 6.3)."""
        auth_config.public_key_material = None
        auth_config.jwks_url = None
        module = make_auth_module(auth_config)

        rs256_token = self._build_rs256_token()
        jwt_token = module._parse_jwt_token(rs256_token)
        assert jwt_token is not None and jwt_token.algorithm == "RS256"

        endpoints = [MockEndpoint("https://api.example.com/test")]
        findings = await module._test_jwt_algorithm_confusion(
            jwt_token=jwt_token,
            auth_context=AuthContext(name="rs", type=AuthType.JWT, token=rs256_token),
            endpoints=endpoints,
        )

        assert findings == []
        # No attack request issued when there is no key.
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_algorithm_confusion_uses_real_key_no_placeholder(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Confusion token is HMAC-signed with the REAL key bytes, never a
        placeholder (Req 6.1, 6.4)."""
        material = "-----BEGIN PUBLIC KEY-----\nREALKEYBYTES\n-----END PUBLIC KEY-----"
        auth_config.public_key_material = material
        auth_config.jwks_url = None
        module = make_auth_module(auth_config)

        rs256_token = self._build_rs256_token()
        jwt_token = module._parse_jwt_token(rs256_token)

        success = Response(
            status_code=200, headers={}, content=b'{"data": "ok"}', text='{"data": "ok"}',
            url="https://api.example.com/test", elapsed=0.1, request_method="GET"
        )
        mock_http_client.request.return_value = success

        endpoints = [MockEndpoint("https://api.example.com/test")]
        findings = await module._test_jwt_algorithm_confusion(
            jwt_token=jwt_token,
            auth_context=AuthContext(name="rs", type=AuthType.JWT, token=rs256_token),
            endpoints=endpoints,
        )

        assert len(findings) == 1
        assert findings[0].category == "JWT_ALGORITHM_CONFUSION"

        # The confused token must be HMAC-signed with the real key bytes.
        confused_auth = mock_http_client.set_auth_context.call_args[0][0]
        confused_token = confused_auth.token
        header_b64, payload_b64, signature_b64 = confused_token.split(".")
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(material.encode("utf-8"),
                     f"{header_b64}.{payload_b64}".encode(),
                     hashlib.sha256).digest()
        ).decode().rstrip("=")
        assert signature_b64 == expected_sig

        # And NOT signed with any literal placeholder string.
        for placeholder in ("public_key", "-----BEGIN PUBLIC KEY-----", "cert"):
            placeholder_sig = base64.urlsafe_b64encode(
                hmac.new(placeholder.encode(),
                         f"{header_b64}.{payload_b64}".encode(),
                         hashlib.sha256).digest()
            ).decode().rstrip("=")
            assert signature_b64 != placeholder_sig

    # ------------------------------------------------------------------
    # Task 6.2 - Evidence-based anonymous access (Requirements 7.1-7.4)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_anonymous_access_reported_when_equivalent_and_protected(
        self, auth_module, mock_http_client
    ):
        """Protected data + equivalent anon/auth responses => reported (Req 7.3)."""
        body = '{"users": [{"id": 1, "email": "john@example.com", "role": "user"}]}'
        resp = Response(
            status_code=200, headers={}, content=body.encode(), text=body,
            url="https://api.example.com/api/profile", elapsed=0.1, request_method="GET"
        )
        # Anonymous request, then authenticated baseline (identical => equivalent).
        mock_http_client.request.side_effect = [resp, resp]

        findings = await auth_module._test_anonymous_access(
            [MockEndpoint("https://api.example.com/api/profile")]
        )

        assert len(findings) == 1
        assert findings[0].category == "AUTH_ANONYMOUS_ACCESS"
        assert findings[0].owasp_category == "API2"
        assert "equivalent: True" in findings[0].evidence
        assert "email" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_anonymous_access_not_reported_when_responses_differ(
        self, auth_module, mock_http_client
    ):
        """Protected data but anon/auth differ (distinct identity) => not reported (Req 7.1)."""
        anon_body = '{"users": [{"id": 1, "email": "anon@example.com"}]}'
        auth_body = '{"users": [{"id": 2, "email": "real@example.com"}]}'
        anon = Response(200, {}, anon_body.encode(), anon_body,
                        "https://api.example.com/api/profile", 0.1, "GET")
        auth = Response(200, {}, auth_body.encode(), auth_body,
                        "https://api.example.com/api/profile", 0.1, "GET")
        mock_http_client.request.side_effect = [anon, auth]

        findings = await auth_module._test_anonymous_access(
            [MockEndpoint("https://api.example.com/api/profile")]
        )

        assert findings == []

    @pytest.mark.asyncio
    async def test_anonymous_access_not_reported_without_protected_data(
        self, auth_module, mock_http_client
    ):
        """Accessible response with no protected data => not reported (Req 7.3)."""
        body = '{"items": [{"sku": "abc", "price": 10, "category": "tools"}]}'
        resp = Response(200, {}, body.encode(), body,
                        "https://api.example.com/api/items", 0.1, "GET")
        mock_http_client.request.return_value = resp

        findings = await auth_module._test_anonymous_access(
            [MockEndpoint("https://api.example.com/api/items")]
        )

        assert findings == []

    # ------------------------------------------------------------------
    # Task 6.3 - Validly-signed-but-expired token (Requirements 8.1-8.5)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_expired_token_accepted_with_known_secret(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """A validly-signed expired token accepted => JWT_EXPIRED_TOKEN_ACCEPTED (Req 8.1, 8.2)."""
        from utils import jwt_utils

        auth_config.signing_secret = "known-secret"
        module = make_auth_module(auth_config)

        # A current (non-expired) HS256 token to derive header/payload from.
        token = encode_simple_jwt({"alg": "HS256", "typ": "JWT"},
                                  {"sub": "u1", "exp": int(time.time()) + 3600},
                                  "known-secret")
        jwt_token = module._parse_jwt_token(token)

        success = Response(200, {}, b'{"ok": true}', '{"ok": true}',
                           "https://api.example.com/test", 0.1, "GET")
        mock_http_client.request.return_value = success

        findings = await module._test_with_expired_token(
            auth_context=AuthContext(name="u1", type=AuthType.JWT, token=token),
            jwt_token=jwt_token,
            endpoints=[MockEndpoint("https://api.example.com/test")],
        )

        assert len(findings) == 1
        assert findings[0].category == "JWT_EXPIRED_TOKEN_ACCEPTED"

        # The token sent was validly signed with the known secret and expired.
        sent_auth = mock_http_client.set_auth_context.call_args[0][0]
        assert jwt_utils.verify_hmac_secret(sent_auth.token, "known-secret") is True
        decoded = jwt_utils.decode_jwt(sent_auth.token)
        assert decoded["payload"]["exp"] < int(time.time())

    @pytest.mark.asyncio
    async def test_expired_token_test_skipped_without_signing_key(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """No signing key known => expiration test is skipped, no request issued (Req 8.4)."""
        auth_config.signing_secret = None
        module = make_auth_module(auth_config)
        module._recovered_secret = None

        token = encode_simple_jwt({"alg": "HS256", "typ": "JWT"},
                                  {"sub": "u1", "exp": int(time.time()) + 3600},
                                  "whatever")
        jwt_token = module._parse_jwt_token(token)

        findings = await module._test_with_expired_token(
            auth_context=AuthContext(name="u1", type=AuthType.JWT, token=token),
            jwt_token=jwt_token,
            endpoints=[MockEndpoint("https://api.example.com/test")],
        )

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_expired_token_emission_failure_aborts(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """A finding-emission failure must propagate (not be swallowed) (Req 8.3)."""
        auth_config.signing_secret = "known-secret"
        module = make_auth_module(auth_config)

        token = encode_simple_jwt({"alg": "HS256", "typ": "JWT"},
                                  {"sub": "u1", "exp": int(time.time()) + 3600},
                                  "known-secret")
        jwt_token = module._parse_jwt_token(token)

        success = Response(200, {}, b'{"ok": true}', '{"ok": true}',
                           "https://api.example.com/test", 0.1, "GET")
        mock_http_client.request.return_value = success

        with patch("modules.owasp.auth_testing.Finding",
                   side_effect=RuntimeError("emit failure")):
            with pytest.raises(RuntimeError):
                await module._test_with_expired_token(
                    auth_context=AuthContext(name="u1", type=AuthType.JWT, token=token),
                    jwt_token=jwt_token,
                    endpoints=[MockEndpoint("https://api.example.com/test")],
                )

    def test_recovered_weak_secret_used_as_signing_key(
        self, make_auth_module, auth_config
    ):
        """A recovered weak secret is used when no operator secret is set (Req 8.1)."""
        auth_config.signing_secret = None
        module = make_auth_module(auth_config)
        assert module._get_signing_secret() is None
        module._recovered_secret = "recovered"
        assert module._get_signing_secret() == "recovered"
        # Operator-supplied secret takes precedence.
        auth_config.signing_secret = "operator"
        assert module._get_signing_secret() == "operator"

    # ------------------------------------------------------------------
    # Task 6.4 - Context-aware weak-algorithm labeling (Requirements 9.1, 9.2)
    # ------------------------------------------------------------------

    def test_weak_algorithm_labeling_context_aware(self, auth_module):
        """Only 'none' (or demonstrated weak HMAC) is weak; HS256/RS256 are not (Req 9.1, 9.2)."""
        # 'none' is always weak.
        assert auth_module._is_weak_algorithm("none") is True
        assert auth_module._is_weak_algorithm("NONE") is True

        # HS256/RS256 are NOT inherently weak.
        assert auth_module._is_weak_algorithm("HS256") is False
        assert auth_module._is_weak_algorithm("RS256") is False
        assert auth_module._is_weak_algorithm("HS512") is False

        # HMAC algorithm with a demonstrated recovered weak secret IS weak.
        assert auth_module._is_weak_algorithm("HS256", recovered_secret="secret") is True

        # A recovered secret does not make RS256 (non-HMAC) weak.
        assert auth_module._is_weak_algorithm("RS256", recovered_secret="secret") is False

        # Defensive: None / empty.
        assert auth_module._is_weak_algorithm(None) is False
        assert auth_module._is_weak_algorithm("") is False

    # ------------------------------------------------------------------
    # Task 6.5 - Safe-Mode-gated logout test (Requirements 9.3-9.5, 21.x)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_logout_invalidation_skipped_in_safe_mode(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Safe Mode on => logout-invalidation test is skipped (Req 9.3, 21.2)."""
        auth_config.safe_mode = True
        auth_config.test_logout_invalidation = True
        module = make_auth_module(auth_config)

        findings = await module._test_logout_invalidation(
            [MockEndpoint("https://api.example.com/logout", "POST")]
        )

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_logout_invalidation_skipped_when_disabled(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """config.test_logout_invalidation == False => skipped regardless of Safe Mode (Req 9.5)."""
        auth_config.safe_mode = False
        auth_config.test_logout_invalidation = False
        module = make_auth_module(auth_config)

        findings = await module._test_logout_invalidation(
            [MockEndpoint("https://api.example.com/logout", "POST")]
        )

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_logout_invalidation_runs_when_safe_mode_off(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Safe Mode off => logout-invalidation test runs and can report (Req 9.4)."""
        auth_config.safe_mode = False
        auth_config.test_logout_invalidation = True
        module = make_auth_module(auth_config)

        logout = Response(200, {}, b'{"message": "ok"}', '{"message": "ok"}',
                          "https://api.example.com/logout", 0.1, "POST")
        access = Response(200, {}, b'{"user": {"id": 1}}', '{"user": {"id": 1}}',
                          "https://api.example.com/users", 0.1, "GET")

        def side_effect(method, url):
            return logout if "logout" in url else access

        mock_http_client.request.side_effect = side_effect

        endpoints = [
            MockEndpoint("https://api.example.com/logout", "POST"),
            MockEndpoint("https://api.example.com/users", "GET"),
        ]
        findings = await module._test_logout_invalidation(endpoints)

        assert any(f.category == "JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT" for f in findings)

    def _build_rs256_token(self) -> str:
        """Build an RS256-headed token (signature value is irrelevant for the
        confusion test, which re-signs with HS256)."""
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "user123", "role": "admin"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{'A' * 32}"


def encode_simple_jwt(header: dict, payload: dict, secret: str) -> str:
    """Helper: encode an HS256 JWT for tests."""
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(),
                         hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


if __name__ == "__main__":
    pytest.main([__file__])