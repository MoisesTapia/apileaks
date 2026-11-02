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

from modules.owasp.auth_testing import AuthenticationTestingModule, JWTToken, OAuthFlowInputs
from utils.http_client import HTTPRequestEngine, Response
from utils import jwt_utils
from core.config import AuthTestingConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


def _make_rsa_public_key_pem() -> str:
    """Generate a real RSA public key in PEM (SubjectPublicKeyInfo) form.

    Used by the algorithm-confusion key-variant tests so that
    ``jwt_utils._public_key_variants`` can parse the material and derive the
    ``pem_with_newline`` / ``pem_without_newline`` / ``der`` representations.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _make_self_signed_cert_pem() -> str:
    """Generate a real self-signed X.509 certificate in PEM form.

    Certificate material lets ``_public_key_variants`` additionally derive the
    certificate-bound ``x5c_cert_der`` representation (four variants total).
    """
    import datetime as _dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "apileaks-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _hmac_sig_b64(key_bytes: bytes, header_payload: str) -> str:
    """Compute the base64url HMAC-SHA256 signature segment for a header.payload."""
    signature = hmac.new(key_bytes, header_payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


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
        """Confusion token is HMAC-signed with the REAL key-representation bytes,
        never a placeholder (Req 6.1, 6.4, 60.2).

        A negative-control baseline (invalid HMAC key) is rejected while the
        public-key-derived variant is accepted, so success is confirmed through
        the response-analyzer baseline comparison (Req 60.4)."""
        material = _make_rsa_public_key_pem()
        auth_config.public_key_material = material
        auth_config.jwks_url = None
        module = make_auth_module(auth_config)

        rs256_token = self._build_rs256_token()
        jwt_token = module._parse_jwt_token(rs256_token)

        rejected = Response(
            status_code=401, headers={}, content=b'{"error": "unauthorized"}',
            text='{"error": "unauthorized"}',
            url="https://api.example.com/test", elapsed=0.1, request_method="GET"
        )
        accepted = Response(
            status_code=200, headers={}, content=b'{"data": "ok"}', text='{"data": "ok"}',
            url="https://api.example.com/test", elapsed=0.1, request_method="GET"
        )
        # 1st call = negative-control baseline (rejected), 2nd = first variant (accepted).
        mock_http_client.request.side_effect = [rejected, accepted]

        endpoints = [MockEndpoint("https://api.example.com/test")]
        findings = await module._test_jwt_algorithm_confusion(
            jwt_token=jwt_token,
            auth_context=AuthContext(name="rs", type=AuthType.JWT, token=rs256_token),
            endpoints=endpoints,
        )

        assert len(findings) == 1
        assert findings[0].category == "JWT_ALGORITHM_CONFUSION"
        assert findings[0].owasp_category == "API2"

        # The accepted confused token must be HMAC-signed with a REAL public-key
        # representation, never a placeholder. The last set_auth_context call is
        # the variant that was accepted.
        variants = dict(jwt_utils._public_key_variants(material.encode("utf-8")))
        confused_auth = mock_http_client.set_auth_context.call_args[0][0]
        confused_token = confused_auth.token
        header_b64, payload_b64, signature_b64 = confused_token.split(".")
        header_payload = f"{header_b64}.{payload_b64}"

        # It matches exactly one of the real public-key representation bytes.
        assert signature_b64 in {
            _hmac_sig_b64(kb, header_payload) for kb in variants.values()
        }

        # And NOT signed with any literal placeholder string.
        for placeholder in ("public_key", "-----BEGIN PUBLIC KEY-----", "cert"):
            assert signature_b64 != _hmac_sig_b64(placeholder.encode(), header_payload)

    @pytest.mark.asyncio
    async def test_algorithm_confusion_attempts_every_representation(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Every derivable public-key representation is attempted as the HMAC key
        (Req 60.1). Certificate material yields all four representations."""
        cert_pem = _make_self_signed_cert_pem()
        auth_config.public_key_material = cert_pem
        auth_config.jwks_url = None
        module = make_auth_module(auth_config)

        rs256_token = self._build_rs256_token()
        jwt_token = module._parse_jwt_token(rs256_token)

        # Every request (baseline + each variant) is rejected -> no finding, but
        # every representation must still have been submitted.
        rejected = Response(
            status_code=401, headers={}, content=b'{"error": "unauthorized"}',
            text='{"error": "unauthorized"}',
            url="https://api.example.com/test", elapsed=0.1, request_method="GET"
        )
        mock_http_client.request.return_value = rejected

        endpoints = [MockEndpoint("https://api.example.com/test")]
        findings = await module._test_jwt_algorithm_confusion(
            jwt_token=jwt_token,
            auth_context=AuthContext(name="rs", type=AuthType.JWT, token=rs256_token),
            endpoints=endpoints,
        )

        # No representation was accepted -> no finding reported.
        assert findings == []

        # The certificate produces representations including the four core ones.
        expected_reps = {name for name, _ in
                         jwt_utils._public_key_variants(cert_pem.encode("utf-8"))}
        assert {"pem_with_newline", "pem_without_newline", "der", "x5c_cert_der"}.issubset(expected_reps)

        # Each representation was attempted through the shared HTTP client: the
        # per-variant auth contexts name the representation submitted.
        submitted_names = [
            call.args[0].name for call in mock_http_client.set_auth_context.call_args_list
        ]
        for rep in expected_reps:
            assert any(name.endswith(f"_confused_{rep}") for name in submitted_names), rep
        # A negative-control baseline was established first.
        assert any(name.endswith("_confusion_baseline") for name in submitted_names)

    @pytest.mark.asyncio
    async def test_algorithm_confusion_evidence_names_accepted_representation(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """The finding evidence names the accepted key representation (Req 60.3),
        confirmed via the analyzer baseline comparison (Req 60.4)."""
        material = _make_rsa_public_key_pem()
        auth_config.public_key_material = material
        auth_config.jwks_url = None
        module = make_auth_module(auth_config)

        rs256_token = self._build_rs256_token()
        jwt_token = module._parse_jwt_token(rs256_token)

        # Representation order from the helper (pem_with_newline first).
        variants = jwt_utils._public_key_variants(material.encode("utf-8"))
        variant_names = [name for name, _ in variants]
        # The SECOND representation is the one the target accepts.
        accepted_rep = variant_names[1]

        rejected = Response(
            status_code=401, headers={}, content=b'{"error": "unauthorized"}',
            text='{"error": "unauthorized"}',
            url="https://api.example.com/test", elapsed=0.1, request_method="GET"
        )
        accepted = Response(
            status_code=200, headers={}, content=b'{"data": "ok", "user": {"id": 1}}',
            text='{"data": "ok", "user": {"id": 1}}',
            url="https://api.example.com/test", elapsed=0.1, request_method="GET"
        )
        # baseline rejected, first variant rejected, second variant accepted.
        mock_http_client.request.side_effect = [rejected, rejected, accepted]

        endpoints = [MockEndpoint("https://api.example.com/test")]
        findings = await module._test_jwt_algorithm_confusion(
            jwt_token=jwt_token,
            auth_context=AuthContext(name="rs", type=AuthType.JWT, token=rs256_token),
            endpoints=endpoints,
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "JWT_ALGORITHM_CONFUSION"
        assert finding.owasp_category == "API2"
        # Evidence names exactly the accepted representation.
        assert accepted_rep in finding.evidence
        # The token that was accepted was signed with that representation's bytes.
        accepted_key_bytes = dict(variants)[accepted_rep]
        confused_auth = mock_http_client.set_auth_context.call_args[0][0]
        assert confused_auth.name.endswith(f"_confused_{accepted_rep}")
        header_b64, payload_b64, signature_b64 = confused_auth.token.split(".")
        assert signature_b64 == _hmac_sig_b64(
            accepted_key_bytes, f"{header_b64}.{payload_b64}"
        )
        # Header/payload preserved: alg switched to HS256, payload unchanged (Req 60.2).
        import json as _json
        decoded_header = _json.loads(
            base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4))
        )
        decoded_payload = _json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )
        assert decoded_header["alg"] == "HS256"
        assert decoded_payload == jwt_token.payload

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


# ======================================================================
# Task 31.1 - Advanced auth-module example-based unit tests
# (Requirements 37.7, 38.1, 39.1, 39.2, 40.1, 40.4, 41.1, 41.2, 41.3, 42.1)
#
# Example-based coverage for the hardened Auth_Module probes:
#   * throttling-signal classification (429 / lockout / increasing-delay)
#   * secret-in-URL detection + redaction
#   * MFA bypass including non-discriminating suppression
#   * reset-token predictability + Safe-Mode/opt-in skip logging
#   * the three OAuth sub-probes (redirect_uri / aud / state)
#   * the bounded token-revocation race
# ======================================================================


def _resp(status_code=200, body="{}", url="https://api.example.com/x",
          method="GET", elapsed=0.1, headers=None):
    """Build a Response with sensible defaults for these example tests."""
    if isinstance(body, str):
        content = body.encode()
        text = body
    else:
        content = body
        text = body.decode(errors="replace")
    return Response(
        status_code=status_code,
        headers=headers or {},
        content=content,
        text=text,
        url=url,
        elapsed=elapsed,
        request_method=method,
    )


# --- Module-level fixtures shared by the Task 31.1 test classes below ---

@pytest.fixture
def auth_config():
    """Fresh AuthTestingConfig for the advanced-probe tests."""
    return AuthTestingConfig(
        enabled=True,
        jwt_testing=True,
        weak_secrets_wordlist="wordlists/jwt_secrets.txt",
        test_logout_invalidation=True,
    )


@pytest.fixture
def auth_contexts():
    """A single valid bearer context is sufficient for the advanced probes."""
    return [
        AuthContext(
            name="user",
            type=AuthType.BEARER,
            token="bearer_token_123",
            privilege_level=1,
        )
    ]


@pytest.fixture
def mock_http_client():
    """Mock HTTP client with async request()."""
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    client.current_auth_context = None
    return client


@pytest.fixture
def make_auth_module(auth_contexts, mock_http_client):
    """Factory to build a module with a custom AuthTestingConfig."""
    wordlist = "secret\npassword\nadmin\n"

    def _make(config, contexts=None):
        with patch("builtins.open", mock_open(read_data=wordlist)):
            with patch("pathlib.Path.exists", return_value=True):
                return AuthenticationTestingModule(
                    config, mock_http_client,
                    contexts if contexts is not None else auth_contexts,
                )
    return _make


@pytest.fixture
def auth_module(make_auth_module, auth_config):
    """A default-config auth module for pure-classifier / builder tests."""
    return make_auth_module(auth_config)


class TestThrottlingSignals:
    """Requirement 37.5-37.7: classify 429 / lockout / increasing-delay signals."""

    def test_http_429_is_throttled(self, auth_module):
        responses = [_resp(200), _resp(200), _resp(429)]
        result = auth_module._classify_throttling(responses)
        assert result["throttled"] is True
        signals = result["evidence"]["signals"]
        assert signals["http_429"] is True
        assert signals["account_lockout"] is False
        # Evidence records issued-count and observed status codes (Req 37.7).
        assert result["evidence"]["responses_observed"] == 3
        assert 429 in result["evidence"]["status_codes"]

    def test_account_lockout_is_throttled(self, auth_module):
        lockout = _resp(423, body='{"error": "account locked, try again later"}')
        responses = [_resp(200), lockout]
        result = auth_module._classify_throttling(responses)
        assert result["throttled"] is True
        assert result["evidence"]["signals"]["account_lockout"] is True

    def test_lockout_403_with_too_many_attempts(self, auth_module):
        lockout = _resp(403, body='{"message": "Too many attempts"}')
        result = auth_module._classify_throttling([lockout])
        assert result["throttled"] is True
        assert result["evidence"]["signals"]["account_lockout"] is True

    def test_increasing_delay_is_throttled(self, auth_module):
        # Non-decreasing latency with final > first, >= 3 samples.
        responses = [
            _resp(200, elapsed=0.1),
            _resp(200, elapsed=0.4),
            _resp(200, elapsed=0.9),
        ]
        result = auth_module._classify_throttling(responses)
        assert result["throttled"] is True
        assert result["evidence"]["signals"]["increasing_delay"] is True

    def test_flat_latency_not_throttled(self, auth_module):
        responses = [
            _resp(200, elapsed=0.2),
            _resp(200, elapsed=0.2),
            _resp(200, elapsed=0.2),
        ]
        result = auth_module._classify_throttling(responses)
        assert result["throttled"] is False
        assert result["evidence"]["signals"]["increasing_delay"] is False

    def test_no_throttling_signals(self, auth_module):
        responses = [_resp(200), _resp(401), _resp(200)]
        result = auth_module._classify_throttling(responses)
        assert result["throttled"] is False
        sig = result["evidence"]["signals"]
        assert not any([sig["http_429"], sig["account_lockout"], sig["increasing_delay"]])

    @pytest.mark.asyncio
    async def test_rate_limiting_reports_when_no_throttling(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """No throttling with aggressive opt-in => both findings, evidence has attempts (Req 37.5-37.7)."""
        auth_config.safe_mode = False
        auth_config.allow_aggressive = True
        auth_config.rate_limit_attempts = 4
        auth_config.benign_username = "probe_user"
        module = make_auth_module(auth_config)

        mock_http_client.request.return_value = _resp(
            200, body='{"error": "invalid credentials"}',
            url="https://api.example.com/login", method="POST"
        )

        findings = await module._test_rate_limiting("https://api.example.com/login")

        categories = {f.category for f in findings}
        assert "AUTH_NO_RATE_LIMITING" in categories
        assert "AUTH_CREDENTIAL_STUFFING_EXPOSURE" in categories
        for f in findings:
            assert f.owasp_category == "API2"
            # Evidence embeds the number of attempts issued (Req 37.7).
            assert "4" in f.evidence
        # Bounded to the configured attempt count (Req 37.2).
        assert mock_http_client.request.await_count == 4

    @pytest.mark.asyncio
    async def test_rate_limiting_skipped_without_opt_in(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Aggressive opt-in absent => probe skipped, no requests (Req 37.8)."""
        auth_config.safe_mode = False
        auth_config.allow_aggressive = False
        module = make_auth_module(auth_config)

        findings = await module._test_rate_limiting("https://api.example.com/login")

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_rate_limiting_stops_early_on_429(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """A 429 signal stops the burst early and yields no finding (Req 37.2, 37.5)."""
        auth_config.safe_mode = False
        auth_config.allow_aggressive = True
        auth_config.rate_limit_attempts = 10
        module = make_auth_module(auth_config)

        mock_http_client.request.return_value = _resp(
            429, body='{"error": "too many requests"}',
            url="https://api.example.com/login", method="POST"
        )

        findings = await module._test_rate_limiting("https://api.example.com/login")

        assert findings == []
        # Stopped after the first 429 rather than issuing all 10.
        assert mock_http_client.request.await_count == 1


class TestSecretInUrl:
    """Requirement 38: valid secret accepted in URL query string + redaction."""

    @pytest.mark.asyncio
    async def test_secret_in_url_detected_and_redacted(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Valid secret in URL accepted while invalid rejected => AUTH_SECRET_IN_URL (Req 38.1-38.3)."""
        module = make_auth_module(auth_config)
        secret = "super-secret-token-value-123"
        ctx = AuthContext(name="u", type=AuthType.BEARER, token=secret, privilege_level=1)

        # Negative control (invalid secret) is rejected (401); the valid secret is
        # accepted (200) with distinct content so the probe reports.
        def side_effect(method, url, **kwargs):
            if secret in url:
                return _resp(200, body='{"data": "authenticated ok"}', url=url, method=method)
            return _resp(401, body='{"error": "unauthorized"}', url=url, method=method)

        mock_http_client.request.side_effect = side_effect

        findings = await module._test_secret_in_url("https://api.example.com/data", ctx)

        assert len(findings) >= 1
        f = findings[0]
        assert f.category == "AUTH_SECRET_IN_URL"
        assert f.owasp_category == "API2"
        # The offending parameter name is one of the probed credential params.
        assert any(p in f.evidence for p in module.SECRET_URL_PARAM_NAMES)
        # Leakage surfaces are named (Req 38.3).
        assert "Referer" in f.evidence or "browser history" in f.evidence
        # The secret value itself is never echoed (redacted, Req 38.3).
        assert secret not in f.evidence

    @pytest.mark.asyncio
    async def test_secret_in_url_suppressed_when_non_discriminating(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Endpoint that accepts any URL secret (non-discriminating) => suppressed (Req 3)."""
        module = make_auth_module(auth_config)
        ctx = AuthContext(name="u", type=AuthType.BEARER, token="secret-abc", privilege_level=1)

        # Every request (invalid control included) returns identical success =>
        # baseline non-discriminating => no false positive.
        mock_http_client.request.return_value = _resp(
            200, body='{"data": "always ok"}', url="https://api.example.com/data"
        )

        findings = await module._test_secret_in_url("https://api.example.com/data", ctx)

        assert findings == []

    @pytest.mark.asyncio
    async def test_secret_in_url_skipped_without_secret(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """No secret in the auth context => test skipped, no requests (Req 38.1)."""
        module = make_auth_module(auth_config)
        ctx = AuthContext(name="u", type=AuthType.BEARER, token="", privilege_level=1)

        findings = await module._test_secret_in_url("https://api.example.com/data", ctx)

        assert findings == []
        mock_http_client.request.assert_not_called()

    def test_build_secret_in_url_preserves_other_params(self, auth_module):
        """The named param is set to the secret while other params are preserved."""
        url = "https://api.example.com/data?foo=bar&page=2"
        built = auth_module._build_secret_in_url(url, "token", "S3CR3T")
        assert "token=S3CR3T" in built
        assert "foo=bar" in built
        assert "page=2" in built


class TestMfaBypass:
    """Requirement 39: provisional-token MFA bypass + non-discriminating suppression."""

    @pytest.mark.asyncio
    async def test_mfa_bypass_detected(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Provisional token grants access that invalid token does not => AUTH_MFA_BYPASS (Req 39.1, 39.2)."""
        module = make_auth_module(auth_config)
        provisional = "provisional-pre-mfa-token"

        def side_effect(method, url, **kwargs):
            ctx = mock_http_client.current_auth_context
            token = getattr(ctx, "token", None) if ctx else None
            if token == provisional:
                return _resp(200, body='{"profile": {"id": 1, "name": "real"}}',
                             url=url, method=method)
            # Invalid negative-control token is rejected.
            return _resp(401, body='{"error": "unauthorized"}', url=url, method=method)

        # set_auth_context should record the context used for the next request.
        def set_ctx(ctx):
            mock_http_client.current_auth_context = ctx
        mock_http_client.set_auth_context.side_effect = set_ctx
        mock_http_client.request.side_effect = side_effect

        findings = await module._test_mfa_bypass(
            provisional, "https://api.example.com/protected"
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "AUTH_MFA_BYPASS"
        assert f.owasp_category == "API2"
        assert f.severity == Severity.CRITICAL
        # Provisional token value is redacted from evidence (reuses redactor).
        assert provisional not in f.evidence

    @pytest.mark.asyncio
    async def test_mfa_bypass_suppressed_when_non_discriminating(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Endpoint that accepts any token (non-discriminating) => suppressed (Req 39.4)."""
        module = make_auth_module(auth_config)

        # Every request returns identical success => baseline non-discriminating.
        mock_http_client.request.return_value = _resp(
            200, body='{"data": "always ok"}', url="https://api.example.com/protected"
        )

        findings = await module._test_mfa_bypass(
            "provisional-token", "https://api.example.com/protected"
        )

        assert findings == []

    @pytest.mark.asyncio
    async def test_mfa_bypass_skipped_without_inputs(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Missing multi-step flow inputs => skipped, no requests (Req 39.5)."""
        module = make_auth_module(auth_config)

        findings = await module._test_mfa_bypass("", "https://api.example.com/protected")

        assert findings == []
        mock_http_client.request.assert_not_called()


class TestResetTokenPredictability:
    """Requirement 40: predictable reset-token detection + Safe-Mode/opt-in skip log."""

    @pytest.mark.asyncio
    async def test_sequential_reset_tokens_reported(
        self, make_auth_module, auth_config
    ):
        """Sequential all-digit tokens => AUTH_PREDICTABLE_RESET_TOKEN (Req 40.1, 40.3)."""
        module = make_auth_module(auth_config)

        findings = await module._test_reset_token_predictability(
            ["1001", "1002", "1003"]
        )

        assert len(findings) >= 1
        f = findings[0]
        assert f.category == "AUTH_PREDICTABLE_RESET_TOKEN"
        assert f.owasp_category == "API2"
        assert "predictable" in f.evidence.lower()

    @pytest.mark.asyncio
    async def test_md5_of_email_reset_token_reported(
        self, make_auth_module, auth_config
    ):
        """MD5(email) reset token => predictable hash-of-known-input (Req 40.1)."""
        module = make_auth_module(auth_config)
        email = "victim@example.com"
        md5_token = hashlib.md5(email.encode()).hexdigest()

        findings = await module._test_reset_token_predictability(
            [md5_token], known_inputs=[email]
        )

        assert len(findings) == 1
        assert findings[0].category == "AUTH_PREDICTABLE_RESET_TOKEN"

    @pytest.mark.asyncio
    async def test_random_uuid4_reset_token_not_reported(
        self, make_auth_module, auth_config
    ):
        """UUIDv4 reset tokens are not predictable => no finding (Req 40.1)."""
        import uuid as _uuid
        module = make_auth_module(auth_config)

        tokens = [str(_uuid.uuid4()) for _ in range(3)]
        findings = await module._test_reset_token_predictability(tokens)

        assert findings == []

    @pytest.mark.asyncio
    async def test_reset_token_skip_logged_in_safe_mode(
        self, make_auth_module, auth_config
    ):
        """No observed tokens + Safe Mode => skipped with a Safe-Mode skip log (Req 40.4, 40.5)."""
        auth_config.safe_mode = True
        module = make_auth_module(auth_config)

        with patch.object(module.logger, "info") as mock_info:
            findings = await module._test_reset_token_predictability([])

        assert findings == []
        assert mock_info.called
        logged = " ".join(str(c) for c in mock_info.call_args_list).lower()
        assert "safe_mode" in logged or "safe mode" in logged

    @pytest.mark.asyncio
    async def test_reset_token_skip_logged_without_opt_in(
        self, make_auth_module, auth_config
    ):
        """No observed tokens + no destructive opt-in => skipped with opt-in skip log (Req 40.4)."""
        auth_config.safe_mode = False
        auth_config.allow_destructive = False
        module = make_auth_module(auth_config)

        with patch.object(module.logger, "info") as mock_info:
            findings = await module._test_reset_token_predictability([])

        assert findings == []
        assert mock_info.called


class TestOAuthSubProbes:
    """Requirement 41: redirect_uri / audience-confusion / missing-state sub-probes."""

    @pytest.mark.asyncio
    async def test_redirect_uri_accepted_reported(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Attacker redirect_uri accepted => AUTH_OAUTH_REDIRECT_URI (Req 41.1, 41.2)."""
        module = make_auth_module(auth_config)
        inputs = OAuthFlowInputs(
            authorize_url="https://auth.example.com/authorize?client_id=abc&state=xyz",
            registered_redirect_uri="https://app.example.com/callback",
            attacker_redirect_uri="https://evil.example.com/callback",
            state_present=True,
        )

        mock_http_client.request.return_value = _resp(
            200, body='{"ok": true}', url=inputs.authorize_url
        )

        finding = await module._build_redirect_uri_finding(inputs)

        assert finding is not None
        assert finding.category == "AUTH_OAUTH_REDIRECT_URI"
        assert finding.owasp_category == "API2"
        assert "evil.example.com" in finding.evidence

    @pytest.mark.asyncio
    async def test_redirect_uri_rejected_no_finding(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Attacker redirect_uri rejected (400) => no finding (Req 41.1)."""
        module = make_auth_module(auth_config)
        inputs = OAuthFlowInputs(
            authorize_url="https://auth.example.com/authorize?client_id=abc&state=xyz",
            registered_redirect_uri="https://app.example.com/callback",
            attacker_redirect_uri="https://evil.example.com/callback",
            state_present=True,
        )
        mock_http_client.request.return_value = _resp(
            400, body='{"error": "invalid redirect_uri"}', url=inputs.authorize_url
        )

        finding = await module._build_redirect_uri_finding(inputs)

        assert finding is None

    @pytest.mark.asyncio
    async def test_audience_confusion_reported(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Foreign-audience token accepted => AUTH_TOKEN_AUDIENCE_CONFUSION (Req 41.3)."""
        module = make_auth_module(auth_config)
        foreign_token = "token-issued-for-another-app"
        inputs = OAuthFlowInputs(
            authorize_url="https://auth.example.com/authorize?client_id=abc&state=xyz",
            registered_redirect_uri="https://app.example.com/callback",
            attacker_redirect_uri="",
            foreign_aud_token=foreign_token,
            state_present=True,
        )
        mock_http_client.request.return_value = _resp(
            200, body='{"data": "accepted"}', url=inputs.authorize_url
        )

        finding = await module._check_audience_confusion(inputs)

        assert finding is not None
        assert finding.category == "AUTH_TOKEN_AUDIENCE_CONFUSION"
        assert finding.owasp_category == "API2"
        # The foreign token value must be redacted from evidence.
        assert foreign_token not in finding.evidence

    def test_missing_state_reported(self, make_auth_module, auth_config):
        """Authorization URL without a state parameter => AUTH_OAUTH_MISSING_STATE (Req 41.4)."""
        module = make_auth_module(auth_config)
        inputs = OAuthFlowInputs(
            authorize_url="https://auth.example.com/authorize?client_id=abc",
            registered_redirect_uri="https://app.example.com/callback",
            attacker_redirect_uri="",
            state_present=False,
        )

        finding = module._check_missing_state(inputs)

        assert finding is not None
        assert finding.category == "AUTH_OAUTH_MISSING_STATE"
        assert finding.owasp_category == "API2"

    def test_present_state_no_finding(self, make_auth_module, auth_config):
        """A non-empty state parameter present => no missing-state finding (Req 41.4)."""
        module = make_auth_module(auth_config)
        inputs = OAuthFlowInputs(
            authorize_url="https://auth.example.com/authorize?client_id=abc&state=xyz",
            registered_redirect_uri="https://app.example.com/callback",
            attacker_redirect_uri="",
            state_present=True,
        )

        finding = module._check_missing_state(inputs)

        assert finding is None

    @pytest.mark.asyncio
    async def test_oauth_flow_skipped_without_inputs(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """No OAuth_Flow inputs => skipped, no requests (Req 41.6)."""
        module = make_auth_module(auth_config)

        findings = await module._test_oauth_flow(None)

        assert findings == []
        mock_http_client.request.assert_not_called()


class TestRevocationRace:
    """Requirement 42: bounded token-revocation race probe."""

    @pytest.mark.asyncio
    async def test_revocation_race_detected(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Token accepted after logout under concurrency => AUTH_TOKEN_REVOCATION_RACE (Req 42.1, 42.3)."""
        auth_config.safe_mode = False
        auth_config.allow_aggressive = True
        auth_config.revocation_race_requests = 4
        module = make_auth_module(auth_config)

        def side_effect(method, url, **kwargs):
            if "logout" in url:
                return _resp(200, body='{"message": "logged out"}', url=url, method="POST")
            # Protected request still honored after logout.
            return _resp(200, body='{"data": "still accessible"}', url=url, method="GET")

        mock_http_client.request.side_effect = side_effect

        findings = await module._test_revocation_race(
            "valid-token",
            "https://api.example.com/logout",
            "https://api.example.com/protected",
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "AUTH_TOKEN_REVOCATION_RACE"
        assert f.owasp_category == "API2"
        # Bounded by the configured request count (1 logout + N protected).
        assert mock_http_client.request.await_count == 4

    @pytest.mark.asyncio
    async def test_revocation_race_skipped_without_opt_in(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Aggressive opt-in absent => probe skipped, no requests (Req 42.5)."""
        auth_config.safe_mode = False
        auth_config.allow_aggressive = False
        module = make_auth_module(auth_config)

        findings = await module._test_revocation_race(
            "valid-token",
            "https://api.example.com/logout",
            "https://api.example.com/protected",
        )

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_revocation_race_skipped_in_safe_mode(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Safe Mode on => probe skipped even with opt-in (Req 42.5)."""
        auth_config.safe_mode = True
        auth_config.allow_aggressive = True
        module = make_auth_module(auth_config)

        findings = await module._test_revocation_race(
            "valid-token",
            "https://api.example.com/logout",
            "https://api.example.com/protected",
        )

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_revocation_race_no_finding_when_token_rejected_after_logout(
        self, make_auth_module, auth_config, mock_http_client
    ):
        """Token rejected (401) after logout => no finding (Req 42.3)."""
        auth_config.safe_mode = False
        auth_config.allow_aggressive = True
        auth_config.revocation_race_requests = 4
        module = make_auth_module(auth_config)

        def side_effect(method, url, **kwargs):
            if "logout" in url:
                return _resp(200, body='{"message": "logged out"}', url=url, method="POST")
            return _resp(401, body='{"error": "token revoked"}', url=url, method="GET")

        mock_http_client.request.side_effect = side_effect

        findings = await module._test_revocation_race(
            "valid-token",
            "https://api.example.com/logout",
            "https://api.example.com/protected",
        )

        assert findings == []
