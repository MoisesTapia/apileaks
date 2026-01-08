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
        """Test anonymous access severity classification"""
        # Mock response with sensitive data (long enough to trigger sensitive data check)
        sensitive_response = Response(
            status_code=200,
            headers={},
            content=b'{"users": [{"id": 1, "name": "John Doe", "email": "user@example.com", "password": "hashed_password_123", "token": "secret_token_abc123", "phone": "+1-555-0123", "address": "123 Main St", "role": "admin", "permissions": ["read", "write", "delete"]}]}',
            text='{"users": [{"id": 1, "name": "John Doe", "email": "user@example.com", "password": "hashed_password_123", "token": "secret_token_abc123", "phone": "+1-555-0123", "address": "123 Main St", "role": "admin", "permissions": ["read", "write", "delete"]}]}',
            url="",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Mock response without sensitive data (long enough to trigger check)
        normal_response = Response(
            status_code=200,
            headers={},
            content=b'{"products": [{"id": 1, "name": "Product A", "description": "A great product for testing purposes", "category": "electronics", "price": 99.99, "availability": "in_stock", "manufacturer": "Test Corp", "model": "TC-001"}]}',
            text='{"products": [{"id": 1, "name": "Product A", "description": "A great product for testing purposes", "category": "electronics", "price": 99.99, "availability": "in_stock", "manufacturer": "Test Corp", "model": "TC-001"}]}',
            url="",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Short response (won't trigger sensitive data check)
        short_response = Response(
            status_code=200,
            headers={},
            content=b'{"data": "test"}',
            text='{"data": "test"}',
            url="",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Critical endpoints (admin, management, users, etc.)
        critical_endpoints = [
            "https://api.example.com/admin/settings",
            "https://api.example.com/management/config",
            "https://api.example.com/api/admin/settings",
            "https://api.example.com/users",  # /users pattern is critical
            "https://api.example.com/api/users"  # /api/users pattern is critical
        ]
        
        for endpoint in critical_endpoints:
            severity = auth_module._classify_anonymous_access_severity(endpoint, short_response)
            assert severity == Severity.CRITICAL
        
        # High severity endpoints (API endpoints without critical patterns)
        high_endpoints = [
            "https://api.example.com/api/products",
            "https://api.example.com/v1/items",
            "https://api.example.com/rest/catalog"
        ]
        
        for endpoint in high_endpoints:
            # With sensitive data should be CRITICAL
            severity = auth_module._classify_anonymous_access_severity(endpoint, sensitive_response)
            assert severity == Severity.CRITICAL
            
            # Without sensitive data but long response should be HIGH
            severity = auth_module._classify_anonymous_access_severity(endpoint, normal_response)
            assert severity == Severity.HIGH
            
            # With short response should be MEDIUM (falls through to default)
            severity = auth_module._classify_anonymous_access_severity(endpoint, short_response)
            assert severity == Severity.MEDIUM
        
        # Medium severity endpoints
        medium_endpoints = [
            "https://api.example.com/public/info",
            "https://api.example.com/status",
            "https://example.com/home"
        ]
        
        for endpoint in medium_endpoints:
            severity = auth_module._classify_anonymous_access_severity(endpoint, short_response)
            assert severity == Severity.MEDIUM
    
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
        
        # Mock accessible response for anonymous access
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"data": "accessible"}',
            text='{"data": "accessible"}',
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


if __name__ == "__main__":
    pytest.main([__file__])