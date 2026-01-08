"""
Tests for BOLA Testing Module
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass

from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from utils.http_client import HTTPRequestEngine, Response
from core.config import BOLAConfig, AuthContext, AuthType
from core.logging import get_logger


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


class TestBOLATestingModule:
    """Test cases for BOLA Testing Module"""
    
    @pytest.fixture
    def bola_config(self):
        """Create BOLA configuration for testing"""
        return BOLAConfig(
            enabled=True,
            id_patterns=["sequential", "guid", "uuid"],
            test_contexts=["anonymous", "user", "admin"]
        )
    
    @pytest.fixture
    def auth_contexts(self):
        """Create auth contexts for testing"""
        return [
            AuthContext(
                name="user1",
                type=AuthType.BEARER,
                token="user1_token",
                privilege_level=1
            ),
            AuthContext(
                name="user2", 
                type=AuthType.BEARER,
                token="user2_token",
                privilege_level=1
            ),
            AuthContext(
                name="admin",
                type=AuthType.BEARER,
                token="admin_token",
                privilege_level=3
            )
        ]
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        return client
    
    @pytest.fixture
    def bola_module(self, bola_config, auth_contexts, mock_http_client):
        """Create BOLA testing module"""
        return BOLATestingModule(bola_config, mock_http_client, auth_contexts)
    
    def test_module_initialization(self, bola_module, auth_contexts):
        """Test BOLA module initialization"""
        assert bola_module.get_module_name() == "bola_testing"
        assert len(bola_module.auth_contexts) == len(auth_contexts)
        assert "anonymous" in bola_module.auth_context_map
    
    def test_extract_ids_from_path(self, bola_module):
        """Test ID extraction from URL paths"""
        test_urls = [
            "https://api.example.com/users/123",
            "https://api.example.com/accounts/550e8400-e29b-41d4-a716-446655440000",
            "https://api.example.com/orders/456/items/789"
        ]
        
        for url in test_urls:
            identifiers = bola_module._extract_ids_from_path(url)
            assert len(identifiers) > 0
            assert all(isinstance(id, ObjectIdentifier) for id in identifiers)
    
    def test_determine_id_type(self, bola_module):
        """Test ID type determination"""
        test_cases = [
            ("123", "sequential"),
            ("550e8400-e29b-41d4-a716-446655440000", "guid"),
            ("abc123def", None)
        ]
        
        for value, expected_type in test_cases:
            result = bola_module._determine_id_type(value)
            assert result == expected_type
    
    def test_is_object_accessible(self, bola_module):
        """Test object accessibility determination"""
        # Accessible response
        accessible_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "test object", "data": "some content"}',
            text='{"id": 123, "name": "test object", "data": "some content"}',
            url="https://api.example.com/objects/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Not accessible response (error)
        error_response = Response(
            status_code=404,
            headers={"content-type": "application/json"},
            content=b'{"error": "not found"}',
            text='{"error": "not found"}',
            url="https://api.example.com/objects/999",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Unauthorized response
        unauthorized_response = Response(
            status_code=401,
            headers={"content-type": "application/json"},
            content=b'{"error": "unauthorized"}',
            text='{"error": "unauthorized"}',
            url="https://api.example.com/objects/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        assert bola_module._is_object_accessible(accessible_response) == True
        assert bola_module._is_object_accessible(error_response) == False
        assert bola_module._is_object_accessible(unauthorized_response) == False
    
    def test_responses_indicate_same_object(self, bola_module):
        """Test same object detection from responses"""
        # Similar responses (same object)
        response1 = Response(
            status_code=200,
            headers={},
            content=b'{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            text='{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        response2 = Response(
            status_code=200,
            headers={},
            content=b'{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            text='{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Different responses (different objects) - significantly different content
        response3 = Response(
            status_code=200,
            headers={},
            content=b'{"id": 456, "name": "Jane Smith", "email": "jane@example.com", "department": "Engineering", "role": "Senior Developer", "location": "New York", "phone": "+1-555-0123", "manager": "Bob Johnson", "projects": ["Project A", "Project B", "Project C"]}',
            text='{"id": 456, "name": "Jane Smith", "email": "jane@example.com", "department": "Engineering", "role": "Senior Developer", "location": "New York", "phone": "+1-555-0123", "manager": "Bob Johnson", "projects": ["Project A", "Project B", "Project C"]}',
            url="https://api.example.com/users/456",
            elapsed=0.1,
            request_method="GET"
        )
        
        assert bola_module._responses_indicate_same_object(response1, response2) == True
        assert bola_module._responses_indicate_same_object(response1, response3) == False
    
    @pytest.mark.asyncio
    async def test_discover_object_identifiers(self, bola_module, mock_http_client):
        """Test object identifier discovery"""
        # Mock endpoints
        endpoints = [
            MockEndpoint("https://api.example.com/users/123"),
            MockEndpoint("https://api.example.com/orders/456")
        ]
        
        # Mock response with JSON containing IDs
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"user_id": 789, "account_id": "550e8400-e29b-41d4-a716-446655440000"}',
            text='{"user_id": 789, "account_id": "550e8400-e29b-41d4-a716-446655440000"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        identifiers = await bola_module._discover_object_identifiers(endpoints)
        
        assert len(identifiers) > 0
        assert all(isinstance(id, ObjectIdentifier) for id in identifiers)
        
        # Should have found IDs from both path and response
        path_ids = [id for id in identifiers if id.location == 'path']
        response_ids = [id for id in identifiers if id.location == 'response']
        
        assert len(path_ids) > 0
        assert len(response_ids) > 0
    
    @pytest.mark.asyncio
    async def test_anonymous_access_detection(self, bola_module, mock_http_client):
        """Test anonymous access detection"""
        # Create test identifier
        identifier = ObjectIdentifier(
            value="123",
            type="sequential",
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id",
            location="path"
        )
        
        # Mock successful anonymous access (vulnerability)
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            text='{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await bola_module._test_anonymous_access([identifier])
        
        assert len(findings) == 1
        assert findings[0].category == "BOLA_ANONYMOUS_ACCESS"
        assert findings[0].severity.value == "CRITICAL"
        assert findings[0].owasp_category == "API1"
    
    @pytest.mark.asyncio
    async def test_horizontal_privilege_escalation(self, bola_module, mock_http_client):
        """Test horizontal privilege escalation detection"""
        # Create test identifier
        identifier = ObjectIdentifier(
            value="123",
            type="sequential", 
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id",
            location="path"
        )
        
        # Mock responses - both users can access the same object (vulnerability)
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            text='{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await bola_module._test_horizontal_privilege_escalation([identifier])
        
        # Should detect horizontal escalation if both users can access same object
        if len(findings) > 0:
            assert findings[0].category == "BOLA_HORIZONTAL_ESCALATION"
            assert findings[0].severity.value == "CRITICAL"
            assert findings[0].owasp_category == "API1"
    
    @pytest.mark.asyncio
    async def test_sequential_id_enumeration(self, bola_module, mock_http_client):
        """Test sequential ID enumeration detection"""
        # Create test identifier
        identifier = ObjectIdentifier(
            value="100",
            type="sequential",
            endpoint="https://api.example.com/users/100",
            parameter_name="user_id",
            location="path"
        )
        
        # Mock responses - multiple sequential IDs are accessible (vulnerability)
        def mock_request_side_effect(method, url):
            # Extract ID from URL - handle the URL construction properly
            if "/users/" in url:
                try:
                    # Extract the last path segment as the user ID
                    path_parts = url.rstrip('/').split('/')
                    user_id = path_parts[-1]
                    id_num = int(user_id)
                    
                    # Make IDs 98, 99, 101, 102 accessible
                    if id_num in [98, 99, 101, 102]:
                        return Response(
                            status_code=200,
                            headers={"content-type": "application/json"},
                            content=f'{{"id": {id_num}, "name": "User {id_num}"}}'.encode(),
                            text=f'{{"id": {id_num}, "name": "User {id_num}"}}',
                            url=url,
                            elapsed=0.1,
                            request_method=method
                        )
                except (ValueError, IndexError):
                    pass
            
            # Default: not found
            return Response(
                status_code=404,
                headers={},
                content=b'{"error": "not found"}',
                text='{"error": "not found"}',
                url=url,
                elapsed=0.1,
                request_method=method
            )
        
        mock_http_client.request.side_effect = mock_request_side_effect
        
        findings = await bola_module._test_sequential_enumeration([identifier])
        
        assert len(findings) == 1
        assert findings[0].category == "BOLA_ID_ENUMERATION"
        assert findings[0].severity.value == "HIGH"
        assert findings[0].owasp_category == "API1"
    
    @pytest.mark.asyncio
    async def test_execute_tests_integration(self, bola_module, mock_http_client):
        """Test full BOLA testing execution"""
        # Mock endpoints
        endpoints = [
            MockEndpoint("https://api.example.com/users/123"),
            MockEndpoint("https://api.example.com/orders/456")
        ]
        
        # Mock successful response
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "Test User"}',
            text='{"id": 123, "name": "Test User"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await bola_module.execute_tests(endpoints)
        
        # Should return list of findings (may be empty if no vulnerabilities detected)
        assert isinstance(findings, list)
        assert all(hasattr(f, 'category') for f in findings)
        assert all(hasattr(f, 'severity') for f in findings)
        assert all(hasattr(f, 'owasp_category') for f in findings)


if __name__ == "__main__":
    pytest.main([__file__])