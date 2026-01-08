"""
Tests for Fuzzing Orchestrator and Endpoint Discovery
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from modules.fuzzing.orchestrator import (
    FuzzingOrchestrator, EndpointFuzzer, Endpoint, EndpointStatus, FuzzingStats
)
from core.config import FuzzingConfig, EndpointFuzzingConfig, ParameterFuzzingConfig, HeaderFuzzingConfig
from utils.http_client import HTTPRequestEngine, Response


class TestEndpointFuzzer:
    """Test endpoint fuzzer functionality"""
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        return client
    
    @pytest.fixture
    def fuzzing_config(self):
        """Create fuzzing configuration"""
        return FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist="test_wordlist.txt",
                methods=["GET", "POST"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=True,
            max_depth=2
        )
    
    @pytest.fixture
    def endpoint_fuzzer(self, mock_http_client, fuzzing_config):
        """Create endpoint fuzzer"""
        return EndpointFuzzer(mock_http_client, fuzzing_config)
    
    @pytest.fixture
    def temp_wordlist(self):
        """Create temporary wordlist file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("admin\napi\ntest\nlogin\n")
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_load_wordlist(self, endpoint_fuzzer, temp_wordlist):
        """Test wordlist loading"""
        wordlist = await endpoint_fuzzer._load_wordlist(temp_wordlist)
        
        assert len(wordlist) == 4
        assert "admin" in wordlist
        assert "api" in wordlist
        assert "test" in wordlist
        assert "login" in wordlist
    
    @pytest.mark.asyncio
    async def test_load_wordlist_with_comments(self, endpoint_fuzzer):
        """Test wordlist loading with comments and empty lines"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# This is a comment\nadmin\n\n# Another comment\napi\n\ntest\n")
            temp_path = f.name
        
        try:
            wordlist = await endpoint_fuzzer._load_wordlist(temp_path)
            
            assert len(wordlist) == 3
            assert "admin" in wordlist
            assert "api" in wordlist
            assert "test" in wordlist
            assert "# This is a comment" not in wordlist
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_test_endpoint_success(self, endpoint_fuzzer, mock_http_client):
        """Test successful endpoint testing"""
        # Mock successful response
        mock_response = Response(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            content=b'{"success": true}',
            text='{"success": true}',
            url='http://example.com/admin',
            elapsed=0.5,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/admin', 'admin', 0)
        
        assert endpoint is not None
        assert endpoint.url == 'http://example.com/admin'
        assert endpoint.method == 'GET'
        assert endpoint.status_code == 200
        assert endpoint.status == EndpointStatus.VALID
        assert endpoint.endpoint_type == "admin"  # Should be classified as admin
        assert endpoint.discovered_via == "wordlist"
    
    @pytest.mark.asyncio
    async def test_test_endpoint_auth_required(self, endpoint_fuzzer, mock_http_client):
        """Test endpoint requiring authentication"""
        # Mock 401 response
        mock_response = Response(
            status_code=401,
            headers={'WWW-Authenticate': 'Bearer'},
            content=b'Unauthorized',
            text='Unauthorized',
            url='http://example.com/admin',
            elapsed=0.2,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/admin', 'admin', 0)
        
        assert endpoint is not None
        assert endpoint.status == EndpointStatus.AUTH_REQUIRED
        assert endpoint.auth_required is True
    
    @pytest.mark.asyncio
    async def test_test_endpoint_not_found(self, endpoint_fuzzer, mock_http_client):
        """Test endpoint not found (404)"""
        # Mock 404 response
        mock_response = Response(
            status_code=404,
            headers={},
            content=b'Not Found',
            text='Not Found',
            url='http://example.com/nonexistent',
            elapsed=0.1,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/nonexistent', 'nonexistent', 0)
        
        # Should return None for 404s (not interesting)
        assert endpoint is None
    
    @pytest.mark.asyncio
    async def test_test_endpoint_redirect(self, endpoint_fuzzer, mock_http_client):
        """Test endpoint with redirect"""
        # Mock redirect response
        mock_response = Response(
            status_code=302,
            headers={'Location': '/login'},
            content=b'Redirecting...',
            text='Redirecting...',
            url='http://example.com/admin',
            elapsed=0.1,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/admin', 'admin', 0)
        
        assert endpoint is not None
        assert endpoint.status == EndpointStatus.REDIRECT
        assert endpoint.redirect_location == '/login'
    
    def test_classify_endpoint(self, endpoint_fuzzer):
        """Test endpoint classification"""
        # Test admin endpoint
        admin_endpoint = Endpoint(
            url='http://example.com/admin',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        endpoint_fuzzer._classify_endpoint(admin_endpoint, 'admin')
        assert admin_endpoint.endpoint_type == "admin"
        
        # Test API endpoint
        api_endpoint = Endpoint(
            url='http://example.com/api',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        endpoint_fuzzer._classify_endpoint(api_endpoint, 'api')
        assert api_endpoint.endpoint_type == "api_version"
        
        # Test auth endpoint
        auth_endpoint = Endpoint(
            url='http://example.com/login',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        endpoint_fuzzer._classify_endpoint(auth_endpoint, 'login')
        assert auth_endpoint.endpoint_type == "authentication"


class TestFuzzingOrchestrator:
    """Test fuzzing orchestrator functionality"""
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        return client
    
    @pytest.fixture
    def fuzzing_config(self):
        """Create fuzzing configuration"""
        return FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist="wordlists/endpoints.txt",
                methods=["GET", "POST"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=True),
            headers=HeaderFuzzingConfig(enabled=True),
            recursive=False,
            max_depth=1
        )
    
    @pytest.fixture
    def fuzzing_orchestrator(self, fuzzing_config, mock_http_client):
        """Create fuzzing orchestrator"""
        return FuzzingOrchestrator(fuzzing_config, mock_http_client)
    
    def test_initialization(self, fuzzing_orchestrator, fuzzing_config):
        """Test orchestrator initialization"""
        assert fuzzing_orchestrator.config == fuzzing_config
        assert fuzzing_orchestrator.http_client is not None
        assert isinstance(fuzzing_orchestrator.stats, FuzzingStats)
        assert fuzzing_orchestrator.endpoint_fuzzer is not None
    
    @pytest.mark.asyncio
    async def test_discover_endpoints_disabled(self, fuzzing_orchestrator):
        """Test endpoint discovery when disabled"""
        fuzzing_orchestrator.config.endpoints.enabled = False
        
        endpoints = await fuzzing_orchestrator.discover_endpoints('http://example.com')
        
        assert len(endpoints) == 0
    
    @pytest.mark.asyncio
    async def test_discover_endpoints_success(self, fuzzing_orchestrator, mock_http_client):
        """Test successful endpoint discovery"""
        # Mock the endpoint fuzzer's discover_endpoints method
        mock_endpoints = [
            Endpoint(
                url='http://example.com/admin',
                method='GET',
                status_code=200,
                response_size=100,
                response_time=0.5,
                endpoint_type="admin"
            ),
            Endpoint(
                url='http://example.com/api',
                method='GET',
                status_code=401,
                response_size=50,
                response_time=0.2,
                auth_required=True
            )
        ]
        
        with patch.object(fuzzing_orchestrator.endpoint_fuzzer, 'discover_endpoints', 
                         return_value=mock_endpoints) as mock_discover:
            endpoints = await fuzzing_orchestrator.discover_endpoints('http://example.com')
            
            assert len(endpoints) == 2
            assert endpoints[0].url == 'http://example.com/admin'
            assert endpoints[1].auth_required is True
            mock_discover.assert_called_once_with('http://example.com', 'wordlists/endpoints.txt')
    
    @pytest.mark.asyncio
    async def test_fuzz_parameters_disabled(self, fuzzing_orchestrator):
        """Test parameter fuzzing when disabled"""
        fuzzing_orchestrator.config.parameters.enabled = False
        
        findings = await fuzzing_orchestrator.fuzz_parameters([])
        
        assert len(findings) == 0
    
    @pytest.mark.asyncio
    async def test_fuzz_headers_disabled(self, fuzzing_orchestrator):
        """Test header fuzzing when disabled"""
        fuzzing_orchestrator.config.headers.enabled = False
        
        findings = await fuzzing_orchestrator.fuzz_headers([])
        
        assert len(findings) == 0
    
    def test_get_fuzzing_statistics(self, fuzzing_orchestrator):
        """Test getting fuzzing statistics"""
        stats = fuzzing_orchestrator.get_fuzzing_statistics()
        
        assert isinstance(stats, FuzzingStats)
        assert stats.endpoints_tested == 0
        assert stats.success_rate == 0.0
    
    def test_get_discovered_endpoints(self, fuzzing_orchestrator):
        """Test getting discovered endpoints"""
        # Add some mock endpoints to the endpoint fuzzer
        mock_endpoint = Endpoint(
            url='http://example.com/test',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        fuzzing_orchestrator.endpoint_fuzzer.discovered_endpoints['http://example.com/test'] = mock_endpoint
        
        endpoints = fuzzing_orchestrator.get_discovered_endpoints()
        
        assert len(endpoints) == 1
        assert endpoints[0].url == 'http://example.com/test'
    
    def test_get_endpoints_by_status(self, fuzzing_orchestrator):
        """Test filtering endpoints by status"""
        # Add mock endpoints with different statuses
        valid_endpoint = Endpoint(
            url='http://example.com/valid',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        auth_endpoint = Endpoint(
            url='http://example.com/auth',
            method='GET',
            status_code=401,
            response_size=50,
            response_time=0.2
        )
        
        fuzzing_orchestrator.endpoint_fuzzer.discovered_endpoints.update({
            'http://example.com/valid': valid_endpoint,
            'http://example.com/auth': auth_endpoint
        })
        
        valid_endpoints = fuzzing_orchestrator.get_endpoints_by_status(EndpointStatus.VALID)
        auth_endpoints = fuzzing_orchestrator.get_endpoints_by_status(EndpointStatus.AUTH_REQUIRED)
        
        assert len(valid_endpoints) == 1
        assert valid_endpoints[0].url == 'http://example.com/valid'
        assert len(auth_endpoints) == 1
        assert auth_endpoints[0].url == 'http://example.com/auth'
    
    def test_get_endpoints_by_type(self, fuzzing_orchestrator):
        """Test filtering endpoints by type"""
        # Add mock endpoints with different types
        admin_endpoint = Endpoint(
            url='http://example.com/admin',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5,
            endpoint_type="admin"
        )
        api_endpoint = Endpoint(
            url='http://example.com/api',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5,
            endpoint_type="api_version"
        )
        
        fuzzing_orchestrator.endpoint_fuzzer.discovered_endpoints.update({
            'http://example.com/admin': admin_endpoint,
            'http://example.com/api': api_endpoint
        })
        
        admin_endpoints = fuzzing_orchestrator.get_endpoints_by_type("admin")
        api_endpoints = fuzzing_orchestrator.get_endpoints_by_type("api_version")
        
        assert len(admin_endpoints) == 1
        assert admin_endpoints[0].url == 'http://example.com/admin'
        assert len(api_endpoints) == 1
        assert api_endpoints[0].url == 'http://example.com/api'


class TestEndpoint:
    """Test Endpoint model functionality"""
    
    def test_endpoint_status_properties(self):
        """Test endpoint status classification"""
        # Test valid endpoint (2xx)
        valid_endpoint = Endpoint(
            url='http://example.com/test',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        assert valid_endpoint.status == EndpointStatus.VALID
        
        # Test auth required (401/403)
        auth_endpoint = Endpoint(
            url='http://example.com/admin',
            method='GET',
            status_code=401,
            response_size=50,
            response_time=0.2
        )
        assert auth_endpoint.status == EndpointStatus.AUTH_REQUIRED
        
        # Test not found (404)
        not_found_endpoint = Endpoint(
            url='http://example.com/missing',
            method='GET',
            status_code=404,
            response_size=20,
            response_time=0.1
        )
        assert not_found_endpoint.status == EndpointStatus.NOT_FOUND
        
        # Test redirect (3xx)
        redirect_endpoint = Endpoint(
            url='http://example.com/old',
            method='GET',
            status_code=302,
            response_size=30,
            response_time=0.1
        )
        assert redirect_endpoint.status == EndpointStatus.REDIRECT
        
        # Test server error (5xx)
        error_endpoint = Endpoint(
            url='http://example.com/error',
            method='GET',
            status_code=500,
            response_size=100,
            response_time=1.0
        )
        assert error_endpoint.status == EndpointStatus.ERROR


class TestFuzzingStats:
    """Test FuzzingStats functionality"""
    
    def test_success_rate_calculation(self):
        """Test success rate calculation"""
        stats = FuzzingStats()
        
        # Test with no requests
        assert stats.success_rate == 0.0
        
        # Test with some requests
        stats.total_requests = 100
        stats.successful_requests = 80
        assert stats.success_rate == 80.0
        
        # Test with all successful
        stats.successful_requests = 100
        assert stats.success_rate == 100.0
        
        # Test with no successful
        stats.successful_requests = 0
        assert stats.success_rate == 0.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])