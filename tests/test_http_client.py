"""
Tests for HTTP Request Engine
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch
import httpx

from utils.http_client import (
    HTTPRequestEngine, RateLimiter, Request, Response, 
    RetryConfig, PerformanceMetrics, RequestMethod
)
from core.config import RateLimitConfig, AuthContext, AuthType


class TestRateLimiter:
    """Test rate limiter functionality"""
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initializes correctly"""
        config = RateLimitConfig(
            requests_per_second=10,
            burst_size=20,
            adaptive=True
        )
        
        rate_limiter = RateLimiter(config)
        
        assert rate_limiter.config == config
        assert rate_limiter.tokens == 20.0
        assert rate_limiter.current_rps == 10.0
        assert rate_limiter.consecutive_rate_limits == 0
    
    @pytest.mark.asyncio
    async def test_rate_limiter_acquire_with_tokens(self):
        """Test acquiring permission when tokens are available"""
        config = RateLimitConfig(requests_per_second=10, burst_size=5)
        rate_limiter = RateLimiter(config)
        
        # Should acquire immediately when tokens available
        start_time = time.time()
        await rate_limiter.acquire()
        elapsed = time.time() - start_time
        
        assert elapsed < 0.1  # Should be nearly immediate
        assert rate_limiter.tokens == 4.0  # One token consumed
    
    @pytest.mark.asyncio
    async def test_rate_limiter_backoff_on_rate_limit(self):
        """Test backoff behavior on rate limit response"""
        config = RateLimitConfig(
            requests_per_second=10,
            backoff_factor=2.0,
            respect_retry_after=True
        )
        rate_limiter = RateLimiter(config)
        
        # Create mock rate limit response
        response = Response(
            status_code=429,
            headers={'Retry-After': '2'},
            content=b'Rate limited',
            text='Rate limited',
            url='http://example.com',
            elapsed=0.1,
            request_method='GET'
        )
        
        await rate_limiter.handle_rate_limit_response(response)
        
        assert rate_limiter.consecutive_rate_limits == 1
        assert rate_limiter.backoff_until > time.time()
    
    @pytest.mark.asyncio
    async def test_adaptive_throttling(self):
        """Test adaptive throttling reduces RPS"""
        config = RateLimitConfig(
            requests_per_second=10,
            adaptive=True,
            backoff_factor=2.0
        )
        rate_limiter = RateLimiter(config)
        
        # Simulate multiple rate limit responses
        response = Response(
            status_code=429,
            headers={},
            content=b'Rate limited',
            text='Rate limited',
            url='http://example.com',
            elapsed=0.1,
            request_method='GET'
        )
        
        # First rate limit
        await rate_limiter.handle_rate_limit_response(response)
        assert rate_limiter.current_rps == 10.0  # No change yet
        
        # Second rate limit - should trigger adaptive throttling
        await rate_limiter.handle_rate_limit_response(response)
        assert rate_limiter.current_rps == 5.0  # Halved


class TestHTTPRequestEngine:
    """Test HTTP request engine functionality"""
    
    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter for testing"""
        config = RateLimitConfig(requests_per_second=100, burst_size=10)
        return RateLimiter(config)
    
    @pytest.fixture
    def retry_config(self):
        """Create retry config for testing"""
        return RetryConfig(max_attempts=3, backoff_factor=1.5)
    
    @pytest.fixture
    def http_engine(self, rate_limiter, retry_config):
        """Create HTTP engine for testing"""
        return HTTPRequestEngine(rate_limiter, retry_config)
    
    def test_http_engine_initialization(self, http_engine):
        """Test HTTP engine initializes correctly"""
        assert http_engine.rate_limiter is not None
        assert http_engine.retry_config is not None
        assert http_engine.timeout == 30.0
        assert http_engine.verify_ssl is True
        assert isinstance(http_engine.metrics, PerformanceMetrics)
    
    @pytest.mark.asyncio
    async def test_successful_request(self, http_engine):
        """Test successful HTTP request"""
        # Mock httpx client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.content = b'{"success": true}'
        mock_response.text = '{"success": true}'
        mock_response.url = 'http://example.com/test'
        
        with patch.object(http_engine, 'client') as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            http_engine._client_initialized = True
            
            response = await http_engine.request('GET', 'http://example.com/test')
            
            assert response.status_code == 200
            assert response.text == '{"success": true}'
            assert response.is_success is True
            assert http_engine.metrics.total_requests == 1
            assert http_engine.metrics.successful_requests == 1
    
    @pytest.mark.asyncio
    async def test_request_with_retry_on_timeout(self, http_engine):
        """Test request retry on timeout"""
        with patch.object(http_engine, 'client') as mock_client:
            # First call raises timeout, second succeeds
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.content = b'success'
            mock_response.text = 'success'
            mock_response.url = 'http://example.com/test'
            
            mock_client.request = AsyncMock(
                side_effect=[httpx.TimeoutException("Timeout"), mock_response]
            )
            http_engine._client_initialized = True
            
            response = await http_engine.request('GET', 'http://example.com/test')
            
            assert response.status_code == 200
            assert http_engine.metrics.retried_requests == 1
            assert mock_client.request.call_count == 2
    
    @pytest.mark.asyncio
    async def test_authentication_bearer(self, http_engine):
        """Test Bearer token authentication"""
        auth_context = AuthContext(
            name="test_user",
            type=AuthType.BEARER,
            token="test_token_123"
        )
        
        http_engine.set_auth_context(auth_context)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b'authenticated'
        mock_response.text = 'authenticated'
        mock_response.url = 'http://example.com/test'
        
        with patch.object(http_engine, 'client') as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            http_engine._client_initialized = True
            
            response = await http_engine.request('GET', 'http://example.com/test')
            
            # Check that Authorization header was added
            call_args = mock_client.request.call_args
            headers = call_args[1]['headers']
            assert 'Authorization' in headers
            assert headers['Authorization'] == 'Bearer test_token_123'
    
    @pytest.mark.asyncio
    async def test_authentication_basic(self, http_engine):
        """Test Basic authentication"""
        auth_context = AuthContext(
            name="test_user",
            type=AuthType.BASIC,
            token="",  # Not used for basic auth
            username="testuser",
            password="testpass"
        )
        
        http_engine.set_auth_context(auth_context)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b'authenticated'
        mock_response.text = 'authenticated'
        mock_response.url = 'http://example.com/test'
        
        with patch.object(http_engine, 'client') as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            http_engine._client_initialized = True
            
            response = await http_engine.request('GET', 'http://example.com/test')
            
            # Check that Authorization header was added with Basic auth
            call_args = mock_client.request.call_args
            headers = call_args[1]['headers']
            assert 'Authorization' in headers
            assert headers['Authorization'].startswith('Basic ')
    
    @pytest.mark.asyncio
    async def test_batch_requests(self, http_engine):
        """Test batch request execution"""
        requests = [
            Request('GET', 'http://example.com/1'),
            Request('GET', 'http://example.com/2'),
            Request('POST', 'http://example.com/3', json={'data': 'test'})
        ]
        
        mock_responses = []
        for i in range(3):
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.content = f'response_{i}'.encode()
            mock_response.text = f'response_{i}'
            mock_response.url = f'http://example.com/{i+1}'
            mock_responses.append(mock_response)
        
        with patch.object(http_engine, 'client') as mock_client:
            mock_client.request = AsyncMock(side_effect=mock_responses)
            http_engine._client_initialized = True
            
            responses = await http_engine.batch_request(requests)
            
            assert len(responses) == 3
            assert all(r.status_code == 200 for r in responses)
            assert mock_client.request.call_count == 3
    
    def test_performance_metrics(self, http_engine):
        """Test performance metrics calculation"""
        metrics = http_engine.metrics
        
        # Simulate some requests
        metrics.total_requests = 100
        metrics.successful_requests = 95
        metrics.failed_requests = 5
        metrics.total_response_time = 50.0
        
        assert metrics.success_rate == 95.0
        assert metrics.average_response_time == 0.5
    
    @pytest.mark.asyncio
    async def test_health_check(self, http_engine):
        """Test health check functionality"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b'OK'
        mock_response.text = 'OK'
        mock_response.url = 'https://httpbin.org/status/200'
        
        with patch.object(http_engine, 'client') as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            http_engine._client_initialized = True
            
            is_healthy = await http_engine.health_check()
            assert is_healthy is True
    
    @pytest.mark.asyncio
    async def test_context_manager(self, http_engine):
        """Test HTTP engine as async context manager"""
        async with http_engine as engine:
            assert engine._client_initialized is True
            assert engine.client is not None
        
        # Client should be closed after context exit
        assert engine._client_initialized is False


class TestResponse:
    """Test Response object functionality"""
    
    def test_response_properties(self):
        """Test response property methods"""
        # Success response
        success_response = Response(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            content=b'{"data": "test"}',
            text='{"data": "test"}',
            url='http://example.com',
            elapsed=0.5,
            request_method='GET'
        )
        
        assert success_response.is_success is True
        assert success_response.is_redirect is False
        assert success_response.is_client_error is False
        assert success_response.is_server_error is False
        
        # Redirect response
        redirect_response = Response(
            status_code=301,
            headers={'Location': 'http://example.com/new'},
            content=b'',
            text='',
            url='http://example.com',
            elapsed=0.1,
            request_method='GET'
        )
        
        assert redirect_response.is_redirect is True
        assert redirect_response.is_success is False
        
        # Client error response
        error_response = Response(
            status_code=404,
            headers={},
            content=b'Not Found',
            text='Not Found',
            url='http://example.com',
            elapsed=0.2,
            request_method='GET'
        )
        
        assert error_response.is_client_error is True
        assert error_response.is_success is False
        
        # Server error response
        server_error_response = Response(
            status_code=500,
            headers={},
            content=b'Internal Server Error',
            text='Internal Server Error',
            url='http://example.com',
            elapsed=1.0,
            request_method='POST'
        )
        
        assert server_error_response.is_server_error is True
        assert server_error_response.is_success is False


if __name__ == '__main__':
    pytest.main([__file__])