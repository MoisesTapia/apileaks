"""
Integration tests for HTTP Request Engine
Tests against real endpoints to verify functionality
"""

import pytest
import asyncio
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from core.config import RateLimitConfig, AuthContext, AuthType


@pytest.mark.asyncio
async def test_real_http_request():
    """Test HTTP client against a real endpoint"""
    # Create rate limiter and retry config
    rate_config = RateLimitConfig(requests_per_second=5, burst_size=10)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    
    # Create HTTP engine
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # Test GET request to httpbin
        response = await http_engine.request('GET', 'https://httpbin.org/get')
        
        assert response.status_code == 200
        assert response.is_success
        assert 'httpbin.org' in response.url
        
        # Verify metrics were updated
        metrics = http_engine.get_performance_metrics()
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 1


@pytest.mark.asyncio
async def test_rate_limiting_behavior():
    """Test rate limiting behavior with multiple requests"""
    # Create strict rate limiter
    rate_config = RateLimitConfig(requests_per_second=2, burst_size=3)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=1)
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # Make multiple requests and measure timing
        import time
        start_time = time.time()
        
        responses = []
        for i in range(5):
            response = await http_engine.request('GET', f'https://httpbin.org/delay/0')
            responses.append(response)
        
        elapsed = time.time() - start_time
        
        # Should take at least 1 second due to rate limiting (2 RPS for 5 requests)
        assert elapsed >= 1.0
        assert all(r.status_code == 200 for r in responses)


@pytest.mark.asyncio
async def test_authentication_integration():
    """Test authentication with real endpoint"""
    rate_config = RateLimitConfig(requests_per_second=10, burst_size=5)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # Test Bearer token authentication
        auth_context = AuthContext(
            name="test_bearer",
            type=AuthType.BEARER,
            token="test-token-123"
        )
        
        http_engine.set_auth_context(auth_context)
        
        # httpbin.org/bearer endpoint accepts any Bearer token and returns 200
        response = await http_engine.request('GET', 'https://httpbin.org/bearer')
        
        # httpbin.org/bearer returns 200 with token details for any Bearer token
        assert response.status_code == 200
        assert "authenticated" in response.text
        assert "test-token-123" in response.text


@pytest.mark.asyncio
async def test_retry_on_server_error():
    """Test retry behavior on server errors"""
    rate_config = RateLimitConfig(requests_per_second=10, burst_size=5)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(
        max_attempts=3,
        retry_on_status=[500, 502, 503, 504],
        backoff_factor=1.1  # Small backoff for faster test
    )
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # httpbin.org/status/500 always returns 500
        response = await http_engine.request('GET', 'https://httpbin.org/status/500')
        
        assert response.status_code == 500
        
        # Check that retries were attempted
        metrics = http_engine.get_performance_metrics()
        assert metrics.retried_requests > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])