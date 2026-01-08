#!/usr/bin/env python3
"""
APILeak HTTP Client Demo
Demonstrates the HTTP Request Engine capabilities
"""

import asyncio
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, Request
from core.config import RateLimitConfig, AuthContext, AuthType
from core.logging import setup_logging


async def demo_basic_requests():
    """Demonstrate basic HTTP requests"""
    print("=== Basic HTTP Requests Demo ===")
    
    # Setup rate limiter and retry config
    rate_config = RateLimitConfig(requests_per_second=5, burst_size=10)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=3)
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # GET request
        print("Making GET request...")
        response = await http_engine.request('GET', 'https://httpbin.org/get')
        print(f"GET Response: {response.status_code} - {len(response.content)} bytes")
        
        # POST request with JSON
        print("Making POST request with JSON...")
        response = await http_engine.request(
            'POST', 
            'https://httpbin.org/post',
            json={'message': 'Hello from APILeak!', 'test': True}
        )
        print(f"POST Response: {response.status_code} - {len(response.content)} bytes")
        
        # Request with custom headers
        print("Making request with custom headers...")
        response = await http_engine.request(
            'GET',
            'https://httpbin.org/headers',
            headers={'X-Custom-Header': 'APILeak-Demo', 'User-Agent': 'APILeak/0.1.0'}
        )
        print(f"Headers Response: {response.status_code}")
        
        # Show performance metrics
        metrics = http_engine.get_performance_metrics()
        print(f"\nPerformance Metrics:")
        print(f"  Total Requests: {metrics.total_requests}")
        print(f"  Success Rate: {metrics.success_rate:.1f}%")
        print(f"  Average Response Time: {metrics.average_response_time:.3f}s")


async def demo_authentication():
    """Demonstrate authentication methods"""
    print("\n=== Authentication Demo ===")
    
    rate_config = RateLimitConfig(requests_per_second=3, burst_size=5)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # Bearer token authentication
        print("Testing Bearer token authentication...")
        bearer_auth = AuthContext(
            name="bearer_user",
            type=AuthType.BEARER,
            token="fake-bearer-token-123"
        )
        
        http_engine.set_auth_context(bearer_auth)
        response = await http_engine.request('GET', 'https://httpbin.org/bearer')
        print(f"Bearer Auth Response: {response.status_code} (401 expected with fake token)")
        
        # Basic authentication
        print("Testing Basic authentication...")
        basic_auth = AuthContext(
            name="basic_user",
            type=AuthType.BASIC,
            token="",  # Not used for basic auth
            username="testuser",
            password="testpass"
        )
        
        http_engine.set_auth_context(basic_auth)
        response = await http_engine.request('GET', 'https://httpbin.org/basic-auth/testuser/testpass')
        print(f"Basic Auth Response: {response.status_code} (200 expected)")
        
        # API Key authentication
        print("Testing API Key authentication...")
        api_key_auth = AuthContext(
            name="api_user",
            type=AuthType.API_KEY,
            token="demo-api-key-456"
        )
        
        http_engine.set_auth_context(api_key_auth)
        response = await http_engine.request('GET', 'https://httpbin.org/headers')
        print(f"API Key Auth Response: {response.status_code}")


async def demo_batch_requests():
    """Demonstrate batch request processing"""
    print("\n=== Batch Requests Demo ===")
    
    rate_config = RateLimitConfig(requests_per_second=10, burst_size=15)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # Create batch of requests
        requests = [
            Request('GET', 'https://httpbin.org/delay/1'),
            Request('GET', 'https://httpbin.org/json'),
            Request('GET', 'https://httpbin.org/uuid'),
            Request('POST', 'https://httpbin.org/post', json={'batch_id': i}) 
            for i in range(3)
        ]
        
        print(f"Executing batch of {len(requests)} requests...")
        import time
        start_time = time.time()
        
        responses = await http_engine.batch_request(requests)
        
        elapsed = time.time() - start_time
        successful = sum(1 for r in responses if r.is_success)
        
        print(f"Batch completed in {elapsed:.2f}s")
        print(f"Successful requests: {successful}/{len(responses)}")
        
        # Show individual response status codes
        for i, response in enumerate(responses):
            print(f"  Request {i+1}: {response.status_code} ({response.elapsed:.3f}s)")


async def demo_rate_limiting():
    """Demonstrate rate limiting behavior"""
    print("\n=== Rate Limiting Demo ===")
    
    # Create strict rate limiter
    rate_config = RateLimitConfig(
        requests_per_second=2,  # Very low rate
        burst_size=3,
        adaptive=True,
        respect_retry_after=True
    )
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=1)
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        print("Making 5 requests with 2 RPS limit...")
        
        import time
        start_time = time.time()
        
        for i in range(5):
            response = await http_engine.request('GET', f'https://httpbin.org/delay/0')
            elapsed = time.time() - start_time
            print(f"Request {i+1}: {response.status_code} at {elapsed:.2f}s")
        
        total_elapsed = time.time() - start_time
        print(f"Total time: {total_elapsed:.2f}s (should be ~2s due to rate limiting)")


async def demo_error_handling():
    """Demonstrate error handling and retry logic"""
    print("\n=== Error Handling Demo ===")
    
    rate_config = RateLimitConfig(requests_per_second=5, burst_size=10)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(
        max_attempts=3,
        retry_on_status=[500, 502, 503, 504],
        backoff_factor=1.5
    )
    
    async with HTTPRequestEngine(rate_limiter, retry_config) as http_engine:
        # Test server error with retry
        print("Testing server error with retry...")
        response = await http_engine.request('GET', 'https://httpbin.org/status/500')
        print(f"Server Error Response: {response.status_code}")
        
        # Test timeout handling
        print("Testing timeout handling...")
        try:
            response = await http_engine.request('GET', 'https://httpbin.org/delay/5', timeout=2.0)
            print(f"Timeout Response: {response.status_code}")
        except Exception as e:
            print(f"Timeout handled: {type(e).__name__}")
        
        # Show retry metrics
        metrics = http_engine.get_performance_metrics()
        print(f"Retried requests: {metrics.retried_requests}")


async def main():
    """Run all demos"""
    # Setup logging
    setup_logging(level="INFO")
    
    print("APILeak HTTP Request Engine Demo")
    print("=" * 40)
    
    try:
        await demo_basic_requests()
        await demo_authentication()
        await demo_batch_requests()
        await demo_rate_limiting()
        await demo_error_handling()
        
        print("\n=== Demo Complete ===")
        print("HTTP Request Engine is working correctly!")
        
    except Exception as e:
        print(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())