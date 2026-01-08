#!/usr/bin/env python3
"""
APILeak Colored HTTP Requests Demo
Demonstrates the colored HTTP request output feature with status code filtering
"""

import asyncio
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from core.config import RateLimitConfig
from core.logging import setup_logging, get_logger


async def demo_colored_requests():
    """Demonstrate colored HTTP request output with status code filtering"""
    logger = get_logger(__name__)
    logger.info("Starting Enhanced Colored HTTP Requests Demo")
    
    # Setup HTTP client with rate limiting
    rate_config = RateLimitConfig(requests_per_second=5, burst_size=10)
    retry_config = RetryConfig(max_attempts=1)
    rate_limiter = RateLimiter(rate_config)
    
    print("\n=== Enhanced Colored HTTP Request Output Demo ===")
    print("This demo shows the new features:")
    print("1. HTTP requests are now shown by DEFAULT (no --log-level needed)")
    print("2. Status code filtering with --status-code option")
    print("\nColor coding:")
    print("  [+] Green  - 2xx Success responses")
    print("  [-] Yellow - 3xx Redirect responses") 
    print("  [*] Gray   - 4xx Client error responses")
    print("  [x] Red    - 5xx Server error responses")
    
    # Test 1: Show all requests (default behavior)
    print("\n--- Test 1: All HTTP requests (default behavior) ---")
    async with HTTPRequestEngine(rate_limiter, retry_config) as client:
        test_urls = [
            ('https://httpbin.org/status/200', '200 OK'),
            ('https://httpbin.org/status/404', '404 Not Found'),
            ('https://httpbin.org/status/500', '500 Server Error'),
        ]
        
        for url, description in test_urls:
            print(f"Testing: {description}")
            try:
                await client.request('GET', url)
                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"Request failed: {e}")
    
    # Test 2: Filter only 200 status codes
    print("\n--- Test 2: Filter only 200 status codes ---")
    status_filter = [200]  # Only show 200 responses
    async with HTTPRequestEngine(rate_limiter, retry_config, status_code_filter=status_filter) as client:
        test_urls = [
            ('https://httpbin.org/status/200', '200 OK - SHOULD SHOW'),
            ('https://httpbin.org/status/404', '404 Not Found - SHOULD NOT SHOW'),
            ('https://httpbin.org/status/500', '500 Server Error - SHOULD NOT SHOW'),
        ]
        
        for url, description in test_urls:
            print(f"Testing: {description}")
            try:
                await client.request('GET', url)
                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"Request failed: {e}")
    
    # Test 3: Filter multiple status codes (200, 404)
    print("\n--- Test 3: Filter 200 and 404 status codes ---")
    status_filter = [200, 404]  # Show both 200 and 404 responses
    async with HTTPRequestEngine(rate_limiter, retry_config, status_code_filter=status_filter) as client:
        test_urls = [
            ('https://httpbin.org/status/200', '200 OK - SHOULD SHOW'),
            ('https://httpbin.org/status/404', '404 Not Found - SHOULD SHOW'),
            ('https://httpbin.org/status/500', '500 Server Error - SHOULD NOT SHOW'),
        ]
        
        for url, description in test_urls:
            print(f"Testing: {description}")
            try:
                await client.request('GET', url)
                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"Request failed: {e}")
    
    print("\n=== Demo Complete ===")
    print("New features implemented:")
    print("✅ HTTP requests now show by default (no --log-level needed)")
    print("✅ --status-code option for filtering (e.g., --status-code 200,404)")
    print("✅ Works with all scan types: dir, par, full")
    logger.info("Enhanced Colored HTTP Requests Demo completed")


if __name__ == "__main__":
    # Setup logging (but HTTP output will show regardless)
    setup_logging(level="WARNING")  # Even with WARNING level, HTTP requests will show
    
    # Run demo
    asyncio.run(demo_colored_requests())