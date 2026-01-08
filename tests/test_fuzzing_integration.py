"""
Integration tests for Fuzzing Orchestrator
Tests against real endpoints to verify functionality
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from modules.fuzzing.orchestrator import FuzzingOrchestrator, EndpointStatus
from core.config import FuzzingConfig, EndpointFuzzingConfig, ParameterFuzzingConfig, HeaderFuzzingConfig, RateLimitConfig
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig


@pytest.mark.asyncio
async def test_real_endpoint_discovery():
    """Test endpoint discovery against a real target"""
    # Create temporary wordlist with endpoints that exist on httpbin.org
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("get\npost\nput\ndelete\nstatus\nbearer\nbasic-auth\nnonexistent\n")
        temp_wordlist = f.name
    
    try:
        # Create configuration
        fuzzing_config = FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist=temp_wordlist,
                methods=["GET"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=False,
            max_depth=1
        )
        
        # Create HTTP client with conservative rate limiting
        rate_config = RateLimitConfig(requests_per_second=2, burst_size=5)
        rate_limiter = RateLimiter(rate_config)
        retry_config = RetryConfig(max_attempts=2)
        
        async with HTTPRequestEngine(rate_limiter, retry_config) as http_client:
            # Create fuzzing orchestrator
            orchestrator = FuzzingOrchestrator(fuzzing_config, http_client)
            
            # Test against httpbin.org (reliable test endpoint)
            endpoints = await orchestrator.discover_endpoints('https://httpbin.org')
            
            # Verify we found some endpoints
            assert len(endpoints) > 0
            
            # Check that we found expected endpoints
            endpoint_urls = [e.url for e in endpoints]
            assert any('get' in url for url in endpoint_urls), "Should find /get endpoint"
            
            # Verify endpoint classification
            valid_endpoints = orchestrator.get_endpoints_by_status(EndpointStatus.VALID)
            auth_required_endpoints = orchestrator.get_endpoints_by_status(EndpointStatus.AUTH_REQUIRED)
            
            # Should have some valid endpoints
            assert len(valid_endpoints) > 0, "Should have at least one valid endpoint"
            
            print(f"Found {len(endpoints)} total endpoints")
            print(f"Valid endpoints: {len(valid_endpoints)}")
            print(f"Auth required endpoints: {len(auth_required_endpoints)}")
            
            # Get statistics
            stats = orchestrator.get_fuzzing_statistics()
            assert stats.endpoints_tested > 0
            assert stats.total_requests > 0
            
            print(f"Statistics: {stats.endpoints_tested} tested, {stats.success_rate:.1f}% success rate")
            
    finally:
        # Cleanup
        os.unlink(temp_wordlist)


@pytest.mark.asyncio
async def test_endpoint_classification():
    """Test endpoint classification with known endpoints"""
    # Create wordlist with specific endpoints we know exist on httpbin.org
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("get\npost\nstatus\nbearer\nbasic-auth\nnonexistent\n")
        temp_wordlist = f.name
    
    try:
        fuzzing_config = FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist=temp_wordlist,
                methods=["GET"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=False,
            max_depth=1
        )
        
        rate_config = RateLimitConfig(requests_per_second=2, burst_size=5)
        rate_limiter = RateLimiter(rate_config)
        retry_config = RetryConfig(max_attempts=2)
        
        async with HTTPRequestEngine(rate_limiter, retry_config) as http_client:
            orchestrator = FuzzingOrchestrator(fuzzing_config, http_client)
            endpoints = await orchestrator.discover_endpoints('https://httpbin.org')
            
            # Find specific endpoints
            get_endpoints = [e for e in endpoints if e.url.endswith('/get')]
            bearer_endpoints = [e for e in endpoints if e.url.endswith('/bearer')]
            
            # Verify we found expected endpoints
            assert len(get_endpoints) > 0, "Should find /get endpoint"
            
            # The /get endpoint should be valid (200)
            get_endpoint = get_endpoints[0]
            assert get_endpoint.status == EndpointStatus.VALID
            
            # Print discovered endpoints for debugging
            print("\nDiscovered endpoints:")
            for endpoint in endpoints:
                print(f"  {endpoint.method} {endpoint.url} -> {endpoint.status_code} ({endpoint.status.value})")
            
    finally:
        os.unlink(temp_wordlist)


@pytest.mark.asyncio
async def test_recursive_fuzzing():
    """Test recursive fuzzing functionality"""
    # Create wordlist with paths that might have sub-paths
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("status\nget\n")
        temp_wordlist = f.name
    
    try:
        fuzzing_config = FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist=temp_wordlist,
                methods=["GET"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=True,
            max_depth=2
        )
        
        rate_config = RateLimitConfig(requests_per_second=2, burst_size=5)
        rate_limiter = RateLimiter(rate_config)
        retry_config = RetryConfig(max_attempts=2)
        
        async with HTTPRequestEngine(rate_limiter, retry_config) as http_client:
            orchestrator = FuzzingOrchestrator(fuzzing_config, http_client)
            endpoints = await orchestrator.discover_endpoints('https://httpbin.org')
            
            # With recursive fuzzing, we should test more URLs
            stats = orchestrator.get_fuzzing_statistics()
            
            print(f"Recursive fuzzing tested {stats.endpoints_tested} endpoints")
            print(f"Found {len(endpoints)} valid endpoints")
            
            # Should have tested more endpoints due to recursion
            assert stats.endpoints_tested >= len(temp_wordlist.split('\n')) * len(fuzzing_config.endpoints.methods)
            
    finally:
        os.unlink(temp_wordlist)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])