"""
Integration tests for Core Engine with Fuzzing Orchestrator
"""

import pytest
import tempfile
import os
from unittest.mock import patch

from core.engine import APILeakCore
from core.config import APILeakConfig, TargetConfig, FuzzingConfig, EndpointFuzzingConfig, ParameterFuzzingConfig, HeaderFuzzingConfig, OWASPConfig, AuthConfig, RateLimitConfig, ReportConfig


@pytest.mark.asyncio
async def test_core_engine_with_fuzzing_orchestrator():
    """Test core engine integration with fuzzing orchestrator"""
    # Create temporary wordlist
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("get\npost\nstatus\n")
        temp_wordlist = f.name
    
    try:
        # Create configuration
        config = APILeakConfig(
            target=TargetConfig(base_url="https://httpbin.org"),
            fuzzing=FuzzingConfig(
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
            ),
            owasp_testing=OWASPConfig(enabled_modules=[]),
            authentication=AuthConfig(),
            rate_limiting=RateLimitConfig(requests_per_second=2, burst_size=5),
            reporting=ReportConfig()
        )
        
        # Create core engine
        core = APILeakCore(config)
        
        # Run scan
        results = await core.run_scan("https://httpbin.org")
        
        # Verify results
        assert results is not None
        assert results.target_url == "https://httpbin.org"
        assert results.statistics.endpoints_discovered > 0
        assert results.fuzzing_results is not None
        assert results.fuzzing_results["endpoints_tested"] > 0
        
        # Verify discovered endpoints
        discovered_endpoints = core.get_discovered_endpoints()
        assert len(discovered_endpoints) > 0
        
        # Check that we found the /get endpoint
        get_endpoints = [e for e in discovered_endpoints if e.url.endswith('/get')]
        assert len(get_endpoints) > 0
        
        print(f"Scan completed successfully:")
        print(f"  - Endpoints discovered: {results.statistics.endpoints_discovered}")
        print(f"  - Total requests: {results.fuzzing_results['total_requests']}")
        print(f"  - Success rate: {results.fuzzing_results['success_rate']:.1f}%")
        print(f"  - Duration: {results.performance_metrics.duration}")
        
    finally:
        os.unlink(temp_wordlist)


@pytest.mark.asyncio
async def test_core_engine_health_check():
    """Test core engine health check"""
    config = APILeakConfig(
        target=TargetConfig(base_url="https://httpbin.org"),
        fuzzing=FuzzingConfig(),
        owasp_testing=OWASPConfig(),
        authentication=AuthConfig(),
        rate_limiting=RateLimitConfig(),
        reporting=ReportConfig()
    )
    
    core = APILeakCore(config)
    
    # Test health check
    health = await core.health_check()
    
    assert health["status"] in ["healthy", "degraded"]
    assert health["configuration_loaded"] is True
    assert "timestamp" in health
    assert "scan_id" in health


def test_core_engine_status():
    """Test core engine status reporting"""
    config = APILeakConfig(
        target=TargetConfig(base_url="https://httpbin.org"),
        fuzzing=FuzzingConfig(),
        owasp_testing=OWASPConfig(enabled_modules=["bola", "auth"]),
        authentication=AuthConfig(),
        rate_limiting=RateLimitConfig(),
        reporting=ReportConfig()
    )
    
    core = APILeakCore(config)
    
    # Test status
    status = core.get_scan_status()
    
    assert status["target"] == "https://httpbin.org"
    assert status["is_running"] is False
    assert status["enabled_owasp_modules"] == ["bola", "auth"]
    assert "scan_id" in status


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])