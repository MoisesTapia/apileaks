"""
Tests for Intelligent WAF System
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from modules.advanced.intelligent_waf_system import (
    IntelligentWAFSystem, 
    IntelligentWAFConfig,
    WAFSystemState
)
from modules.advanced.waf_detector import WAFType, WAFDetectionResult
from modules.advanced.adaptive_throttling import RateLimitInfo, RateLimitType, ThrottleStrategy


class MockResponse:
    """Mock HTTP response"""
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class MockHTTPClient:
    """Mock HTTP client"""
    def __init__(self, responses=None):
        self.responses = responses or []
        self.request_count = 0
    
    async def request(self, method, url, **kwargs):
        if self.request_count < len(self.responses):
            response = self.responses[self.request_count]
        else:
            response = MockResponse()
        
        self.request_count += 1
        return response


@pytest.fixture
def waf_config():
    """WAF system configuration for testing"""
    return IntelligentWAFConfig(
        enable_waf_detection=True,
        enable_adaptive_throttling=True,
        initial_throttle_rate=2.0,
        min_throttle_rate=0.5,
        max_throttle_rate=5.0,
        throttle_strategy=ThrottleStrategy.ADAPTIVE
    )


@pytest.fixture
def mock_monitoring():
    """Mock monitoring system"""
    monitoring = Mock()
    monitoring.logger = Mock()
    monitoring.record_request = Mock()
    monitoring.record_rate_limit = Mock()
    monitoring.record_timeout = Mock()
    return monitoring


@pytest.mark.asyncio
async def test_waf_system_initialization(waf_config, mock_monitoring):
    """Test WAF system initialization"""
    waf_system = IntelligentWAFSystem(waf_config, mock_monitoring)
    
    assert waf_system.config == waf_config
    assert waf_system.monitoring == mock_monitoring
    assert isinstance(waf_system.state, WAFSystemState)
    assert not waf_system.state.waf_detected
    assert not waf_system.state.rate_limits_detected


@pytest.mark.asyncio
async def test_waf_detection_positive():
    """Test positive WAF detection"""
    # Mock responses that indicate Cloudflare WAF
    responses = [
        MockResponse(
            status_code=200,
            headers={
                "server": "cloudflare",
                "cf-ray": "12345-ABC"
            }
        ),
        MockResponse(
            status_code=403,
            text="attention required cloudflare security check"
        )
    ]
    
    http_client = MockHTTPClient(responses)
    waf_system = IntelligentWAFSystem()
    
    # Mock the WAF detector
    with patch.object(waf_system.waf_detector, 'detect_waf') as mock_detect:
        mock_detect.return_value = WAFDetectionResult(
            detected=True,
            waf_type=WAFType.CLOUDFLARE,
            confidence=0.9,
            detection_method="passive",
            evasion_techniques=["case_variation", "url_encoding"]
        )
        
        await waf_system.initialize_for_target(http_client, "https://example.com")
        
        assert waf_system.state.waf_detected
        assert waf_system.state.waf_info.waf_type == WAFType.CLOUDFLARE
        assert waf_system.state.waf_info.confidence == 0.9
        assert "case_variation" in waf_system.state.evasion_techniques_active


@pytest.mark.asyncio
async def test_rate_limit_detection():
    """Test rate limit detection"""
    responses = [
        MockResponse(
            status_code=200,
            headers={
                "x-ratelimit-limit": "100",
                "x-ratelimit-remaining": "95",
                "x-ratelimit-reset": "1640995200"
            }
        )
    ]
    
    http_client = MockHTTPClient(responses)
    waf_system = IntelligentWAFSystem()
    
    # Mock the rate limit detector
    with patch.object(waf_system.rate_limit_detector, 'detect_rate_limits') as mock_detect:
        mock_detect.return_value = RateLimitInfo(
            detected=True,
            limit_type=RateLimitType.REQUESTS_PER_HOUR,
            limit_value=100,
            detection_confidence=0.9,
            detection_method="header_analysis"
        )
        
        await waf_system.initialize_for_target(http_client, "https://example.com")
        
        assert waf_system.state.rate_limits_detected
        assert waf_system.state.rate_limit_info.limit_type == RateLimitType.REQUESTS_PER_HOUR
        assert waf_system.state.rate_limit_info.limit_value == 100


@pytest.mark.asyncio
async def test_intelligent_request_normal():
    """Test intelligent request with normal response"""
    responses = [MockResponse(status_code=200, text="success")]
    http_client = MockHTTPClient(responses)
    
    waf_system = IntelligentWAFSystem()
    waf_system.http_client = http_client
    waf_system.target_url = "https://example.com"
    
    # Mock adaptive throttling
    with patch.object(waf_system.adaptive_throttling, 'throttled_request') as mock_request:
        mock_request.return_value = responses[0]
        
        response = await waf_system.make_intelligent_request("GET", "https://example.com/api")
        
        assert response.status_code == 200
        assert waf_system.state.total_requests == 1
        assert waf_system.state.blocked_requests == 0


@pytest.mark.asyncio
async def test_intelligent_request_blocked():
    """Test intelligent request with blocked response"""
    blocked_response = MockResponse(status_code=403, text="blocked by waf")
    success_response = MockResponse(status_code=200, text="success")
    
    http_client = MockHTTPClient([blocked_response, success_response])
    
    waf_system = IntelligentWAFSystem()
    waf_system.http_client = http_client
    waf_system.target_url = "https://example.com"
    waf_system.state.waf_detected = True
    waf_system.state.waf_info = WAFDetectionResult(
        detected=True,
        waf_type=WAFType.CLOUDFLARE,
        confidence=0.9,
        evasion_techniques=["case_variation"]
    )
    
    # Mock adaptive throttling and evasion
    with patch.object(waf_system.adaptive_throttling, 'throttled_request') as mock_request:
        with patch.object(waf_system, '_attempt_evasion') as mock_evasion:
            mock_request.return_value = blocked_response
            mock_evasion.return_value = success_response
            
            response = await waf_system.make_intelligent_request("GET", "https://example.com/api")
            
            assert response.status_code == 200
            assert waf_system.state.total_requests == 1
            assert waf_system.state.blocked_requests == 1
            assert waf_system.state.successful_evasions == 1


@pytest.mark.asyncio
async def test_user_agent_rotation():
    """Test user agent rotation functionality"""
    waf_system = IntelligentWAFSystem()
    
    # Get multiple user agents
    ua1 = waf_system.user_agent_rotator.get_next_user_agent()
    ua2 = waf_system.user_agent_rotator.get_next_user_agent()
    ua3 = waf_system.user_agent_rotator.get_next_user_agent()
    
    # Should be different (with high probability)
    assert ua1 != ua2 or ua2 != ua3
    
    # Random user agent should be from the list
    random_ua = waf_system.user_agent_rotator.get_random_user_agent()
    assert random_ua in waf_system.user_agent_rotator.user_agents


def test_system_status():
    """Test system status reporting"""
    waf_system = IntelligentWAFSystem()
    waf_system.state.waf_detected = True
    waf_system.state.waf_info = WAFDetectionResult(
        detected=True,
        waf_type=WAFType.CLOUDFLARE,
        confidence=0.9,
        evasion_techniques=["case_variation", "url_encoding"]
    )
    waf_system.state.total_requests = 100
    waf_system.state.blocked_requests = 10
    waf_system.state.successful_evasions = 8
    
    status = waf_system.get_system_status()
    
    assert status["waf_detection"]["detected"] is True
    assert status["waf_detection"]["type"] == "cloudflare"
    assert status["waf_detection"]["confidence"] == 0.9
    assert status["statistics"]["total_requests"] == 100
    assert status["statistics"]["blocked_requests"] == 10
    assert status["statistics"]["successful_evasions"] == 8
    assert status["statistics"]["block_rate"] == 0.1
    assert status["statistics"]["evasion_success_rate"] == 0.8


def test_system_reset():
    """Test system reset functionality"""
    waf_system = IntelligentWAFSystem()
    
    # Set some state
    waf_system.state.waf_detected = True
    waf_system.state.total_requests = 50
    waf_system.state.blocked_requests = 5
    
    # Reset system
    waf_system.reset_system()
    
    # Verify reset
    assert not waf_system.state.waf_detected
    assert waf_system.state.total_requests == 0
    assert waf_system.state.blocked_requests == 0


@pytest.mark.asyncio
async def test_evasion_payload_generation():
    """Test WAF evasion payload generation"""
    waf_system = IntelligentWAFSystem()
    waf_system.state.waf_detected = True
    waf_system.state.waf_info = WAFDetectionResult(
        detected=True,
        waf_type=WAFType.CLOUDFLARE,
        confidence=0.9,
        evasion_techniques=["case_variation", "url_encoding"]
    )
    
    # Mock the WAF detector's evasion payload generation
    with patch.object(waf_system.waf_detector, 'get_evasion_payloads') as mock_payloads:
        mock_payloads.return_value = [
            "' OR '1'='1",
            "' oR '1'='1",
            "%27%20OR%20%271%27%3D%271"
        ]
        
        evasion_payload = await waf_system._apply_waf_evasion("' OR '1'='1")
        
        assert evasion_payload in mock_payloads.return_value
        mock_payloads.assert_called_once_with(WAFType.CLOUDFLARE, "' OR '1'='1")


if __name__ == "__main__":
    pytest.main([__file__])