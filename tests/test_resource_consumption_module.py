"""
Tests for Resource Consumption Testing Module
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass

from modules.owasp.resource_consumption import ResourceConsumptionModule, ResourceTestResult, RateLimitTestResult
from utils.http_client import HTTPRequestEngine, Response
from core.config import ResourceTestingConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


class TestResourceConsumptionModule:
    """Test cases for Resource Consumption Testing Module"""
    
    @pytest.fixture
    def resource_config(self):
        """Create Resource Testing configuration for testing"""
        return ResourceTestingConfig(
            enabled=True,
            burst_size=100,
            large_payload_sizes=[1024*1024, 10*1024*1024],  # 1MB, 10MB
            json_depth_limit=1000
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
    def resource_module(self, resource_config, auth_contexts, mock_http_client):
        """Create Resource Consumption testing module"""
        return ResourceConsumptionModule(resource_config, mock_http_client, auth_contexts)
    
    def test_module_initialization(self, resource_module, auth_contexts):
        """Test Resource Consumption module initialization"""
        assert resource_module.get_module_name() == "resource_consumption"
        assert len(resource_module.auth_contexts) == len(auth_contexts)
        assert len(resource_module.REDOS_PATTERNS) > 0
        assert len(resource_module.COMPLEX_QUERY_PATTERNS) > 0
        assert len(resource_module.PAYLOAD_SIZES) > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting_detection(self, resource_module, mock_http_client):
        """Test rate limiting detection with burst requests"""
        # Mock endpoints
        endpoints = [
            MockEndpoint("https://api.example.com/users"),
            MockEndpoint("https://api.example.com/orders", "POST")
        ]
        
        # Mock successful responses (no rate limiting)
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"success": true}',
            text='{"success": true}',
            url="https://api.example.com/users",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_rate_limiting(endpoints)
        
        # Should detect missing rate limiting
        assert len(findings) >= 1
        rate_limit_findings = [f for f in findings if f.category == "MISSING_RATE_LIMITING"]
        assert len(rate_limit_findings) > 0
        assert rate_limit_findings[0].severity == Severity.MEDIUM
        assert rate_limit_findings[0].owasp_category == "API4"
    
    @pytest.mark.asyncio
    async def test_rate_limiting_with_blocking(self, resource_module, mock_http_client):
        """Test rate limiting detection when server blocks requests"""
        endpoints = [MockEndpoint("https://api.example.com/users")]
        
        # Mock responses - some succeed, some get rate limited
        def mock_request_side_effect(*args, **kwargs):
            # Simulate rate limiting after some requests
            if hasattr(mock_request_side_effect, 'call_count'):
                mock_request_side_effect.call_count += 1
            else:
                mock_request_side_effect.call_count = 1
            
            if mock_request_side_effect.call_count > 20:  # Rate limit after 20 requests
                return Response(
                    status_code=429,
                    headers={"retry-after": "60"},
                    content=b'{"error": "Too Many Requests"}',
                    text='{"error": "Too Many Requests"}',
                    url="https://api.example.com/users",
                    elapsed=0.1,
                    request_method="GET"
                )
            else:
                return Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=b'{"success": true}',
                    text='{"success": true}',
                    url="https://api.example.com/users",
                    elapsed=0.1,
                    request_method="GET"
                )
        
        mock_http_client.request.side_effect = mock_request_side_effect
        
        findings = await resource_module._test_rate_limiting(endpoints)
        
        # Should not report missing rate limiting since server blocks requests
        rate_limit_findings = [f for f in findings if f.category == "MISSING_RATE_LIMITING"]
        assert len(rate_limit_findings) == 0
    
    @pytest.mark.asyncio
    async def test_large_payload_acceptance(self, resource_module, mock_http_client):
        """Test large payload acceptance detection"""
        # Mock POST endpoint
        endpoints = [MockEndpoint("https://api.example.com/upload", "POST")]
        
        # Mock successful response to large payload
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"uploaded": true, "size": 1048576}',
            text='{"uploaded": true, "size": 1048576}',
            url="https://api.example.com/upload",
            elapsed=2.5,  # Slow response indicating processing
            request_method="POST"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_large_payloads(endpoints)
        
        # Should detect large payload acceptance
        assert len(findings) >= 1
        large_payload_findings = [f for f in findings if f.category == "LARGE_PAYLOAD_ACCEPTED"]
        assert len(large_payload_findings) > 0
        assert large_payload_findings[0].severity in [Severity.MEDIUM, Severity.HIGH]
        assert large_payload_findings[0].owasp_category == "API4"
    
    @pytest.mark.asyncio
    async def test_large_payload_rejection(self, resource_module, mock_http_client):
        """Test when server properly rejects large payloads"""
        endpoints = [MockEndpoint("https://api.example.com/upload", "POST")]
        
        # Mock rejection response
        mock_response = Response(
            status_code=413,  # Payload Too Large
            headers={"content-type": "application/json"},
            content=b'{"error": "Payload too large"}',
            text='{"error": "Payload too large"}',
            url="https://api.example.com/upload",
            elapsed=0.1,
            request_method="POST"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_large_payloads(endpoints)
        
        # Should not report vulnerability since server rejects large payloads
        large_payload_findings = [f for f in findings if f.category == "LARGE_PAYLOAD_ACCEPTED"]
        assert len(large_payload_findings) == 0
    
    @pytest.mark.asyncio
    async def test_deeply_nested_json_acceptance(self, resource_module, mock_http_client):
        """Test deeply nested JSON acceptance detection"""
        endpoints = [MockEndpoint("https://api.example.com/data", "POST")]
        
        # Mock successful response to deeply nested JSON
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"processed": true, "depth": 1000}',
            text='{"processed": true, "depth": 1000}',
            url="https://api.example.com/data",
            elapsed=3.0,  # Slow response indicating deep processing
            request_method="POST"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_json_nesting(endpoints)
        
        # Should detect deeply nested JSON acceptance
        nested_findings = [f for f in findings if f.category == "DEEP_JSON_NESTING_ACCEPTED"]
        assert len(nested_findings) >= 1
        assert nested_findings[0].severity == Severity.MEDIUM
        assert nested_findings[0].owasp_category == "API4"
    
    @pytest.mark.asyncio
    async def test_large_json_array_acceptance(self, resource_module, mock_http_client):
        """Test large JSON array acceptance detection"""
        endpoints = [MockEndpoint("https://api.example.com/batch", "POST")]
        
        # Mock successful response to large array
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"processed": 10000, "items": "accepted"}',
            text='{"processed": 10000, "items": "accepted"}',
            url="https://api.example.com/batch",
            elapsed=4.0,  # Slow response indicating array processing
            request_method="POST"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_json_nesting(endpoints)
        
        # Should detect large array acceptance
        array_findings = [f for f in findings if f.category == "LARGE_JSON_ARRAY_ACCEPTED"]
        assert len(array_findings) >= 1
        assert array_findings[0].severity == Severity.MEDIUM
        assert array_findings[0].owasp_category == "API4"
    
    @pytest.mark.asyncio
    async def test_redos_vulnerability_detection(self, resource_module, mock_http_client):
        """Test ReDoS vulnerability detection"""
        endpoints = [MockEndpoint("https://api.example.com/validate")]
        
        # Mock slow response indicating ReDoS
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"validation": "timeout"}',
            text='{"validation": "timeout"}',
            url="https://api.example.com/validate",
            elapsed=6.0,  # Very slow response indicating ReDoS
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_redos_patterns(endpoints)
        
        # Should detect ReDoS vulnerability
        redos_findings = [f for f in findings if f.category == "REDOS_VULNERABILITY"]
        assert len(redos_findings) >= 1
        assert redos_findings[0].severity == Severity.HIGH
        assert redos_findings[0].owasp_category == "API4"
    
    @pytest.mark.asyncio
    async def test_redos_no_vulnerability(self, resource_module, mock_http_client):
        """Test when no ReDoS vulnerability exists"""
        endpoints = [MockEndpoint("https://api.example.com/validate")]
        
        # Mock fast response - no ReDoS
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"validation": "success"}',
            text='{"validation": "success"}',
            url="https://api.example.com/validate",
            elapsed=0.1,  # Fast response
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_redos_patterns(endpoints)
        
        # Should not detect ReDoS vulnerability
        redos_findings = [f for f in findings if f.category == "REDOS_VULNERABILITY"]
        assert len(redos_findings) == 0
    
    @pytest.mark.asyncio
    async def test_complex_query_processing(self, resource_module, mock_http_client):
        """Test complex query processing detection"""
        endpoints = [MockEndpoint("https://api.example.com/search")]
        
        # Mock response indicating complex query processing
        mock_response = Response(
            status_code=500,  # Server error from complex query
            headers={"content-type": "application/json"},
            content=b'{"error": "Database timeout", "sql": "complex query"}',
            text='{"error": "Database timeout", "sql": "complex query"}',
            url="https://api.example.com/search",
            elapsed=4.0,  # Slow response
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_complex_queries(endpoints)
        
        # Should detect complex query processing
        query_findings = [f for f in findings if f.category == "COMPLEX_QUERY_PROCESSED"]
        assert len(query_findings) >= 1
        assert query_findings[0].severity == Severity.HIGH  # Server error = HIGH
        assert query_findings[0].owasp_category == "API4"
    
    @pytest.mark.asyncio
    async def test_complex_query_safe_processing(self, resource_module, mock_http_client):
        """Test when complex queries are safely handled"""
        endpoints = [MockEndpoint("https://api.example.com/search")]
        
        # Mock safe response - query rejected or safely handled
        mock_response = Response(
            status_code=400,  # Bad request - query rejected
            headers={"content-type": "application/json"},
            content=b'{"error": "Invalid query format"}',
            text='{"error": "Invalid query format"}',
            url="https://api.example.com/search",
            elapsed=0.1,  # Fast rejection
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module._test_complex_queries(endpoints)
        
        # Should not detect vulnerability since query was rejected quickly
        query_findings = [f for f in findings if f.category == "COMPLEX_QUERY_PROCESSED"]
        assert len(query_findings) == 0
    
    @pytest.mark.asyncio
    async def test_perform_burst_test(self, resource_module, mock_http_client):
        """Test burst test performance"""
        # Mock successful responses
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"success": true}',
            text='{"success": true}',
            url="https://api.example.com/test",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        result = await resource_module._perform_burst_test("https://api.example.com/test", "GET")
        
        assert isinstance(result, RateLimitTestResult)
        assert result.endpoint == "https://api.example.com/test"
        assert result.method == "GET"
        assert result.total_requests == resource_module.config.burst_size
        assert result.successful_requests <= result.total_requests
        assert not result.rate_limited  # All requests succeeded
    
    @pytest.mark.asyncio
    async def test_test_single_large_payload(self, resource_module, mock_http_client):
        """Test single large payload testing"""
        # Mock successful response
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"uploaded": true}',
            text='{"uploaded": true}',
            url="https://api.example.com/upload",
            elapsed=1.5,
            request_method="POST"
        )
        
        mock_http_client.request.return_value = mock_response
        
        result = await resource_module._test_single_large_payload(
            "https://api.example.com/upload", 
            "POST", 
            1024*1024  # 1MB
        )
        
        assert isinstance(result, ResourceTestResult)
        assert result.endpoint == "https://api.example.com/upload"
        assert result.method == "POST"
        assert result.test_type == "large_payload"
        assert result.payload_size == 1024*1024
        assert result.success == True
        assert result.response_time > 0
    
    @pytest.mark.asyncio
    async def test_execute_tests_integration(self, resource_module, mock_http_client):
        """Test full Resource Consumption testing execution"""
        # Mock endpoints
        endpoints = [
            MockEndpoint("https://api.example.com/users"),
            MockEndpoint("https://api.example.com/upload", "POST"),
            MockEndpoint("https://api.example.com/search")
        ]
        
        # Mock successful response that indicates vulnerabilities
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"success": true, "processed": true}',
            text='{"success": true, "processed": true}',
            url="https://api.example.com/users",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await resource_module.execute_tests(endpoints)
        
        # Should return list of findings
        assert isinstance(findings, list)
        assert all(hasattr(f, 'category') for f in findings)
        assert all(hasattr(f, 'severity') for f in findings)
        assert all(hasattr(f, 'owasp_category') for f in findings)
        
        # Should have findings from rate limiting tests at minimum
        categories = [f.category for f in findings]
        assert "MISSING_RATE_LIMITING" in categories
    
    def test_redos_patterns_coverage(self, resource_module):
        """Test that ReDoS patterns are comprehensive"""
        patterns = resource_module.REDOS_PATTERNS
        
        # Should have various types of problematic patterns
        assert len(patterns) >= 5
        
        # Should include common ReDoS patterns
        pattern_strings = ''.join(patterns)
        assert '(a+)+' in pattern_strings  # Nested quantifiers
        assert '(a|a)*' in pattern_strings  # Alternation with overlap
        assert '([a-zA-Z]+)*' in pattern_strings  # Character class with quantifiers
    
    def test_complex_query_patterns_coverage(self, resource_module):
        """Test that complex query patterns are comprehensive"""
        patterns = resource_module.COMPLEX_QUERY_PATTERNS
        
        # Should have various types of complex queries
        assert len(patterns) >= 5
        
        # Should include SQL injection and complex queries
        pattern_strings = ''.join(patterns)
        assert 'SELECT' in pattern_strings
        assert 'UNION' in pattern_strings
        assert 'DROP TABLE' in pattern_strings
        assert 'SLEEP' in pattern_strings or 'BENCHMARK' in pattern_strings
    
    def test_payload_sizes_configuration(self, resource_module):
        """Test payload sizes configuration"""
        sizes = resource_module.PAYLOAD_SIZES
        
        # Should have multiple payload sizes
        assert len(sizes) >= 3
        
        # Should include 1MB, 10MB, 100MB
        assert 1024*1024 in sizes  # 1MB
        assert 10*1024*1024 in sizes  # 10MB
        assert 100*1024*1024 in sizes  # 100MB


if __name__ == "__main__":
    pytest.main([__file__])