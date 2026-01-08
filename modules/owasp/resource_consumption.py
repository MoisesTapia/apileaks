"""
Resource Consumption Testing Module
Implements OWASP API4 - Unrestricted Resource Consumption testing
"""

import asyncio
import json
import re
import time
import random
import string
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin

from .registry import OWASPModule
from utils.findings import Finding, FindingsCollector
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import ResourceTestingConfig, AuthContext, Severity
from core.logging import get_logger


@dataclass
class ResourceTestResult:
    """Result of a resource consumption test"""
    endpoint: str
    method: str
    test_type: str
    payload_size: int
    response_time: float
    status_code: int
    response_size: int
    success: bool
    evidence: str


@dataclass
class RateLimitTestResult:
    """Result of rate limiting test"""
    endpoint: str
    method: str
    total_requests: int
    successful_requests: int
    blocked_requests: int
    average_response_time: float
    rate_limited: bool
    evidence: str


class ResourceConsumptionModule(OWASPModule):
    """
    Resource Consumption Testing Module for detecting Unrestricted Resource Consumption
    
    This module implements comprehensive testing for OWASP API Security Top 10 #4:
    - Tests rate limiting with burst of 100 requests
    - Tests large payload acceptance (1MB, 10MB, 100MB)
    - Detects JSON deeply nested and large arrays
    - Identifies ReDoS patterns and complex queries
    - Validates resource consumption controls
    """
    
    # ReDoS patterns that can cause exponential backtracking
    REDOS_PATTERNS = [
        r"(a+)+$",
        r"([a-zA-Z]+)*$",
        r"(a|a)*$",
        r"(a|b)*aaac$",
        r"^(a+)+$",
        r"^([a-z]*)*$",
        r"^(([a-z])*)*$",
        r"(x+x+)+y",
        r"([a-zA-Z0-9]*)([a-zA-Z0-9]*)*$",
        r"^(a*)*$"
    ]
    
    # Complex query patterns that might cause performance issues
    COMPLEX_QUERY_PATTERNS = [
        "SELECT * FROM users WHERE id IN (SELECT id FROM orders WHERE total > (SELECT AVG(total) FROM orders))",
        "' OR 1=1 UNION SELECT * FROM information_schema.tables--",
        "'; DROP TABLE users; --",
        "' AND (SELECT COUNT(*) FROM users) > 1000 --",
        "' OR SLEEP(10) --",
        "' OR BENCHMARK(10000000, MD5(1)) --",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"
    ]
    
    # Large payload sizes to test (in bytes)
    PAYLOAD_SIZES = [
        1024 * 1024,      # 1MB
        10 * 1024 * 1024, # 10MB
        100 * 1024 * 1024 # 100MB
    ]
    
    def __init__(self, config: ResourceTestingConfig, http_client: HTTPRequestEngine, 
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="resource_consumption")
        
        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        
        self.logger.info("Resource Consumption Testing Module initialized",
                        burst_size=config.burst_size,
                        payload_sizes=len(self.PAYLOAD_SIZES),
                        redos_patterns=len(self.REDOS_PATTERNS))
    
    def get_module_name(self) -> str:
        """Get module name"""
        return "resource_consumption"
    
    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute resource consumption tests on discovered endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of resource consumption findings
        """
        self.logger.info("Starting resource consumption testing", endpoints_count=len(endpoints))
        
        findings = []
        
        try:
            # Step 1: Test rate limiting with burst requests (Requirement 4.1)
            rate_limit_findings = await self._test_rate_limiting(endpoints)
            findings.extend(rate_limit_findings)
            self.logger.debug("Rate limiting testing completed", findings=len(rate_limit_findings))
            
            # Step 2: Test large payload acceptance (Requirement 4.2)
            large_payload_findings = await self._test_large_payloads(endpoints)
            findings.extend(large_payload_findings)
            self.logger.debug("Large payload testing completed", findings=len(large_payload_findings))
            
            # Step 3: Test deeply nested JSON and large arrays (Requirement 4.3)
            json_nesting_findings = await self._test_json_nesting(endpoints)
            findings.extend(json_nesting_findings)
            self.logger.debug("JSON nesting testing completed", findings=len(json_nesting_findings))
            
            # Step 4: Test ReDoS patterns (Requirement 4.4)
            redos_findings = await self._test_redos_patterns(endpoints)
            findings.extend(redos_findings)
            self.logger.debug("ReDoS pattern testing completed", findings=len(redos_findings))
            
            # Step 5: Test complex queries (Requirement 4.5)
            complex_query_findings = await self._test_complex_queries(endpoints)
            findings.extend(complex_query_findings)
            self.logger.debug("Complex query testing completed", findings=len(complex_query_findings))
            
        except Exception as e:
            self.logger.error("Resource consumption testing failed", error=str(e))
            raise
        
        self.logger.info("Resource consumption testing completed",
                        total_findings=len(findings),
                        critical_findings=len([f for f in findings if f.severity == Severity.CRITICAL]))
        
        return findings
    
    async def _test_rate_limiting(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test rate limiting with burst requests (Requirement 4.1)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of rate limiting findings
        """
        findings = []
        self.logger.info("Testing rate limiting", burst_size=self.config.burst_size)
        
        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
            
            try:
                # Perform burst test
                rate_limit_result = await self._perform_burst_test(endpoint_url, method)
                
                # Check if rate limiting is missing or ineffective
                if not rate_limit_result.rate_limited:
                    finding = Finding(
                        id="",  # Will be set by findings collector
                        scan_id="",
                        category="MISSING_RATE_LIMITING",
                        owasp_category="API4",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=200,
                        response_size=0,
                        response_time=rate_limit_result.average_response_time,
                        evidence=f"Endpoint accepts {rate_limit_result.successful_requests} rapid requests "
                                f"without rate limiting. {rate_limit_result.evidence}",
                        recommendation="Implement rate limiting to prevent abuse. "
                                     "Consider implementing per-IP, per-user, or per-endpoint limits.",
                        payload=f"Burst test: {self.config.burst_size} requests"
                    )
                    findings.append(finding)
                    
                    self.logger.warning("Missing rate limiting detected",
                                      endpoint=endpoint_url,
                                      successful_requests=rate_limit_result.successful_requests)
                
            except Exception as e:
                self.logger.debug("Rate limiting test failed",
                                endpoint=endpoint_url,
                                error=str(e))
        
        return findings
    
    async def _perform_burst_test(self, endpoint: str, method: str) -> RateLimitTestResult:
        """
        Perform burst test on endpoint
        
        Args:
            endpoint: Endpoint URL to test
            method: HTTP method to use
            
        Returns:
            Rate limit test result
        """
        total_requests = self.config.burst_size
        successful_requests = 0
        blocked_requests = 0
        response_times = []
        
        # Create tasks for concurrent requests
        tasks = []
        for i in range(total_requests):
            task = self._make_burst_request(endpoint, method, i)
            tasks.append(task)
        
        # Execute all requests concurrently
        start_time = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Analyze responses
        for response in responses:
            if isinstance(response, Exception):
                blocked_requests += 1
            elif isinstance(response, Response):
                if response.status_code == 429:  # Too Many Requests
                    blocked_requests += 1
                elif 200 <= response.status_code < 400:
                    successful_requests += 1
                    response_times.append(response.elapsed)
                else:
                    blocked_requests += 1
        
        average_response_time = sum(response_times) / len(response_times) if response_times else 0
        rate_limited = blocked_requests > (total_requests * 0.1)  # More than 10% blocked
        
        evidence = f"Sent {total_requests} requests in {end_time - start_time:.2f}s. "
        evidence += f"Successful: {successful_requests}, Blocked: {blocked_requests}"
        
        return RateLimitTestResult(
            endpoint=endpoint,
            method=method,
            total_requests=total_requests,
            successful_requests=successful_requests,
            blocked_requests=blocked_requests,
            average_response_time=average_response_time,
            rate_limited=rate_limited,
            evidence=evidence
        )
    
    async def _make_burst_request(self, endpoint: str, method: str, request_id: int) -> Response:
        """
        Make a single request as part of burst test
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            request_id: Request identifier
            
        Returns:
            HTTP response
        """
        try:
            # Add small random delay to simulate realistic burst
            await asyncio.sleep(random.uniform(0, 0.1))
            
            response = await self.http_client.request(method, endpoint)
            return response
            
        except Exception as e:
            self.logger.debug("Burst request failed",
                            endpoint=endpoint,
                            request_id=request_id,
                            error=str(e))
            raise
    
    async def _test_large_payloads(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test large payload acceptance (Requirement 4.2)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of large payload findings
        """
        findings = []
        self.logger.info("Testing large payload acceptance", sizes=self.PAYLOAD_SIZES)
        
        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        # Filter endpoints that accept POST/PUT data
        data_endpoints = [ep for ep in endpoints 
                         if hasattr(ep, 'method') and ep.method in ['POST', 'PUT', 'PATCH']]
        
        if not data_endpoints:
            # If no POST/PUT endpoints found, test a few GET endpoints with large query params
            data_endpoints = endpoints[:3]  # Test first 3 endpoints
        
        for endpoint in data_endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'POST'
            
            for payload_size in self.config.large_payload_sizes:
                try:
                    result = await self._test_single_large_payload(endpoint_url, method, payload_size)
                    
                    if result.success:
                        # Determine severity based on payload size
                        severity = Severity.HIGH if payload_size >= 10 * 1024 * 1024 else Severity.MEDIUM
                        
                        finding = Finding(
                            id="",
                            scan_id="",
                            category="LARGE_PAYLOAD_ACCEPTED",
                            owasp_category="API4",
                            severity=severity,
                            endpoint=endpoint_url,
                            method=method,
                            status_code=result.status_code,
                            response_size=result.response_size,
                            response_time=result.response_time,
                            evidence=f"Endpoint accepts large payload of {payload_size // (1024*1024)}MB. "
                                    f"Response time: {result.response_time:.2f}s. {result.evidence}",
                            recommendation="Implement payload size limits to prevent resource exhaustion. "
                                         "Consider implementing request size validation and timeouts.",
                            payload=f"Large payload: {payload_size} bytes"
                        )
                        findings.append(finding)
                        
                        self.logger.warning("Large payload accepted",
                                          endpoint=endpoint_url,
                                          payload_size_mb=payload_size // (1024*1024),
                                          response_time=result.response_time)
                
                except Exception as e:
                    self.logger.debug("Large payload test failed",
                                    endpoint=endpoint_url,
                                    payload_size=payload_size,
                                    error=str(e))
        
        return findings
    
    async def _test_single_large_payload(self, endpoint: str, method: str, 
                                       payload_size: int) -> ResourceTestResult:
        """
        Test single large payload on endpoint
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            payload_size: Size of payload in bytes
            
        Returns:
            Resource test result
        """
        # Generate large payload
        if method in ['POST', 'PUT', 'PATCH']:
            # Create large JSON payload
            large_data = 'x' * (payload_size - 100)  # Leave room for JSON structure
            payload = json.dumps({"data": large_data, "test": "resource_consumption"})
        else:
            # For GET requests, create large query parameter
            large_param = 'x' * min(payload_size, 8192)  # Limit query param size
            endpoint = f"{endpoint}?large_param={large_param}"
            payload = None
        
        start_time = time.time()
        
        try:
            if payload:
                response = await self.http_client.request(
                    method, endpoint,
                    json=json.loads(payload),
                    headers={'Content-Type': 'application/json'}
                )
            else:
                response = await self.http_client.request(method, endpoint)
            
            end_time = time.time()
            response_time = response.elapsed  # Use the response's elapsed time
            
            # Consider successful if server accepts and processes the request
            success = 200 <= response.status_code < 400  # Only 2xx and 3xx are success
            
            evidence = f"Status: {response.status_code}, Response size: {len(response.content)} bytes"
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type="large_payload",
                payload_size=payload_size,
                response_time=response_time,
                status_code=response.status_code,
                response_size=len(response.content),
                success=success,
                evidence=evidence
            )
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type="large_payload",
                payload_size=payload_size,
                response_time=response_time,
                status_code=0,
                response_size=0,
                success=False,
                evidence=f"Request failed: {str(e)}"
            )
    
    async def _test_json_nesting(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test deeply nested JSON and large arrays (Requirement 4.3)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of JSON nesting findings
        """
        findings = []
        self.logger.info("Testing JSON nesting and large arrays", depth_limit=self.config.json_depth_limit)
        
        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        # Filter endpoints that accept JSON data
        json_endpoints = [ep for ep in endpoints 
                         if hasattr(ep, 'method') and ep.method in ['POST', 'PUT', 'PATCH']]
        
        if not json_endpoints:
            json_endpoints = endpoints[:3]  # Test first 3 endpoints
        
        for endpoint in json_endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'POST'
            
            try:
                # Test deeply nested JSON
                nested_result = await self._test_deeply_nested_json(endpoint_url, method)
                if nested_result.success:
                    finding = Finding(
                        id="",
                        scan_id="",
                        category="DEEP_JSON_NESTING_ACCEPTED",
                        owasp_category="API4",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=nested_result.status_code,
                        response_size=nested_result.response_size,
                        response_time=nested_result.response_time,
                        evidence=f"Endpoint accepts deeply nested JSON (depth: {self.config.json_depth_limit}). "
                                f"Response time: {nested_result.response_time:.2f}s. {nested_result.evidence}",
                        recommendation="Implement JSON depth limits to prevent stack overflow attacks. "
                                     "Consider limiting nesting depth to reasonable levels (e.g., 10-20 levels).",
                        payload=f"Nested JSON depth: {self.config.json_depth_limit}"
                    )
                    findings.append(finding)
                
                # Test large JSON arrays
                array_result = await self._test_large_json_array(endpoint_url, method)
                if array_result.success:
                    finding = Finding(
                        id="",
                        scan_id="",
                        category="LARGE_JSON_ARRAY_ACCEPTED",
                        owasp_category="API4",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=array_result.status_code,
                        response_size=array_result.response_size,
                        response_time=array_result.response_time,
                        evidence=f"Endpoint accepts large JSON array (10000 elements). "
                                f"Response time: {array_result.response_time:.2f}s. {array_result.evidence}",
                        recommendation="Implement array size limits to prevent memory exhaustion. "
                                     "Consider limiting array elements to reasonable numbers.",
                        payload="Large JSON array: 10000 elements"
                    )
                    findings.append(finding)
                
            except Exception as e:
                self.logger.debug("JSON nesting test failed",
                                endpoint=endpoint_url,
                                error=str(e))
        
        return findings
    
    async def _test_deeply_nested_json(self, endpoint: str, method: str) -> ResourceTestResult:
        """
        Test deeply nested JSON payload
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            
        Returns:
            Resource test result
        """
        # Create deeply nested JSON
        nested_json = {}
        current = nested_json
        
        for i in range(self.config.json_depth_limit):
            current["level"] = i
            current["data"] = "test_data"
            if i < self.config.json_depth_limit - 1:
                current["nested"] = {}
                current = current["nested"]
        
        return await self._test_json_payload(endpoint, method, nested_json, "deeply_nested")
    
    async def _test_large_json_array(self, endpoint: str, method: str) -> ResourceTestResult:
        """
        Test large JSON array payload
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            
        Returns:
            Resource test result
        """
        # Create large array
        large_array = []
        for i in range(10000):  # 10k elements
            large_array.append({
                "id": i,
                "data": f"element_{i}",
                "value": random.randint(1, 1000)
            })
        
        payload = {"array": large_array, "test": "large_array"}
        
        return await self._test_json_payload(endpoint, method, payload, "large_array")
    
    async def _test_json_payload(self, endpoint: str, method: str, 
                               payload: Dict[str, Any], test_type: str) -> ResourceTestResult:
        """
        Test JSON payload on endpoint
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            payload: JSON payload to send
            test_type: Type of test being performed
            
        Returns:
            Resource test result
        """
        start_time = time.time()
        
        try:
            response = await self.http_client.request(
                method, endpoint,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            end_time = time.time()
            response_time = response.elapsed  # Use the response's elapsed time
            
            # Consider successful if server accepts and processes the request
            success = 200 <= response.status_code < 400  # Only 2xx and 3xx are success
            
            evidence = f"Status: {response.status_code}, Response size: {len(response.content)} bytes"
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type=test_type,
                payload_size=len(json.dumps(payload)),
                response_time=response_time,
                status_code=response.status_code,
                response_size=len(response.content),
                success=success,
                evidence=evidence
            )
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type=test_type,
                payload_size=len(json.dumps(payload)) if payload else 0,
                response_time=response_time,
                status_code=0,
                response_size=0,
                success=False,
                evidence=f"Request failed: {str(e)}"
            )
    
    async def _test_redos_patterns(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test ReDoS (Regular Expression Denial of Service) patterns (Requirement 4.4)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of ReDoS findings
        """
        findings = []
        self.logger.info("Testing ReDoS patterns", patterns_count=len(self.REDOS_PATTERNS))
        
        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
            
            for pattern in self.REDOS_PATTERNS:
                try:
                    result = await self._test_redos_pattern(endpoint_url, method, pattern)
                    
                    # If response time is significantly high, it might indicate ReDoS
                    if result.response_time > 5.0 and result.success:  # More than 5 seconds AND successful
                        finding = Finding(
                            id="",
                            scan_id="",
                            category="REDOS_VULNERABILITY",
                            owasp_category="API4",
                            severity=Severity.HIGH,
                            endpoint=endpoint_url,
                            method=method,
                            status_code=result.status_code,
                            response_size=result.response_size,
                            response_time=result.response_time,
                            evidence=f"Potential ReDoS vulnerability detected. "
                                    f"Response time: {result.response_time:.2f}s for pattern: {pattern}. "
                                    f"{result.evidence}",
                            recommendation="Review regular expression usage for potential ReDoS vulnerabilities. "
                                         "Implement timeouts for regex operations and validate input patterns.",
                            payload=f"ReDoS pattern: {pattern}"
                        )
                        findings.append(finding)
                        
                        self.logger.warning("Potential ReDoS detected",
                                          endpoint=endpoint_url,
                                          pattern=pattern,
                                          response_time=result.response_time)
                
                except Exception as e:
                    self.logger.debug("ReDoS pattern test failed",
                                    endpoint=endpoint_url,
                                    pattern=pattern,
                                    error=str(e))
        
        return findings
    
    async def _test_redos_pattern(self, endpoint: str, method: str, pattern: str) -> ResourceTestResult:
        """
        Test ReDoS pattern on endpoint
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            pattern: ReDoS pattern to test
            
        Returns:
            Resource test result
        """
        # Create malicious input that could trigger ReDoS
        # Generate string that would cause exponential backtracking
        malicious_input = "a" * 50 + "X"  # String that won't match but causes backtracking
        
        start_time = time.time()
        
        try:
            if method in ['POST', 'PUT', 'PATCH']:
                # Send as JSON data
                payload = {
                    "input": malicious_input,
                    "pattern": pattern,
                    "test": "redos"
                }
                response = await self.http_client.request(
                    method, endpoint,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )
            else:
                # Send as query parameter
                test_endpoint = f"{endpoint}?input={malicious_input}&pattern={pattern}"
                response = await self.http_client.request(method, test_endpoint)
            
            end_time = time.time()
            response_time = response.elapsed  # Use the response's elapsed time
            
            evidence = f"Status: {response.status_code}, Response size: {len(response.content)} bytes"
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type="redos",
                payload_size=len(malicious_input),
                response_time=response_time,
                status_code=response.status_code,
                response_size=len(response.content),
                success=True,
                evidence=evidence
            )
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time  # Keep manual calculation for exceptions
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type="redos",
                payload_size=len(malicious_input),
                response_time=response_time,
                status_code=0,
                response_size=0,
                success=False,
                evidence=f"Request failed: {str(e)}"
            )
    
    async def _test_complex_queries(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test complex queries that might cause performance issues (Requirement 4.5)
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of complex query findings
        """
        findings = []
        self.logger.info("Testing complex queries", patterns_count=len(self.COMPLEX_QUERY_PATTERNS))
        
        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])
        
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'
            
            for query_pattern in self.COMPLEX_QUERY_PATTERNS:
                try:
                    result = await self._test_complex_query(endpoint_url, method, query_pattern)
                    
                    # Check for signs that complex query was processed
                    if result.success and (result.response_time > 3.0 or 
                                         result.status_code == 500):
                        
                        severity = Severity.HIGH if result.status_code == 500 else Severity.MEDIUM
                        
                        finding = Finding(
                            id="",
                            scan_id="",
                            category="COMPLEX_QUERY_PROCESSED",
                            owasp_category="API4",
                            severity=severity,
                            endpoint=endpoint_url,
                            method=method,
                            status_code=result.status_code,
                            response_size=result.response_size,
                            response_time=result.response_time,
                            evidence=f"Complex query processed by endpoint. "
                                    f"Response time: {result.response_time:.2f}s. "
                                    f"Query: {query_pattern[:100]}... {result.evidence}",
                            recommendation="Implement query complexity limits and input validation. "
                                         "Use parameterized queries and avoid dynamic query construction.",
                            payload=f"Complex query: {query_pattern[:100]}..."
                        )
                        findings.append(finding)
                        
                        self.logger.warning("Complex query processed",
                                          endpoint=endpoint_url,
                                          query_pattern=query_pattern[:50],
                                          response_time=result.response_time,
                                          status_code=result.status_code)
                
                except Exception as e:
                    self.logger.debug("Complex query test failed",
                                    endpoint=endpoint_url,
                                    query_pattern=query_pattern[:50],
                                    error=str(e))
        
        return findings
    
    async def _test_complex_query(self, endpoint: str, method: str, 
                                query_pattern: str) -> ResourceTestResult:
        """
        Test complex query on endpoint
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            query_pattern: Complex query pattern to test
            
        Returns:
            Resource test result
        """
        start_time = time.time()
        
        try:
            if method in ['POST', 'PUT', 'PATCH']:
                # Send as JSON data
                payload = {
                    "query": query_pattern,
                    "search": query_pattern,
                    "filter": query_pattern,
                    "test": "complex_query"
                }
                response = await self.http_client.request(
                    method, endpoint,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )
            else:
                # Send as query parameters
                import urllib.parse
                encoded_query = urllib.parse.quote(query_pattern)
                test_endpoint = f"{endpoint}?query={encoded_query}&search={encoded_query}"
                response = await self.http_client.request(method, test_endpoint)
            
            end_time = time.time()
            response_time = response.elapsed  # Use the response's elapsed time
            
            # Check response for error indicators
            error_indicators = ["error", "exception", "sql", "database", "timeout"]
            response_text = response.text.lower() if response.text else ""
            has_error_indicators = any(indicator in response_text for indicator in error_indicators)
            
            evidence = f"Status: {response.status_code}, Response size: {len(response.content)} bytes"
            if has_error_indicators:
                evidence += ", Contains error indicators"
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type="complex_query",
                payload_size=len(query_pattern),
                response_time=response_time,
                status_code=response.status_code,
                response_size=len(response.content),
                success=True,
                evidence=evidence
            )
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            return ResourceTestResult(
                endpoint=endpoint,
                method=method,
                test_type="complex_query",
                payload_size=len(query_pattern),
                response_time=response_time,
                status_code=0,
                response_size=0,
                success=False,
                evidence=f"Request failed: {str(e)}"
            )