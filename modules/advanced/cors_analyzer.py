"""
CORS Analyzer Module
Analyzes CORS policies and configurations for security vulnerabilities
"""

import asyncio
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse
from datetime import datetime
from uuid import uuid4

from core.logging import get_logger
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, Severity


@dataclass
class CORSTestResult:
    """Result of a CORS policy test"""
    origin: str
    method: str
    endpoint: str
    allowed: bool = False
    access_control_allow_origin: Optional[str] = None
    access_control_allow_methods: Optional[str] = None
    access_control_allow_headers: Optional[str] = None
    access_control_allow_credentials: Optional[str] = None
    access_control_max_age: Optional[str] = None
    status_code: int = 0
    response_time: float = 0.0
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CORSAnalysis:
    """Complete CORS analysis results"""
    wildcard_origin: bool = False
    credentials_allowed: bool = False
    dangerous_methods: List[str] = field(default_factory=list)
    security_risk: str = "LOW"
    allowed_origins: Set[str] = field(default_factory=set)
    allowed_methods: Set[str] = field(default_factory=set)
    allowed_headers: Set[str] = field(default_factory=set)
    test_results: List[CORSTestResult] = field(default_factory=list)


@dataclass
class CORSAnalyzerConfig:
    """Configuration for CORS analyzer"""
    enabled: bool = True
    test_origins: List[str] = field(default_factory=lambda: [
        "https://evil.com",
        "https://attacker.com", 
        "http://localhost:3000",
        "https://example.com",
        "null",
        "*"
    ])
    test_methods: List[str] = field(default_factory=lambda: [
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
    ])
    test_headers: List[str] = field(default_factory=lambda: [
        "Content-Type", "Authorization", "X-Requested-With", "X-Custom-Header"
    ])
    timeout: float = 10.0
    max_concurrent: int = 5


class CORSAnalyzer:
    """
    CORS Policy Analyzer
    
    Analyzes Cross-Origin Resource Sharing (CORS) policies for security vulnerabilities.
    Tests various origins, methods, and headers to identify misconfigurations.
    
    Requirements: 19.1, 19.2, 19.5
    """
    
    def __init__(self, config: CORSAnalyzerConfig, http_client: HTTPRequestEngine):
        """
        Initialize CORS Analyzer
        
        Args:
            config: CORS analyzer configuration
            http_client: HTTP client for making requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__).bind(component="cors_analyzer")
        
        # Analysis results
        self.analysis_results: Dict[str, CORSAnalysis] = {}
        
        self.logger.info("CORS Analyzer initialized",
                        test_origins=len(config.test_origins),
                        test_methods=len(config.test_methods),
                        timeout=config.timeout)
    
    async def analyze_cors_policy(self, endpoints: List[str]) -> Dict[str, CORSAnalysis]:
        """
        Analyze CORS policies for multiple endpoints
        
        Args:
            endpoints: List of endpoint URLs to analyze
            
        Returns:
            Dictionary mapping endpoints to their CORS analysis results
        """
        if not self.config.enabled:
            self.logger.info("CORS analysis disabled")
            return {}
        
        self.logger.info("Starting CORS policy analysis", endpoints_count=len(endpoints))
        
        # Analyze each endpoint
        for endpoint in endpoints:
            try:
                analysis = await self._analyze_endpoint_cors(endpoint)
                self.analysis_results[endpoint] = analysis
                
                self.logger.info("CORS analysis completed for endpoint",
                                endpoint=endpoint,
                                security_risk=analysis.security_risk,
                                wildcard_origin=analysis.wildcard_origin)
            
            except Exception as e:
                self.logger.error("CORS analysis failed for endpoint",
                                endpoint=endpoint,
                                error=str(e))
                # Create empty analysis for failed endpoint
                self.analysis_results[endpoint] = CORSAnalysis()
        
        self.logger.info("CORS policy analysis completed",
                        endpoints_analyzed=len(self.analysis_results))
        
        return self.analysis_results
    
    async def _analyze_endpoint_cors(self, endpoint: str) -> CORSAnalysis:
        """
        Analyze CORS policy for a single endpoint
        
        Args:
            endpoint: Endpoint URL to analyze
            
        Returns:
            CORSAnalysis with complete results
        """
        analysis = CORSAnalysis()
        
        # Test different origins with OPTIONS preflight requests
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        tasks = []
        
        for origin in self.config.test_origins:
            for method in self.config.test_methods:
                task = self._test_cors_request(semaphore, endpoint, origin, method)
                tasks.append(task)
        
        # Execute all tests concurrently
        test_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        valid_results = []
        for result in test_results:
            if isinstance(result, CORSTestResult):
                valid_results.append(result)
            elif isinstance(result, Exception):
                self.logger.warning("CORS test failed", error=str(result))
        
        analysis.test_results = valid_results
        
        # Analyze results for security issues
        self._analyze_cors_security(analysis)
        
        return analysis
    
    async def _test_cors_request(self, semaphore: asyncio.Semaphore,
                               endpoint: str, origin: str, method: str) -> CORSTestResult:
        """
        Test CORS policy with specific origin and method
        
        Args:
            semaphore: Concurrency control semaphore
            endpoint: Target endpoint
            origin: Origin header value
            method: HTTP method to test
            
        Returns:
            CORSTestResult with test results
        """
        async with semaphore:
            result = CORSTestResult(
                origin=origin,
                method=method,
                endpoint=endpoint
            )
            
            try:
                # Prepare headers for preflight request
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': method,
                    'Access-Control-Request-Headers': 'Content-Type,Authorization'
                }
                
                # Make OPTIONS preflight request
                response = await self.http_client.request(
                    method="OPTIONS",
                    url=endpoint,
                    headers=headers,
                    timeout=self.config.timeout
                )
                
                result.status_code = response.status_code
                result.response_time = response.elapsed
                
                # Extract CORS headers
                result.access_control_allow_origin = response.headers.get('Access-Control-Allow-Origin')
                result.access_control_allow_methods = response.headers.get('Access-Control-Allow-Methods')
                result.access_control_allow_headers = response.headers.get('Access-Control-Allow-Headers')
                result.access_control_allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
                result.access_control_max_age = response.headers.get('Access-Control-Max-Age')
                
                # Determine if request would be allowed
                result.allowed = self._is_cors_request_allowed(result, origin, method)
                
                self.logger.debug("CORS test completed",
                                endpoint=endpoint,
                                origin=origin,
                                method=method,
                                allowed=result.allowed,
                                status_code=response.status_code)
            
            except Exception as e:
                result.error = str(e)
                self.logger.debug("CORS test failed",
                                endpoint=endpoint,
                                origin=origin,
                                method=method,
                                error=str(e))
            
            return result
    
    def _is_cors_request_allowed(self, result: CORSTestResult, origin: str, method: str) -> bool:
        """
        Determine if CORS request would be allowed based on response headers
        
        Args:
            result: CORS test result with headers
            origin: Requested origin
            method: Requested method
            
        Returns:
            True if request would be allowed
        """
        # Check if origin is allowed
        allow_origin = result.access_control_allow_origin
        if not allow_origin:
            return False
        
        # Wildcard allows all origins
        if allow_origin == "*":
            origin_allowed = True
        # Exact match
        elif allow_origin == origin:
            origin_allowed = True
        else:
            origin_allowed = False
        
        # Check if method is allowed
        allow_methods = result.access_control_allow_methods
        if allow_methods:
            allowed_methods = [m.strip().upper() for m in allow_methods.split(',')]
            method_allowed = method.upper() in allowed_methods
        else:
            # If no methods specified, assume basic methods are allowed
            method_allowed = method.upper() in ['GET', 'POST', 'HEAD']
        
        return origin_allowed and method_allowed
    
    def _analyze_cors_security(self, analysis: CORSAnalysis) -> None:
        """
        Analyze CORS test results for security vulnerabilities
        
        Args:
            analysis: CORSAnalysis to populate with security findings
        """
        # Collect all unique values
        for result in analysis.test_results:
            if result.access_control_allow_origin:
                analysis.allowed_origins.add(result.access_control_allow_origin)
            
            if result.access_control_allow_methods:
                methods = [m.strip().upper() for m in result.access_control_allow_methods.split(',')]
                analysis.allowed_methods.update(methods)
            
            if result.access_control_allow_headers:
                headers = [h.strip() for h in result.access_control_allow_headers.split(',')]
                analysis.allowed_headers.update(headers)
        
        # Check for wildcard origin
        analysis.wildcard_origin = "*" in analysis.allowed_origins
        
        # Check for credentials allowed with wildcard
        credentials_with_wildcard = False
        for result in analysis.test_results:
            if (result.access_control_allow_origin == "*" and 
                result.access_control_allow_credentials and
                result.access_control_allow_credentials.lower() == "true"):
                credentials_with_wildcard = True
                analysis.credentials_allowed = True
                break
        
        # Check for dangerous methods
        dangerous_methods = ["DELETE", "PUT", "PATCH"]
        analysis.dangerous_methods = [m for m in dangerous_methods if m in analysis.allowed_methods]
        
        # Determine security risk level
        if credentials_with_wildcard:
            analysis.security_risk = "CRITICAL"
        elif analysis.wildcard_origin and analysis.dangerous_methods:
            analysis.security_risk = "HIGH"
        elif analysis.wildcard_origin or analysis.dangerous_methods:
            analysis.security_risk = "MEDIUM"
        else:
            analysis.security_risk = "LOW"
        
        self.logger.debug("CORS security analysis completed",
                         wildcard_origin=analysis.wildcard_origin,
                         credentials_allowed=analysis.credentials_allowed,
                         dangerous_methods=len(analysis.dangerous_methods),
                         security_risk=analysis.security_risk)
    
    def generate_findings(self) -> List[Finding]:
        """
        Generate findings from CORS analysis results
        
        Returns:
            List of findings related to CORS misconfigurations
        """
        findings = []
        
        for endpoint, analysis in self.analysis_results.items():
            # Wildcard origin with credentials - CRITICAL
            if analysis.wildcard_origin and analysis.credentials_allowed:
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="cors_analysis",
                    category="CORS_WILDCARD_WITH_CREDENTIALS",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=Severity.CRITICAL,
                    endpoint=endpoint,
                    method="OPTIONS",
                    status_code=200,
                    response_size=0,
                    response_time=0.0,
                    evidence="CORS policy allows wildcard origin (*) with credentials enabled",
                    recommendation="Never use wildcard origin (*) with Access-Control-Allow-Credentials: true. "
                                 "Specify explicit origins instead.",
                    payload="Origin: *",
                    response_snippet="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                    headers={}
                )
                findings.append(finding)
            
            # Wildcard origin - HIGH/MEDIUM
            elif analysis.wildcard_origin:
                severity = Severity.HIGH if analysis.dangerous_methods else Severity.MEDIUM
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="cors_analysis",
                    category="CORS_WILDCARD_ORIGIN",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=severity,
                    endpoint=endpoint,
                    method="OPTIONS",
                    status_code=200,
                    response_size=0,
                    response_time=0.0,
                    evidence=f"CORS policy allows wildcard origin (*) with methods: {', '.join(analysis.allowed_methods)}",
                    recommendation="Avoid using wildcard origin (*) in production. "
                                 "Specify explicit allowed origins for better security.",
                    payload="Origin: *",
                    response_snippet=f"Access-Control-Allow-Origin: *, Methods: {', '.join(analysis.allowed_methods)}",
                    headers={}
                )
                findings.append(finding)
            
            # Dangerous methods allowed
            if analysis.dangerous_methods:
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="cors_analysis",
                    category="CORS_DANGEROUS_METHODS",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=Severity.MEDIUM,
                    endpoint=endpoint,
                    method="OPTIONS",
                    status_code=200,
                    response_size=0,
                    response_time=0.0,
                    evidence=f"CORS policy allows dangerous methods: {', '.join(analysis.dangerous_methods)}",
                    recommendation="Review if dangerous methods (DELETE, PUT, PATCH) need to be allowed via CORS. "
                                 "Restrict to necessary methods only.",
                    payload=f"Access-Control-Request-Method: {analysis.dangerous_methods[0]}",
                    response_snippet=f"Access-Control-Allow-Methods: {', '.join(analysis.allowed_methods)}",
                    headers={}
                )
                findings.append(finding)
            
            # Overly permissive origins
            suspicious_origins = [origin for origin in analysis.allowed_origins 
                                if any(pattern in origin.lower() for pattern in ['evil', 'attacker', 'malicious'])]
            
            if suspicious_origins:
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="cors_analysis",
                    category="CORS_SUSPICIOUS_ORIGINS",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=Severity.HIGH,
                    endpoint=endpoint,
                    method="OPTIONS",
                    status_code=200,
                    response_size=0,
                    response_time=0.0,
                    evidence=f"CORS policy allows suspicious origins: {', '.join(suspicious_origins)}",
                    recommendation="Review allowed origins and remove any suspicious or test domains from production CORS policy.",
                    payload=f"Origin: {suspicious_origins[0]}",
                    response_snippet=f"Access-Control-Allow-Origin: {suspicious_origins[0]}",
                    headers={}
                )
                findings.append(finding)
        
        return findings
    
    def get_analysis_results(self) -> Dict[str, CORSAnalysis]:
        """
        Get complete CORS analysis results
        
        Returns:
            Dictionary mapping endpoints to their CORS analysis
        """
        return self.analysis_results.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get CORS analysis statistics
        
        Returns:
            Dictionary with analysis statistics
        """
        total_endpoints = len(self.analysis_results)
        wildcard_endpoints = sum(1 for analysis in self.analysis_results.values() 
                               if analysis.wildcard_origin)
        high_risk_endpoints = sum(1 for analysis in self.analysis_results.values() 
                                if analysis.security_risk in ["CRITICAL", "HIGH"])
        
        return {
            "total_endpoints_analyzed": total_endpoints,
            "wildcard_origin_endpoints": wildcard_endpoints,
            "high_risk_endpoints": high_risk_endpoints,
            "total_tests_performed": sum(len(analysis.test_results) 
                                       for analysis in self.analysis_results.values()),
            "average_response_time": sum(
                sum(result.response_time for result in analysis.test_results if result.response_time > 0)
                for analysis in self.analysis_results.values()
            ) / max(1, sum(len(analysis.test_results) for analysis in self.analysis_results.values()))
        }