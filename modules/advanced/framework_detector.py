"""
Framework Detection Module
Identifies API frameworks (FastAPI, Express, Django, Flask) and adapts payloads accordingly
"""

import re
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from core.logging import get_logger
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, Severity


class FrameworkType(str, Enum):
    """Supported framework types"""
    FASTAPI = "FastAPI"
    EXPRESS = "Express.js"
    DJANGO = "Django"
    FLASK = "Flask"
    SPRING_BOOT = "Spring Boot"
    ASP_NET = "ASP.NET"
    RAILS = "Ruby on Rails"
    LARAVEL = "Laravel"
    UNKNOWN = "Unknown"


@dataclass
class FrameworkSignature:
    """Framework detection signature"""
    name: FrameworkType
    headers: Dict[str, str] = field(default_factory=dict)
    error_patterns: List[str] = field(default_factory=list)
    response_patterns: List[str] = field(default_factory=list)
    default_endpoints: List[str] = field(default_factory=list)
    confidence_weight: float = 1.0


@dataclass
class Framework:
    """Detected framework information"""
    name: FrameworkType
    version: Optional[str] = None
    confidence: float = 0.0
    detection_method: str = "unknown"
    specific_vulnerabilities: List[str] = field(default_factory=list)
    framework_endpoints: List[str] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FrameworkDetectionConfig:
    """Configuration for framework detection"""
    enabled: bool = True
    adapt_payloads: bool = True
    test_framework_endpoints: bool = True
    max_error_requests: int = 5
    timeout: float = 10.0
    confidence_threshold: float = 0.6


class FrameworkDetector:
    """
    Framework Detection Module
    
    Identifies API frameworks based on:
    - HTTP headers (Server, X-Powered-By, etc.)
    - Error message patterns
    - Response characteristics
    - Default endpoints
    
    Requirements: 17.1, 17.2, 17.3, 17.4, 17.5
    """
    
    def __init__(self, config: FrameworkDetectionConfig, http_client: HTTPRequestEngine):
        """
        Initialize Framework Detector
        
        Args:
            config: Framework detection configuration
            http_client: HTTP client for making requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__).bind(component="framework_detector")
        
        # Initialize framework signatures
        self.signatures = self._initialize_signatures()
        
        # Detection results
        self.detected_frameworks: List[Framework] = []
        self.findings: List[Finding] = []
        
        self.logger.info("Framework Detector initialized",
                        signatures_loaded=len(self.signatures),
                        adapt_payloads=config.adapt_payloads)
    
    def _initialize_signatures(self) -> Dict[FrameworkType, FrameworkSignature]:
        """Initialize framework detection signatures"""
        signatures = {}
        
        # FastAPI signatures
        signatures[FrameworkType.FASTAPI] = FrameworkSignature(
            name=FrameworkType.FASTAPI,
            headers={
                "server": r"uvicorn|hypercorn|daphne",
                "x-powered-by": r"fastapi"
            },
            error_patterns=[
                r'"detail":\s*".*"',  # FastAPI error format
                r'{"detail":',
                r'422 Unprocessable Entity',
                r'ValidationError',
                r'pydantic'
            ],
            response_patterns=[
                r'"openapi":\s*"3\.',  # OpenAPI 3.x spec
                r'/docs',  # Swagger docs endpoint
                r'/redoc',  # ReDoc endpoint
                r'{"title":.*"version":.*"openapi":'
            ],
            default_endpoints=[
                "/docs", "/redoc", "/openapi.json", "/api/v1", "/health"
            ],
            confidence_weight=1.0
        )
        
        # Express.js signatures
        signatures[FrameworkType.EXPRESS] = FrameworkSignature(
            name=FrameworkType.EXPRESS,
            headers={
                "x-powered-by": r"express",
                "server": r"express"
            },
            error_patterns=[
                r'Cannot GET /',
                r'Error: Cannot find module',
                r'at Function\.Module\._resolveFilename',
                r'express.*error',
                r'node\.js.*error'
            ],
            response_patterns=[
                r'Express server',
                r'node_modules',
                r'package\.json'
            ],
            default_endpoints=[
                "/api", "/api/v1", "/health", "/status", "/ping"
            ],
            confidence_weight=1.0
        )
        
        # Django signatures
        signatures[FrameworkType.DJANGO] = FrameworkSignature(
            name=FrameworkType.DJANGO,
            headers={
                "server": r"django|wsgi",
                "x-powered-by": r"django"
            },
            error_patterns=[
                r'DisallowedHost',
                r'django\.core\.exceptions',
                r'django\.urls\.exceptions',
                r'CSRF verification failed',
                r'django.*error',
                r'Page not found \(404\)'
            ],
            response_patterns=[
                r'Django administration',
                r'csrfmiddlewaretoken',
                r'django_language',
                r'sessionid'
            ],
            default_endpoints=[
                "/admin/", "/api/", "/api/v1/", "/health/", "/status/"
            ],
            confidence_weight=1.0
        )
        
        # Flask signatures
        signatures[FrameworkType.FLASK] = FrameworkSignature(
            name=FrameworkType.FLASK,
            headers={
                "server": r"flask|werkzeug|gunicorn",
                "x-powered-by": r"flask"
            },
            error_patterns=[
                r'werkzeug\.exceptions',
                r'flask\.app',
                r'Internal Server Error',
                r'The method is not allowed for the requested URL',
                r'404 Not Found',
                r'Werkzeug.*error'
            ],
            response_patterns=[
                r'Flask',
                r'Werkzeug',
                r'session cookie'
            ],
            default_endpoints=[
                "/api", "/api/v1", "/health", "/status"
            ],
            confidence_weight=1.0
        )
        
        # Spring Boot signatures
        signatures[FrameworkType.SPRING_BOOT] = FrameworkSignature(
            name=FrameworkType.SPRING_BOOT,
            headers={
                "server": r"tomcat|jetty|undertow",
                "x-powered-by": r"spring"
            },
            error_patterns=[
                r'Whitelabel Error Page',
                r'org\.springframework',
                r'java\.lang\.',
                r'NoHandlerFoundException',
                r'HttpRequestMethodNotSupportedException'
            ],
            response_patterns=[
                r'Spring Boot',
                r'actuator',
                r'management\.endpoints'
            ],
            default_endpoints=[
                "/actuator", "/actuator/health", "/api", "/api/v1", "/management"
            ],
            confidence_weight=1.0
        )
        
        # ASP.NET signatures
        signatures[FrameworkType.ASP_NET] = FrameworkSignature(
            name=FrameworkType.ASP_NET,
            headers={
                "server": r"microsoft-iis|kestrel",
                "x-powered-by": r"asp\.net",
                "x-aspnet-version": r".*"
            },
            error_patterns=[
                r'System\.Web\.',
                r'Microsoft\.AspNetCore',
                r'Server Error in.*Application',
                r'Runtime Error',
                r'\.NET Framework'
            ],
            response_patterns=[
                r'ASP\.NET',
                r'__VIEWSTATE',
                r'__EVENTVALIDATION'
            ],
            default_endpoints=[
                "/api", "/api/v1", "/health", "/swagger"
            ],
            confidence_weight=1.0
        )
        
        return signatures
    
    async def detect_framework(self, target_url: str, additional_endpoints: List[str] = None) -> Optional[Framework]:
        """
        Detect framework for target URL
        
        Args:
            target_url: Target URL to analyze
            additional_endpoints: Additional endpoints to test for framework detection
            
        Returns:
            Framework object if detected, None otherwise
        """
        self.logger.info("Starting framework detection", target=target_url)
        
        if not self.config.enabled:
            self.logger.info("Framework detection disabled")
            return None
        
        # Initialize detection results
        detection_scores = {framework_type: 0.0 for framework_type in FrameworkType}
        detection_evidence = {framework_type: [] for framework_type in FrameworkType}
        
        # Phase 1: Header-based detection
        await self._detect_from_headers(target_url, detection_scores, detection_evidence)
        
        # Phase 2: Error pattern detection
        await self._detect_from_error_patterns(target_url, detection_scores, detection_evidence)
        
        # Phase 3: Response pattern detection
        await self._detect_from_response_patterns(target_url, detection_scores, detection_evidence)
        
        # Phase 4: Default endpoints detection
        if self.config.test_framework_endpoints:
            await self._detect_from_default_endpoints(target_url, detection_scores, detection_evidence)
        
        # Phase 5: Additional endpoints analysis
        if additional_endpoints:
            await self._analyze_additional_endpoints(additional_endpoints, detection_scores, detection_evidence)
        
        # Determine best match
        best_framework = self._determine_best_framework(detection_scores, detection_evidence)
        
        if best_framework:
            self.detected_frameworks.append(best_framework)
            self.logger.info("Framework detected",
                           framework=best_framework.name,
                           confidence=best_framework.confidence,
                           method=best_framework.detection_method)
        else:
            self.logger.info("No framework detected with sufficient confidence")
        
        return best_framework
    
    async def _detect_from_headers(self, target_url: str, scores: Dict[FrameworkType, float], 
                                 evidence: Dict[FrameworkType, List[str]]) -> None:
        """Detect framework from HTTP headers"""
        try:
            response = await self.http_client.request("GET", target_url, timeout=self.config.timeout)
            
            for framework_type, signature in self.signatures.items():
                for header_name, pattern in signature.headers.items():
                    header_value = response.headers.get(header_name, "").lower()
                    if header_value and re.search(pattern, header_value, re.IGNORECASE):
                        scores[framework_type] += 2.0 * signature.confidence_weight
                        evidence[framework_type].append(f"Header {header_name}: {header_value}")
                        self.logger.debug("Header match found",
                                        framework=framework_type,
                                        header=header_name,
                                        value=header_value)
        
        except Exception as e:
            self.logger.warning("Header detection failed", error=str(e))
    
    async def _detect_from_error_patterns(self, target_url: str, scores: Dict[FrameworkType, float],
                                        evidence: Dict[FrameworkType, List[str]]) -> None:
        """Detect framework from error message patterns"""
        error_endpoints = [
            "/nonexistent-endpoint-12345",
            "/admin/nonexistent",
            "/api/invalid-endpoint",
            "/test/error/trigger"
        ]
        
        requests_made = 0
        for endpoint in error_endpoints:
            if requests_made >= self.config.max_error_requests:
                break
            
            try:
                test_url = target_url.rstrip('/') + endpoint
                response = await self.http_client.request("GET", test_url, timeout=self.config.timeout)
                
                response_text = response.text[:5000]  # Limit analysis to first 5KB
                
                for framework_type, signature in self.signatures.items():
                    for pattern in signature.error_patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            scores[framework_type] += 1.5 * signature.confidence_weight
                            evidence[framework_type].append(f"Error pattern: {pattern}")
                            self.logger.debug("Error pattern match",
                                            framework=framework_type,
                                            pattern=pattern,
                                            endpoint=endpoint)
                
                requests_made += 1
                
            except Exception as e:
                self.logger.debug("Error pattern test failed", endpoint=endpoint, error=str(e))
                requests_made += 1
    
    async def _detect_from_response_patterns(self, target_url: str, scores: Dict[FrameworkType, float],
                                           evidence: Dict[FrameworkType, List[str]]) -> None:
        """Detect framework from response content patterns"""
        try:
            response = await self.http_client.request("GET", target_url, timeout=self.config.timeout)
            response_text = response.text[:10000]  # Limit analysis to first 10KB
            
            for framework_type, signature in self.signatures.items():
                for pattern in signature.response_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        scores[framework_type] += 1.0 * signature.confidence_weight
                        evidence[framework_type].append(f"Response pattern: {pattern}")
                        self.logger.debug("Response pattern match",
                                        framework=framework_type,
                                        pattern=pattern)
        
        except Exception as e:
            self.logger.warning("Response pattern detection failed", error=str(e))
    
    async def _detect_from_default_endpoints(self, target_url: str, scores: Dict[FrameworkType, float],
                                           evidence: Dict[FrameworkType, List[str]]) -> None:
        """Detect framework from default endpoints"""
        for framework_type, signature in self.signatures.items():
            for endpoint in signature.default_endpoints:
                try:
                    test_url = target_url.rstrip('/') + endpoint
                    response = await self.http_client.request("GET", test_url, timeout=self.config.timeout)
                    
                    # Successful response to framework-specific endpoint
                    if 200 <= response.status_code < 400:
                        scores[framework_type] += 0.5 * signature.confidence_weight
                        evidence[framework_type].append(f"Default endpoint accessible: {endpoint}")
                        self.logger.debug("Default endpoint accessible",
                                        framework=framework_type,
                                        endpoint=endpoint,
                                        status=response.status_code)
                
                except Exception as e:
                    self.logger.debug("Default endpoint test failed",
                                    framework=framework_type,
                                    endpoint=endpoint,
                                    error=str(e))
    
    async def _analyze_additional_endpoints(self, endpoints: List[str], scores: Dict[FrameworkType, float],
                                          evidence: Dict[FrameworkType, List[str]]) -> None:
        """Analyze additional endpoints for framework patterns"""
        for endpoint in endpoints[:10]:  # Limit to avoid overwhelming
            try:
                response = await self.http_client.request("GET", endpoint, timeout=self.config.timeout)
                response_text = response.text[:5000]
                
                for framework_type, signature in self.signatures.items():
                    # Check response patterns
                    for pattern in signature.response_patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            scores[framework_type] += 0.3 * signature.confidence_weight
                            evidence[framework_type].append(f"Additional endpoint pattern: {pattern}")
                    
                    # Check error patterns on 4xx/5xx responses
                    if response.status_code >= 400:
                        for pattern in signature.error_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                scores[framework_type] += 0.3 * signature.confidence_weight
                                evidence[framework_type].append(f"Additional endpoint error: {pattern}")
            
            except Exception as e:
                self.logger.debug("Additional endpoint analysis failed", endpoint=endpoint, error=str(e))
    
    def _determine_best_framework(self, scores: Dict[FrameworkType, float], 
                                evidence: Dict[FrameworkType, List[str]]) -> Optional[Framework]:
        """Determine the best framework match from detection scores"""
        # Find highest scoring framework
        best_framework_type = max(scores.keys(), key=lambda k: scores[k])
        best_score = scores[best_framework_type]
        
        # Check if score meets confidence threshold
        if best_score < self.config.confidence_threshold:
            return None
        
        # Calculate confidence percentage
        total_possible_score = 5.0  # Maximum possible score from all detection methods
        confidence = min(best_score / total_possible_score, 1.0)
        
        # Determine detection method
        detection_methods = []
        if any("Header" in ev for ev in evidence[best_framework_type]):
            detection_methods.append("headers")
        if any("Error pattern" in ev for ev in evidence[best_framework_type]):
            detection_methods.append("error_patterns")
        if any("Response pattern" in ev for ev in evidence[best_framework_type]):
            detection_methods.append("response_patterns")
        if any("Default endpoint" in ev for ev in evidence[best_framework_type]):
            detection_methods.append("default_endpoints")
        
        detection_method = ", ".join(detection_methods) if detection_methods else "unknown"
        
        # Get framework-specific vulnerabilities
        specific_vulns = self._get_framework_vulnerabilities(best_framework_type)
        
        # Get framework-specific endpoints
        framework_endpoints = self.signatures[best_framework_type].default_endpoints.copy()
        
        return Framework(
            name=best_framework_type,
            confidence=confidence,
            detection_method=detection_method,
            specific_vulnerabilities=specific_vulns,
            framework_endpoints=framework_endpoints,
            additional_info={
                "detection_score": best_score,
                "evidence": evidence[best_framework_type]
            }
        )
    
    def _get_framework_vulnerabilities(self, framework_type: FrameworkType) -> List[str]:
        """Get framework-specific vulnerabilities to test"""
        vulnerability_map = {
            FrameworkType.FASTAPI: [
                "OpenAPI spec exposure (/docs, /redoc, /openapi.json)",
                "Pydantic model injection",
                "Async endpoint race conditions",
                "JWT algorithm confusion"
            ],
            FrameworkType.EXPRESS: [
                "Prototype pollution",
                "Path traversal via express.static",
                "CORS misconfiguration",
                "Body parser vulnerabilities"
            ],
            FrameworkType.DJANGO: [
                "Django admin exposure (/admin/)",
                "CSRF token bypass",
                "SQL injection via ORM",
                "Template injection"
            ],
            FrameworkType.FLASK: [
                "Debug mode exposure",
                "Werkzeug debugger PIN bypass",
                "Template injection (Jinja2)",
                "Session cookie manipulation"
            ],
            FrameworkType.SPRING_BOOT: [
                "Actuator endpoints exposure",
                "Spring Expression Language injection",
                "Deserialization vulnerabilities",
                "Path traversal"
            ],
            FrameworkType.ASP_NET: [
                "ViewState manipulation",
                "Request validation bypass",
                "Configuration exposure",
                "Deserialization attacks"
            ]
        }
        
        return vulnerability_map.get(framework_type, [])
    
    def get_framework_specific_payloads(self, framework: Framework) -> List[str]:
        """
        Get framework-specific payloads for testing
        
        Args:
            framework: Detected framework
            
        Returns:
            List of framework-specific payloads
        """
        if not self.config.adapt_payloads:
            return []
        
        payload_map = {
            FrameworkType.FASTAPI: [
                # Pydantic model injection
                '{"__class__": {"__init__": {"__globals__": {"flag": "test"}}}}',
                # OpenAPI manipulation
                '/docs/../../../etc/passwd',
                # Async race condition
                '{"id": 1, "action": "delete"}',
            ],
            FrameworkType.EXPRESS: [
                # Prototype pollution
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                # Path traversal
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            ],
            FrameworkType.DJANGO: [
                # Template injection
                '{{7*7}}',
                '{{request.META}}',
                # ORM injection
                "'; DROP TABLE users; --",
                # Admin bypass
                '/admin/../admin/',
            ],
            FrameworkType.FLASK: [
                # Jinja2 template injection
                '{{7*7}}',
                '{{config}}',
                '{{request.environ}}',
                # Werkzeug debugger
                '/console',
                # Session manipulation
                'session=.eJyrVkosLcmIz8nPS1WyUoKi1GAjKzUYiOJSi5Iy8_NTSzKTU1PySzJSixSslKxqAQAAAP__',
            ],
            FrameworkType.SPRING_BOOT: [
                # SpEL injection
                '${7*7}',
                '#{7*7}',
                # Actuator endpoints
                '/actuator/env',
                '/actuator/configprops',
                # Path traversal
                '/..;/..;/..;/etc/passwd',
            ],
            FrameworkType.ASP_NET: [
                # ViewState manipulation
                '__VIEWSTATE=/wEPDwUKLTI2NjY5',
                # Request validation bypass
                '<script>alert(1)</script>',
                # Configuration exposure
                '/web.config',
                '/app.config',
            ]
        }
        
        return payload_map.get(framework.name, [])
    
    def generate_findings(self) -> List[Finding]:
        """
        Generate findings from framework detection
        
        Returns:
            List of findings
        """
        findings = []
        
        for framework in self.detected_frameworks:
            # Framework detection finding
            finding = Finding(
                id=f"framework_detected_{framework.name.lower()}",
                scan_id="framework_detection",
                category="FRAMEWORK_DETECTION",
                owasp_category=None,
                severity=Severity.INFO,
                endpoint="",
                method="GET",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=f"Framework detected: {framework.name} (confidence: {framework.confidence:.2f})",
                recommendation=f"Review {framework.name}-specific security configurations and vulnerabilities",
                payload=""
            )
            findings.append(finding)
            
            # High confidence framework detection with specific vulnerabilities
            if framework.confidence > 0.8 and framework.specific_vulnerabilities:
                vuln_finding = Finding(
                    id=f"framework_vulns_{framework.name.lower()}",
                    scan_id="framework_detection",
                    category="FRAMEWORK_VULNERABILITIES",
                    owasp_category=None,
                    severity=Severity.MEDIUM,
                    endpoint="",
                    method="GET",
                    status_code=200,
                    response_size=0,
                    response_time=0.0,
                    evidence=f"Framework {framework.name} detected with known vulnerability patterns",
                    recommendation=f"Test for {framework.name}-specific vulnerabilities: {', '.join(framework.specific_vulnerabilities[:3])}",
                    payload=""
                )
                findings.append(vuln_finding)
        
        self.findings = findings
        return findings.copy()
    
    def get_detected_frameworks(self) -> List[Framework]:
        """
        Get all detected frameworks
        
        Returns:
            List of detected frameworks
        """
        return self.detected_frameworks.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get framework detection statistics
        
        Returns:
            Dictionary with detection statistics
        """
        return {
            "frameworks_detected": len(self.detected_frameworks),
            "detection_enabled": self.config.enabled,
            "payload_adaptation_enabled": self.config.adapt_payloads,
            "confidence_threshold": self.config.confidence_threshold,
            "detected_framework_names": [f.name for f in self.detected_frameworks],
            "total_findings": len(self.findings)
        }