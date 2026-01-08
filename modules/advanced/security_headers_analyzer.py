"""
Security Headers Analyzer Module
Analyzes HTTP security headers for proper configuration and missing protections
"""

import asyncio
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from core.logging import get_logger
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, Severity


@dataclass
class SecurityHeaderCheck:
    """Security header check result"""
    header_name: str
    present: bool
    value: Optional[str] = None
    is_secure: bool = False
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class SecurityHeadersAnalysis:
    """Complete security headers analysis"""
    endpoint: str
    status_code: int
    response_time: float
    headers_checked: Dict[str, SecurityHeaderCheck] = field(default_factory=dict)
    security_score: int = 0  # 0-100 score
    missing_headers: List[str] = field(default_factory=list)
    insecure_headers: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityHeadersConfig:
    """Configuration for security headers analyzer"""
    enabled: bool = True
    timeout: float = 10.0
    max_concurrent: int = 5
    check_headers: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "X-Frame-Options": {
            "required": True,
            "secure_values": ["DENY", "SAMEORIGIN"],
            "weight": 15
        },
        "Content-Security-Policy": {
            "required": True,
            "secure_patterns": ["default-src", "script-src", "object-src"],
            "insecure_patterns": ["unsafe-inline", "unsafe-eval", "*"],
            "weight": 20
        },
        "Strict-Transport-Security": {
            "required": True,
            "secure_patterns": ["max-age=", "includeSubDomains"],
            "min_max_age": 31536000,  # 1 year
            "weight": 20
        },
        "X-Content-Type-Options": {
            "required": True,
            "secure_values": ["nosniff"],
            "weight": 10
        },
        "X-XSS-Protection": {
            "required": False,  # Deprecated but still good to have
            "secure_values": ["1; mode=block"],
            "weight": 5
        },
        "Referrer-Policy": {
            "required": True,
            "secure_values": ["strict-origin-when-cross-origin", "strict-origin", "no-referrer"],
            "weight": 10
        },
        "Permissions-Policy": {
            "required": False,
            "secure_patterns": ["geolocation=", "microphone=", "camera="],
            "weight": 10
        },
        "X-Permitted-Cross-Domain-Policies": {
            "required": False,
            "secure_values": ["none", "master-only"],
            "weight": 5
        },
        "Cache-Control": {
            "required": False,
            "secure_patterns": ["no-cache", "no-store", "private"],
            "insecure_patterns": ["public"],
            "weight": 5
        }
    })


class SecurityHeadersAnalyzer:
    """
    Security Headers Analyzer
    
    Analyzes HTTP security headers to identify missing or misconfigured security protections.
    Checks for critical headers like CSP, HSTS, X-Frame-Options, and others.
    
    Requirements: 19.3, 19.4
    """
    
    def __init__(self, config: SecurityHeadersConfig, http_client: HTTPRequestEngine):
        """
        Initialize Security Headers Analyzer
        
        Args:
            config: Security headers analyzer configuration
            http_client: HTTP client for making requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__).bind(component="security_headers_analyzer")
        
        # Analysis results
        self.analysis_results: Dict[str, SecurityHeadersAnalysis] = {}
        
        self.logger.info("Security Headers Analyzer initialized",
                        headers_to_check=len(config.check_headers),
                        timeout=config.timeout)
    
    async def analyze_security_headers(self, endpoints: List[str]) -> Dict[str, SecurityHeadersAnalysis]:
        """
        Analyze security headers for multiple endpoints
        
        Args:
            endpoints: List of endpoint URLs to analyze
            
        Returns:
            Dictionary mapping endpoints to their security headers analysis
        """
        if not self.config.enabled:
            self.logger.info("Security headers analysis disabled")
            return {}
        
        self.logger.info("Starting security headers analysis", endpoints_count=len(endpoints))
        
        # Analyze each endpoint
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        tasks = [
            self._analyze_endpoint_headers(semaphore, endpoint)
            for endpoint in endpoints
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            endpoint = endpoints[i]
            if isinstance(result, SecurityHeadersAnalysis):
                self.analysis_results[endpoint] = result
                
                self.logger.info("Security headers analysis completed for endpoint",
                                endpoint=endpoint,
                                security_score=result.security_score,
                                missing_headers=len(result.missing_headers))
            
            elif isinstance(result, Exception):
                self.logger.error("Security headers analysis failed for endpoint",
                                endpoint=endpoint,
                                error=str(result))
                # Create empty analysis for failed endpoint
                self.analysis_results[endpoint] = SecurityHeadersAnalysis(
                    endpoint=endpoint,
                    status_code=0,
                    response_time=0.0
                )
        
        self.logger.info("Security headers analysis completed",
                        endpoints_analyzed=len(self.analysis_results))
        
        return self.analysis_results
    
    async def _analyze_endpoint_headers(self, semaphore: asyncio.Semaphore, 
                                      endpoint: str) -> SecurityHeadersAnalysis:
        """
        Analyze security headers for a single endpoint
        
        Args:
            semaphore: Concurrency control semaphore
            endpoint: Endpoint URL to analyze
            
        Returns:
            SecurityHeadersAnalysis with complete results
        """
        async with semaphore:
            analysis = SecurityHeadersAnalysis(
                endpoint=endpoint,
                status_code=0,
                response_time=0.0
            )
            
            try:
                # Make request to get headers
                response = await self.http_client.request(
                    method="GET",
                    url=endpoint,
                    timeout=self.config.timeout
                )
                
                analysis.status_code = response.status_code
                analysis.response_time = response.elapsed
                
                # Analyze each configured header
                for header_name, header_config in self.config.check_headers.items():
                    check_result = self._check_security_header(
                        header_name, 
                        response.headers, 
                        header_config
                    )
                    analysis.headers_checked[header_name] = check_result
                    
                    # Track missing and insecure headers
                    if not check_result.present and header_config.get("required", False):
                        analysis.missing_headers.append(header_name)
                    elif check_result.present and not check_result.is_secure:
                        analysis.insecure_headers.append(header_name)
                
                # Calculate security score
                analysis.security_score = self._calculate_security_score(analysis)
                
                self.logger.debug("Security headers analyzed",
                                endpoint=endpoint,
                                status_code=response.status_code,
                                security_score=analysis.security_score,
                                missing_count=len(analysis.missing_headers))
            
            except Exception as e:
                self.logger.error("Security headers analysis failed",
                                endpoint=endpoint,
                                error=str(e))
                analysis.status_code = 0
                analysis.response_time = 0.0
            
            return analysis
    
    def _check_security_header(self, header_name: str, headers: Dict[str, str], 
                             config: Dict[str, Any]) -> SecurityHeaderCheck:
        """
        Check a specific security header
        
        Args:
            header_name: Name of the header to check
            headers: Response headers dictionary
            config: Header configuration
            
        Returns:
            SecurityHeaderCheck with analysis results
        """
        check = SecurityHeaderCheck(
            header_name=header_name,
            present=False
        )
        
        # Check if header is present (case-insensitive)
        header_value = None
        for key, value in headers.items():
            if key.lower() == header_name.lower():
                header_value = value
                check.present = True
                check.value = value
                break
        
        if not check.present:
            if config.get("required", False):
                check.issues.append(f"Required security header {header_name} is missing")
                check.recommendations.append(f"Add {header_name} header with appropriate value")
            return check
        
        # Check header value security
        check.is_secure = self._is_header_value_secure(header_name, header_value, config)
        
        if not check.is_secure:
            check.issues.extend(self._get_header_issues(header_name, header_value, config))
            check.recommendations.extend(self._get_header_recommendations(header_name, config))
        
        return check
    
    def _is_header_value_secure(self, header_name: str, value: str, config: Dict[str, Any]) -> bool:
        """
        Check if header value is secure based on configuration
        
        Args:
            header_name: Header name
            value: Header value
            config: Header configuration
            
        Returns:
            True if header value is secure
        """
        if not value:
            return False
        
        value_lower = value.lower()
        
        # Check secure values
        secure_values = config.get("secure_values", [])
        if secure_values:
            return any(secure_val.lower() in value_lower for secure_val in secure_values)
        
        # Check secure patterns
        secure_patterns = config.get("secure_patterns", [])
        if secure_patterns:
            has_secure_pattern = any(pattern.lower() in value_lower for pattern in secure_patterns)
            if not has_secure_pattern:
                return False
        
        # Check insecure patterns
        insecure_patterns = config.get("insecure_patterns", [])
        if insecure_patterns:
            has_insecure_pattern = any(pattern.lower() in value_lower for pattern in insecure_patterns)
            if has_insecure_pattern:
                return False
        
        # Special checks for specific headers
        if header_name.lower() == "strict-transport-security":
            return self._check_hsts_security(value, config)
        elif header_name.lower() == "content-security-policy":
            return self._check_csp_security(value, config)
        
        return True
    
    def _check_hsts_security(self, value: str, config: Dict[str, Any]) -> bool:
        """Check HSTS header security"""
        if "max-age=" not in value.lower():
            return False
        
        # Extract max-age value
        try:
            max_age_part = [part for part in value.split(';') if 'max-age=' in part.lower()][0]
            max_age_value = int(max_age_part.split('=')[1].strip())
            min_max_age = config.get("min_max_age", 31536000)  # 1 year default
            
            return max_age_value >= min_max_age
        except (IndexError, ValueError):
            return False
    
    def _check_csp_security(self, value: str, config: Dict[str, Any]) -> bool:
        """Check CSP header security"""
        value_lower = value.lower()
        
        # Check for dangerous directives
        insecure_patterns = config.get("insecure_patterns", [])
        for pattern in insecure_patterns:
            if pattern.lower() in value_lower:
                return False
        
        # Check for required directives
        secure_patterns = config.get("secure_patterns", [])
        if secure_patterns:
            return any(pattern.lower() in value_lower for pattern in secure_patterns)
        
        return True
    
    def _get_header_issues(self, header_name: str, value: str, config: Dict[str, Any]) -> List[str]:
        """Get list of issues with header value"""
        issues = []
        
        # Check for insecure patterns
        insecure_patterns = config.get("insecure_patterns", [])
        for pattern in insecure_patterns:
            if pattern.lower() in value.lower():
                issues.append(f"{header_name} contains insecure directive: {pattern}")
        
        # Special checks
        if header_name.lower() == "strict-transport-security":
            if "includesubdomains" not in value.lower():
                issues.append("HSTS header should include includeSubDomains directive")
            
            try:
                max_age_part = [part for part in value.split(';') if 'max-age=' in part.lower()][0]
                max_age_value = int(max_age_part.split('=')[1].strip())
                if max_age_value < 31536000:  # 1 year
                    issues.append("HSTS max-age should be at least 1 year (31536000 seconds)")
            except (IndexError, ValueError):
                issues.append("HSTS header has invalid max-age value")
        
        return issues
    
    def _get_header_recommendations(self, header_name: str, config: Dict[str, Any]) -> List[str]:
        """Get recommendations for header configuration"""
        recommendations = []
        
        if header_name.lower() == "x-frame-options":
            recommendations.append("Use 'DENY' or 'SAMEORIGIN' to prevent clickjacking attacks")
        elif header_name.lower() == "content-security-policy":
            recommendations.append("Implement a strict CSP policy without 'unsafe-inline' or 'unsafe-eval'")
        elif header_name.lower() == "strict-transport-security":
            recommendations.append("Use max-age of at least 1 year and include includeSubDomains")
        elif header_name.lower() == "x-content-type-options":
            recommendations.append("Set to 'nosniff' to prevent MIME type sniffing")
        elif header_name.lower() == "referrer-policy":
            recommendations.append("Use 'strict-origin-when-cross-origin' or stricter policy")
        
        return recommendations
    
    def _calculate_security_score(self, analysis: SecurityHeadersAnalysis) -> int:
        """
        Calculate security score based on header analysis
        
        Args:
            analysis: Security headers analysis
            
        Returns:
            Security score from 0-100
        """
        total_weight = sum(config.get("weight", 10) for config in self.config.check_headers.values())
        earned_score = 0
        
        for header_name, check in analysis.headers_checked.items():
            header_config = self.config.check_headers.get(header_name, {})
            weight = header_config.get("weight", 10)
            
            if check.present and check.is_secure:
                earned_score += weight
            elif check.present and not check.is_secure:
                earned_score += weight * 0.5  # Partial credit for present but insecure
        
        return int((earned_score / total_weight) * 100) if total_weight > 0 else 0
    
    def generate_findings(self) -> List[Finding]:
        """
        Generate findings from security headers analysis
        
        Returns:
            List of findings related to security headers
        """
        findings = []
        
        for endpoint, analysis in self.analysis_results.items():
            # Missing critical security headers
            critical_missing = [header for header in analysis.missing_headers 
                              if self.config.check_headers.get(header, {}).get("required", False)]
            
            if critical_missing:
                severity = Severity.HIGH if len(critical_missing) > 2 else Severity.MEDIUM
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="security_headers",
                    category="MISSING_SECURITY_HEADERS",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=severity,
                    endpoint=endpoint,
                    method="GET",
                    status_code=analysis.status_code,
                    response_size=0,
                    response_time=analysis.response_time,
                    evidence=f"Missing critical security headers: {', '.join(critical_missing)}",
                    recommendation="Implement missing security headers to protect against common web vulnerabilities. "
                                 "Review OWASP security headers guide for proper configuration.",
                    payload=None,
                    response_snippet=f"Missing headers: {len(critical_missing)}, Security score: {analysis.security_score}%",
                    headers={}
                )
                findings.append(finding)
            
            # Insecure header configurations
            if analysis.insecure_headers:
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="security_headers",
                    category="INSECURE_SECURITY_HEADERS",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=Severity.MEDIUM,
                    endpoint=endpoint,
                    method="GET",
                    status_code=analysis.status_code,
                    response_size=0,
                    response_time=analysis.response_time,
                    evidence=f"Insecure security header configurations: {', '.join(analysis.insecure_headers)}",
                    recommendation="Review and fix insecure security header configurations. "
                                 "Remove unsafe directives and use secure values.",
                    payload=None,
                    response_snippet=f"Insecure headers: {len(analysis.insecure_headers)}",
                    headers={}
                )
                findings.append(finding)
            
            # Low security score
            if analysis.security_score < 50:
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="security_headers",
                    category="LOW_SECURITY_HEADERS_SCORE",
                    owasp_category="API7",  # Security Misconfiguration
                    severity=Severity.MEDIUM,
                    endpoint=endpoint,
                    method="GET",
                    status_code=analysis.status_code,
                    response_size=0,
                    response_time=analysis.response_time,
                    evidence=f"Low security headers score: {analysis.security_score}%",
                    recommendation="Improve security headers configuration to achieve better protection. "
                                 "Implement missing headers and fix insecure configurations.",
                    payload=None,
                    response_snippet=f"Security score: {analysis.security_score}%",
                    headers={}
                )
                findings.append(finding)
            
            # Specific header issues
            for header_name, check in analysis.headers_checked.items():
                if check.issues:
                    severity = Severity.HIGH if "strict-transport-security" in header_name.lower() else Severity.MEDIUM
                    
                    finding = Finding(
                        id=str(uuid4()),
                        scan_id="security_headers",
                        category=f"SECURITY_HEADER_ISSUE_{header_name.upper().replace('-', '_')}",
                        owasp_category="API7",  # Security Misconfiguration
                        severity=severity,
                        endpoint=endpoint,
                        method="GET",
                        status_code=analysis.status_code,
                        response_size=0,
                        response_time=analysis.response_time,
                        evidence=f"{header_name} header issues: {'; '.join(check.issues)}",
                        recommendation='; '.join(check.recommendations) if check.recommendations else 
                                     f"Fix {header_name} header configuration",
                        payload=None,
                        response_snippet=f"{header_name}: {check.value}" if check.value else f"{header_name}: missing",
                        headers={}
                    )
                    findings.append(finding)
        
        return findings
    
    def get_analysis_results(self) -> Dict[str, SecurityHeadersAnalysis]:
        """
        Get complete security headers analysis results
        
        Returns:
            Dictionary mapping endpoints to their security headers analysis
        """
        return self.analysis_results.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get security headers analysis statistics
        
        Returns:
            Dictionary with analysis statistics
        """
        if not self.analysis_results:
            return {
                "total_endpoints_analyzed": 0,
                "average_security_score": 0,
                "endpoints_with_missing_headers": 0,
                "endpoints_with_insecure_headers": 0,
                "most_common_missing_header": None
            }
        
        total_endpoints = len(self.analysis_results)
        average_score = sum(analysis.security_score for analysis in self.analysis_results.values()) / total_endpoints
        
        endpoints_with_missing = sum(1 for analysis in self.analysis_results.values() 
                                   if analysis.missing_headers)
        endpoints_with_insecure = sum(1 for analysis in self.analysis_results.values() 
                                    if analysis.insecure_headers)
        
        # Find most common missing header
        missing_header_counts = {}
        for analysis in self.analysis_results.values():
            for header in analysis.missing_headers:
                missing_header_counts[header] = missing_header_counts.get(header, 0) + 1
        
        most_common_missing = max(missing_header_counts.items(), key=lambda x: x[1])[0] if missing_header_counts else None
        
        return {
            "total_endpoints_analyzed": total_endpoints,
            "average_security_score": round(average_score, 1),
            "endpoints_with_missing_headers": endpoints_with_missing,
            "endpoints_with_insecure_headers": endpoints_with_insecure,
            "most_common_missing_header": most_common_missing,
            "total_headers_checked": len(self.config.check_headers)
        }