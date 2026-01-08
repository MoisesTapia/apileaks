"""
Response Analyzer
Intelligent analysis of HTTP responses for vulnerability detection
"""

import re
import json
import statistics
from typing import List, Dict, Any, Optional, Pattern, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from core.logging import get_logger
from core.config import Severity


class EndpointStatus(str, Enum):
    """Endpoint status classification"""
    VALID = "valid"
    AUTH_REQUIRED = "auth_required"
    NOT_FOUND = "not_found"
    ERROR = "error"
    REDIRECT = "redirect"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"


@dataclass
class Finding:
    """Security finding"""
    id: str
    category: str
    severity: str
    endpoint: str
    method: str
    evidence: str
    recommendation: str


@dataclass
class SecurityFinding:
    """Security-specific finding"""
    finding_type: str
    severity: Severity
    description: str
    evidence: str
    confidence: float = 0.8
    remediation: str = ""


@dataclass
class TimingAnalysis:
    """Timing analysis results"""
    average_response_time: float
    min_response_time: float
    max_response_time: float
    timing_anomalies: List[str]
    potential_timing_attacks: List[str] = field(default_factory=list)
    response_time_variance: float = 0.0


@dataclass
class AnalysisRules:
    """Analysis rules configuration"""
    sensitive_data_patterns: Dict[str, Pattern] = field(default_factory=dict)
    error_patterns: Dict[str, Pattern] = field(default_factory=dict)
    stack_trace_patterns: List[Pattern] = field(default_factory=list)
    security_headers: List[str] = field(default_factory=list)
    timing_threshold: float = 2.0  # seconds
    size_anomaly_threshold: float = 0.5  # 50% difference


@dataclass
class RequestContext:
    """Request context for analysis"""
    endpoint: str
    method: str
    payload: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    auth_context: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class ResponseAnalyzer:
    """
    Response Analyzer for intelligent HTTP response analysis
    
    Provides advanced pattern matching and classification for:
    - Vulnerability detection through response analysis
    - Endpoint status classification with intelligent logic
    - Security issue identification with regex patterns
    - Timing pattern analysis for potential attacks
    - Error message and stack trace detection
    - Sensitive data exposure detection
    """
    
    def __init__(self, analysis_rules: Optional[AnalysisRules] = None):
        """
        Initialize Response Analyzer with advanced pattern matching
        
        Args:
            analysis_rules: Analysis rules configuration
        """
        self.analysis_rules = analysis_rules or self._get_default_rules()
        self.logger = get_logger(__name__)
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
        self.logger.info("Response Analyzer initialized with advanced pattern matching")
    
    def _get_default_rules(self) -> AnalysisRules:
        """Get default analysis rules with comprehensive patterns"""
        
        # Sensitive data patterns
        sensitive_patterns = {
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', re.IGNORECASE),
            'password': re.compile(r'(?i)(password|passwd|pwd)["\s]*[:=]["\s]*["\']([^"\']{6,})["\']', re.IGNORECASE),
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            'private_key': re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', re.IGNORECASE),
            'secret_key': re.compile(r'(?i)(secret[_-]?key|secretkey)["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})', re.IGNORECASE)
        }
        
        # Error message patterns
        error_patterns = {
            'sql_error': re.compile(r'(?i)(sql|mysql|postgresql|oracle|sqlite).*(error|exception|syntax)', re.IGNORECASE),
            'path_disclosure': re.compile(r'(?i)(\/[a-zA-Z0-9_\-\/\.]+\.(php|asp|aspx|jsp|py|rb|pl))', re.IGNORECASE),
            'debug_info': re.compile(r'(?i)(debug|trace|stack|exception|error).*line\s*\d+', re.IGNORECASE),
            'database_error': re.compile(r'(?i)(database|db).*(connection|error|failed|timeout)', re.IGNORECASE),
            'internal_error': re.compile(r'(?i)(internal\s+server\s+error|500\s+error|application\s+error)', re.IGNORECASE)
        }
        
        # Stack trace patterns
        stack_trace_patterns = [
            re.compile(r'at\s+[\w\.$]+\([\w\.]+:\d+\)', re.IGNORECASE),  # Java stack trace
            re.compile(r'File\s+"[^"]+",\s+line\s+\d+', re.IGNORECASE),  # Python stack trace
            re.compile(r'in\s+[^\s]+\s+on\s+line\s+\d+', re.IGNORECASE),  # PHP stack trace
            re.compile(r'at\s+[\w\.]+\s+\([^)]+:\d+:\d+\)', re.IGNORECASE),  # JavaScript stack trace
            re.compile(r'Traceback\s+\(most\s+recent\s+call\s+last\)', re.IGNORECASE),  # Python traceback
            re.compile(r'Exception\s+in\s+thread\s+"[^"]+"', re.IGNORECASE)  # Java exception
        ]
        
        # Security headers to check
        security_headers = [
            'X-Frame-Options',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies'
        ]
        
        return AnalysisRules(
            sensitive_data_patterns=sensitive_patterns,
            error_patterns=error_patterns,
            stack_trace_patterns=stack_trace_patterns,
            security_headers=security_headers,
            timing_threshold=2.0,
            size_anomaly_threshold=0.5
        )
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for better performance"""
        # Patterns are already compiled in _get_default_rules
        self.logger.debug("Regex patterns compiled for performance optimization")
    
    def analyze_response(self, response: Any, context: RequestContext) -> List[Finding]:
        """
        Analyze HTTP response for vulnerabilities with advanced pattern matching
        
        Args:
            response: HTTP response to analyze
            context: Request context
            
        Returns:
            List of security findings
        """
        self.logger.debug("Analyzing response with advanced pattern matching", 
                         status_code=response.status_code,
                         url=context.endpoint,
                         method=context.method)
        
        findings = []
        
        try:
            # Get response content safely
            response_text = self._get_response_text(response)
            response_headers = getattr(response, 'headers', {})
            
            # Detect sensitive data exposure
            sensitive_findings = self._detect_sensitive_data(response_text, context)
            findings.extend(sensitive_findings)
            
            # Detect error messages and stack traces
            error_findings = self._detect_error_messages(response_text, context)
            findings.extend(error_findings)
            
            # Analyze security headers
            header_findings = self._analyze_security_headers(response_headers, context)
            findings.extend(header_findings)
            
            # Detect information disclosure
            info_findings = self._detect_information_disclosure(response_text, response_headers, context)
            findings.extend(info_findings)
            
            # Analyze response size anomalies
            size_findings = self._analyze_response_size(response, context)
            findings.extend(size_findings)
            
            self.logger.debug("Response analysis completed", 
                            findings_count=len(findings),
                            endpoint=context.endpoint)
            
        except Exception as e:
            self.logger.error("Response analysis failed", 
                            error=str(e),
                            endpoint=context.endpoint)
        
        return findings
    
    def _get_response_text(self, response: Any) -> str:
        """Safely extract response text"""
        try:
            if hasattr(response, 'text'):
                return response.text
            elif hasattr(response, 'content'):
                return response.content.decode('utf-8', errors='ignore')
            else:
                return str(response)
        except Exception:
            return ""
    
    def _detect_sensitive_data(self, response_text: str, context: RequestContext) -> List[Finding]:
        """Detect sensitive data exposure in response"""
        findings = []
        
        for data_type, pattern in self.analysis_rules.sensitive_data_patterns.items():
            matches = pattern.findall(response_text)
            
            if matches:
                # Mask sensitive data in evidence
                masked_matches = []
                for match in matches[:3]:  # Limit to first 3 matches
                    if isinstance(match, tuple):
                        # For patterns with groups, mask the sensitive part
                        masked_match = match[0] + "=" + "*" * min(len(match[1]), 8) + "..."
                    else:
                        # For simple matches, mask most of it
                        masked_match = match[:4] + "*" * min(len(match) - 4, 8) + "..."
                    masked_matches.append(masked_match)
                
                finding = Finding(
                    id=f"sensitive_data_{data_type}_{hash(context.endpoint)}",
                    category="SENSITIVE_DATA_EXPOSURE",
                    severity=Severity.HIGH.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence=f"Sensitive {data_type} detected in response: {', '.join(masked_matches)}",
                    recommendation=f"Remove {data_type} from API responses or implement proper data filtering"
                )
                findings.append(finding)
        
        return findings
    
    def _detect_error_messages(self, response_text: str, context: RequestContext) -> List[Finding]:
        """Detect error messages and stack traces"""
        findings = []
        
        # Check for error patterns
        for error_type, pattern in self.analysis_rules.error_patterns.items():
            if pattern.search(response_text):
                finding = Finding(
                    id=f"error_disclosure_{error_type}_{hash(context.endpoint)}",
                    category="ERROR_MESSAGE_DISCLOSURE",
                    severity=Severity.MEDIUM.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence=f"Error message disclosure detected: {error_type}",
                    recommendation="Implement generic error messages and proper error handling"
                )
                findings.append(finding)
        
        # Check for stack traces
        for pattern in self.analysis_rules.stack_trace_patterns:
            if pattern.search(response_text):
                finding = Finding(
                    id=f"stack_trace_{hash(context.endpoint)}",
                    category="STACK_TRACE_DISCLOSURE",
                    severity=Severity.MEDIUM.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence="Stack trace detected in response",
                    recommendation="Disable debug mode and implement proper error handling"
                )
                findings.append(finding)
                break  # Only report once per response
        
        return findings
    
    def _analyze_security_headers(self, headers: Dict[str, str], context: RequestContext) -> List[Finding]:
        """Analyze security headers"""
        findings = []
        missing_headers = []
        
        # Convert headers to case-insensitive dict
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header in self.analysis_rules.security_headers:
            if header.lower() not in headers_lower:
                missing_headers.append(header)
        
        if missing_headers:
            finding = Finding(
                id=f"missing_security_headers_{hash(context.endpoint)}",
                category="MISSING_SECURITY_HEADERS",
                severity=Severity.LOW.value,
                endpoint=context.endpoint,
                method=context.method,
                evidence=f"Missing security headers: {', '.join(missing_headers)}",
                recommendation="Implement missing security headers to improve security posture"
            )
            findings.append(finding)
        
        # Check for insecure header values
        if 'x-frame-options' in headers_lower:
            if headers_lower['x-frame-options'].lower() in ['allowall', 'allow-from *']:
                finding = Finding(
                    id=f"insecure_frame_options_{hash(context.endpoint)}",
                    category="INSECURE_SECURITY_HEADER",
                    severity=Severity.MEDIUM.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence=f"Insecure X-Frame-Options: {headers_lower['x-frame-options']}",
                    recommendation="Set X-Frame-Options to DENY or SAMEORIGIN"
                )
                findings.append(finding)
        
        return findings
    
    def _detect_information_disclosure(self, response_text: str, headers: Dict[str, str], context: RequestContext) -> List[Finding]:
        """Detect various forms of information disclosure"""
        findings = []
        
        # Check for server information disclosure
        server_header = headers.get('Server', headers.get('server', ''))
        if server_header:
            # Check if server header reveals version information
            version_pattern = re.compile(r'[\d\.]+', re.IGNORECASE)
            if version_pattern.search(server_header):
                finding = Finding(
                    id=f"server_version_disclosure_{hash(context.endpoint)}",
                    category="INFORMATION_DISCLOSURE",
                    severity=Severity.LOW.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence=f"Server version disclosed: {server_header}",
                    recommendation="Configure server to hide version information"
                )
                findings.append(finding)
        
        # Check for technology disclosure in headers
        tech_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in tech_headers:
            if header in headers or header.lower() in headers:
                value = headers.get(header, headers.get(header.lower(), ''))
                finding = Finding(
                    id=f"tech_disclosure_{header.lower()}_{hash(context.endpoint)}",
                    category="INFORMATION_DISCLOSURE",
                    severity=Severity.LOW.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence=f"Technology disclosure: {header}: {value}",
                    recommendation=f"Remove or configure {header} header"
                )
                findings.append(finding)
        
        # Check for directory listing
        if re.search(r'<title>Index of /', response_text, re.IGNORECASE):
            finding = Finding(
                id=f"directory_listing_{hash(context.endpoint)}",
                category="DIRECTORY_LISTING",
                severity=Severity.MEDIUM.value,
                endpoint=context.endpoint,
                method=context.method,
                evidence="Directory listing detected",
                recommendation="Disable directory listing on web server"
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_response_size(self, response: Any, context: RequestContext) -> List[Finding]:
        """Analyze response size for anomalies"""
        findings = []
        
        try:
            response_size = len(self._get_response_text(response))
            
            # Check for unusually large responses (potential DoS)
            if response_size > 10 * 1024 * 1024:  # 10MB
                finding = Finding(
                    id=f"large_response_{hash(context.endpoint)}",
                    category="LARGE_RESPONSE",
                    severity=Severity.LOW.value,
                    endpoint=context.endpoint,
                    method=context.method,
                    evidence=f"Unusually large response: {response_size} bytes",
                    recommendation="Implement response size limits and pagination"
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.debug("Response size analysis failed", error=str(e))
        
        return findings
    
    
    def classify_endpoint_status(self, response: Any) -> EndpointStatus:
        """
        Classify endpoint status based on response with intelligent logic
        
        Args:
            response: HTTP response
            
        Returns:
            Endpoint status classification
        """
        status_code = getattr(response, 'status_code', 0)
        headers = getattr(response, 'headers', {})
        response_text = self._get_response_text(response)
        
        # Rate limiting detection
        if status_code == 429 or 'rate limit' in response_text.lower():
            return EndpointStatus.RATE_LIMITED
        
        # Success responses
        if 200 <= status_code < 300:
            return EndpointStatus.VALID
        
        # Redirect responses
        if 300 <= status_code < 400:
            return EndpointStatus.REDIRECT
        
        # Authentication/Authorization required
        if status_code in [401, 403]:
            # Check if it's actually an auth requirement vs access denied
            auth_indicators = ['unauthorized', 'authentication', 'login', 'token']
            if any(indicator in response_text.lower() for indicator in auth_indicators):
                return EndpointStatus.AUTH_REQUIRED
            else:
                return EndpointStatus.AUTH_REQUIRED  # Default for 401/403
        
        # Not found
        if status_code == 404:
            return EndpointStatus.NOT_FOUND
        
        # Server errors
        if 500 <= status_code < 600:
            return EndpointStatus.SERVER_ERROR
        
        # Client errors (other than auth and not found)
        if 400 <= status_code < 500:
            return EndpointStatus.ERROR
        
        # Default case
        return EndpointStatus.ERROR
    
    def detect_security_issues(self, response: Any) -> List[SecurityFinding]:
        """
        Detect security issues in response with comprehensive analysis
        
        Args:
            response: HTTP response
            
        Returns:
            List of security findings
        """
        security_findings = []
        
        try:
            response_text = self._get_response_text(response)
            headers = getattr(response, 'headers', {})
            status_code = getattr(response, 'status_code', 0)
            
            # CORS policy analysis
            cors_findings = self._analyze_cors_policy(headers)
            security_findings.extend(cors_findings)
            
            # Content type analysis
            content_type_findings = self._analyze_content_type(headers, response_text)
            security_findings.extend(content_type_findings)
            
            # Authentication bypass detection
            auth_findings = self._detect_auth_bypass(response_text, status_code)
            security_findings.extend(auth_findings)
            
            # Injection vulnerability indicators
            injection_findings = self._detect_injection_indicators(response_text)
            security_findings.extend(injection_findings)
            
        except Exception as e:
            self.logger.error("Security issue detection failed", error=str(e))
        
        return security_findings
    
    def _analyze_cors_policy(self, headers: Dict[str, str]) -> List[SecurityFinding]:
        """Analyze CORS policy for security issues"""
        findings = []
        
        # Convert to case-insensitive dict
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for wildcard CORS
        access_control_origin = headers_lower.get('access-control-allow-origin', '')
        if access_control_origin == '*':
            # Check if credentials are also allowed (dangerous combination)
            credentials = headers_lower.get('access-control-allow-credentials', '').lower()
            if credentials == 'true':
                finding = SecurityFinding(
                    finding_type="DANGEROUS_CORS_POLICY",
                    severity=Severity.HIGH,
                    description="Dangerous CORS policy: wildcard origin with credentials",
                    evidence=f"Access-Control-Allow-Origin: {access_control_origin}, Access-Control-Allow-Credentials: {credentials}",
                    confidence=0.9,
                    remediation="Specify explicit origins instead of wildcard when allowing credentials"
                )
                findings.append(finding)
            else:
                finding = SecurityFinding(
                    finding_type="PERMISSIVE_CORS_POLICY",
                    severity=Severity.MEDIUM,
                    description="Permissive CORS policy: wildcard origin",
                    evidence=f"Access-Control-Allow-Origin: {access_control_origin}",
                    confidence=0.8,
                    remediation="Consider specifying explicit allowed origins"
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_content_type(self, headers: Dict[str, str], response_text: str) -> List[SecurityFinding]:
        """Analyze content type for security issues"""
        findings = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        content_type = headers_lower.get('content-type', '').lower()
        
        # Check for missing X-Content-Type-Options
        if 'x-content-type-options' not in headers_lower:
            finding = SecurityFinding(
                finding_type="MISSING_CONTENT_TYPE_OPTIONS",
                severity=Severity.LOW,
                description="Missing X-Content-Type-Options header",
                evidence="X-Content-Type-Options header not present",
                confidence=0.9,
                remediation="Add X-Content-Type-Options: nosniff header"
            )
            findings.append(finding)
        
        # Check for potential MIME type confusion
        if content_type.startswith('text/html') and response_text:
            # Check if HTML content might be interpreted as script
            if '<script' in response_text.lower() or 'javascript:' in response_text.lower():
                finding = SecurityFinding(
                    finding_type="POTENTIAL_XSS_VECTOR",
                    severity=Severity.MEDIUM,
                    description="HTML content with script elements detected",
                    evidence="Response contains script elements in HTML content",
                    confidence=0.7,
                    remediation="Implement proper output encoding and CSP headers"
                )
                findings.append(finding)
        
        return findings
    
    def _detect_auth_bypass(self, response_text: str, status_code: int) -> List[SecurityFinding]:
        """Detect potential authentication bypass indicators"""
        findings = []
        
        # Look for admin/privileged content in responses
        admin_indicators = [
            'admin panel', 'administrator', 'admin dashboard',
            'user management', 'system settings', 'admin console'
        ]
        
        if any(indicator in response_text.lower() for indicator in admin_indicators):
            if status_code == 200:  # Successful access to admin content
                finding = SecurityFinding(
                    finding_type="POTENTIAL_AUTH_BYPASS",
                    severity=Severity.HIGH,
                    description="Administrative content accessible",
                    evidence="Response contains administrative interface indicators",
                    confidence=0.6,
                    remediation="Verify proper authentication and authorization controls"
                )
                findings.append(finding)
        
        return findings
    
    def _detect_injection_indicators(self, response_text: str) -> List[SecurityFinding]:
        """Detect potential injection vulnerability indicators"""
        findings = []
        
        # SQL injection error indicators
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
            'sqlite_', 'postgresql', 'syntax error', 'quoted string'
        ]
        
        if any(error in response_text.lower() for error in sql_errors):
            finding = SecurityFinding(
                finding_type="SQL_INJECTION_INDICATOR",
                severity=Severity.HIGH,
                description="Potential SQL injection vulnerability detected",
                evidence="Response contains SQL error messages",
                confidence=0.8,
                remediation="Implement parameterized queries and input validation"
            )
            findings.append(finding)
        
        # Command injection indicators
        command_indicators = [
            'command not found', 'permission denied', '/bin/', '/usr/bin/',
            'no such file or directory', 'syntax error near'
        ]
        
        if any(indicator in response_text.lower() for indicator in command_indicators):
            finding = SecurityFinding(
                finding_type="COMMAND_INJECTION_INDICATOR",
                severity=Severity.HIGH,
                description="Potential command injection vulnerability detected",
                evidence="Response contains command execution indicators",
                confidence=0.7,
                remediation="Implement proper input validation and avoid system calls"
            )
            findings.append(finding)
        
        return findings
    
    def analyze_timing_patterns(self, responses: List[Any]) -> TimingAnalysis:
        """
        Analyze timing patterns in responses with anomaly detection
        
        Args:
            responses: List of HTTP responses with timing data
            
        Returns:
            Timing analysis results with anomaly detection
        """
        if not responses:
            return TimingAnalysis(
                average_response_time=0.0,
                min_response_time=0.0,
                max_response_time=0.0,
                timing_anomalies=[],
                potential_timing_attacks=[],
                response_time_variance=0.0
            )
        
        # Extract response times
        response_times = []
        for response in responses:
            if hasattr(response, 'response_time'):
                response_times.append(response.response_time)
            elif hasattr(response, 'elapsed'):
                response_times.append(response.elapsed.total_seconds())
            else:
                # Default timing if not available
                response_times.append(0.0)
        
        if not response_times:
            return TimingAnalysis(
                average_response_time=0.0,
                min_response_time=0.0,
                max_response_time=0.0,
                timing_anomalies=[],
                potential_timing_attacks=[],
                response_time_variance=0.0
            )
        
        # Calculate basic statistics
        avg_time = statistics.mean(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        
        # Calculate variance
        variance = statistics.variance(response_times) if len(response_times) > 1 else 0.0
        
        # Detect timing anomalies
        anomalies = []
        potential_attacks = []
        
        # Check for responses significantly slower than average
        threshold = self.analysis_rules.timing_threshold
        for i, time in enumerate(response_times):
            if time > avg_time + threshold:
                anomalies.append(f"Response {i+1}: {time:.2f}s (significantly slower than average {avg_time:.2f}s)")
        
        # Detect potential timing attack patterns
        if len(response_times) >= 10:  # Need sufficient data
            # Check for bimodal distribution (potential timing attack indicator)
            sorted_times = sorted(response_times)
            median = statistics.median(sorted_times)
            
            fast_responses = [t for t in response_times if t < median]
            slow_responses = [t for t in response_times if t >= median]
            
            if len(fast_responses) > 0 and len(slow_responses) > 0:
                fast_avg = statistics.mean(fast_responses)
                slow_avg = statistics.mean(slow_responses)
                
                # If there's a significant gap between fast and slow responses
                if slow_avg > fast_avg * 2:
                    potential_attacks.append(
                        f"Potential timing attack pattern detected: "
                        f"Fast responses avg {fast_avg:.2f}s, slow responses avg {slow_avg:.2f}s"
                    )
        
        # Check for consistently slow responses (potential DoS)
        if avg_time > 5.0:  # 5 seconds average
            potential_attacks.append(f"Consistently slow responses detected (avg: {avg_time:.2f}s)")
        
        return TimingAnalysis(
            average_response_time=avg_time,
            min_response_time=min_time,
            max_response_time=max_time,
            timing_anomalies=anomalies,
            potential_timing_attacks=potential_attacks,
            response_time_variance=variance
        )