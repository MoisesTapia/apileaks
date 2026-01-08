"""
Tests for Response Analyzer
"""

import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime
from typing import Dict, Any

from utils.response_analyzer import (
    ResponseAnalyzer, 
    EndpointStatus, 
    Finding, 
    SecurityFinding, 
    TimingAnalysis,
    AnalysisRules,
    RequestContext
)
from core.config import Severity


class TestResponseAnalyzer:
    """Test Response Analyzer functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.analyzer = ResponseAnalyzer()
        self.context = RequestContext(
            endpoint="https://api.example.com/users",
            method="GET"
        )
    
    def create_mock_response(self, status_code: int = 200, text: str = "", headers: Dict[str, str] = None) -> Mock:
        """Create a mock HTTP response"""
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.headers = headers or {}
        response.content = text.encode('utf-8')
        return response
    
    def test_classify_endpoint_status_valid(self):
        """Test classification of valid endpoints"""
        response = self.create_mock_response(200, "Success")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.VALID
    
    def test_classify_endpoint_status_auth_required(self):
        """Test classification of auth required endpoints"""
        response = self.create_mock_response(401, "Unauthorized")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.AUTH_REQUIRED
        
        response = self.create_mock_response(403, "Forbidden")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.AUTH_REQUIRED
    
    def test_classify_endpoint_status_not_found(self):
        """Test classification of not found endpoints"""
        response = self.create_mock_response(404, "Not Found")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.NOT_FOUND
    
    def test_classify_endpoint_status_rate_limited(self):
        """Test classification of rate limited endpoints"""
        response = self.create_mock_response(429, "Rate limit exceeded")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.RATE_LIMITED
        
        # Test rate limit detection in response text
        response = self.create_mock_response(200, "Rate limit exceeded")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.RATE_LIMITED
    
    def test_classify_endpoint_status_redirect(self):
        """Test classification of redirect endpoints"""
        response = self.create_mock_response(301, "Moved Permanently")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.REDIRECT
        
        response = self.create_mock_response(302, "Found")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.REDIRECT
    
    def test_classify_endpoint_status_server_error(self):
        """Test classification of server error endpoints"""
        response = self.create_mock_response(500, "Internal Server Error")
        status = self.analyzer.classify_endpoint_status(response)
        assert status == EndpointStatus.SERVER_ERROR
    
    def test_detect_sensitive_data_api_key(self):
        """Test detection of API key in response"""
        response_text = '{"api_key": "sk_test_1234567890abcdef", "user": "test"}'
        response = self.create_mock_response(200, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect API key exposure
        api_key_findings = [f for f in findings if f.category == "SENSITIVE_DATA_EXPOSURE"]
        assert len(api_key_findings) > 0
        assert "api_key" in api_key_findings[0].evidence.lower()
        assert api_key_findings[0].severity == Severity.HIGH.value
    
    def test_detect_sensitive_data_jwt_token(self):
        """Test detection of JWT token in response"""
        response_text = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
        response = self.create_mock_response(200, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect JWT token exposure
        jwt_findings = [f for f in findings if f.category == "SENSITIVE_DATA_EXPOSURE"]
        assert len(jwt_findings) > 0
    
    def test_detect_sensitive_data_password(self):
        """Test detection of password in response"""
        response_text = '{"username": "admin", "password": "secret123", "role": "admin"}'
        response = self.create_mock_response(200, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect password exposure
        password_findings = [f for f in findings if f.category == "SENSITIVE_DATA_EXPOSURE"]
        assert len(password_findings) > 0
        assert "password" in password_findings[0].evidence.lower()
    
    def test_detect_error_messages_sql_error(self):
        """Test detection of SQL error messages"""
        response_text = 'MySQL Error: You have an error in your SQL syntax near "SELECT * FROM users"'
        response = self.create_mock_response(500, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect SQL error disclosure
        error_findings = [f for f in findings if f.category == "ERROR_MESSAGE_DISCLOSURE"]
        assert len(error_findings) > 0
        assert error_findings[0].severity == Severity.MEDIUM.value
    
    def test_detect_stack_trace_java(self):
        """Test detection of Java stack trace"""
        response_text = '''
        Exception in thread "main" java.lang.NullPointerException
        at com.example.MyClass.method(MyClass.java:42)
        at com.example.Main.main(Main.java:10)
        '''
        response = self.create_mock_response(500, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect stack trace disclosure
        stack_findings = [f for f in findings if f.category == "STACK_TRACE_DISCLOSURE"]
        assert len(stack_findings) > 0
        assert stack_findings[0].severity == Severity.MEDIUM.value
    
    def test_detect_stack_trace_python(self):
        """Test detection of Python stack trace"""
        response_text = '''
        Traceback (most recent call last):
        File "/app/main.py", line 25, in process_request
        File "/app/utils.py", line 10, in validate_input
        ValueError: Invalid input provided
        '''
        response = self.create_mock_response(500, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect stack trace disclosure
        stack_findings = [f for f in findings if f.category == "STACK_TRACE_DISCLOSURE"]
        assert len(stack_findings) > 0
    
    def test_analyze_security_headers_missing(self):
        """Test detection of missing security headers"""
        headers = {"Content-Type": "application/json"}
        response = self.create_mock_response(200, '{"data": "test"}', headers)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect missing security headers
        header_findings = [f for f in findings if f.category == "MISSING_SECURITY_HEADERS"]
        assert len(header_findings) > 0
        assert header_findings[0].severity == Severity.LOW.value
    
    def test_analyze_security_headers_insecure_frame_options(self):
        """Test detection of insecure X-Frame-Options"""
        headers = {
            "Content-Type": "application/json",
            "X-Frame-Options": "ALLOWALL"
        }
        response = self.create_mock_response(200, '{"data": "test"}', headers)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect insecure frame options
        insecure_findings = [f for f in findings if f.category == "INSECURE_SECURITY_HEADER"]
        assert len(insecure_findings) > 0
        assert insecure_findings[0].severity == Severity.MEDIUM.value
    
    def test_detect_information_disclosure_server_version(self):
        """Test detection of server version disclosure"""
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Content-Type": "text/html"
        }
        response = self.create_mock_response(200, "<html>Test</html>", headers)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect server version disclosure
        info_findings = [f for f in findings if f.category == "INFORMATION_DISCLOSURE"]
        assert len(info_findings) > 0
        assert "Apache/2.4.41" in info_findings[0].evidence
    
    def test_detect_information_disclosure_technology(self):
        """Test detection of technology disclosure"""
        headers = {
            "X-Powered-By": "PHP/7.4.3",
            "Content-Type": "text/html"
        }
        response = self.create_mock_response(200, "<html>Test</html>", headers)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect technology disclosure
        tech_findings = [f for f in findings if f.category == "INFORMATION_DISCLOSURE"]
        assert len(tech_findings) > 0
        assert "PHP/7.4.3" in tech_findings[0].evidence
    
    def test_detect_directory_listing(self):
        """Test detection of directory listing"""
        response_text = '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>'
        response = self.create_mock_response(200, response_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect directory listing
        dir_findings = [f for f in findings if f.category == "DIRECTORY_LISTING"]
        assert len(dir_findings) > 0
        assert dir_findings[0].severity == Severity.MEDIUM.value
    
    def test_analyze_response_size_large(self):
        """Test detection of unusually large responses"""
        # Create a large response (>10MB)
        large_text = "x" * (11 * 1024 * 1024)  # 11MB
        response = self.create_mock_response(200, large_text)
        
        findings = self.analyzer.analyze_response(response, self.context)
        
        # Should detect large response
        size_findings = [f for f in findings if f.category == "LARGE_RESPONSE"]
        assert len(size_findings) > 0
        assert size_findings[0].severity == Severity.LOW.value
    
    def test_detect_security_issues_cors_wildcard(self):
        """Test detection of dangerous CORS policy"""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        response = self.create_mock_response(200, '{"data": "test"}', headers)
        
        security_findings = self.analyzer.detect_security_issues(response)
        
        # Should detect dangerous CORS policy
        cors_findings = [f for f in security_findings if f.finding_type == "DANGEROUS_CORS_POLICY"]
        assert len(cors_findings) > 0
        assert cors_findings[0].severity == Severity.HIGH
    
    def test_detect_security_issues_permissive_cors(self):
        """Test detection of permissive CORS policy"""
        headers = {
            "Access-Control-Allow-Origin": "*"
        }
        response = self.create_mock_response(200, '{"data": "test"}', headers)
        
        security_findings = self.analyzer.detect_security_issues(response)
        
        # Should detect permissive CORS policy
        cors_findings = [f for f in security_findings if f.finding_type == "PERMISSIVE_CORS_POLICY"]
        assert len(cors_findings) > 0
        assert cors_findings[0].severity == Severity.MEDIUM
    
    def test_detect_security_issues_xss_vector(self):
        """Test detection of potential XSS vector"""
        headers = {"Content-Type": "text/html"}
        response_text = '<html><script>alert("xss")</script></html>'
        response = self.create_mock_response(200, response_text, headers)
        
        security_findings = self.analyzer.detect_security_issues(response)
        
        # Should detect potential XSS vector
        xss_findings = [f for f in security_findings if f.finding_type == "POTENTIAL_XSS_VECTOR"]
        assert len(xss_findings) > 0
        assert xss_findings[0].severity == Severity.MEDIUM
    
    def test_detect_security_issues_sql_injection(self):
        """Test detection of SQL injection indicators"""
        response_text = 'MySQL Error: You have an error in your SQL syntax'
        response = self.create_mock_response(500, response_text)
        
        security_findings = self.analyzer.detect_security_issues(response)
        
        # Should detect SQL injection indicator
        sql_findings = [f for f in security_findings if f.finding_type == "SQL_INJECTION_INDICATOR"]
        assert len(sql_findings) > 0
        assert sql_findings[0].severity == Severity.HIGH
    
    def test_analyze_timing_patterns_basic(self):
        """Test basic timing pattern analysis"""
        # Create mock responses with timing data
        responses = []
        for i in range(5):
            response = Mock()
            response.response_time = 0.1 + (i * 0.05)  # 0.1, 0.15, 0.2, 0.25, 0.3
            responses.append(response)
        
        timing_analysis = self.analyzer.analyze_timing_patterns(responses)
        
        assert timing_analysis.average_response_time == 0.2
        assert timing_analysis.min_response_time == 0.1
        assert abs(timing_analysis.max_response_time - 0.3) < 0.001  # Account for floating point precision
        assert timing_analysis.response_time_variance > 0
    
    def test_analyze_timing_patterns_anomalies(self):
        """Test timing anomaly detection"""
        # Create responses with one anomalously slow response
        responses = []
        for i in range(4):
            response = Mock()
            response.response_time = 0.1  # Fast responses
            responses.append(response)
        
        # Add one slow response
        slow_response = Mock()
        slow_response.response_time = 5.0  # Very slow
        responses.append(slow_response)
        
        timing_analysis = self.analyzer.analyze_timing_patterns(responses)
        
        # Should detect timing anomaly
        assert len(timing_analysis.timing_anomalies) > 0
        assert "significantly slower" in timing_analysis.timing_anomalies[0]
    
    def test_analyze_timing_patterns_potential_attack(self):
        """Test detection of potential timing attack patterns"""
        # Create bimodal distribution (fast and slow responses)
        responses = []
        
        # Fast responses
        for i in range(10):
            response = Mock()
            response.response_time = 0.1
            responses.append(response)
        
        # Slow responses
        for i in range(10):
            response = Mock()
            response.response_time = 2.0
            responses.append(response)
        
        timing_analysis = self.analyzer.analyze_timing_patterns(responses)
        
        # Should detect potential timing attack pattern
        assert len(timing_analysis.potential_timing_attacks) > 0
        assert "timing attack pattern" in timing_analysis.potential_timing_attacks[0]
    
    def test_analyze_timing_patterns_empty_list(self):
        """Test timing analysis with empty response list"""
        timing_analysis = self.analyzer.analyze_timing_patterns([])
        
        assert timing_analysis.average_response_time == 0.0
        assert timing_analysis.min_response_time == 0.0
        assert timing_analysis.max_response_time == 0.0
        assert len(timing_analysis.timing_anomalies) == 0
    
    def test_get_response_text_various_formats(self):
        """Test response text extraction from various response formats"""
        # Test with text attribute
        response1 = Mock()
        response1.text = "test response"
        text1 = self.analyzer._get_response_text(response1)
        assert text1 == "test response"
        
        # Test with content attribute
        response2 = Mock()
        del response2.text  # Remove text attribute
        response2.content = b"test response"
        text2 = self.analyzer._get_response_text(response2)
        assert text2 == "test response"
        
        # Test with string conversion fallback
        response3 = "string response"
        text3 = self.analyzer._get_response_text(response3)
        assert text3 == "string response"
    
    def test_custom_analysis_rules(self):
        """Test analyzer with custom analysis rules"""
        import re
        
        custom_rules = AnalysisRules()
        custom_rules.sensitive_data_patterns = {
            'custom_secret': re.compile(r'secret_key:\s*([a-zA-Z0-9]+)', re.IGNORECASE)
        }
        
        analyzer = ResponseAnalyzer(custom_rules)
        
        response_text = 'Configuration: secret_key: abc123def456'
        response = self.create_mock_response(200, response_text)
        
        findings = analyzer.analyze_response(response, self.context)
        
        # Should detect custom secret pattern
        secret_findings = [f for f in findings if f.category == "SENSITIVE_DATA_EXPOSURE"]
        assert len(secret_findings) > 0
        assert "custom_secret" in secret_findings[0].evidence


if __name__ == "__main__":
    pytest.main([__file__])