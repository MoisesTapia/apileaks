"""
Test suite for Property Level Authorization Testing Module
Tests detection of sensitive data exposure, mass assignment, and undocumented fields
"""

import pytest
import json
import uuid
from unittest.mock import AsyncMock, Mock
from datetime import datetime

from modules.owasp.property_level_auth import PropertyLevelAuthModule, SensitiveField
from core.config import PropertyTestingConfig, AuthContext, AuthType, Severity
from utils.http_client import Response
from utils.findings import Finding


class TestPropertyLevelAuthModule:
    """Test cases for Property Level Authorization Module"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Create test configuration
        self.config = PropertyTestingConfig(
            enabled=True,
            sensitive_fields=["password", "api_key", "secret"],
            mass_assignment_fields=["is_admin", "role", "user_id"]
        )
        
        # Create test auth contexts
        self.auth_contexts = [
            AuthContext(
                name="anonymous",
                type=AuthType.BEARER,
                token="",
                privilege_level=0
            ),
            AuthContext(
                name="user",
                type=AuthType.BEARER,
                token="user_token_123",
                privilege_level=1
            ),
            AuthContext(
                name="admin",
                type=AuthType.BEARER,
                token="admin_token_456",
                privilege_level=3
            )
        ]
        
        # Create mock HTTP client
        self.mock_http_client = Mock()
        self.mock_http_client.set_auth_context = Mock()
        self.mock_http_client.request = AsyncMock()
        
        # Initialize module
        self.module = PropertyLevelAuthModule(
            self.config, 
            self.mock_http_client, 
            self.auth_contexts
        )
    
    def test_module_initialization(self):
        """Test module initialization"""
        assert self.module.get_module_name() == "property_level_auth"
        assert len(self.module.auth_contexts) == 3
        assert "anonymous" in self.module.auth_context_map
        assert "user" in self.module.auth_context_map
        assert "admin" in self.module.auth_context_map
    
    def test_sensitive_field_detection_json(self):
        """Test detection of sensitive fields in JSON responses"""
        # Create mock response with sensitive data
        response_data = {
            "user_id": 123,
            "username": "testuser",
            "password": "secret123",
            "api_key": "sk_test_123456789",
            "email": "user@example.com",
            "profile": {
                "ssn": "123-45-6789",
                "credit_card": "4111-1111-1111-1111"
            }
        }
        
        response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(response_data).encode(),
            text=json.dumps(response_data),
            url="https://api.example.com/user/123",
            elapsed=0.5,
            request_method="GET"
        )
        
        # Test sensitive field detection
        sensitive_fields = self.module._detect_sensitive_fields(response, "https://api.example.com/user/123")
        
        # Should detect password, api_key, ssn, and credit_card
        assert len(sensitive_fields) >= 4
        
        field_names = [field.field_name for field in sensitive_fields]
        assert "password" in field_names
        assert "api_key" in field_names
        assert "ssn" in field_names
        assert "credit_card" in field_names
    
    def test_sensitive_field_classification(self):
        """Test classification of sensitive field types"""
        test_cases = [
            ("password", "password"),
            ("api_key", "api_key"),
            ("ssn", "personal_data"),
            ("credit_card", "financial"),
            ("internal_debug", "internal")
        ]
        
        for field_name, expected_type in test_cases:
            sensitivity_type = self.module._get_sensitivity_type(field_name)
            assert sensitivity_type == expected_type
    
    def test_mass_assignment_test_value_generation(self):
        """Test generation of test values for mass assignment"""
        test_cases = [
            ("is_admin", True),
            ("role", "admin"),
            ("permissions", ["admin", "write", "delete"]),
            ("user_id", 999999),
            ("balance", 1000000)
        ]
        
        for field_name, expected_type in test_cases:
            test_value = self.module._generate_test_value(field_name)
            assert type(test_value) == type(expected_type)
    
    def test_readonly_field_test_value_generation(self):
        """Test generation of test values for read-only fields"""
        test_cases = [
            ("id", 123),
            ("created_at", "2023-01-01T00:00:00Z"),
            ("version", 1)
        ]
        
        for field_name, original_value in test_cases:
            test_value = self.module._generate_readonly_test_value(field_name, original_value)
            assert test_value != original_value
    
    def test_sensitive_data_severity_classification(self):
        """Test severity classification for sensitive data exposure"""
        user_context = self.auth_contexts[1]  # Regular user
        admin_context = self.auth_contexts[2]  # Admin user
        
        # Test critical severity for passwords and API keys
        password_field = SensitiveField(
            field_name="password",
            field_value="secret123",
            field_path="password",
            endpoint="/api/user",
            sensitivity_type="password",
            context="response_body"
        )
        
        severity = self.module._classify_sensitive_data_severity(password_field, user_context)
        assert severity == Severity.CRITICAL
        
        # Test high severity for personal data exposed to low-privilege users
        personal_field = SensitiveField(
            field_name="ssn",
            field_value="123-45-6789",
            field_path="profile.ssn",
            endpoint="/api/user",
            sensitivity_type="personal_data",
            context="response_body"
        )
        
        severity = self.module._classify_sensitive_data_severity(personal_field, user_context)
        assert severity == Severity.HIGH
        
        # Same field should be medium for admin users
        severity = self.module._classify_sensitive_data_severity(personal_field, admin_context)
        assert severity == Severity.MEDIUM
    
    def test_mass_assignment_severity_classification(self):
        """Test severity classification for mass assignment vulnerabilities"""
        user_context = self.auth_contexts[1]
        
        # Test critical severity for admin privilege escalation
        severity = self.module._classify_mass_assignment_severity("is_admin", user_context)
        assert severity == Severity.CRITICAL
        
        severity = self.module._classify_mass_assignment_severity("role", user_context)
        assert severity == Severity.CRITICAL
        
        # Test high severity for user ID manipulation
        severity = self.module._classify_mass_assignment_severity("user_id", user_context)
        assert severity == Severity.HIGH
        
        # Test medium severity for status changes
        severity = self.module._classify_mass_assignment_severity("is_active", user_context)
        assert severity == Severity.MEDIUM
    
    def test_extract_fields_from_response(self):
        """Test extraction of fields from JSON response"""
        response_data = {
            "id": 123,
            "name": "Test User",
            "active": True,
            "nested": {
                "value": "test"
            }
        }
        
        response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(response_data).encode(),
            text=json.dumps(response_data),
            url="https://api.example.com/user",
            elapsed=0.5,
            request_method="GET"
        )
        
        fields = self.module._extract_fields_from_response(response)
        
        assert "id" in fields
        assert "name" in fields
        assert "active" in fields
        assert fields["id"] == 123
        assert fields["name"] == "Test User"
        assert fields["active"] is True
    
    def test_contains_sensitive_data_patterns(self):
        """Test detection of sensitive data patterns in values"""
        test_cases = [
            ("sk_test_1234567890abcdef1234567890abcdef", True),  # API key pattern
            ("123-45-6789", True),  # SSN pattern
            ("4111-1111-1111-1111", True),  # Credit card pattern
            ("user@example.com", True),  # Email pattern
            ("regular_text", False),  # Regular text
            ("123", False)  # Short text
        ]
        
        for value, expected in test_cases:
            result = self.module._contains_sensitive_data(value)
            assert result == expected, f"Failed for value: {value}"
    
    def test_is_potentially_undocumented_field_filtering(self):
        """Test filtering of potentially undocumented fields"""
        test_cases = [
            ("custom_field", True),  # Should be flagged
            ("business_data", True),  # Should be flagged
            ("id", False),  # Common field, should be filtered
            ("created_at", False),  # Common field, should be filtered
            ("timestamp", False),  # Common field, should be filtered
            ("status", False),  # Common field, should be filtered
        ]
        
        for field_name, expected in test_cases:
            result = self.module._is_potentially_undocumented(field_name)
            assert result == expected, f"Failed for field: {field_name}"
    
    @pytest.mark.asyncio
    async def test_sensitive_data_exposure_detection(self):
        """Test end-to-end sensitive data exposure detection"""
        # Setup mock response with sensitive data
        response_data = {
            "user_id": 123,
            "username": "testuser",
            "password": "secret123",  # Sensitive field
            "api_key": "sk_test_123456789"  # Sensitive field
        }
        
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(response_data).encode(),
            text=json.dumps(response_data),
            url="https://api.example.com/user/123",
            elapsed=0.5,
            request_method="GET"
        )
        
        # Configure mock HTTP client
        self.mock_http_client.request.return_value = mock_response
        
        # Create test endpoints
        mock_endpoint = Mock()
        mock_endpoint.url = "https://api.example.com/user/123"
        mock_endpoint.method = "GET"
        endpoints = [mock_endpoint]
        
        # Execute test
        findings = await self.module._test_sensitive_data_exposure(endpoints)
        
        # Verify findings
        assert len(findings) > 0
        
        # Check that sensitive fields were detected
        sensitive_categories = [f.category for f in findings]
        assert "SENSITIVE_DATA_EXPOSURE" in sensitive_categories
        
        # Verify findings have correct OWASP category
        for finding in findings:
            if finding.category == "SENSITIVE_DATA_EXPOSURE":
                assert finding.owasp_category == "API3"
                assert finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_mass_assignment_detection(self):
        """Test end-to-end mass assignment detection"""
        # Setup baseline response
        baseline_data = {"id": 123, "name": "Test User", "role": "user"}
        baseline_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(baseline_data).encode(),
            text=json.dumps(baseline_data),
            url="https://api.example.com/user/123",
            elapsed=0.5,
            request_method="GET"
        )
        
        # Setup test response (mass assignment successful)
        test_data = {"id": 123, "name": "Test User", "role": "admin", "is_admin": True}
        test_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(test_data).encode(),
            text=json.dumps(test_data),
            url="https://api.example.com/user/123",
            elapsed=0.6,
            request_method="POST"
        )
        
        # Configure mock HTTP client to return baseline first, then test response for each mass assignment test
        responses = [baseline_response]  # First call for baseline
        # Add test responses for each mass assignment field that will be tested
        for _ in self.module.mass_assignment_fields:
            responses.append(test_response)
        
        self.mock_http_client.request.side_effect = responses
        
        # Create test endpoints
        mock_endpoint = Mock()
        mock_endpoint.url = "https://api.example.com/user/123"
        endpoints = [mock_endpoint]
        
        # Execute test
        findings = await self.module._test_mass_assignment(endpoints)
        
        # Verify findings - should have at least one finding since is_admin appears in response
        assert len(findings) > 0
        
        # Check that mass assignment was detected
        mass_assignment_findings = [f for f in findings if f.category == "MASS_ASSIGNMENT"]
        assert len(mass_assignment_findings) > 0
        
        # Verify findings have correct properties
        for finding in mass_assignment_findings:
            assert finding.owasp_category == "API3"
            assert finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    
    def test_is_mass_assignment_successful(self):
        """Test detection of successful mass assignment"""
        # Create baseline response
        baseline_data = {"id": 123, "name": "Test User", "role": "user"}
        baseline_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(baseline_data).encode(),
            text=json.dumps(baseline_data),
            url="https://api.example.com/user/123",
            elapsed=0.5,
            request_method="GET"
        )
        
        # Test case 1: Response contains the test field
        test_data = {"id": 123, "name": "Test User", "role": "user", "is_admin": True}
        test_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(test_data).encode(),
            text=json.dumps(test_data),
            url="https://api.example.com/user/123",
            elapsed=0.6,
            request_method="POST"
        )
        
        result = self.module._is_mass_assignment_successful(
            baseline_response, test_response, "is_admin", True
        )
        assert result is True
        
        # Test case 2: Response doesn't contain test field (unsuccessful)
        test_data_2 = {"id": 123, "name": "Test User", "role": "user"}
        test_response_2 = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(test_data_2).encode(),
            text=json.dumps(test_data_2),
            url="https://api.example.com/user/123",
            elapsed=0.5,
            request_method="POST"
        )
        
        result = self.module._is_mass_assignment_successful(
            baseline_response, test_response_2, "is_admin", True
        )
        assert result is False
        
        # Test case 3: Request failed (unsuccessful)
        failed_response = Response(
            status_code=400,
            headers={"content-type": "application/json"},
            content=b'{"error": "Bad request"}',
            text='{"error": "Bad request"}',
            url="https://api.example.com/user/123",
            elapsed=0.3,
            request_method="POST"
        )
        
        result = self.module._is_mass_assignment_successful(
            baseline_response, failed_response, "is_admin", True
        )
        assert result is False