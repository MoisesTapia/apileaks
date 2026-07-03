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
        """Test severity classification for sensitive data exposure (Req 12.2).

        Severity is driven by the TYPE of exposed data and the PRIVILEGE LEVEL of
        the requesting context (corrected behavior):
          - credentials/api_key/financial -> CRITICAL regardless of privilege
          - personal_data -> privilege<=0 HIGH, ==1 MEDIUM, >=2 LOW
        """
        anon_context = self.auth_contexts[0]   # privilege_level 0
        user_context = self.auth_contexts[1]   # privilege_level 1
        admin_context = self.auth_contexts[2]  # privilege_level 3
        
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
        
        personal_field = SensitiveField(
            field_name="ssn",
            field_value="123-45-6789",
            field_path="profile.ssn",
            endpoint="/api/user",
            sensitivity_type="personal_data",
            context="response_body"
        )
        
        # Personal data exposed to an anonymous (privilege<=0) context is HIGH.
        severity = self.module._classify_sensitive_data_severity(personal_field, anon_context)
        assert severity == Severity.HIGH
        
        # Personal data exposed to a regular user (privilege==1) is MEDIUM.
        severity = self.module._classify_sensitive_data_severity(personal_field, user_context)
        assert severity == Severity.MEDIUM
        
        # Personal data seen by a high-privilege/admin context (privilege>=2) is LOW.
        severity = self.module._classify_sensitive_data_severity(personal_field, admin_context)
        assert severity == Severity.LOW
    
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
        """Test end-to-end mass assignment detection.

        Corrected behavior (Requirements 10.1-10.3): success is determined by
        Persistence_Verification - the exact injected field/value must be
        reflected in the write response body OR in a safe GET re-read of the
        object, independent of response size/time deltas. This models a
        genuinely vulnerable endpoint whose write echoes (persists) whatever
        payload is submitted, so every injected field is confirmed to persist.
        """
        endpoint_url = "https://api.example.com/user/123"

        async def _mock_request(method, url, **kwargs):
            # Baseline / re-read GETs return the current object state.
            data = {"id": 123, "name": "Test User", "role": "user"}
            if method.upper() not in ("GET", "HEAD", "OPTIONS"):
                # Vulnerable write endpoint: reflect (persist) the injected payload.
                payload = kwargs.get("json") or {}
                data.update(payload)
            return Response(
                status_code=200,
                headers={"content-type": "application/json"},
                content=json.dumps(data).encode(),
                text=json.dumps(data),
                url=url,
                elapsed=0.5,
                request_method=method,
            )

        self.mock_http_client.request = AsyncMock(side_effect=_mock_request)

        # Create test endpoints
        mock_endpoint = Mock()
        mock_endpoint.url = endpoint_url
        endpoints = [mock_endpoint]
        
        # Execute test
        findings = await self.module._test_mass_assignment(endpoints)
        
        # Verify findings - the vulnerable endpoint persists injected fields,
        # so persistence-verified mass assignment findings are reported.
        assert len(findings) > 0
        
        # Check that mass assignment was detected
        mass_assignment_findings = [f for f in findings if f.category == "MASS_ASSIGNMENT"]
        assert len(mass_assignment_findings) > 0
        
        # Verify findings have correct properties
        for finding in mass_assignment_findings:
            assert finding.owasp_category == "API3"
            assert finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_is_mass_assignment_successful(self):
        """Test detection of successful mass assignment via persistence evidence (Req 10.1).

        Corrected behavior: the method is async with signature
        (test_response, endpoint, field_name, test_value) and returns a
        persistence-evidence STRING on success (injected value reflected in the
        write response OR in a safe GET re-read), otherwise None. Response
        size/time deltas are NOT success signals.
        """
        endpoint = "https://api.example.com/user/123"
        
        # Case 1: injected field/value reflected directly in the write response
        # body -> success, returns an evidence string.
        test_data = {"id": 123, "name": "Test User", "role": "user", "is_admin": True}
        test_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(test_data).encode(),
            text=json.dumps(test_data),
            url=endpoint,
            elapsed=0.6,
            request_method="POST"
        )
        
        result = await self.module._is_mass_assignment_successful(
            test_response, endpoint, "is_admin", True
        )
        assert isinstance(result, str)
        assert "is_admin" in result
        
        # Case 2: write response does NOT reflect the value AND a safe GET
        # re-read also does not reflect it -> unsuccessful (None). A large
        # response body (size delta) without reflection is still unsuccessful.
        big_data = {"id": 123, "name": "Test User", "role": "user",
                    "padding": "x" * 5000}
        test_response_2 = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(big_data).encode(),
            text=json.dumps(big_data),
            url=endpoint,
            elapsed=2.5,  # large time delta, must NOT count as success
            request_method="POST"
        )
        reread_no_reflect = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps({"id": 123, "role": "user"}).encode(),
            text=json.dumps({"id": 123, "role": "user"}),
            url=endpoint,
            elapsed=0.4,
            request_method="GET"
        )
        self.mock_http_client.request.return_value = reread_no_reflect
        
        result = await self.module._is_mass_assignment_successful(
            test_response_2, endpoint, "is_admin", True
        )
        assert result is None
        
        # Case 3: write response does NOT reflect the value, but a safe GET
        # re-read confirms the injected value persisted -> success (string).
        reread_reflect = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps({"id": 123, "role": "user", "is_admin": True}).encode(),
            text=json.dumps({"id": 123, "role": "user", "is_admin": True}),
            url=endpoint,
            elapsed=0.4,
            request_method="GET"
        )
        self.mock_http_client.request.return_value = reread_reflect
        
        result = await self.module._is_mass_assignment_successful(
            test_response_2, endpoint, "is_admin", True
        )
        assert isinstance(result, str)
        assert "is_admin" in result
        
        # Case 4: write request failed (non-2xx) -> unsuccessful (None), no
        # re-read attempted.
        failed_response = Response(
            status_code=400,
            headers={"content-type": "application/json"},
            content=b'{"error": "Bad request"}',
            text='{"error": "Bad request"}',
            url=endpoint,
            elapsed=0.3,
            request_method="POST"
        )
        
        result = await self.module._is_mass_assignment_successful(
            failed_response, endpoint, "is_admin", True
        )
        assert result is None

    def test_contains_sensitive_data_requires_corroboration(self):
        """Sufficient patterns/prefixes flag; generic long strings need corroboration (Req 12.2).

        A specific pattern (SSN/credit-card/email/sk_ key) or a known credential
        prefix is self-sufficient evidence. A plain, low-entropy 32+ char string
        is NOT sensitive on its own; it only flags when corroborated by a
        sensitive field name or high Shannon entropy.
        """
        # Self-sufficient patterns / prefixes.
        assert self.module._contains_sensitive_data("123-45-6789") is True          # SSN
        assert self.module._contains_sensitive_data("4111-1111-1111-1111") is True  # credit card
        assert self.module._contains_sensitive_data("user@example.com") is True     # email
        assert self.module._contains_sensitive_data(
            "sk_test_1234567890abcdef1234567890abcdef") is True                      # sk_ key
        assert self.module._contains_sensitive_data(
            "AKIAIOSFODNN7EXAMPLE") is True                                          # AWS access key prefix

        # A plain long low-entropy string (matches [A-Za-z0-9]{32,} shape) is NOT
        # flagged on its own without corroboration.
        low_entropy_blob = "a" * 40
        assert self.module._shannon_entropy(low_entropy_blob) < \
            self.module.CREDENTIAL_ENTROPY_THRESHOLD
        assert self.module._contains_sensitive_data(low_entropy_blob) is False

        # Corroboration 1: a sensitive field name flags the same blob.
        assert self.module._contains_sensitive_data(
            low_entropy_blob, field_name="password") is True

        # Corroboration 2: a high-entropy 32+ char blob flags on its own.
        high_entropy_blob = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ1234"
        assert self.module._shannon_entropy(high_entropy_blob) >= \
            self.module.CREDENTIAL_ENTROPY_THRESHOLD
        assert self.module._contains_sensitive_data(high_entropy_blob) is True

    @pytest.mark.asyncio
    async def test_personal_data_not_reported_to_authorized_context(self):
        """Personal data exposed only to an authorized context is not a finding (Req 12.3).

        Exposed to a high-privilege (admin) context that is authorized to view
        it -> NO SENSITIVE_DATA_EXPOSURE finding for the personal_data field.
        Exposed to an unauthorized (anonymous) context -> finding IS produced.
        """
        response_data = {"user_id": 5, "ssn": "123-45-6789"}
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(response_data).encode(),
            text=json.dumps(response_data),
            url="https://api.example.com/user/5",
            elapsed=0.4,
            request_method="GET"
        )

        mock_endpoint = Mock()
        mock_endpoint.url = "https://api.example.com/user/5"
        mock_endpoint.method = "GET"
        endpoints = [mock_endpoint]

        # Authorized context: admin (privilege_level >= 2) -> no personal_data finding.
        admin_only = [AuthContext(name="admin", type=AuthType.BEARER,
                                  token="admin_tok", privilege_level=3)]
        admin_module = PropertyLevelAuthModule(self.config, self.mock_http_client, admin_only)
        self.mock_http_client.request = AsyncMock(return_value=mock_response)
        admin_module.http_client = self.mock_http_client

        findings = await admin_module._test_sensitive_data_exposure(endpoints)
        personal_findings = [
            f for f in findings if "personal_data" in (f.evidence or "")
        ]
        assert len(personal_findings) == 0

        # Unauthorized context: anonymous (privilege_level 0) -> finding produced.
        anon_only = [AuthContext(name="anonymous", type=AuthType.BEARER,
                                 token="", privilege_level=0)]
        anon_module = PropertyLevelAuthModule(self.config, self.mock_http_client, anon_only)
        self.mock_http_client.request = AsyncMock(return_value=mock_response)
        anon_module.http_client = self.mock_http_client

        findings = await anon_module._test_sensitive_data_exposure(endpoints)
        personal_findings = [
            f for f in findings if "personal_data" in (f.evidence or "")
        ]
        assert len(personal_findings) > 0

    @pytest.mark.asyncio
    async def test_undocumented_fields_gated_on_context_count(self):
        """Undocumented-field comparison is gated on >= 2 supplied contexts (Req 13.2).

        With 0 or 1 supplied auth contexts the comparison is skipped and returns
        an empty list without issuing any requests. With 2 contexts the
        comparison runs (requests are issued).
        """
        mock_endpoint = Mock()
        mock_endpoint.url = "https://api.example.com/user/1"
        mock_endpoint.method = "GET"
        endpoints = [mock_endpoint]

        success_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps({"id": 1, "name": "x"}).encode(),
            text=json.dumps({"id": 1, "name": "x"}),
            url="https://api.example.com/user/1",
            elapsed=0.3,
            request_method="GET"
        )

        # 0 contexts -> skipped, empty, no requests.
        client0 = Mock()
        client0.set_auth_context = Mock()
        client0.request = AsyncMock(return_value=success_response)
        module0 = PropertyLevelAuthModule(self.config, client0, [])
        findings = await module0._test_undocumented_fields(endpoints)
        assert findings == []
        client0.request.assert_not_called()

        # 1 context -> skipped, empty, no requests.
        client1 = Mock()
        client1.set_auth_context = Mock()
        client1.request = AsyncMock(return_value=success_response)
        module1 = PropertyLevelAuthModule(
            self.config, client1,
            [AuthContext(name="user", type=AuthType.BEARER, token="t", privilege_level=1)]
        )
        findings = await module1._test_undocumented_fields(endpoints)
        assert findings == []
        client1.request.assert_not_called()

        # 2 contexts -> comparison runs (requests are issued).
        client2 = Mock()
        client2.set_auth_context = Mock()
        client2.request = AsyncMock(return_value=success_response)
        module2 = PropertyLevelAuthModule(
            self.config, client2,
            [
                AuthContext(name="user", type=AuthType.BEARER, token="t1", privilege_level=1),
                AuthContext(name="admin", type=AuthType.BEARER, token="t2", privilege_level=3),
            ]
        )
        findings = await module2._test_undocumented_fields(endpoints)
        assert isinstance(findings, list)
        assert client2.request.call_count > 0
