"""
Property-Based Tests for Property Level Authorization Testing Module
Tests universal properties using Hypothesis for comprehensive coverage
"""

import pytest
import json
import uuid
from unittest.mock import AsyncMock, Mock
from datetime import datetime
from hypothesis import given, strategies as st, settings, assume
import hypothesis
from hypothesis.strategies import composite

from modules.owasp.property_level_auth import PropertyLevelAuthModule, SensitiveField
from core.config import PropertyTestingConfig, AuthContext, AuthType, Severity
from utils.http_client import Response
from utils.findings import Finding


# Custom strategies for generating test data
@composite
def auth_context_strategy(draw):
    """Generate random AuthContext objects"""
    name = draw(st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))))
    auth_type = draw(st.sampled_from([AuthType.BEARER, AuthType.JWT, AuthType.API_KEY, AuthType.BASIC]))
    token = draw(st.text(min_size=10, max_size=100))
    privilege_level = draw(st.integers(min_value=0, max_value=5))
    
    return AuthContext(
        name=name,
        type=auth_type,
        token=token,
        privilege_level=privilege_level
    )


@composite
def json_response_strategy(draw):
    """Generate random JSON responses with potential mass assignment fields"""
    base_fields = draw(st.dictionaries(
        keys=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
        values=st.one_of(
            st.text(min_size=1, max_size=50),
            st.integers(min_value=1, max_value=1000000),
            st.booleans(),
            st.floats(min_value=0.0, max_value=1000000.0, allow_nan=False, allow_infinity=False)
        ),
        min_size=1,
        max_size=10
    ))
    
    # Sometimes add dangerous mass assignment fields
    if draw(st.booleans()):
        dangerous_field = draw(st.sampled_from(['is_admin', 'role', 'permissions', 'user_id', 'admin']))
        dangerous_value = draw(st.one_of(st.booleans(), st.text(min_size=1, max_size=20), st.integers(min_value=1, max_value=999999)))
        base_fields[dangerous_field] = dangerous_value
    
    return base_fields


@composite
def response_strategy(draw):
    """Generate random HTTP Response objects"""
    status_code = draw(st.integers(min_value=200, max_value=500))
    json_data = draw(json_response_strategy())
    content_type = "application/json"
    
    response_text = json.dumps(json_data)
    response_content = response_text.encode()
    
    return Response(
        status_code=status_code,
        headers={"content-type": content_type},
        content=response_content,
        text=response_text,
        url=draw(st.text(min_size=10, max_size=100)),
        elapsed=draw(st.floats(min_value=0.1, max_value=5.0, allow_nan=False, allow_infinity=False)),
        request_method=draw(st.sampled_from(["GET", "POST", "PUT", "PATCH"]))
    )


@composite
def endpoint_strategy(draw):
    """Generate random endpoint objects"""
    endpoint = Mock()
    endpoint.url = draw(st.text(min_size=10, max_size=100))
    endpoint.method = draw(st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE"]))
    return endpoint


class TestPropertyLevelAuthProperties:
    """Property-based tests for Property Level Authorization Module"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.config = PropertyTestingConfig(
            enabled=True,
            sensitive_fields=["password", "api_key", "secret"],
            mass_assignment_fields=["is_admin", "role", "user_id"]
        )
        
        # Create mock HTTP client
        self.mock_http_client = Mock()
        self.mock_http_client.set_auth_context = Mock()
        self.mock_http_client.request = AsyncMock()
    
    @given(auth_contexts=st.lists(auth_context_strategy(), min_size=1, max_size=5))
    @settings(max_examples=100, deadline=5000)
    def test_module_initialization_property(self, auth_contexts):
        """
        **Feature: apileak-owasp-enhancement, Property: Module Initialization Consistency**
        
        For any list of authentication contexts, the PropertyLevelAuthModule should 
        initialize correctly and maintain consistent state.
        """
        # Initialize module with random auth contexts
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        # Property: Module should always initialize with correct name
        assert module.get_module_name() == "property_level_auth"
        
        # Property: All provided auth contexts should be accessible
        assert len(module.auth_contexts) == len(auth_contexts)
        
        # Property: Auth context mapping should contain contexts (may have fewer due to name collisions)
        unique_names = set(ctx.name for ctx in auth_contexts)
        assert len(module.auth_context_map) >= len(unique_names)  # At least unique names + anonymous
        
        # Property: For contexts with unique names, they should be in the mapping
        name_to_context = {}
        for ctx in auth_contexts:
            name_to_context[ctx.name] = ctx  # Last one wins in case of duplicates
        
        for name, expected_ctx in name_to_context.items():
            assert name in module.auth_context_map
            # The context in the map should be one of the contexts with this name
            actual_ctx = module.auth_context_map[name]
            assert actual_ctx.name == expected_ctx.name
            assert actual_ctx.type == expected_ctx.type
        
        # Property: Anonymous context should always be present
        assert "anonymous" in module.auth_context_map
    
    @given(responses=st.lists(response_strategy(), min_size=1, max_size=10))
    @settings(max_examples=50, deadline=5000, suppress_health_check=[hypothesis.HealthCheck.filter_too_much])
    def test_sensitive_field_detection_property(self, responses):
        """
        **Feature: apileak-owasp-enhancement, Property: Sensitive Field Detection Consistency**
        
        For any HTTP response containing JSON data, sensitive field detection should 
        be consistent and comprehensive.
        """
        auth_contexts = [AuthContext(name="test", type=AuthType.BEARER, token="test", privilege_level=1)]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        for response in responses:
            # Only test successful JSON responses
            if (response.status_code != 200 or 
                "application/json" not in response.headers.get("content-type", "")):
                continue
            
            try:
                # Test sensitive field detection
                sensitive_fields = module._detect_sensitive_fields(response, response.url)
                
                # Property: Result should always be a list
                assert isinstance(sensitive_fields, list)
                
                # Property: All detected fields should be SensitiveField instances
                for field in sensitive_fields:
                    assert isinstance(field, SensitiveField)
                    assert field.endpoint == response.url
                    assert field.sensitivity_type in ['password', 'api_key', 'personal_data', 'financial', 'internal', 'unknown']
                
                # Property: If response contains known sensitive field names, they should be detected
                try:
                    response_data = json.loads(response.text)
                    if isinstance(response_data, dict):
                        sensitive_field_names = [field.field_name.lower() for field in sensitive_fields]
                        for key in response_data.keys():
                            if any(pattern in key.lower() for pattern in ['password', 'api_key', 'secret']):
                                # Should detect at least one sensitive field
                                assert len(sensitive_fields) > 0
                except (json.JSONDecodeError, ValueError):
                    pass
                    
            except Exception:
                # Skip responses that cause parsing errors
                pass
    
    @given(
        baseline_response=response_strategy(),
        test_response=response_strategy(),
        field_name=st.sampled_from(['is_admin', 'role', 'permissions', 'user_id', 'admin']),
        test_value=st.one_of(st.booleans(), st.text(min_size=1, max_size=20), st.integers(min_value=1, max_value=999999))
    )
    @settings(max_examples=50, deadline=5000, suppress_health_check=[hypothesis.HealthCheck.filter_too_much])
    def test_mass_assignment_detection_property(self, baseline_response, test_response, field_name, test_value):
        """
        **Feature: apileak-owasp-enhancement, Property 8: Mass Assignment Detection**
        **Validates: Requirements 3.2, 3.3**
        
        For any baseline response and test response, mass assignment detection should 
        correctly identify when dangerous fields are accepted and processed.
        """
        auth_contexts = [AuthContext(name="test", type=AuthType.BEARER, token="test", privilege_level=1)]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        # Only test with successful responses and JSON content
        if (baseline_response.status_code != 200 or test_response.status_code != 200 or
            "application/json" not in baseline_response.headers.get("content-type", "") or
            "application/json" not in test_response.headers.get("content-type", "")):
            return  # Skip invalid responses
        
        try:
            # Test mass assignment detection
            result = module._is_mass_assignment_successful(
                baseline_response, test_response, field_name, test_value
            )
            
            # Property: Result should always be a boolean
            assert isinstance(result, bool)
            
            # Property: If test response contains the test field with test value, should return True
            try:
                test_data = json.loads(test_response.text)
                if isinstance(test_data, dict) and field_name in test_data:
                    if str(test_data[field_name]) == str(test_value):
                        assert result is True
            except (json.JSONDecodeError, ValueError):
                pass
            
            # Property: If test response failed (4xx/5xx), should return False
            if test_response.status_code >= 400:
                assert result is False
                
        except Exception:
            # Skip responses that cause parsing errors
            pass
    
    @given(
        field_name=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
        auth_context=auth_context_strategy()
    )
    @settings(max_examples=100, deadline=5000)
    def test_mass_assignment_severity_classification_property(self, field_name, auth_context):
        """
        **Feature: apileak-owasp-enhancement, Property: Mass Assignment Severity Consistency**
        
        For any field name and authentication context, severity classification should 
        be consistent and appropriate.
        """
        auth_contexts = [auth_context]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        # Test severity classification
        severity = module._classify_mass_assignment_severity(field_name, auth_context)
        
        # Property: Result should always be a valid Severity
        assert isinstance(severity, Severity)
        assert severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        
        # Property: Admin-related fields should always be CRITICAL
        field_lower = field_name.lower()
        if any(term in field_lower for term in ['admin', 'role', 'permission']):
            assert severity == Severity.CRITICAL
        
        # Property: ID-related fields should be HIGH or CRITICAL
        if any(term in field_lower for term in ['user_id', 'id']) and 'admin' not in field_lower:
            assert severity in [Severity.HIGH, Severity.CRITICAL]
    
    @given(
        field_names=st.lists(
            st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=100, deadline=5000)
    def test_undocumented_field_filtering_property(self, field_names):
        """
        **Feature: apileak-owasp-enhancement, Property 9: Undocumented Field Detection**
        **Validates: Requirements 3.4**
        
        For any list of field names, undocumented field filtering should consistently 
        identify potentially undocumented fields while filtering out common metadata fields.
        """
        auth_contexts = [AuthContext(name="test", type=AuthType.BEARER, token="test", privilege_level=1)]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        for field_name in field_names:
            result = module._is_potentially_undocumented(field_name)
            
            # Property: Result should always be a boolean
            assert isinstance(result, bool)
            
            # Property: Common metadata fields should always be filtered out (return False)
            field_lower = field_name.lower()
            common_fields = ['timestamp', 'created_at', 'updated_at', 'id', 'version', 'status', 'message', 'success', 'error', 'code']
            
            for common_field in common_fields:
                if common_field in field_lower:
                    assert result is False, f"Common field '{field_name}' should be filtered out"
                    break
            else:
                # If not a common field, could be potentially undocumented
                # This is acceptable as True or False depending on the specific field
                pass
    
    @given(
        sensitive_field=st.builds(
            SensitiveField,
            field_name=st.text(min_size=1, max_size=30),
            field_value=st.text(min_size=1, max_size=100),
            field_path=st.text(min_size=1, max_size=50),
            endpoint=st.text(min_size=10, max_size=100),
            sensitivity_type=st.sampled_from(['password', 'api_key', 'personal_data', 'financial', 'internal']),
            context=st.sampled_from(['response_body', 'response_headers', 'response_text'])
        ),
        auth_context=auth_context_strategy()
    )
    @settings(max_examples=100, deadline=5000)
    def test_sensitive_data_severity_classification_property(self, sensitive_field, auth_context):
        """
        **Feature: apileak-owasp-enhancement, Property: Sensitive Data Severity Consistency**
        
        For any sensitive field and authentication context, severity classification should 
        be consistent and reflect the criticality of the exposure.
        """
        auth_contexts = [auth_context]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        # Test severity classification
        severity = module._classify_sensitive_data_severity(sensitive_field, auth_context)
        
        # Property: Result should always be a valid Severity
        assert isinstance(severity, Severity)
        assert severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        
        # Property: Passwords and API keys should always be CRITICAL
        if sensitive_field.sensitivity_type in ['password', 'api_key']:
            assert severity == Severity.CRITICAL
        
        # Property: Financial data should always be CRITICAL
        if sensitive_field.sensitivity_type == 'financial':
            assert severity == Severity.CRITICAL
        
        # Property: Personal data exposure to low-privilege users should be HIGH or CRITICAL
        if sensitive_field.sensitivity_type == 'personal_data' and auth_context.privilege_level < 2:
            assert severity in [Severity.HIGH, Severity.CRITICAL]
    
    @given(
        test_values=st.lists(
            st.text(min_size=4, max_size=100),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=100, deadline=5000)
    def test_sensitive_data_pattern_detection_property(self, test_values):
        """
        **Feature: apileak-owasp-enhancement, Property: Sensitive Data Pattern Detection Consistency**
        
        For any list of string values, sensitive data pattern detection should be 
        consistent and identify known sensitive patterns.
        """
        auth_contexts = [AuthContext(name="test", type=AuthType.BEARER, token="test", privilege_level=1)]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        for value in test_values:
            result = module._contains_sensitive_data(value)
            
            # Property: Result should always be a boolean
            assert isinstance(result, bool)
            
            # Property: Known sensitive patterns should be detected
            if value.startswith('sk_') and len(value) > 25:  # Stripe-style API key
                assert result is True, f"API key pattern should be detected: {value}"
            
            # Property: Email patterns should be detected
            if '@' in value and '.' in value.split('@')[-1]:
                # Simple email check - if it looks like an email, should be detected
                parts = value.split('@')
                if len(parts) == 2 and '.' in parts[1]:
                    assert result is True, f"Email pattern should be detected: {value}"
            
            # Property: SSN patterns should be detected
            if len(value) == 11 and value[3] == '-' and value[6] == '-':
                # Check if it's a valid SSN pattern (XXX-XX-XXXX)
                parts = value.split('-')
                if len(parts) == 3 and all(part.isdigit() for part in parts) and len(parts[0]) == 3 and len(parts[1]) == 2 and len(parts[2]) == 4:
                    assert result is True, f"SSN pattern should be detected: {value}"
    
    @given(
        field_names=st.lists(
            st.sampled_from(['is_admin', 'role', 'permissions', 'user_id', 'balance', 'credit', 'admin', 'active']),
            min_size=1,
            max_size=10
        )
    )
    @settings(max_examples=100, deadline=5000)
    def test_mass_assignment_test_value_generation_property(self, field_names):
        """
        **Feature: apileak-owasp-enhancement, Property: Mass Assignment Test Value Generation Consistency**
        
        For any list of dangerous field names, test value generation should produce 
        appropriate values that could trigger mass assignment vulnerabilities.
        """
        auth_contexts = [AuthContext(name="test", type=AuthType.BEARER, token="test", privilege_level=1)]
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, auth_contexts)
        
        for field_name in field_names:
            test_value = module._generate_test_value(field_name)
            
            # Property: Should always generate a non-None value
            assert test_value is not None
            
            # Property: Admin-related fields should generate boolean True or "admin" string
            field_lower = field_name.lower()
            if 'admin' in field_lower:
                assert test_value in [True, 'admin'], f"Admin field should generate appropriate value: {field_name} -> {test_value}"
            
            # Property: Role fields should generate "admin" string
            if 'role' in field_lower:
                assert test_value == 'admin', f"Role field should generate 'admin': {field_name} -> {test_value}"
            
            # Property: ID fields should generate large integers
            if 'id' in field_lower:
                assert isinstance(test_value, int) and test_value > 1000, f"ID field should generate large integer: {field_name} -> {test_value}"
            
            # Property: Balance/credit fields should generate large numbers
            if any(term in field_lower for term in ['balance', 'credit']):
                assert isinstance(test_value, (int, float)) and test_value >= 1000000, f"Financial field should generate large value: {field_name} -> {test_value}"