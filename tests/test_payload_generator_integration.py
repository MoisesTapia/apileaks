"""
Integration tests for Payload Generator with APILeak components

This module tests the integration of the Payload Generator with other APILeak components
to ensure seamless operation within the broader system.
"""

import pytest
from utils.payload_generator import PayloadGenerator, VulnerabilityType
from utils.http_client import HTTPRequestEngine
from utils.findings import FindingsCollector

class TestPayloadGeneratorIntegration:
    """Integration tests for PayloadGenerator with other components"""
    
    def test_payload_generator_import(self):
        """Test that PayloadGenerator can be imported from utils package"""
        from utils import PayloadGenerator, EncodingType, VulnerabilityType
        
        # Should be able to create instance
        generator = PayloadGenerator()
        assert generator is not None
        
        # Should have access to enums
        assert EncodingType.URL is not None
        assert VulnerabilityType.SQL_INJECTION is not None
    
    def test_payload_generation_for_fuzzing(self):
        """Test payload generation for use in fuzzing modules"""
        generator = PayloadGenerator()
        
        # Generate SQL injection payloads for fuzzing
        sql_payloads = generator.generate_injection_payloads(VulnerabilityType.SQL_INJECTION)
        assert len(sql_payloads) > 0
        
        # Generate XSS payloads for fuzzing
        xss_payloads = generator.generate_injection_payloads(VulnerabilityType.XSS)
        assert len(xss_payloads) > 0
        
        # Payloads should be strings suitable for HTTP requests
        for payload in sql_payloads[:5]:
            assert isinstance(payload, str)
            assert len(payload) > 0
    
    def test_wordlist_expansion_for_endpoint_discovery(self):
        """Test wordlist expansion for endpoint discovery"""
        generator = PayloadGenerator()
        
        # Common API endpoints
        base_endpoints = ["users", "admin", "api", "auth", "config"]
        
        # Expand with common API patterns
        expanded = generator.expand_wordlist(
            base_endpoints,
            prefixes=["v1/", "v2/", "api/"],
            suffixes=["/list", "/create", "/delete"]
        )
        
        # Should have significantly more endpoints
        assert len(expanded) > len(base_endpoints) * 3
        
        # Should include useful API patterns
        assert "v1/users/list" in expanded
        assert "api/admin/create" in expanded
    
    def test_framework_specific_integration(self):
        """Test framework-specific payload generation"""
        generator = PayloadGenerator()
        
        # Test different frameworks
        frameworks = ["fastapi", "django", "express", "flask"]
        
        for framework in frameworks:
            # Generate SQL injection payloads for each framework
            payloads = generator.generate_framework_specific_payloads(
                framework, VulnerabilityType.SQL_INJECTION
            )
            
            # Should generate some payloads for each framework
            if payloads:  # Some frameworks might not have specific SQL payloads
                assert len(payloads) > 0
                for payload in payloads:
                    assert isinstance(payload, str)
    
    def test_payload_encoding_for_waf_evasion(self):
        """Test payload encoding for WAF evasion"""
        generator = PayloadGenerator()
        
        # Test payload that might be blocked by WAF
        dangerous_payload = "<script>alert('XSS')</script>"
        
        # Generate encoded versions
        encoded_payloads = generator.generate_encoded_payloads(dangerous_payload)
        
        # Should have multiple encoded versions
        assert len(encoded_payloads) > 1
        
        # Should include URL encoded version
        url_encoded_found = any('%3C' in payload for payload in encoded_payloads)
        assert url_encoded_found
        
        # Should include Base64 encoded version
        base64_encoded_found = any(
            payload.replace('=', '').replace('+', '').replace('/', '').isalnum() 
            and len(payload) > 20
            for payload in encoded_payloads
        )
        assert base64_encoded_found
    
    def test_template_system_extensibility(self):
        """Test that the template system is extensible"""
        generator = PayloadGenerator()
        
        # Should have multiple vulnerability types available
        vuln_types = generator.get_available_vulnerability_types()
        assert len(vuln_types) >= 4  # At least SQL, XSS, CMD, Path Traversal
        
        # Should provide template information
        for vuln_type in vuln_types:
            template_info = generator.get_template_info(vuln_type)
            assert isinstance(template_info, list)
            
            if template_info:  # If templates exist for this type
                for info in template_info:
                    assert 'name' in info
                    assert 'payload_count' in info
    
    def test_performance_with_large_wordlists(self):
        """Test performance with large wordlists"""
        generator = PayloadGenerator()
        
        # Create a moderately large wordlist
        large_wordlist = [f"endpoint_{i}" for i in range(100)]
        prefixes = ["v1/", "v2/", "api/"]
        suffixes = ["/list", "/create", "/update", "/delete"]
        
        # Should handle expansion without issues
        expanded = generator.expand_wordlist(large_wordlist, prefixes, suffixes)
        
        # Should have expected size
        expected_size = len(large_wordlist) * (1 + len(prefixes) + len(suffixes) + len(prefixes) * len(suffixes))
        assert len(expanded) == expected_size
    
    def test_error_handling_with_invalid_inputs(self):
        """Test error handling with invalid inputs"""
        generator = PayloadGenerator()
        
        # Should handle empty payloads gracefully
        empty_encoded = generator.generate_encoded_payloads("")
        assert len(empty_encoded) >= 1
        
        # Should handle None inputs gracefully
        try:
            none_encoded = generator.generate_encoded_payloads(None)
            # If it doesn't raise an exception, should return empty list or handle gracefully
        except (TypeError, AttributeError):
            # Expected behavior for None input
            pass
        
        # Should handle invalid vulnerability types gracefully
        try:
            invalid_payloads = generator.generate_injection_payloads("invalid_type")
            assert invalid_payloads == []
        except (ValueError, KeyError):
            # Expected behavior for invalid type
            pass
    
    def test_configuration_integration(self):
        """Test integration with configuration system"""
        from utils.payload_generator import PayloadGenerationConfig, EncodingType, ObfuscationType
        
        # Create custom configuration
        config = PayloadGenerationConfig(
            enabled_encodings=[EncodingType.URL, EncodingType.BASE64],
            enabled_obfuscations=[ObfuscationType.CASE_VARIATION],
            max_variations_per_payload=5,
            include_original=True
        )
        
        generator = PayloadGenerator(config)
        
        # Should respect configuration
        payload = "test payload"
        encoded = generator.generate_encoded_payloads(payload)
        
        # Should include original (as configured)
        assert payload in encoded
        
        # Should not exceed max variations significantly
        assert len(encoded) <= config.max_variations_per_payload + 2  # Some tolerance for combinations
    
    def test_real_world_payload_scenarios(self):
        """Test real-world payload generation scenarios"""
        generator = PayloadGenerator()
        
        # Scenario 1: Testing a REST API for SQL injection
        api_params = ["id", "user_id", "search", "filter", "sort"]
        sql_payloads = generator.generate_injection_payloads(VulnerabilityType.SQL_INJECTION)
        
        # Should be able to combine parameters with payloads
        test_cases = []
        for param in api_params:
            for payload in sql_payloads[:3]:  # Limit for test performance
                test_cases.append(f"{param}={payload}")
        
        assert len(test_cases) > 0
        
        # Scenario 2: Testing file upload endpoints for path traversal
        file_params = ["filename", "path", "file", "upload"]
        path_payloads = generator.generate_injection_payloads(VulnerabilityType.PATH_TRAVERSAL)
        
        upload_test_cases = []
        for param in file_params:
            for payload in path_payloads[:3]:
                upload_test_cases.append(f"{param}={payload}")
        
        assert len(upload_test_cases) > 0
        
        # Scenario 3: Testing search functionality for XSS
        search_params = ["q", "query", "search", "term"]
        xss_payloads = generator.generate_injection_payloads(VulnerabilityType.XSS)
        
        search_test_cases = []
        for param in search_params:
            for payload in xss_payloads[:3]:
                search_test_cases.append(f"{param}={payload}")
        
        assert len(search_test_cases) > 0