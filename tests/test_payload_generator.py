"""
Tests for the Payload Generator module

This module tests the comprehensive payload generation capabilities including:
- Encoding functionality (URL, Base64, HTML, Unicode)
- Obfuscation techniques (case variations, mutations)
- Injection payload generation
- Template system functionality
- Wordlist transformations

Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
"""

import pytest
import base64
import urllib.parse
import html
from pathlib import Path
from utils.payload_generator import (
    PayloadGenerator, PayloadGenerationConfig, PayloadTemplate,
    EncodingType, ObfuscationType, VulnerabilityType
)

class TestPayloadGenerator:
    """Test suite for PayloadGenerator class"""
    
    @pytest.fixture
    def payload_generator(self):
        """Create a PayloadGenerator instance for testing"""
        config = PayloadGenerationConfig(
            enabled_encodings=[EncodingType.URL, EncodingType.BASE64, EncodingType.HTML],
            enabled_obfuscations=[ObfuscationType.CASE_VARIATION, ObfuscationType.MUTATION],
            max_variations_per_payload=5,
            include_original=True
        )
        return PayloadGenerator(config)
    
    @pytest.fixture
    def sample_payload(self):
        """Sample payload for testing"""
        return "' OR '1'='1' --"
    
    def test_url_encoding(self, payload_generator, sample_payload):
        """Test URL encoding functionality"""
        encoded_payloads = payload_generator.generate_encoded_payloads(
            sample_payload, [EncodingType.URL]
        )
        
        # Should include original and URL encoded version
        assert len(encoded_payloads) >= 2
        assert sample_payload in encoded_payloads
        
        # Check URL encoded version exists
        url_encoded = urllib.parse.quote(sample_payload, safe='')
        assert url_encoded in encoded_payloads
    
    def test_base64_encoding(self, payload_generator, sample_payload):
        """Test Base64 encoding functionality"""
        encoded_payloads = payload_generator.generate_encoded_payloads(
            sample_payload, [EncodingType.BASE64]
        )
        
        # Should include original and Base64 encoded version
        assert len(encoded_payloads) >= 2
        assert sample_payload in encoded_payloads
        
        # Check Base64 encoded version exists
        b64_encoded = base64.b64encode(sample_payload.encode()).decode()
        assert b64_encoded in encoded_payloads
    
    def test_html_encoding(self, payload_generator, sample_payload):
        """Test HTML encoding functionality"""
        encoded_payloads = payload_generator.generate_encoded_payloads(
            sample_payload, [EncodingType.HTML]
        )
        
        # Should include original and HTML encoded version
        assert len(encoded_payloads) >= 2
        assert sample_payload in encoded_payloads
        
        # Check HTML encoded version exists
        html_encoded = html.escape(sample_payload)
        assert html_encoded in encoded_payloads
    
    def test_unicode_encoding(self, payload_generator, sample_payload):
        """Test Unicode encoding functionality"""
        encoded_payloads = payload_generator.generate_encoded_payloads(
            sample_payload, [EncodingType.UNICODE]
        )
        
        # Should include original and Unicode encoded version
        assert len(encoded_payloads) >= 2
        assert sample_payload in encoded_payloads
        
        # Check Unicode encoded version exists (should contain \u sequences)
        unicode_versions = [p for p in encoded_payloads if '\\u' in p]
        assert len(unicode_versions) > 0
    
    def test_multiple_encodings(self, payload_generator, sample_payload):
        """Test multiple encoding types applied to same payload"""
        encodings = [EncodingType.URL, EncodingType.BASE64, EncodingType.HTML]
        encoded_payloads = payload_generator.generate_encoded_payloads(
            sample_payload, encodings
        )
        
        # Should include original, individual encodings, and combinations
        assert len(encoded_payloads) >= 4  # original + 3 individual + combinations
        assert sample_payload in encoded_payloads
    
    def test_case_variation_obfuscation(self, payload_generator, sample_payload):
        """Test case variation obfuscation"""
        obfuscated = payload_generator.apply_obfuscation(
            sample_payload, [ObfuscationType.CASE_VARIATION]
        )
        
        # Should include original and case variations
        assert len(obfuscated) >= 2
        assert sample_payload in obfuscated
        
        # Check for uppercase and lowercase versions
        case_variations = [p for p in obfuscated if p != sample_payload]
        assert len(case_variations) > 0
        
        # At least one should be different case
        has_different_case = any(
            p.upper() == sample_payload.upper() and p != sample_payload
            for p in case_variations
        )
        assert has_different_case
    
    def test_mutation_obfuscation(self, payload_generator, sample_payload):
        """Test mutation obfuscation"""
        obfuscated = payload_generator.apply_obfuscation(
            sample_payload, [ObfuscationType.MUTATION]
        )
        
        # Should include original and mutations
        assert len(obfuscated) >= 1
        assert sample_payload in obfuscated
    
    def test_sql_injection_payloads(self, payload_generator):
        """Test SQL injection payload generation"""
        sql_payloads = payload_generator.generate_injection_payloads(
            VulnerabilityType.SQL_INJECTION
        )
        
        # Should generate multiple SQL injection payloads
        assert len(sql_payloads) > 0
        
        # Check for common SQL injection patterns
        sql_patterns = ["OR", "UNION", "SELECT", "--", "'"]
        has_sql_patterns = any(
            any(pattern in payload.upper() for pattern in sql_patterns)
            for payload in sql_payloads
        )
        assert has_sql_patterns
    
    def test_xss_payloads(self, payload_generator):
        """Test XSS payload generation"""
        xss_payloads = payload_generator.generate_injection_payloads(
            VulnerabilityType.XSS
        )
        
        # Should generate multiple XSS payloads
        assert len(xss_payloads) > 0
        
        # Check for common XSS patterns
        xss_patterns = ["<script>", "alert", "onerror", "onload"]
        has_xss_patterns = any(
            any(pattern in payload.lower() for pattern in xss_patterns)
            for payload in xss_payloads
        )
        assert has_xss_patterns
    
    def test_command_injection_payloads(self, payload_generator):
        """Test command injection payload generation"""
        cmd_payloads = payload_generator.generate_injection_payloads(
            VulnerabilityType.COMMAND_INJECTION
        )
        
        # Should generate multiple command injection payloads
        assert len(cmd_payloads) > 0
        
        # Check for common command injection patterns
        cmd_patterns = [";", "|", "&&", "`", "$(", "cat", "whoami"]
        has_cmd_patterns = any(
            any(pattern in payload for pattern in cmd_patterns)
            for payload in cmd_payloads
        )
        assert has_cmd_patterns
    
    def test_path_traversal_payloads(self, payload_generator):
        """Test path traversal payload generation"""
        path_payloads = payload_generator.generate_injection_payloads(
            VulnerabilityType.PATH_TRAVERSAL
        )
        
        # Should generate multiple path traversal payloads
        assert len(path_payloads) > 0
        
        # Check for common path traversal patterns
        path_patterns = ["../", "..\\", "etc/passwd", "%2e%2e"]
        has_path_patterns = any(
            any(pattern in payload for pattern in path_patterns)
            for payload in path_payloads
        )
        assert has_path_patterns
    
    def test_wordlist_expansion_with_prefixes(self, payload_generator):
        """Test wordlist expansion with prefixes"""
        wordlist = ["admin", "user", "test"]
        prefixes = ["api_", "v1_", "old_"]
        
        expanded = payload_generator.expand_wordlist(wordlist, prefixes=prefixes)
        
        # Should include original words and prefixed versions
        assert len(expanded) >= len(wordlist) + len(wordlist) * len(prefixes)
        
        # Check original words are included
        for word in wordlist:
            assert word in expanded
        
        # Check prefixed versions are included
        for word in wordlist:
            for prefix in prefixes:
                assert f"{prefix}{word}" in expanded
    
    def test_wordlist_expansion_with_suffixes(self, payload_generator):
        """Test wordlist expansion with suffixes"""
        wordlist = ["admin", "user", "test"]
        suffixes = ["_api", "_v1", "_old"]
        
        expanded = payload_generator.expand_wordlist(wordlist, suffixes=suffixes)
        
        # Should include original words and suffixed versions
        assert len(expanded) >= len(wordlist) + len(wordlist) * len(suffixes)
        
        # Check original words are included
        for word in wordlist:
            assert word in expanded
        
        # Check suffixed versions are included
        for word in wordlist:
            for suffix in suffixes:
                assert f"{word}{suffix}" in expanded
    
    def test_wordlist_expansion_with_prefixes_and_suffixes(self, payload_generator):
        """Test wordlist expansion with both prefixes and suffixes"""
        wordlist = ["admin", "user"]
        prefixes = ["api_", "v1_"]
        suffixes = ["_old", "_new"]
        
        expanded = payload_generator.expand_wordlist(
            wordlist, prefixes=prefixes, suffixes=suffixes
        )
        
        # Should include original, prefixed, suffixed, and combined versions
        expected_min = (
            len(wordlist) +  # original
            len(wordlist) * len(prefixes) +  # prefixed
            len(wordlist) * len(suffixes) +  # suffixed
            len(wordlist) * len(prefixes) * len(suffixes)  # combined
        )
        assert len(expanded) >= expected_min
        
        # Check combined versions exist
        for word in wordlist:
            for prefix in prefixes:
                for suffix in suffixes:
                    assert f"{prefix}{word}{suffix}" in expanded
    
    def test_framework_specific_payloads_fastapi(self, payload_generator):
        """Test FastAPI-specific payload generation"""
        fastapi_payloads = payload_generator.generate_framework_specific_payloads(
            "fastapi", VulnerabilityType.SQL_INJECTION
        )
        
        # Should generate payloads for FastAPI
        assert len(fastapi_payloads) > 0
    
    def test_framework_specific_payloads_django(self, payload_generator):
        """Test Django-specific payload generation"""
        django_payloads = payload_generator.generate_framework_specific_payloads(
            "django", VulnerabilityType.SSTI
        )
        
        # Should generate SSTI payloads for Django
        assert len(django_payloads) > 0
        
        # Check for Django-specific patterns
        django_patterns = ["settings", "SECRET_KEY", "request.META"]
        has_django_patterns = any(
            any(pattern in payload for pattern in django_patterns)
            for payload in django_payloads
        )
        assert has_django_patterns
    
    def test_get_available_vulnerability_types(self, payload_generator):
        """Test getting available vulnerability types"""
        vuln_types = payload_generator.get_available_vulnerability_types()
        
        # Should include common vulnerability types
        expected_types = [
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.PATH_TRAVERSAL
        ]
        
        for expected_type in expected_types:
            assert expected_type in vuln_types
    
    def test_get_template_info(self, payload_generator):
        """Test getting template information"""
        template_info = payload_generator.get_template_info(VulnerabilityType.SQL_INJECTION)
        
        # Should return template information
        assert len(template_info) > 0
        
        # Check template info structure
        for info in template_info:
            assert 'name' in info
            assert 'description' in info
            assert 'payload_count' in info
            assert 'encodings' in info
            assert 'obfuscations' in info
    
    def test_empty_payload_handling(self, payload_generator):
        """Test handling of empty payloads"""
        empty_payload = ""
        
        # Should handle empty payloads gracefully
        encoded = payload_generator.generate_encoded_payloads(empty_payload)
        assert len(encoded) >= 1  # At least the original empty string
        
        obfuscated = payload_generator.apply_obfuscation(empty_payload)
        assert len(obfuscated) >= 1  # At least the original empty string
    
    def test_special_characters_handling(self, payload_generator):
        """Test handling of special characters in payloads"""
        special_payload = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        
        # Should handle special characters without errors
        encoded = payload_generator.generate_encoded_payloads(special_payload)
        assert len(encoded) > 0
        
        obfuscated = payload_generator.apply_obfuscation(special_payload)
        assert len(obfuscated) > 0
    
    def test_unicode_characters_handling(self, payload_generator):
        """Test handling of Unicode characters in payloads"""
        unicode_payload = "测试数据 🚀 αβγ"
        
        # Should handle Unicode characters without errors
        encoded = payload_generator.generate_encoded_payloads(unicode_payload)
        assert len(encoded) > 0
        
        obfuscated = payload_generator.apply_obfuscation(unicode_payload)
        assert len(obfuscated) > 0
    
    def test_configuration_limits(self):
        """Test configuration limits are respected"""
        config = PayloadGenerationConfig(
            max_variations_per_payload=3,
            include_original=True
        )
        generator = PayloadGenerator(config)
        
        payload = "test payload"
        obfuscated = generator.apply_obfuscation(
            payload, [ObfuscationType.CASE_VARIATION]
        )
        
        # Should respect max variations limit
        assert len(obfuscated) <= config.max_variations_per_payload
    
    def test_no_original_in_results(self):
        """Test excluding original payload from results"""
        config = PayloadGenerationConfig(
            include_original=False,
            enabled_encodings=[EncodingType.URL]
        )
        generator = PayloadGenerator(config)
        
        payload = "test payload"
        encoded = generator.generate_encoded_payloads(payload)
        
        # Should not include original payload
        assert payload not in encoded
        
        # But should include encoded versions
        assert len(encoded) > 0


class TestPayloadGeneratorIntegration:
    """Integration tests for PayloadGenerator with real templates"""
    
    def test_custom_template_loading(self, tmp_path):
        """Test loading custom templates from YAML files"""
        # Create a custom template file
        template_dir = tmp_path / "custom_templates"
        template_dir.mkdir()
        
        custom_template = template_dir / "custom_sql.yaml"
        custom_template.write_text("""
name: "Custom SQL Injection"
vulnerability_type: "sql_injection"
description: "Custom SQL injection payloads"
base_payloads:
  - "' OR 1=1 --"
  - "'; DROP TABLE test; --"
variations:
  - "admin"
  - "test"
encodings:
  - "url"
obfuscations:
  - "case_variation"
        """)
        
        # Create generator with custom templates
        config = PayloadGenerationConfig(custom_templates_dir=str(template_dir))
        generator = PayloadGenerator(config)
        
        # Should load custom template
        sql_payloads = generator.generate_injection_payloads(VulnerabilityType.SQL_INJECTION)
        assert len(sql_payloads) > 0
        
        # Should include custom payloads
        custom_patterns = ["DROP TABLE test"]
        has_custom_patterns = any(
            any(pattern in payload for pattern in custom_patterns)
            for payload in sql_payloads
        )
        assert has_custom_patterns
    
    def test_end_to_end_payload_generation(self):
        """Test complete payload generation workflow"""
        generator = PayloadGenerator()
        
        # Generate comprehensive payloads for SQL injection
        sql_payloads = generator.generate_injection_payloads(VulnerabilityType.SQL_INJECTION)
        
        # Should have multiple payloads with various encodings and obfuscations
        assert len(sql_payloads) > 10
        
        # Should include encoded versions
        encoded_payloads = [p for p in sql_payloads if '%' in p or '\\u' in p]
        assert len(encoded_payloads) > 0
        
        # Should include case variations
        case_variations = [p for p in sql_payloads if p.isupper() or p.islower()]
        assert len(case_variations) > 0
    
    def test_wordlist_integration(self):
        """Test integration with wordlist expansion"""
        generator = PayloadGenerator()
        
        # Test with common API endpoints
        api_endpoints = ["users", "admin", "api"]
        prefixes = ["v1/", "v2/", "api/"]
        suffixes = ["/list", "/create", "/delete"]
        
        expanded = generator.expand_wordlist(api_endpoints, prefixes, suffixes)
        
        # Should create comprehensive endpoint list
        assert len(expanded) > len(api_endpoints)
        
        # Should include combinations like "v1/users/list"
        assert "v1/users/list" in expanded
        assert "api/admin/delete" in expanded