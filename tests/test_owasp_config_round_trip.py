"""
tests/test_owasp_config_round_trip.py

YAML → ConfigurationManager → dataclass field-level assertions for every
OWASP module config that gained new fields in the API3–API10 hardening pass.

Verifies that ``ConfigurationManager.load_config_from_dict`` correctly
propagates every new config field when a YAML/dict source supplies it,
and that the dataclass defaults are intact when the source omits the field.
"""

import pytest
import yaml

from core.config import ConfigurationManager


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _load(yaml_src: str):
    """Parse YAML and load via the real ConfigurationManager."""
    return ConfigurationManager().load_config_from_dict(yaml.safe_load(yaml_src))


_BASE = """
target:
  base_url: https://api.example.com
"""


# ---------------------------------------------------------------------------
# UnsafeConsumptionConfig — new fields: check_redirects, redirect_test_url,
# check_cleartext_upstream
# ---------------------------------------------------------------------------

class TestUnsafeConsumptionConfigRoundTrip:

    def test_new_fields_loaded_from_yaml(self):
        cfg = _load(_BASE + """
owasp_testing:
  unsafe_consumption_testing:
    check_redirects: false
    redirect_test_url: https://oob.example.com
    check_cleartext_upstream: false
""")
        uc = cfg.owasp_testing.unsafe_consumption_testing
        assert uc.check_redirects is False
        assert uc.redirect_test_url == "https://oob.example.com"
        assert uc.check_cleartext_upstream is False

    def test_new_fields_default_when_omitted(self):
        cfg = _load(_BASE + """
owasp_testing:
  unsafe_consumption_testing:
    enabled: true
""")
        uc = cfg.owasp_testing.unsafe_consumption_testing
        assert uc.check_redirects is True
        assert uc.redirect_test_url == "http://169.254.169.254/latest/meta-data/"
        assert uc.check_cleartext_upstream is True

    def test_upstream_indicators_and_payloads_loaded(self):
        cfg = _load(_BASE + """
owasp_testing:
  unsafe_consumption_testing:
    upstream_indicators:
      - fetch
      - webhook
    malformed_payloads:
      - "<img src=x>"
""")
        uc = cfg.owasp_testing.unsafe_consumption_testing
        assert uc.upstream_indicators == ["fetch", "webhook"]
        assert uc.malformed_payloads == ["<img src=x>"]


# ---------------------------------------------------------------------------
# BusinessFlowConfig — new fields: check_quota_decrement, quota_fields,
# inter_request_delay_ms, multi_step_flows
# ---------------------------------------------------------------------------

class TestBusinessFlowConfigRoundTrip:

    def test_new_fields_loaded_from_yaml(self):
        cfg = _load(_BASE + """
owasp_testing:
  business_flow_testing:
    check_quota_decrement: false
    quota_fields:
      - tickets
      - credits
    inter_request_delay_ms: 750
    repetition_limit: 25
""")
        bf = cfg.owasp_testing.business_flow_testing
        assert bf.check_quota_decrement is False
        assert bf.quota_fields == ["tickets", "credits"]
        assert bf.inter_request_delay_ms == 750
        assert bf.repetition_limit == 25

    def test_new_fields_default_when_omitted(self):
        cfg = _load(_BASE + """
owasp_testing:
  business_flow_testing:
    enabled: true
""")
        bf = cfg.owasp_testing.business_flow_testing
        assert bf.check_quota_decrement is True
        assert bf.inter_request_delay_ms == 0
        assert len(bf.quota_fields) > 0       # built-in defaults present
        assert bf.multi_step_flows == []

    def test_sensitive_flow_patterns_loaded(self):
        cfg = _load(_BASE + """
owasp_testing:
  business_flow_testing:
    sensitive_flow_patterns:
      - /buy
      - /bid
""")
        assert cfg.owasp_testing.business_flow_testing.sensitive_flow_patterns == [
            "/buy", "/bid"
        ]


# ---------------------------------------------------------------------------
# FunctionAuthConfig — new fields: allow_destructive, role_fields, role_values,
# api_versions, bfla_output_file
# ---------------------------------------------------------------------------

class TestFunctionAuthConfigRoundTrip:

    def test_new_fields_loaded_from_yaml(self):
        cfg = _load(_BASE + """
owasp_testing:
  function_auth_testing:
    admin_endpoints:
      - /backstage
      - /ops
    dangerous_methods:
      - DELETE
      - PUT
    allow_destructive: true
    role_fields:
      - tier
    role_values:
      - premium
      - enterprise
    api_versions:
      - v1
      - v2
    bfla_output_file: /tmp/bfla.json
""")
        fa = cfg.owasp_testing.function_auth_testing
        assert fa.admin_endpoints == ["/backstage", "/ops"]
        assert fa.dangerous_methods == ["DELETE", "PUT"]
        assert fa.allow_destructive is True
        assert fa.role_fields == ["tier"]
        assert fa.role_values == ["premium", "enterprise"]
        assert fa.api_versions == ["v1", "v2"]
        assert fa.bfla_output_file == "/tmp/bfla.json"

    def test_new_fields_default_when_omitted(self):
        cfg = _load(_BASE + """
owasp_testing:
  function_auth_testing:
    enabled: true
""")
        fa = cfg.owasp_testing.function_auth_testing
        assert fa.allow_destructive is False
        assert fa.bfla_output_file is None
        assert len(fa.role_fields) > 0
        assert len(fa.api_versions) > 0


# ---------------------------------------------------------------------------
# SecurityMisconfigConfig — existing field round-trip
# ---------------------------------------------------------------------------

class TestSecurityMisconfigConfigRoundTrip:

    def test_required_headers_loaded(self):
        cfg = _load(_BASE + """
owasp_testing:
  security_misconfig_testing:
    required_headers:
      - Strict-Transport-Security
      - Permissions-Policy
""")
        sm = cfg.owasp_testing.security_misconfig_testing
        assert sm.required_headers == [
            "Strict-Transport-Security", "Permissions-Policy"
        ]

    def test_default_headers_present_when_omitted(self):
        cfg = _load(_BASE + """
owasp_testing:
  security_misconfig_testing:
    enabled: true
""")
        sm = cfg.owasp_testing.security_misconfig_testing
        assert "Strict-Transport-Security" in sm.required_headers
        assert "Content-Security-Policy" in sm.required_headers


# ---------------------------------------------------------------------------
# InventoryConfig — existing field round-trip
# ---------------------------------------------------------------------------

class TestInventoryConfigRoundTrip:

    def test_detect_deprecated_false_loaded(self):
        cfg = _load(_BASE + """
owasp_testing:
  inventory_testing:
    detect_deprecated: false
""")
        assert cfg.owasp_testing.inventory_testing.detect_deprecated is False

    def test_detect_deprecated_true_by_default(self):
        cfg = _load(_BASE + """
owasp_testing:
  inventory_testing:
    enabled: true
""")
        assert cfg.owasp_testing.inventory_testing.detect_deprecated is True


# ---------------------------------------------------------------------------
# ResourceTestingConfig — existing fields round-trip
# ---------------------------------------------------------------------------

class TestResourceTestingConfigRoundTrip:

    def test_fields_loaded(self):
        cfg = _load(_BASE + """
owasp_testing:
  resource_testing:
    burst_size: 200
    json_depth_limit: 2000
    large_payload_sizes:
      - 524288
      - 5242880
""")
        rt = cfg.owasp_testing.resource_testing
        assert rt.burst_size == 200
        assert rt.json_depth_limit == 2000
        assert rt.large_payload_sizes == [524288, 5242880]

    def test_defaults_present_when_omitted(self):
        cfg = _load(_BASE + """
owasp_testing:
  resource_testing:
    enabled: true
""")
        rt = cfg.owasp_testing.resource_testing
        assert rt.burst_size == 100
        assert rt.json_depth_limit == 1000
        assert len(rt.large_payload_sizes) > 0


# ---------------------------------------------------------------------------
# PropertyTestingConfig — existing fields round-trip
# ---------------------------------------------------------------------------

class TestPropertyTestingConfigRoundTrip:

    def test_fields_loaded(self):
        cfg = _load(_BASE + """
owasp_testing:
  property_testing:
    sensitive_fields:
      - iban
      - cvv
    mass_assignment_fields:
      - balance
      - subscription_tier
""")
        pt = cfg.owasp_testing.property_testing
        assert pt.sensitive_fields == ["iban", "cvv"]
        assert pt.mass_assignment_fields == ["balance", "subscription_tier"]

    def test_defaults_present_when_omitted(self):
        cfg = _load(_BASE + """
owasp_testing:
  property_testing:
    enabled: true
""")
        pt = cfg.owasp_testing.property_testing
        assert "password" in pt.sensitive_fields
        assert "role" in pt.mass_assignment_fields


# ---------------------------------------------------------------------------
# Full OWASPConfig: all 10 modules present and enabled by default
# ---------------------------------------------------------------------------

class TestOWASPConfigDefaults:

    def test_all_ten_modules_enabled_by_default(self):
        cfg = _load(_BASE)
        modules = set(cfg.owasp_testing.enabled_modules)
        expected = {
            "bola", "auth", "property", "resource", "function_auth",
            "ssrf", "business_flow", "security_misconfig", "inventory",
            "unsafe_consumption",
        }
        assert modules == expected

    def test_empty_owasp_section_uses_all_defaults(self):
        """An entirely absent owasp_testing section uses every module default."""
        cfg = _load(_BASE)
        oc = cfg.owasp_testing
        assert oc.unsafe_consumption_testing.check_redirects is True
        assert oc.business_flow_testing.check_quota_decrement is True
        assert oc.function_auth_testing.allow_destructive is False
        assert oc.inventory_testing.detect_deprecated is True
        assert oc.resource_testing.burst_size == 100
