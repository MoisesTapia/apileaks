"""
Engine integration tests for OWASP module registration (v0.2.0)

These tests validate that the engine wires up all ten OWASP detection modules,
that enabling the ``ssrf`` module executes through the OWASP phase without a
"module not registered" warning, and that OWASP coverage can reach 10/10
categories when each module produces a finding.

Validates: Requirements 6.1, 6.2, 6.5, 7.4
"""

import pytest
from unittest.mock import MagicMock

from core.engine import APILeakCore
from core.config import (
    APILeakConfig,
    TargetConfig,
    FuzzingConfig,
    OWASPConfig,
    AuthConfig,
    RateLimitConfig,
    ReportConfig,
    AdvancedDiscoveryConfig,
)
from utils.findings import FindingsCollector


# The full set of OWASP module-name keys the engine must register.
EXPECTED_OWASP_MODULES = [
    "bola",
    "auth",
    "property",
    "function_auth",
    "resource",
    "ssrf",
    "business_flow",
    "security_misconfig",
    "inventory",
    "unsafe_consumption",
]

# One representative finding category per OWASP API category (API1-API10).
# Each category is mapped via FindingsCollector.CATEGORY_TO_OWASP.
CATEGORY_PER_OWASP = [
    ("BOLA_ANONYMOUS_ACCESS", "API1"),
    ("AUTH_BYPASS", "API2"),
    ("SENSITIVE_DATA_EXPOSURE", "API3"),
    ("MISSING_RATE_LIMITING", "API4"),
    ("ADMIN_ACCESS_ANONYMOUS", "API5"),
    ("BUSINESS_FLOW_NO_LIMIT", "API6"),
    ("SSRF_INTERNAL_ACCESS", "API7"),
    ("CORS_MISCONFIGURATION", "API8"),
    ("DEPRECATED_API_VERSION", "API9"),
    ("UNSAFE_UPSTREAM_DATA", "API10"),
]


def _make_config(enabled_modules=None):
    """Build an APILeakConfig with advanced discovery disabled (no network)."""
    if enabled_modules is None:
        enabled_modules = list(EXPECTED_OWASP_MODULES)
    return APILeakConfig(
        target=TargetConfig(base_url="https://api.example.com"),
        fuzzing=FuzzingConfig(),
        owasp_testing=OWASPConfig(enabled_modules=enabled_modules),
        authentication=AuthConfig(),
        rate_limiting=RateLimitConfig(),
        reporting=ReportConfig(),
        advanced_discovery=AdvancedDiscoveryConfig(enabled=False),
    )


@pytest.mark.asyncio
async def test_all_ten_owasp_modules_register():
    """All ten OWASP modules register after initialization (Req 6.1, 6.2)."""
    core = APILeakCore(_make_config())

    await core._initialize_owasp_modules()

    for name in EXPECTED_OWASP_MODULES:
        assert name in core.owasp_modules, f"OWASP module '{name}' was not registered"

    # No unexpected modules and no missing ones.
    assert set(core.owasp_modules.keys()) == set(EXPECTED_OWASP_MODULES)
    assert len(core.owasp_modules) == 10


@pytest.mark.asyncio
async def test_enabling_ssrf_emits_no_not_registered_warning():
    """Enabling ssrf runs the OWASP phase without a not-registered warning (Req 6.5)."""
    core = APILeakCore(_make_config(enabled_modules=["ssrf"]))
    await core._initialize_owasp_modules()

    # ssrf must be a registered module so the engine never logs a warning for it.
    assert "ssrf" in core.owasp_modules

    # Capture log calls emitted while executing the OWASP phase.
    core.logger = MagicMock()
    # Empty endpoint list -> the ssrf module returns [] without network access.
    core.discovered_endpoints = []

    await core._execute_owasp_phase()

    not_registered_warnings = [
        call
        for call in core.logger.warning.call_args_list
        if call.args and call.args[0] == "OWASP module not registered"
    ]
    assert not_registered_warnings == [], (
        f"Unexpected 'module not registered' warning(s): {not_registered_warnings}"
    )


def test_owasp_coverage_reaches_ten_of_ten():
    """One finding per OWASP category produces 10/10 coverage (Req 7.4)."""
    collector = FindingsCollector("test-scan-coverage")

    for category, _owasp in CATEGORY_PER_OWASP:
        collector.add_finding(
            category=category,
            severity=None,  # let the collector auto-classify
            endpoint=f"/api/{category.lower()}",
            method="GET",
            evidence=f"Evidence for {category}",
            recommendation=f"Remediate {category}",
        )

    coverage = collector.get_owasp_coverage()

    assert coverage["total_categories"] == 10
    assert coverage["tested_categories"] == 10
    assert coverage["coverage_percentage"] == 100.0
    assert coverage["untested_categories"] == []

    for _category, owasp in CATEGORY_PER_OWASP:
        assert coverage["categories"][owasp]["tested"] is True, (
            f"{owasp} should be marked as tested"
        )
        assert coverage["categories"][owasp]["findings_count"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
