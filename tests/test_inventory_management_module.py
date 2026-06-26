"""
Tests for Inventory Management Testing Module (OWASP API9)
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass

from modules.owasp.inventory_management import InventoryManagementModule
from modules.advanced.version_fuzzer import APIVersion
from utils.http_client import HTTPRequestEngine
from core.config import InventoryConfig, AuthContext, AuthType, Severity


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


def make_version(version, base_url, status="active", status_code=200,
                 response_time=0.1):
    """Helper to build an APIVersion as returned by VersionFuzzer."""
    return APIVersion(
        version=version,
        base_url=base_url,
        status=status,
        status_code=status_code,
        response_time=response_time,
        accessible=True,
    )


class TestInventoryManagementModule:
    """Test cases for the Inventory Management Testing Module"""

    @pytest.fixture
    def auth_contexts(self):
        return [
            AuthContext(
                name="user1",
                type=AuthType.BEARER,
                token="user1_token",
                privilege_level=1,
            )
        ]

    @pytest.fixture
    def mock_http_client(self):
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        return client

    def _module(self, mock_http_client, auth_contexts, config=None):
        return InventoryManagementModule(
            config or InventoryConfig(), mock_http_client, auth_contexts
        )

    def _patch_fuzzer(self, versions):
        """Patch VersionFuzzer so fuzz_api_versions returns the given versions.

        Returns the patch context manager for use in a `with` block.
        """
        fuzzer_instance = Mock()
        fuzzer_instance.fuzz_api_versions = AsyncMock(return_value=versions)
        return patch(
            "modules.owasp.inventory_management.VersionFuzzer",
            return_value=fuzzer_instance,
        )

    def test_module_initialization(self, mock_http_client, auth_contexts):
        """Module reports the correct name and stores auth contexts."""
        module = self._module(mock_http_client, auth_contexts)
        assert module.get_module_name() == "inventory"
        assert len(module.auth_contexts) == len(auth_contexts)

    @pytest.mark.asyncio
    async def test_deprecated_version_produces_finding(self, mock_http_client,
                                                       auth_contexts):
        """Requirement 4.4: a deprecated version emits DEPRECATED_API_VERSION."""
        module = self._module(mock_http_client, auth_contexts)
        base_url = "https://api.example.com"
        versions = [
            make_version("v1", f"{base_url}/v1", status="deprecated"),
            make_version("v2", f"{base_url}/v2", status="active"),
        ]

        with self._patch_fuzzer(versions):
            endpoints = [MockEndpoint(f"{base_url}/users")]
            findings = await module.execute_tests(endpoints)

        deprecated = [f for f in findings if f.category == "DEPRECATED_API_VERSION"]
        assert len(deprecated) == 1
        finding = deprecated[0]
        assert finding.owasp_category == "API9"
        assert finding.severity == Severity.LOW
        assert finding.method == "GET"

    @pytest.mark.asyncio
    async def test_development_version_produces_undocumented_finding(
            self, mock_http_client, auth_contexts):
        """Requirement 4.3/4.4: a development/shadow version emits
        UNDOCUMENTED_API_VERSION mapped to API9."""
        module = self._module(mock_http_client, auth_contexts)
        base_url = "https://api.example.com"
        versions = [
            make_version("v2", f"{base_url}/v2", status="active"),
            make_version("v3", f"{base_url}/v3", status="development"),
        ]

        with self._patch_fuzzer(versions):
            endpoints = [MockEndpoint(f"{base_url}/users")]
            findings = await module.execute_tests(endpoints)

        undocumented = [f for f in findings
                        if f.category == "UNDOCUMENTED_API_VERSION"]
        assert len(undocumented) == 1
        finding = undocumented[0]
        assert finding.owasp_category == "API9"
        assert finding.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_non_current_active_version_produces_api9_finding(
            self, mock_http_client, auth_contexts):
        """Requirement 4.3: an active but non-current version produces an API9
        NON_CURRENT_API_VERSION finding."""
        module = self._module(mock_http_client, auth_contexts)
        base_url = "https://api.example.com"
        versions = [
            make_version("v1", f"{base_url}/v1", status="active"),
            make_version("v2", f"{base_url}/v2", status="active"),
        ]

        with self._patch_fuzzer(versions):
            endpoints = [MockEndpoint(f"{base_url}/users")]
            findings = await module.execute_tests(endpoints)

        non_current = [f for f in findings
                       if f.category == "NON_CURRENT_API_VERSION"]
        # v1 is non-current (v2 is the highest), v2 is current -> exactly one.
        assert len(non_current) == 1
        finding = non_current[0]
        assert finding.owasp_category == "API9"
        assert finding.payload == "v1"

    @pytest.mark.asyncio
    async def test_execute_tests_returns_list_of_findings(self, mock_http_client,
                                                          auth_contexts):
        """Requirement 4.5: execute_tests completes and returns a list of
        findings."""
        module = self._module(mock_http_client, auth_contexts)
        base_url = "https://api.example.com"
        versions = [
            make_version("v1", f"{base_url}/v1", status="deprecated"),
            make_version("v2", f"{base_url}/v2", status="development"),
            make_version("v3", f"{base_url}/v3", status="active"),
        ]

        with self._patch_fuzzer(versions):
            endpoints = [MockEndpoint(f"{base_url}/users")]
            findings = await module.execute_tests(endpoints)

        assert isinstance(findings, list)
        assert len(findings) >= 1
        assert all(hasattr(f, "category") for f in findings)
        assert all(f.owasp_category == "API9" for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_when_only_current_version(self, mock_http_client,
                                                        auth_contexts):
        """A single active (current) version produces no findings."""
        module = self._module(mock_http_client, auth_contexts)
        base_url = "https://api.example.com"
        versions = [make_version("v1", f"{base_url}/v1", status="active")]

        with self._patch_fuzzer(versions):
            endpoints = [MockEndpoint(f"{base_url}/users")]
            findings = await module.execute_tests(endpoints)

        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_endpoint_list_returns_empty(self, mock_http_client,
                                                     auth_contexts):
        """Requirement 4.6: an empty endpoint list returns [] with no requests."""
        module = self._module(mock_http_client, auth_contexts)

        with self._patch_fuzzer([]) as patched:
            findings = await module.execute_tests([])
            # The fuzzer must never be constructed for an empty endpoint list.
            patched.assert_not_called()

        assert findings == []
        mock_http_client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
