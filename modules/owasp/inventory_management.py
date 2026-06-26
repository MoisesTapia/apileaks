"""
Inventory Management Testing Module
Implements OWASP API9 - Improper Inventory Management testing
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine
from core.config import InventoryConfig, AuthContext, Severity
from core.logging import get_logger

from modules.advanced.version_fuzzer import (
    VersionFuzzer,
    VersionFuzzingConfig,
    APIVersion,
)


# HTTP methods that change server state. This module only issues read/GET
# probes (via the version fuzzer) so it is inherently safe-mode compatible;
# the constant is kept for parity with the other OWASP modules.
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Pattern used to extract a numeric version from a version string such as
# "v2", "api/v3", "version1" -> 2, 3, 1.
_VERSION_NUMBER_RE = re.compile(r"(\d+)")


class InventoryManagementModule(OWASPModule):
    """
    Inventory Management Testing Module for detecting Improper Inventory
    Management (OWASP API9).

    The module reuses ``modules.advanced.version_fuzzer.VersionFuzzer`` (via
    composition) to enumerate API versions reachable from the target. It emits:
      - An API9 finding (``NON_CURRENT_API_VERSION``) for every accessible
        version that is not the current (highest) version.
      - ``DEPRECATED_API_VERSION`` for versions the fuzzer flags as deprecated.
      - ``UNDOCUMENTED_API_VERSION`` for shadow/undocumented (development,
        beta, staging) versions exposed in the environment.

    This module performs only read/GET requests and therefore honors Safe Mode
    without skipping any steps.
    """

    def __init__(self, config: InventoryConfig, http_client: HTTPRequestEngine,
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="inventory")

        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}

        # Safe mode flag (optional attribute on config). This module only issues
        # GET requests, so safe mode does not change its behavior.
        self.safe_mode = getattr(self.config, 'safe_mode', False)

        self.logger.info("Inventory Management Testing Module initialized",
                         detect_deprecated=getattr(config, 'detect_deprecated', True),
                         safe_mode=self.safe_mode)

    def get_module_name(self) -> str:
        """Get module name"""
        return "inventory"

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute inventory management tests on discovered endpoints.

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of inventory findings. Returns [] (with no HTTP requests) for
            an empty endpoint list.
        """
        # Empty-input safety: no endpoints -> no work, no requests.
        if not endpoints:
            self.logger.info("No endpoints provided for inventory testing")
            return []

        self.logger.info("Starting inventory management testing",
                         endpoints_count=len(endpoints),
                         safe_mode=self.safe_mode)

        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])

        findings: List[Finding] = []

        # Derive the distinct base URLs (scheme://host[:port]) from endpoints so
        # we fuzz each host once rather than per endpoint path.
        base_urls = self._collect_base_urls(endpoints)

        for base_url in base_urls:
            try:
                versions = await self._discover_versions(base_url)
                findings.extend(self._classify_versions(base_url, versions))
            except Exception as e:
                self.logger.debug("Inventory version discovery failed",
                                  base_url=base_url,
                                  error=str(e))

        self.logger.info("Inventory management testing completed",
                         total_findings=len(findings),
                         base_urls=len(base_urls))

        return findings

    def _collect_base_urls(self, endpoints: List[Any]) -> List[str]:
        """Extract a de-duplicated list of base URLs from the endpoints."""
        base_urls: List[str] = []
        seen = set()

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            parsed = urlparse(endpoint_url)

            if parsed.scheme and parsed.netloc:
                base = f"{parsed.scheme}://{parsed.netloc}"
            else:
                # Fall back to the raw value (best effort) when it is not a
                # fully-qualified URL.
                base = endpoint_url.rstrip('/')

            if base and base not in seen:
                seen.add(base)
                base_urls.append(base)

        return base_urls

    async def _discover_versions(self, base_url: str) -> List[APIVersion]:
        """
        Enumerate API versions for a base URL by composing VersionFuzzer.

        A fresh fuzzer instance is used per base URL so discovered versions are
        not carried across hosts.
        """
        vf_config = VersionFuzzingConfig(
            detect_deprecated=getattr(self.config, 'detect_deprecated', True)
        )
        fuzzer = VersionFuzzer(vf_config, self.http_client)
        versions = await fuzzer.fuzz_api_versions(base_url)
        return versions or []

    def _classify_versions(self, base_url: str,
                           versions: List[APIVersion]) -> List[Finding]:
        """
        Classify discovered versions into findings:
          - deprecated -> DEPRECATED_API_VERSION
          - development/shadow -> UNDOCUMENTED_API_VERSION
          - active but not the current (highest) version -> NON_CURRENT_API_VERSION
        """
        findings: List[Finding] = []

        if not versions:
            return findings

        # Determine the current (highest-numbered) version so older accessible
        # versions can be flagged as non-current.
        current_version = self._determine_current_version(versions)

        for version in versions:
            status = (version.status or "").lower()

            if status == "deprecated":
                findings.append(self._build_finding(
                    base_url=base_url,
                    version=version,
                    category="DEPRECATED_API_VERSION",
                    owasp_category="API9",
                    severity=Severity.LOW,
                    evidence=(f"Deprecated API version '{version.version}' is still accessible "
                              f"at {version.base_url} (status code {version.status_code})."),
                    recommendation=("Decommission or properly sunset deprecated API versions to "
                                    "reduce attack surface. Communicate deprecation timelines and "
                                    "block access once retired."),
                ))
                continue

            if status == "development":
                findings.append(self._build_finding(
                    base_url=base_url,
                    version=version,
                    category="UNDOCUMENTED_API_VERSION",
                    owasp_category="API9",
                    severity=Severity.LOW,
                    evidence=(f"Undocumented/shadow API version '{version.version}' "
                              f"(development/beta) is exposed at {version.base_url} "
                              f"(status code {version.status_code})."),
                    recommendation=("Remove development, beta, or staging API versions from "
                                    "production environments and ensure every exposed version is "
                                    "documented and inventoried."),
                ))
                continue

            # Active (or otherwise reachable) versions that are not the current
            # version are reported as non-current under API9.
            if current_version is not None and version.version != current_version:
                findings.append(self._build_finding(
                    base_url=base_url,
                    version=version,
                    category="NON_CURRENT_API_VERSION",
                    owasp_category="API9",
                    severity=Severity.LOW,
                    evidence=(f"Non-current API version '{version.version}' is accessible at "
                              f"{version.base_url} alongside current version '{current_version}' "
                              f"(status code {version.status_code})."),
                    recommendation=("Maintain an accurate inventory of API versions. Retire or "
                                    "restrict access to older versions that are superseded by the "
                                    "current version."),
                ))

        return findings

    def _determine_current_version(self,
                                   versions: List[APIVersion]) -> Optional[str]:
        """
        Determine the current version as the one with the highest numeric
        component. Returns the version string, or None when no numeric version
        can be derived.
        """
        best_version: Optional[str] = None
        best_number = -1

        for version in versions:
            number = self._extract_version_number(version.version)
            if number is not None and number > best_number:
                best_number = number
                best_version = version.version

        return best_version

    @staticmethod
    def _extract_version_number(version_str: str) -> Optional[int]:
        """Extract the leading numeric component of a version string."""
        if not version_str:
            return None
        match = _VERSION_NUMBER_RE.search(version_str)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None

    def _build_finding(self, base_url: str, version: APIVersion, category: str,
                       owasp_category: str, severity: Severity,
                       evidence: str, recommendation: str) -> Finding:
        """Construct a Finding for a discovered version."""
        endpoint = version.base_url or base_url
        return Finding(
            id="",
            scan_id="",
            category=category,
            owasp_category=owasp_category,
            severity=severity,
            endpoint=endpoint,
            method="GET",
            status_code=version.status_code,
            response_size=0,
            response_time=version.response_time,
            evidence=evidence,
            recommendation=recommendation,
            payload=version.version,
        )
