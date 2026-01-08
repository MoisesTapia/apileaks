"""
API Version Fuzzing Module
Discovers and compares different API versions (/v1, /v2, /api/v1, etc.)
"""

import asyncio
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

from core.logging import get_logger
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, Severity


@dataclass
class APIVersion:
    """API version information"""
    version: str  # v1, v2, api/v1, etc.
    base_url: str
    endpoints_found: List[str] = field(default_factory=list)
    status: str = "unknown"  # active, deprecated, development, error
    response_time: float = 0.0
    status_code: int = 0
    accessible: bool = False
    version_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VersionComparison:
    """Comparison between API versions"""
    versions: List[APIVersion]
    common_endpoints: List[str] = field(default_factory=list)
    unique_endpoints: Dict[str, List[str]] = field(default_factory=dict)
    deprecated_versions: List[str] = field(default_factory=list)
    development_versions: List[str] = field(default_factory=list)
    version_differences: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class VersionFuzzingConfig:
    """Configuration for version fuzzing"""
    enabled: bool = True
    version_patterns: List[str] = field(default_factory=lambda: [
        "/v1", "/v2", "/v3", "/v4", "/v5",
        "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
        "/api/1", "/api/2", "/api/3",
        "/1", "/2", "/3",
        "/version1", "/version2", "/version3",
        "/ver1", "/ver2", "/ver3"
    ])
    test_endpoints: List[str] = field(default_factory=lambda: [
        "", "/", "/health", "/status", "/info", "/docs", "/swagger",
        "/users", "/user", "/api", "/endpoints", "/version"
    ])
    max_concurrent_requests: int = 5
    timeout: float = 10.0
    compare_endpoints: bool = True
    detect_deprecated: bool = True


class VersionFuzzer:
    """
    API Version Fuzzing Module
    
    Discovers and analyzes different API versions:
    - Tests common version patterns (/v1, /v2, /api/v1)
    - Compares endpoints between versions
    - Identifies deprecated and development versions
    - Maps version-specific functionality
    
    Requirements: 18.1, 18.2, 18.5
    """
    
    def __init__(self, config: VersionFuzzingConfig, http_client: HTTPRequestEngine):
        """
        Initialize Version Fuzzer
        
        Args:
            config: Version fuzzing configuration
            http_client: HTTP client for making requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__).bind(component="version_fuzzer")
        
        # Results storage
        self.discovered_versions: List[APIVersion] = []
        self.version_comparison: Optional[VersionComparison] = None
        self.findings: List[Finding] = []
        
        self.logger.info("Version Fuzzer initialized",
                        patterns_count=len(config.version_patterns),
                        test_endpoints_count=len(config.test_endpoints),
                        compare_enabled=config.compare_endpoints)
    
    async def fuzz_api_versions(self, base_url: str) -> List[APIVersion]:
        """
        Discover API versions for target URL
        
        Args:
            base_url: Base target URL
            
        Returns:
            List of discovered API versions
        """
        self.logger.info("Starting API version discovery", target=base_url)
        
        if not self.config.enabled:
            self.logger.info("Version fuzzing disabled")
            return []
        
        # Clean base URL
        base_url = base_url.rstrip('/')
        
        # Phase 1: Test version patterns
        self.logger.info("Phase 1: Testing version patterns")
        await self._test_version_patterns(base_url)
        
        # Phase 2: Test endpoints for each discovered version
        if self.config.compare_endpoints and self.discovered_versions:
            self.logger.info("Phase 2: Testing endpoints for discovered versions")
            await self._test_version_endpoints()
        
        # Phase 3: Analyze version status and characteristics
        self.logger.info("Phase 3: Analyzing version characteristics")
        await self._analyze_version_characteristics()
        
        # Phase 4: Compare versions if multiple found
        if len(self.discovered_versions) > 1 and self.config.compare_endpoints:
            self.logger.info("Phase 4: Comparing versions")
            self.version_comparison = self._compare_versions()
        
        self.logger.info("Version discovery completed",
                        versions_found=len(self.discovered_versions),
                        accessible_versions=len([v for v in self.discovered_versions if v.accessible]))
        
        return self.discovered_versions.copy()
    
    async def _test_version_patterns(self, base_url: str) -> None:
        """Test common version patterns"""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        tasks = []
        
        for pattern in self.config.version_patterns:
            task = self._test_single_version_pattern(semaphore, base_url, pattern)
            tasks.append(task)
        
        # Execute all version pattern tests
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.warning("Version pattern test failed",
                                  pattern=self.config.version_patterns[i],
                                  error=str(result))
            elif result:
                self.discovered_versions.append(result)
    
    async def _test_single_version_pattern(self, semaphore: asyncio.Semaphore, 
                                         base_url: str, pattern: str) -> Optional[APIVersion]:
        """Test a single version pattern"""
        async with semaphore:
            try:
                version_url = base_url + pattern
                start_time = datetime.now()
                
                response = await self.http_client.request("GET", version_url, timeout=self.config.timeout)
                
                response_time = (datetime.now() - start_time).total_seconds()
                
                # Consider version accessible if we get a reasonable response
                accessible = self._is_version_accessible(response)
                
                if accessible:
                    version = APIVersion(
                        version=pattern.lstrip('/'),
                        base_url=version_url,
                        status_code=response.status_code,
                        response_time=response_time,
                        accessible=True
                    )
                    
                    self.logger.debug("Version pattern accessible",
                                    pattern=pattern,
                                    status_code=response.status_code,
                                    response_time=response_time)
                    
                    return version
                
            except Exception as e:
                self.logger.debug("Version pattern test failed",
                                pattern=pattern,
                                error=str(e))
        
        return None
    
    def _is_version_accessible(self, response: Response) -> bool:
        """Determine if a version endpoint is accessible"""
        # Consider accessible if:
        # - 2xx status codes (success)
        # - 401/403 (requires auth but exists)
        # - 405 (method not allowed but endpoint exists)
        # - Response contains version-related content
        
        if 200 <= response.status_code < 300:
            return True
        
        if response.status_code in [401, 403, 405]:
            return True
        
        # Check for version-related content in response
        response_text = response.text.lower()
        version_indicators = [
            'version', 'api', 'swagger', 'openapi', 'docs',
            'endpoints', 'routes', 'health', 'status'
        ]
        
        if any(indicator in response_text for indicator in version_indicators):
            return True
        
        return False
    
    async def _test_version_endpoints(self) -> None:
        """Test common endpoints for each discovered version"""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        tasks = []
        
        for version in self.discovered_versions:
            for endpoint in self.config.test_endpoints:
                task = self._test_version_endpoint(semaphore, version, endpoint)
                tasks.append(task)
        
        # Execute all endpoint tests
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and update version objects
        result_index = 0
        for version in self.discovered_versions:
            for endpoint in self.config.test_endpoints:
                if result_index < len(results):
                    result = results[result_index]
                    if isinstance(result, tuple) and result[0]:  # (success, endpoint)
                        version.endpoints_found.append(result[1])
                result_index += 1
    
    async def _test_version_endpoint(self, semaphore: asyncio.Semaphore, 
                                   version: APIVersion, endpoint: str) -> Tuple[bool, str]:
        """Test a specific endpoint for a version"""
        async with semaphore:
            try:
                test_url = version.base_url.rstrip('/') + endpoint
                response = await self.http_client.request("GET", test_url, timeout=self.config.timeout)
                
                # Consider endpoint found if accessible
                if self._is_endpoint_accessible(response):
                    self.logger.debug("Version endpoint accessible",
                                    version=version.version,
                                    endpoint=endpoint,
                                    status_code=response.status_code)
                    return (True, endpoint)
                
            except Exception as e:
                self.logger.debug("Version endpoint test failed",
                                version=version.version,
                                endpoint=endpoint,
                                error=str(e))
        
        return (False, endpoint)
    
    def _is_endpoint_accessible(self, response: Response) -> bool:
        """Determine if an endpoint is accessible"""
        # Similar logic to version accessibility but more permissive
        return (200 <= response.status_code < 300 or 
                response.status_code in [401, 403, 405, 422])
    
    async def _analyze_version_characteristics(self) -> None:
        """Analyze characteristics of discovered versions"""
        for version in self.discovered_versions:
            try:
                # Test root version endpoint for more info
                response = await self.http_client.request("GET", version.base_url, 
                                                        timeout=self.config.timeout)
                
                # Analyze response for version characteristics
                version_info = self._extract_version_info(response)
                version.version_info = version_info
                
                # Determine version status
                version.status = self._determine_version_status(response, version_info)
                
                self.logger.debug("Version characteristics analyzed",
                                version=version.version,
                                status=version.status,
                                info_keys=list(version_info.keys()))
                
            except Exception as e:
                self.logger.debug("Version characteristics analysis failed",
                                version=version.version,
                                error=str(e))
                version.status = "error"
    
    def _extract_version_info(self, response: Response) -> Dict[str, Any]:
        """Extract version information from response"""
        info = {}
        response_text = response.text
        
        # Try to extract JSON version info
        try:
            import json
            if response.headers.get('content-type', '').startswith('application/json'):
                json_data = json.loads(response_text)
                
                # Look for common version fields
                version_fields = ['version', 'api_version', 'apiVersion', 'v', 'release']
                for field in version_fields:
                    if field in json_data:
                        info['version_field'] = json_data[field]
                        break
                
                # Look for other useful info
                if 'title' in json_data:
                    info['title'] = json_data['title']
                if 'description' in json_data:
                    info['description'] = json_data['description']
                if 'openapi' in json_data:
                    info['openapi_version'] = json_data['openapi']
                
        except (json.JSONDecodeError, KeyError):
            pass
        
        # Extract version from response headers
        version_headers = ['api-version', 'x-api-version', 'version', 'x-version']
        for header in version_headers:
            if header in response.headers:
                info['header_version'] = response.headers[header]
                break
        
        # Look for deprecation indicators
        deprecation_indicators = [
            'deprecated', 'deprecation', 'sunset', 'end-of-life',
            'legacy', 'obsolete', 'discontinued'
        ]
        
        response_lower = response_text.lower()
        for indicator in deprecation_indicators:
            if indicator in response_lower:
                info['deprecation_indicator'] = indicator
                break
        
        # Look for development/beta indicators
        dev_indicators = [
            'beta', 'alpha', 'preview', 'experimental', 'dev',
            'development', 'staging', 'test', 'canary'
        ]
        
        for indicator in dev_indicators:
            if indicator in response_lower:
                info['development_indicator'] = indicator
                break
        
        return info
    
    def _determine_version_status(self, response: Response, version_info: Dict[str, Any]) -> str:
        """Determine version status based on response and extracted info"""
        # Check for explicit deprecation
        if 'deprecation_indicator' in version_info:
            return "deprecated"
        
        # Check for development status
        if 'development_indicator' in version_info:
            return "development"
        
        # Check deprecation headers
        if 'deprecation' in response.headers or 'sunset' in response.headers:
            return "deprecated"
        
        # Check status code patterns
        if response.status_code == 410:  # Gone
            return "deprecated"
        
        if 200 <= response.status_code < 300:
            return "active"
        
        if response.status_code in [401, 403]:
            return "active"  # Requires auth but active
        
        return "unknown"
    
    def _compare_versions(self) -> VersionComparison:
        """Compare discovered API versions"""
        if len(self.discovered_versions) < 2:
            return VersionComparison(versions=self.discovered_versions)
        
        # Find common endpoints across all versions
        all_endpoints = [set(v.endpoints_found) for v in self.discovered_versions]
        common_endpoints = list(set.intersection(*all_endpoints)) if all_endpoints else []
        
        # Find unique endpoints for each version
        unique_endpoints = {}
        for version in self.discovered_versions:
            version_endpoints = set(version.endpoints_found)
            other_endpoints = set()
            for other_version in self.discovered_versions:
                if other_version.version != version.version:
                    other_endpoints.update(other_version.endpoints_found)
            
            unique = list(version_endpoints - other_endpoints)
            if unique:
                unique_endpoints[version.version] = unique
        
        # Categorize versions by status
        deprecated_versions = [v.version for v in self.discovered_versions if v.status == "deprecated"]
        development_versions = [v.version for v in self.discovered_versions if v.status == "development"]
        
        # Calculate version differences
        version_differences = {}
        for version in self.discovered_versions:
            differences = {
                'endpoint_count': len(version.endpoints_found),
                'response_time': version.response_time,
                'status_code': version.status_code,
                'status': version.status,
                'unique_endpoints': unique_endpoints.get(version.version, []),
                'version_info': version.version_info
            }
            version_differences[version.version] = differences
        
        comparison = VersionComparison(
            versions=self.discovered_versions,
            common_endpoints=common_endpoints,
            unique_endpoints=unique_endpoints,
            deprecated_versions=deprecated_versions,
            development_versions=development_versions,
            version_differences=version_differences
        )
        
        self.logger.info("Version comparison completed",
                        total_versions=len(self.discovered_versions),
                        common_endpoints=len(common_endpoints),
                        deprecated_count=len(deprecated_versions),
                        development_count=len(development_versions))
        
        return comparison
    
    def generate_findings(self) -> List[Finding]:
        """
        Generate findings from version discovery
        
        Returns:
            List of findings
        """
        findings = []
        
        # Multiple versions found
        if len(self.discovered_versions) > 1:
            finding = Finding(
                id="multiple_api_versions",
                scan_id="version_fuzzing",
                category="API_VERSION_DISCOVERY",
                owasp_category=None,
                severity=Severity.INFO,
                endpoint="",
                method="GET",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=f"Multiple API versions discovered: {', '.join([v.version for v in self.discovered_versions])}",
                recommendation="Review all API versions for consistency and security. Consider deprecating old versions.",
                payload=""
            )
            findings.append(finding)
        
        # Deprecated versions still accessible
        deprecated_versions = [v for v in self.discovered_versions if v.status == "deprecated"]
        if deprecated_versions:
            finding = Finding(
                id="deprecated_api_versions",
                scan_id="version_fuzzing",
                category="DEPRECATED_API_VERSION",
                owasp_category=None,
                severity=Severity.MEDIUM,
                endpoint="",
                method="GET",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=f"Deprecated API versions still accessible: {', '.join([v.version for v in deprecated_versions])}",
                recommendation="Disable or properly sunset deprecated API versions to reduce attack surface.",
                payload=""
            )
            findings.append(finding)
        
        # Development versions in production
        dev_versions = [v for v in self.discovered_versions if v.status == "development"]
        if dev_versions:
            finding = Finding(
                id="development_api_versions",
                scan_id="version_fuzzing",
                category="DEVELOPMENT_API_VERSION",
                owasp_category=None,
                severity=Severity.HIGH,
                endpoint="",
                method="GET",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=f"Development API versions accessible: {', '.join([v.version for v in dev_versions])}",
                recommendation="Remove development/beta API versions from production environment.",
                payload=""
            )
            findings.append(finding)
        
        # Version-specific endpoint differences
        if self.version_comparison and self.version_comparison.unique_endpoints:
            for version, unique_eps in self.version_comparison.unique_endpoints.items():
                if len(unique_eps) > 3:  # Only report if significant differences
                    finding = Finding(
                        id=f"version_specific_endpoints_{version}",
                        scan_id="version_fuzzing",
                        category="VERSION_ENDPOINT_DIFFERENCES",
                        owasp_category=None,
                        severity=Severity.LOW,
                        endpoint="",
                        method="GET",
                        status_code=200,
                        response_size=0,
                        response_time=0.0,
                        evidence=f"Version {version} has unique endpoints: {', '.join(unique_eps[:5])}",
                        recommendation=f"Review version-specific endpoints in {version} for security implications.",
                        payload=""
                    )
                    findings.append(finding)
        
        self.findings = findings
        return findings.copy()
    
    def get_discovered_versions(self) -> List[APIVersion]:
        """
        Get all discovered API versions
        
        Returns:
            List of discovered API versions
        """
        return self.discovered_versions.copy()
    
    def get_version_comparison(self) -> Optional[VersionComparison]:
        """
        Get version comparison results
        
        Returns:
            VersionComparison object or None if not compared
        """
        return self.version_comparison
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get version fuzzing statistics
        
        Returns:
            Dictionary with fuzzing statistics
        """
        stats = {
            "versions_discovered": len(self.discovered_versions),
            "accessible_versions": len([v for v in self.discovered_versions if v.accessible]),
            "deprecated_versions": len([v for v in self.discovered_versions if v.status == "deprecated"]),
            "development_versions": len([v for v in self.discovered_versions if v.status == "development"]),
            "active_versions": len([v for v in self.discovered_versions if v.status == "active"]),
            "patterns_tested": len(self.config.version_patterns),
            "comparison_performed": self.version_comparison is not None,
            "total_findings": len(self.findings)
        }
        
        if self.version_comparison:
            stats.update({
                "common_endpoints": len(self.version_comparison.common_endpoints),
                "versions_with_unique_endpoints": len(self.version_comparison.unique_endpoints)
            })
        
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check
        
        Returns:
            Health check results
        """
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version_fuzzing_enabled": self.config.enabled,
            "patterns_configured": len(self.config.version_patterns),
            "test_endpoints_configured": len(self.config.test_endpoints)
        }
        
        # Test HTTP client connectivity
        try:
            client_healthy = await self.http_client.health_check()
            health_status["http_client"] = "healthy" if client_healthy else "degraded"
        except Exception as e:
            health_status["http_client"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
        
        return health_status