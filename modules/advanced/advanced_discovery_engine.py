"""
Advanced Discovery Engine
Orchestrates subdomain discovery, CORS analysis, and security headers analysis
"""

import asyncio
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
from datetime import datetime

from core.logging import get_logger
from utils.http_client import HTTPRequestEngine
from utils.findings import Finding
from .subdomain_discovery import SubdomainDiscovery, SubdomainDiscoveryConfig
from .cors_analyzer import CORSAnalyzer, CORSAnalyzerConfig
from .security_headers_analyzer import SecurityHeadersAnalyzer, SecurityHeadersConfig
from .version_fuzzer import VersionFuzzer, VersionFuzzingConfig, APIVersion, VersionComparison
from .framework_detector import FrameworkDetector, FrameworkDetectionConfig, Framework


@dataclass
class AdvancedDiscoveryConfig:
    """Configuration for advanced discovery engine"""
    subdomain_discovery: SubdomainDiscoveryConfig = field(default_factory=SubdomainDiscoveryConfig)
    cors_analysis: CORSAnalyzerConfig = field(default_factory=CORSAnalyzerConfig)
    security_headers: SecurityHeadersConfig = field(default_factory=SecurityHeadersConfig)
    version_fuzzing: VersionFuzzingConfig = field(default_factory=VersionFuzzingConfig)
    framework_detection: FrameworkDetectionConfig = field(default_factory=FrameworkDetectionConfig)
    max_concurrent_endpoints: int = 5
    timeout: float = 30.0


@dataclass
class AttackSurface:
    """Complete attack surface mapping results"""
    target_domain: str
    discovered_subdomains: List[str] = field(default_factory=list)
    accessible_endpoints: List[str] = field(default_factory=list)
    api_versions: List[APIVersion] = field(default_factory=list)
    detected_framework: Optional[Framework] = None
    cors_analysis_results: Dict[str, Any] = field(default_factory=dict)
    security_headers_results: Dict[str, Any] = field(default_factory=dict)
    version_comparison: Optional[VersionComparison] = None
    total_findings: int = 0
    high_risk_findings: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


class AdvancedDiscoveryEngine:
    """
    Advanced Discovery Engine
    
    Orchestrates comprehensive attack surface mapping including:
    - Subdomain discovery
    - CORS policy analysis
    - Security headers analysis
    
    Requirements: 18.3, 18.4, 19.1, 19.2, 19.3, 19.4, 19.5
    """
    
    def __init__(self, config: AdvancedDiscoveryConfig, http_client: HTTPRequestEngine):
        """
        Initialize Advanced Discovery Engine
        
        Args:
            config: Advanced discovery configuration
            http_client: HTTP client for making requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__).bind(component="advanced_discovery")
        
        # Initialize component modules
        self.subdomain_discovery = SubdomainDiscovery(config.subdomain_discovery, http_client)
        self.cors_analyzer = CORSAnalyzer(config.cors_analysis, http_client)
        self.security_headers_analyzer = SecurityHeadersAnalyzer(config.security_headers, http_client)
        self.version_fuzzer = VersionFuzzer(config.version_fuzzing, http_client)
        self.framework_detector = FrameworkDetector(config.framework_detection, http_client)
        
        # Results storage
        self.attack_surface: Optional[AttackSurface] = None
        self.all_findings: List[Finding] = []
        
        self.logger.info("Advanced Discovery Engine initialized",
                        subdomain_enabled=config.subdomain_discovery.enabled,
                        cors_enabled=config.cors_analysis.enabled,
                        security_headers_enabled=config.security_headers.enabled,
                        version_fuzzing_enabled=config.version_fuzzing.enabled,
                        framework_detection_enabled=config.framework_detection.enabled)
    
    async def map_attack_surface(self, target: str, additional_endpoints: List[str] = None) -> AttackSurface:
        """
        Map complete attack surface for target
        
        Args:
            target: Target URL or domain
            additional_endpoints: Additional endpoints to analyze
            
        Returns:
            AttackSurface with complete mapping results
        """
        self.logger.info("Starting attack surface mapping", target=target)
        
        # Parse target domain
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            domain = target
            base_url = f"https://{target}"
        
        # Initialize attack surface
        self.attack_surface = AttackSurface(target_domain=domain)
        
        # Phase 1: Framework Detection
        self.logger.info("Phase 1: Starting framework detection")
        await self._execute_framework_detection(base_url)
        
        # Phase 2: API Version Discovery
        self.logger.info("Phase 2: Starting API version discovery")
        await self._execute_version_discovery(base_url)
        
        # Phase 3: Subdomain Discovery
        self.logger.info("Phase 3: Starting subdomain discovery")
        await self._execute_subdomain_discovery(domain)
        
        # Phase 4: Endpoint Collection
        self.logger.info("Phase 4: Collecting endpoints for analysis")
        endpoints_to_analyze = self._collect_endpoints_for_analysis(base_url, additional_endpoints)
        
        # Phase 5: CORS Analysis
        self.logger.info("Phase 5: Starting CORS analysis")
        await self._execute_cors_analysis(endpoints_to_analyze)
        
        # Phase 6: Security Headers Analysis
        self.logger.info("Phase 6: Starting security headers analysis")
        await self._execute_security_headers_analysis(endpoints_to_analyze)
        
        # Phase 7: Generate Findings
        self.logger.info("Phase 7: Generating findings")
        await self._generate_all_findings()
        
        # Finalize attack surface
        self.attack_surface.total_findings = len(self.all_findings)
        self.attack_surface.high_risk_findings = len([f for f in self.all_findings 
                                                    if f.severity.value in ["CRITICAL", "HIGH"]])
        
        self.logger.info("Attack surface mapping completed",
                        framework_detected=self.attack_surface.detected_framework.name if self.attack_surface.detected_framework else "None",
                        api_versions_found=len(self.attack_surface.api_versions),
                        subdomains_found=len(self.attack_surface.discovered_subdomains),
                        endpoints_analyzed=len(endpoints_to_analyze),
                        total_findings=self.attack_surface.total_findings,
                        high_risk_findings=self.attack_surface.high_risk_findings)
        
        return self.attack_surface
    
    async def _execute_framework_detection(self, base_url: str) -> None:
        """Execute framework detection phase"""
        if not self.config.framework_detection.enabled:
            self.logger.info("Framework detection disabled")
            return
        
        try:
            detected_framework = await self.framework_detector.detect_framework(base_url)
            self.attack_surface.detected_framework = detected_framework
            
            if detected_framework:
                self.logger.info("Framework detection completed",
                               framework=detected_framework.name,
                               confidence=detected_framework.confidence)
            else:
                self.logger.info("No framework detected")
        
        except Exception as e:
            self.logger.error("Framework detection failed", error=str(e))
    
    async def _execute_version_discovery(self, base_url: str) -> None:
        """Execute API version discovery phase"""
        if not self.config.version_fuzzing.enabled:
            self.logger.info("Version fuzzing disabled")
            return
        
        try:
            discovered_versions = await self.version_fuzzer.fuzz_api_versions(base_url)
            self.attack_surface.api_versions = discovered_versions
            
            # Get version comparison if available
            version_comparison = self.version_fuzzer.get_version_comparison()
            self.attack_surface.version_comparison = version_comparison
            
            self.logger.info("Version discovery completed",
                           versions_found=len(discovered_versions),
                           accessible_versions=len([v for v in discovered_versions if v.accessible]))
        
        except Exception as e:
            self.logger.error("Version discovery failed", error=str(e))
    
    async def _execute_subdomain_discovery(self, domain: str) -> None:
        """Execute subdomain discovery phase"""
        if not self.config.subdomain_discovery.enabled:
            self.logger.info("Subdomain discovery disabled")
            return
        
        try:
            subdomain_results = await self.subdomain_discovery.discover_subdomains(domain)
            
            # Extract accessible subdomains
            accessible_subdomains = [result.subdomain for result in subdomain_results 
                                   if result.is_accessible]
            
            self.attack_surface.discovered_subdomains = accessible_subdomains
            
            self.logger.info("Subdomain discovery completed",
                           total_tested=len(subdomain_results),
                           accessible_found=len(accessible_subdomains))
        
        except Exception as e:
            self.logger.error("Subdomain discovery failed", error=str(e))
    
    def _collect_endpoints_for_analysis(self, base_url: str, additional_endpoints: List[str] = None) -> List[str]:
        """
        Collect all endpoints for CORS and security headers analysis
        
        Args:
            base_url: Base target URL
            additional_endpoints: Additional endpoints from fuzzing
            
        Returns:
            List of endpoints to analyze
        """
        endpoints = []
        
        # Add base target URL
        endpoints.append(base_url)
        
        # Add discovered subdomains as HTTPS URLs
        for subdomain in self.attack_surface.discovered_subdomains:
            if not subdomain.startswith(('http://', 'https://')):
                endpoints.append(f"https://{subdomain}")
                endpoints.append(f"http://{subdomain}")  # Also try HTTP
            else:
                endpoints.append(subdomain)
        
        # Add discovered API version endpoints
        for version in self.attack_surface.api_versions:
            if version.accessible:
                endpoints.append(version.base_url)
                # Add version-specific endpoints
                for endpoint in version.endpoints_found:
                    version_endpoint = version.base_url.rstrip('/') + endpoint
                    endpoints.append(version_endpoint)
        
        # Add additional endpoints from fuzzing
        if additional_endpoints:
            endpoints.extend(additional_endpoints)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_endpoints = []
        for endpoint in endpoints:
            if endpoint not in seen:
                seen.add(endpoint)
                unique_endpoints.append(endpoint)
        
        self.logger.debug("Collected endpoints for analysis", count=len(unique_endpoints))
        return unique_endpoints
    
    async def _execute_cors_analysis(self, endpoints: List[str]) -> None:
        """Execute CORS analysis phase"""
        if not self.config.cors_analysis.enabled:
            self.logger.info("CORS analysis disabled")
            return
        
        try:
            # Limit endpoints to avoid overwhelming the target
            max_endpoints = 20  # Reasonable limit for CORS testing
            endpoints_to_test = endpoints[:max_endpoints]
            
            cors_results = await self.cors_analyzer.analyze_cors_policy(endpoints_to_test)
            self.attack_surface.cors_analysis_results = cors_results
            
            self.logger.info("CORS analysis completed",
                           endpoints_analyzed=len(cors_results))
        
        except Exception as e:
            self.logger.error("CORS analysis failed", error=str(e))
    
    async def _execute_security_headers_analysis(self, endpoints: List[str]) -> None:
        """Execute security headers analysis phase"""
        if not self.config.security_headers.enabled:
            self.logger.info("Security headers analysis disabled")
            return
        
        try:
            # Limit endpoints to avoid overwhelming the target
            max_endpoints = 20  # Reasonable limit for headers testing
            endpoints_to_test = endpoints[:max_endpoints]
            
            headers_results = await self.security_headers_analyzer.analyze_security_headers(endpoints_to_test)
            self.attack_surface.security_headers_results = headers_results
            
            self.logger.info("Security headers analysis completed",
                           endpoints_analyzed=len(headers_results))
        
        except Exception as e:
            self.logger.error("Security headers analysis failed", error=str(e))
    
    async def _generate_all_findings(self) -> None:
        """Generate findings from all analysis components"""
        self.all_findings = []
        
        # Generate framework detection findings
        if self.config.framework_detection.enabled:
            framework_findings = self.framework_detector.generate_findings()
            self.all_findings.extend(framework_findings)
            self.logger.debug("Generated framework findings", count=len(framework_findings))
        
        # Generate version fuzzing findings
        if self.config.version_fuzzing.enabled:
            version_findings = self.version_fuzzer.generate_findings()
            self.all_findings.extend(version_findings)
            self.logger.debug("Generated version findings", count=len(version_findings))
        
        # Generate subdomain discovery findings
        if self.config.subdomain_discovery.enabled:
            subdomain_findings = self.subdomain_discovery.generate_findings()
            self.all_findings.extend(subdomain_findings)
            self.logger.debug("Generated subdomain findings", count=len(subdomain_findings))
        
        # Generate CORS analysis findings
        if self.config.cors_analysis.enabled:
            cors_findings = self.cors_analyzer.generate_findings()
            self.all_findings.extend(cors_findings)
            self.logger.debug("Generated CORS findings", count=len(cors_findings))
        
        # Generate security headers findings
        if self.config.security_headers.enabled:
            headers_findings = self.security_headers_analyzer.generate_findings()
            self.all_findings.extend(headers_findings)
            self.logger.debug("Generated security headers findings", count=len(headers_findings))
        
        self.logger.info("All findings generated", total_findings=len(self.all_findings))
    
    def get_findings(self) -> List[Finding]:
        """
        Get all findings from advanced discovery
        
        Returns:
            List of all findings
        """
        return self.all_findings.copy()
    
    def get_attack_surface(self) -> Optional[AttackSurface]:
        """
        Get complete attack surface mapping
        
        Returns:
            AttackSurface object or None if not mapped yet
        """
        return self.attack_surface
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics from all components
        
        Returns:
            Dictionary with statistics from all analysis components
        """
        stats = {
            "attack_surface_mapped": self.attack_surface is not None,
            "total_findings": len(self.all_findings),
            "high_risk_findings": len([f for f in self.all_findings 
                                     if f.severity.value in ["CRITICAL", "HIGH"]]),
            "components_enabled": {
                "framework_detection": self.config.framework_detection.enabled,
                "version_fuzzing": self.config.version_fuzzing.enabled,
                "subdomain_discovery": self.config.subdomain_discovery.enabled,
                "cors_analysis": self.config.cors_analysis.enabled,
                "security_headers": self.config.security_headers.enabled
            }
        }
        
        if self.attack_surface:
            stats.update({
                "discovered_subdomains": len(self.attack_surface.discovered_subdomains),
                "api_versions_found": len(self.attack_surface.api_versions),
                "framework_detected": self.attack_surface.detected_framework.name if self.attack_surface.detected_framework else None,
                "target_domain": self.attack_surface.target_domain
            })
        
        # Add component-specific statistics
        if self.config.framework_detection.enabled:
            stats["framework_detection"] = self.framework_detector.get_statistics()
        
        if self.config.version_fuzzing.enabled:
            stats["version_fuzzing"] = self.version_fuzzer.get_statistics()
        
        if self.config.subdomain_discovery.enabled:
            stats["subdomain_discovery"] = self.subdomain_discovery.get_statistics()
        
        if self.config.cors_analysis.enabled:
            stats["cors_analysis"] = self.cors_analyzer.get_statistics()
        
        if self.config.security_headers.enabled:
            stats["security_headers"] = self.security_headers_analyzer.get_statistics()
        
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of all components
        
        Returns:
            Health check results
        """
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "framework_detection": self.config.framework_detection.enabled,
                "version_fuzzing": self.config.version_fuzzing.enabled,
                "subdomain_discovery": self.config.subdomain_discovery.enabled,
                "cors_analyzer": self.config.cors_analysis.enabled,
                "security_headers_analyzer": self.config.security_headers.enabled
            }
        }
        
        # Test HTTP client connectivity
        try:
            client_healthy = await self.http_client.health_check()
            health_status["http_client"] = "healthy" if client_healthy else "degraded"
        except Exception as e:
            health_status["http_client"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
        
        return health_status