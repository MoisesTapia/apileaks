"""
APILeak Enhanced Orchestrator
Intelligent orchestration system that combines fuzzing, OWASP testing, and advanced features
"""

import asyncio
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from .logging import get_logger
from .config import APILeakConfig
from utils.findings import FindingsCollector, Finding


@dataclass
class OrchestrationPhase:
    """Represents a phase in the orchestration process"""
    name: str
    description: str
    enabled: bool = True
    dependencies: List[str] = field(default_factory=list)
    priority: int = 1  # Lower number = higher priority


@dataclass
class OrchestrationResults:
    """Results from orchestration execution"""
    phases_executed: List[str] = field(default_factory=list)
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    execution_time: float = 0.0
    advanced_features_used: List[str] = field(default_factory=list)


class EnhancedOrchestrator:
    """
    Enhanced Orchestrator for intelligent coordination of all APILeak components
    
    Responsibilities:
    - Intelligent phase ordering based on dependencies and priorities
    - Dynamic feature enablement based on configuration and discoveries
    - Progress tracking and unified reporting
    - Advanced feature integration (framework detection, WAF evasion, etc.)
    """
    
    def __init__(self, config: APILeakConfig, findings_collector: FindingsCollector):
        """
        Initialize Enhanced Orchestrator
        
        Args:
            config: APILeak configuration
            findings_collector: Findings collector instance
        """
        self.config = config
        self.findings_collector = findings_collector
        self.logger = get_logger(__name__)
        
        # Orchestration state
        self.phases: Dict[str, OrchestrationPhase] = {}
        self.execution_context: Dict[str, Any] = {}
        self.discovered_endpoints: List[Any] = []
        
        # Advanced feature state
        self.framework_detected: Optional[Any] = None
        self.waf_detected: Optional[Any] = None
        self.api_versions_found: List[str] = []
        
        self._initialize_phases()
        
        self.logger.info("Enhanced Orchestrator initialized", 
                        phases_count=len(self.phases))
    
    def _initialize_phases(self) -> None:
        """Initialize orchestration phases based on configuration"""
        
        # Phase 1: Discovery and Reconnaissance
        self.phases["discovery"] = OrchestrationPhase(
            name="discovery",
            description="Endpoint discovery and initial reconnaissance",
            enabled=self.config.fuzzing.endpoints.enabled,
            dependencies=[],
            priority=1
        )
        
        # Phase 2: Advanced Discovery (Framework Detection, Version Fuzzing)
        advanced_enabled = (
            getattr(self.config.advanced_discovery, 'framework_detection', {}).get('enabled', False) or
            getattr(self.config.advanced_discovery, 'version_fuzzing', {}).get('enabled', False)
        )
        self.phases["advanced_discovery"] = OrchestrationPhase(
            name="advanced_discovery",
            description="Framework detection and version fuzzing",
            enabled=advanced_enabled,
            dependencies=["discovery"],
            priority=2
        )
        
        # Phase 3: WAF Detection and Evasion Setup
        waf_enabled = getattr(self.config.advanced_discovery, 'waf_detection', {}).get('enabled', False)
        self.phases["waf_detection"] = OrchestrationPhase(
            name="waf_detection",
            description="WAF detection and evasion setup",
            enabled=waf_enabled,
            dependencies=["discovery"],
            priority=3
        )
        
        # Phase 4: Traditional Fuzzing (Parameters, Headers)
        fuzzing_enabled = (
            self.config.fuzzing.parameters.enabled or 
            self.config.fuzzing.headers.enabled
        )
        self.phases["traditional_fuzzing"] = OrchestrationPhase(
            name="traditional_fuzzing",
            description="Parameter and header fuzzing",
            enabled=fuzzing_enabled,
            dependencies=["discovery"],
            priority=4
        )
        
        # Phase 5: OWASP Specialized Testing
        self.phases["owasp_testing"] = OrchestrationPhase(
            name="owasp_testing",
            description="OWASP API Security Top 10 testing",
            enabled=len(self.config.owasp_testing.enabled_modules) > 0,
            dependencies=["discovery"],
            priority=5
        )
        
        # Phase 6: Advanced Security Analysis (CORS, Security Headers, Subdomain Discovery)
        security_analysis_enabled = (
            self.config.advanced_discovery.cors_analysis or
            self.config.advanced_discovery.security_headers or
            self.config.advanced_discovery.subdomain_discovery
        )
        self.phases["security_analysis"] = OrchestrationPhase(
            name="security_analysis",
            description="CORS analysis, security headers, and subdomain discovery",
            enabled=security_analysis_enabled,
            dependencies=["discovery"],
            priority=6
        )
        
        # Phase 7: Results Aggregation and Enhanced Reporting
        self.phases["results_aggregation"] = OrchestrationPhase(
            name="results_aggregation",
            description="Results aggregation and enhanced reporting",
            enabled=True,
            dependencies=["traditional_fuzzing", "owasp_testing"],
            priority=7
        )
    
    async def execute_orchestration(self, target: str, core_engine: Any) -> OrchestrationResults:
        """
        Execute intelligent orchestration of all phases
        
        Args:
            target: Target URL
            core_engine: APILeak core engine instance
            
        Returns:
            Orchestration results
        """
        start_time = datetime.now()
        results = OrchestrationResults()
        
        self.logger.info("Starting enhanced orchestration", target=target)
        
        try:
            # Get execution order based on dependencies and priorities
            execution_order = self._get_execution_order()
            
            for phase_name in execution_order:
                phase = self.phases[phase_name]
                
                if not phase.enabled:
                    self.logger.debug("Skipping disabled phase", phase=phase_name)
                    continue
                
                self.logger.info("Executing phase", phase=phase_name, description=phase.description)
                
                try:
                    await self._execute_phase(phase_name, target, core_engine)
                    results.phases_executed.append(phase_name)
                    
                    self.logger.info("Phase completed successfully", phase=phase_name)
                    
                except Exception as e:
                    self.logger.error("Phase execution failed", phase=phase_name, error=str(e))
                    # Continue with other phases unless it's a critical dependency
                    if phase_name in ["discovery"]:
                        raise  # Critical phases should stop execution
            
            # Finalize results
            execution_time = (datetime.now() - start_time).total_seconds()
            results.execution_time = execution_time
            
            # Get final statistics
            stats = self.findings_collector.get_statistics()
            results.total_findings = stats["total_findings"]
            results.critical_findings = stats["critical_findings"]
            results.high_findings = stats["high_findings"]
            
            # Track advanced features used
            if self.framework_detected:
                results.advanced_features_used.append("framework_detection")
            if self.waf_detected:
                results.advanced_features_used.append("waf_detection")
            if self.api_versions_found:
                results.advanced_features_used.append("version_fuzzing")
            
            self.logger.info("Enhanced orchestration completed successfully",
                           phases_executed=len(results.phases_executed),
                           total_findings=results.total_findings,
                           execution_time=execution_time,
                           advanced_features=len(results.advanced_features_used))
            
            return results
            
        except Exception as e:
            self.logger.error("Orchestration execution failed", error=str(e))
            raise
    
    def _get_execution_order(self) -> List[str]:
        """
        Get optimal execution order based on dependencies and priorities
        
        Returns:
            List of phase names in execution order
        """
        # Simple topological sort with priority consideration
        executed = set()
        order = []
        
        # Sort phases by priority first
        sorted_phases = sorted(self.phases.items(), key=lambda x: x[1].priority)
        
        def can_execute(phase_name: str) -> bool:
            phase = self.phases[phase_name]
            return all(dep in executed for dep in phase.dependencies)
        
        while len(order) < len([p for p in self.phases.values() if p.enabled]):
            for phase_name, phase in sorted_phases:
                if phase.enabled and phase_name not in executed and can_execute(phase_name):
                    order.append(phase_name)
                    executed.add(phase_name)
                    break
            else:
                # No more phases can be executed - check for circular dependencies
                remaining = [p for p, phase in self.phases.items() if phase.enabled and p not in executed]
                if remaining:
                    self.logger.warning("Circular dependency detected or missing dependencies", 
                                      remaining_phases=remaining)
                    # Add remaining phases anyway
                    order.extend(remaining)
                break
        
        self.logger.debug("Execution order determined", order=order)
        return order
    
    async def _execute_phase(self, phase_name: str, target: str, core_engine: Any) -> None:
        """Execute a specific orchestration phase"""
        
        if phase_name == "discovery":
            await self._execute_discovery_phase(target, core_engine)
        elif phase_name == "advanced_discovery":
            await self._execute_advanced_discovery_phase(target, core_engine)
        elif phase_name == "waf_detection":
            await self._execute_waf_detection_phase(target, core_engine)
        elif phase_name == "traditional_fuzzing":
            await self._execute_traditional_fuzzing_phase(core_engine)
        elif phase_name == "owasp_testing":
            await self._execute_owasp_testing_phase(core_engine)
        elif phase_name == "security_analysis":
            await self._execute_security_analysis_phase(target, core_engine)
        elif phase_name == "results_aggregation":
            await self._execute_results_aggregation_phase(core_engine)
        else:
            self.logger.warning("Unknown phase", phase=phase_name)
    
    async def _execute_discovery_phase(self, target: str, core_engine: Any) -> None:
        """Execute endpoint discovery phase"""
        self.logger.debug("Executing discovery phase")
        
        # Delegate to core engine's discovery implementation
        await core_engine._execute_discovery_phase(target)
        self.discovered_endpoints = core_engine.get_discovered_endpoints()
        
        # Store in execution context
        self.execution_context["discovered_endpoints"] = self.discovered_endpoints
        
        self.logger.info("Discovery phase completed", 
                        endpoints_found=len(self.discovered_endpoints))
    
    async def _execute_advanced_discovery_phase(self, target: str, core_engine: Any) -> None:
        """Execute advanced discovery phase (framework detection, version fuzzing)"""
        self.logger.debug("Executing advanced discovery phase")
        
        try:
            # Framework Detection
            if getattr(self.config.advanced_discovery, 'framework_detection', {}).get('enabled', False):
                await self._execute_framework_detection(target, core_engine)
            
            # Version Fuzzing
            if getattr(self.config.advanced_discovery, 'version_fuzzing', {}).get('enabled', False):
                await self._execute_version_fuzzing(target, core_engine)
            
        except Exception as e:
            self.logger.error("Advanced discovery phase failed", error=str(e))
            # Don't fail the entire orchestration for advanced features
    
    async def _execute_framework_detection(self, target: str, core_engine: Any) -> None:
        """Execute framework detection"""
        try:
            from modules.advanced.framework_detector import FrameworkDetector
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
            
            # Create HTTP client for framework detection
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(max_attempts=3, backoff_factor=2.0)
            http_client = HTTPRequestEngine(rate_limiter, retry_config)
            
            # Initialize framework detector
            framework_detector = FrameworkDetector(http_client)
            
            # Detect framework
            framework_info = await framework_detector.detect_framework(target)
            
            if framework_info:
                self.framework_detected = framework_info
                self.execution_context["framework_detected"] = framework_info
                
                # Add framework detection finding
                finding = self.findings_collector.add_finding(
                    category="FRAMEWORK_DETECTION",
                    severity=None,  # Will be auto-classified as INFO
                    endpoint=target,
                    method="GET",
                    evidence=f"Framework detected: {framework_info.name} (confidence: {framework_info.confidence:.2f})",
                    recommendation="Consider framework-specific security testing"
                )
                
                self.logger.info("Framework detected", 
                               framework=framework_info.name,
                               confidence=framework_info.confidence)
            
        except ImportError:
            self.logger.warning("Framework detector module not available")
        except Exception as e:
            self.logger.error("Framework detection failed", error=str(e))
    
    async def _execute_version_fuzzing(self, target: str, core_engine: Any) -> None:
        """Execute API version fuzzing"""
        try:
            from modules.advanced.version_fuzzer import VersionFuzzer
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
            
            # Create HTTP client for version fuzzing
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(max_attempts=3, backoff_factor=2.0)
            http_client = HTTPRequestEngine(rate_limiter, retry_config)
            
            # Get version patterns from config
            version_patterns = getattr(self.config.advanced_discovery, 'version_fuzzing', {}).get('version_patterns', [
                "/v1", "/v2", "/v3", "/api/v1", "/api/v2"
            ])
            
            # Initialize version fuzzer
            version_fuzzer = VersionFuzzer(http_client, version_patterns)
            
            # Fuzz API versions
            versions_found = await version_fuzzer.fuzz_api_versions(target)
            
            if versions_found:
                self.api_versions_found = versions_found
                self.execution_context["api_versions_found"] = versions_found
                
                # Add version fuzzing findings
                for version in versions_found:
                    finding = self.findings_collector.add_finding(
                        category="API_VERSION_FOUND",
                        severity=None,  # Will be auto-classified as INFO
                        endpoint=f"{target}{version}",
                        method="GET",
                        evidence=f"API version endpoint found: {version}",
                        recommendation="Test all discovered API versions for vulnerabilities"
                    )
                
                self.logger.info("API versions found", versions=versions_found)
            
        except ImportError:
            self.logger.warning("Version fuzzer module not available")
        except Exception as e:
            self.logger.error("Version fuzzing failed", error=str(e))
    
    async def _execute_waf_detection_phase(self, target: str, core_engine: Any) -> None:
        """Execute WAF detection phase"""
        self.logger.debug("Executing WAF detection phase")
        
        try:
            from modules.advanced.waf_detector import WAFDetector
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
            
            # Create HTTP client for WAF detection
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(max_attempts=3, backoff_factor=2.0)
            http_client = HTTPRequestEngine(rate_limiter, retry_config)
            
            # Initialize WAF detector
            waf_detector = WAFDetector(http_client)
            
            # Detect WAF
            waf_info = await waf_detector.detect_waf(target)
            
            if waf_info:
                self.waf_detected = waf_info
                self.execution_context["waf_detected"] = waf_info
                
                # Add WAF detection finding
                finding = self.findings_collector.add_finding(
                    category="WAF_DETECTION",
                    severity=None,  # Will be auto-classified as INFO
                    endpoint=target,
                    method="GET",
                    evidence=f"WAF detected: {waf_info.name} (confidence: {waf_info.confidence:.2f})",
                    recommendation="Use WAF evasion techniques for testing"
                )
                
                self.logger.info("WAF detected", 
                               waf=waf_info.name,
                               confidence=waf_info.confidence)
            
        except ImportError:
            self.logger.warning("WAF detector module not available")
        except Exception as e:
            self.logger.error("WAF detection failed", error=str(e))
    
    async def _execute_traditional_fuzzing_phase(self, core_engine: Any) -> None:
        """Execute traditional fuzzing phase"""
        self.logger.debug("Executing traditional fuzzing phase")
        
        # Delegate to core engine's fuzzing implementation
        fuzzing_results = await core_engine._execute_fuzzing_phase()
        
        # Store results in execution context
        self.execution_context["fuzzing_results"] = fuzzing_results
        
        self.logger.info("Traditional fuzzing phase completed",
                        findings=len(fuzzing_results.get("findings", [])))
    
    async def _execute_owasp_testing_phase(self, core_engine: Any) -> None:
        """Execute OWASP testing phase"""
        self.logger.debug("Executing OWASP testing phase")
        
        # Delegate to core engine's OWASP implementation
        owasp_results = await core_engine._execute_owasp_phase()
        
        # Store results in execution context
        self.execution_context["owasp_results"] = owasp_results
        
        self.logger.info("OWASP testing phase completed",
                        modules_executed=len(owasp_results.get("modules_executed", [])),
                        findings=len(owasp_results.get("findings", [])))
    
    async def _execute_security_analysis_phase(self, target: str, core_engine: Any) -> None:
        """Execute security analysis phase (CORS, security headers, subdomain discovery)"""
        self.logger.debug("Executing security analysis phase")
        
        try:
            # CORS Analysis
            if self.config.advanced_discovery.cors_analysis:
                await self._execute_cors_analysis(target)
            
            # Security Headers Analysis
            if self.config.advanced_discovery.security_headers:
                await self._execute_security_headers_analysis(target)
            
            # Subdomain Discovery
            if self.config.advanced_discovery.subdomain_discovery:
                await self._execute_subdomain_discovery(target)
            
        except Exception as e:
            self.logger.error("Security analysis phase failed", error=str(e))
    
    async def _execute_cors_analysis(self, target: str) -> None:
        """Execute CORS analysis"""
        try:
            from modules.advanced.cors_analyzer import CORSAnalyzer
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
            
            # Create HTTP client
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(max_attempts=3, backoff_factor=2.0)
            http_client = HTTPRequestEngine(rate_limiter, retry_config)
            
            # Initialize CORS analyzer
            cors_analyzer = CORSAnalyzer(http_client)
            
            # Analyze CORS policy
            cors_results = await cors_analyzer.analyze_cors_policy(target)
            
            if cors_results and cors_results.get("findings"):
                for finding_data in cors_results["findings"]:
                    self.findings_collector.add_finding(**finding_data)
                
                self.logger.info("CORS analysis completed", 
                               findings=len(cors_results["findings"]))
            
        except ImportError:
            self.logger.warning("CORS analyzer module not available")
        except Exception as e:
            self.logger.error("CORS analysis failed", error=str(e))
    
    async def _execute_security_headers_analysis(self, target: str) -> None:
        """Execute security headers analysis"""
        try:
            from modules.advanced.security_headers_analyzer import SecurityHeadersAnalyzer
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
            
            # Create HTTP client
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(max_attempts=3, backoff_factor=2.0)
            http_client = HTTPRequestEngine(rate_limiter, retry_config)
            
            # Initialize security headers analyzer
            headers_analyzer = SecurityHeadersAnalyzer(http_client)
            
            # Analyze security headers
            headers_results = await headers_analyzer.analyze_security_headers(target)
            
            if headers_results and headers_results.get("findings"):
                for finding_data in headers_results["findings"]:
                    self.findings_collector.add_finding(**finding_data)
                
                self.logger.info("Security headers analysis completed", 
                               findings=len(headers_results["findings"]))
            
        except ImportError:
            self.logger.warning("Security headers analyzer module not available")
        except Exception as e:
            self.logger.error("Security headers analysis failed", error=str(e))
    
    async def _execute_subdomain_discovery(self, target: str) -> None:
        """Execute subdomain discovery"""
        try:
            from modules.advanced.subdomain_discovery import SubdomainDiscovery
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
            
            # Create HTTP client
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(max_attempts=3, backoff_factor=2.0)
            http_client = HTTPRequestEngine(rate_limiter, retry_config)
            
            # Initialize subdomain discovery
            subdomain_discovery = SubdomainDiscovery(http_client)
            
            # Discover subdomains
            subdomains_results = await subdomain_discovery.discover_subdomains(target)
            
            if subdomains_results and subdomains_results.get("findings"):
                for finding_data in subdomains_results["findings"]:
                    self.findings_collector.add_finding(**finding_data)
                
                self.logger.info("Subdomain discovery completed", 
                               findings=len(subdomains_results["findings"]))
            
        except ImportError:
            self.logger.warning("Subdomain discovery module not available")
        except Exception as e:
            self.logger.error("Subdomain discovery failed", error=str(e))
    
    async def _execute_results_aggregation_phase(self, core_engine: Any) -> None:
        """Execute results aggregation phase"""
        self.logger.debug("Executing results aggregation phase")
        
        # Delegate to core engine's aggregation implementation
        await core_engine._aggregate_results()
        
        # Add orchestration-specific context to results
        if hasattr(core_engine.scan_results, 'orchestration_context'):
            core_engine.scan_results.orchestration_context = self.execution_context
        else:
            setattr(core_engine.scan_results, 'orchestration_context', self.execution_context)
        
        self.logger.info("Results aggregation phase completed")
    
    def get_execution_context(self) -> Dict[str, Any]:
        """Get the current execution context"""
        return self.execution_context.copy()
    
    def get_advanced_results(self) -> Dict[str, Any]:
        """Get advanced features results"""
        return {
            "framework_detected": self.framework_detected,
            "waf_detected": self.waf_detected,
            "api_versions_found": self.api_versions_found,
            "execution_context": self.execution_context
        }