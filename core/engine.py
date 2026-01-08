"""
APILeak Core Engine
Main orchestrator for fuzzing and OWASP testing operations
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from uuid import uuid4

from .config import APILeakConfig, ConfigurationManager
from .logging import get_logger, APILeakLogger
from utils.findings import FindingsCollector, Finding


def _get_status_code_filter(config):
    """Helper function to get status code filter from configuration"""
    if hasattr(config, 'http_output') and config.http_output.status_code_filter:
        return config.http_output.status_code_filter
    return None


@dataclass
class ScanStatistics:
    """Scan execution statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    endpoints_discovered: int = 0
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0


@dataclass
class PerformanceMetrics:
    """Performance metrics for scan execution"""
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[timedelta] = None
    requests_per_second: float = 0.0
    average_response_time: float = 0.0
    memory_usage_mb: float = 0.0


@dataclass
class ScanResults:
    """Complete scan results"""
    scan_id: str
    timestamp: datetime
    target_url: str
    configuration: APILeakConfig
    statistics: ScanStatistics
    performance_metrics: PerformanceMetrics
    findings_collector: Optional[FindingsCollector] = None
    findings: List[Finding] = field(default_factory=list)  # Deprecated - use findings_collector
    fuzzing_results: Optional[Any] = None  # Will be FuzzingResults
    owasp_results: Optional[Any] = None    # Will be OWASPResults


class APILeakCore:
    """
    APILeak Core Engine - Main orchestrator for fuzzing and OWASP testing
    
    Responsibilities:
    - Orchestrate complete fuzzing and OWASP testing execution
    - Manage module lifecycle and coordination
    - Coordinate between discovery, traditional fuzzing, and specialized testing
    - Collect and aggregate results from all modules
    """
    
    def __init__(self, config: APILeakConfig):
        """
        Initialize APILeak Core Engine
        
        Args:
            config: APILeak configuration
        """
        self.config = config
        self.scan_id = str(uuid4())
        self.logger = get_logger(__name__).bind(scan_id=self.scan_id)
        
        # Initialize findings collector
        self.findings_collector = FindingsCollector(self.scan_id)
        
        # Module registries
        self.fuzzing_modules: Dict[str, Any] = {}
        self.owasp_modules: Dict[str, Any] = {}
        
        # Scan state
        self.discovered_endpoints: List[Any] = []  # Will be Endpoint objects
        self.scan_results: Optional[ScanResults] = None
        self.is_running = False
        
        self.logger.info("APILeak Core Engine initialized", 
                        target=config.target.base_url,
                        enabled_modules=config.owasp_testing.enabled_modules)
    
    async def run_scan(self, target: str) -> ScanResults:
        """
        Execute complete APILeak scan with enhanced orchestration
        
        Args:
            target: Target URL to scan
            
        Returns:
            Complete scan results
            
        Raises:
            RuntimeError: If scan is already running
            ValueError: If target is invalid
        """
        if self.is_running:
            raise RuntimeError("Scan is already running")
        
        if not target:
            raise ValueError("Target URL is required")
        
        self.is_running = True
        start_time = datetime.now()
        
        self.logger.info("Starting APILeak scan with enhanced orchestration", target=target)
        
        try:
            # Initialize scan results
            statistics = ScanStatistics()
            performance_metrics = PerformanceMetrics(start_time=start_time)
            
            self.scan_results = ScanResults(
                scan_id=self.scan_id,
                timestamp=start_time,
                target_url=target,
                configuration=self.config,
                statistics=statistics,
                performance_metrics=performance_metrics,
                findings_collector=self.findings_collector
            )
            
            # Initialize Enhanced Orchestrator
            from .orchestrator import EnhancedOrchestrator
            orchestrator = EnhancedOrchestrator(self.config, self.findings_collector)
            
            # Execute enhanced orchestration
            self.logger.info("Starting enhanced orchestration")
            orchestration_results = await orchestrator.execute_orchestration(target, self)
            
            # Store orchestration results
            self.scan_results.orchestration_results = orchestration_results
            
            # Get advanced results from orchestrator
            advanced_results = orchestrator.get_advanced_results()
            if advanced_results:
                setattr(self.scan_results, 'advanced_results', advanced_results)
            
            # Finalize performance metrics
            end_time = datetime.now()
            duration = end_time - start_time
            
            self.scan_results.performance_metrics.end_time = end_time
            self.scan_results.performance_metrics.duration = duration
            
            if statistics.total_requests > 0:
                self.scan_results.performance_metrics.requests_per_second = (
                    statistics.total_requests / duration.total_seconds()
                )
            
            self.logger.info("APILeak scan completed successfully with enhanced orchestration",
                           duration=duration.total_seconds(),
                           total_requests=statistics.total_requests,
                           findings=statistics.findings_count,
                           critical_findings=statistics.critical_findings,
                           phases_executed=len(orchestration_results.phases_executed),
                           advanced_features=len(orchestration_results.advanced_features_used))
            
            return self.scan_results
            
        except Exception as e:
            self.logger.error("Enhanced scan execution failed", error=str(e))
            raise
        finally:
            self.is_running = False
    
    async def _execute_discovery_phase(self, target: str) -> None:
        """Execute endpoint discovery phase"""
        self.logger.debug("Executing endpoint discovery phase")
        
        # Initialize fuzzing orchestrator if not already done
        if not hasattr(self, 'fuzzing_orchestrator'):
            from modules.fuzzing.orchestrator import FuzzingOrchestrator
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, UserAgentRotator
            
            # Create HTTP client for fuzzing
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(
                max_attempts=3,
                backoff_factor=2.0,
                retry_on_status=[429, 502, 503, 504]
            )
            
            # Create user agent rotator based on configuration
            user_agent_rotator = None
            headers_config = self.config.fuzzing.headers
            
            if headers_config.random_user_agent:
                user_agent_rotator = UserAgentRotator(mode="random")
            elif headers_config.user_agent_rotation and headers_config.user_agent_list:
                user_agent_rotator = UserAgentRotator(mode="rotate", user_agent_list=headers_config.user_agent_list)
            elif headers_config.custom_headers.get('User-Agent'):
                custom_ua = headers_config.custom_headers['User-Agent']
                if custom_ua != 'APILeak/0.1.0':  # Only use custom if it's not the default
                    user_agent_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
            
            # Get status code filter for HTTP output
            status_code_filter = _get_status_code_filter(self.config)
            
            http_client = HTTPRequestEngine(rate_limiter, retry_config, user_agent_rotator=user_agent_rotator, status_code_filter=status_code_filter)
            
            # Create fuzzing orchestrator
            self.fuzzing_orchestrator = FuzzingOrchestrator(
                self.config.fuzzing, 
                http_client
            )
        
        # Check if we should do endpoint discovery or just use target for parameter fuzzing
        if self.config.fuzzing.endpoints.enabled:
            # Discover endpoints using fuzzing orchestrator
            try:
                discovered_endpoints = await self.fuzzing_orchestrator.discover_endpoints(target)
                self.discovered_endpoints = discovered_endpoints
                
                self.logger.info("Endpoint discovery phase completed", 
                                endpoints_found=len(self.discovered_endpoints),
                                valid_endpoints=len([e for e in discovered_endpoints if e.status.value == "valid"]),
                                auth_required=len([e for e in discovered_endpoints if e.auth_required]))
                
            except Exception as e:
                self.logger.error("Endpoint discovery failed", error=str(e))
                self.discovered_endpoints = []
        else:
            # For parameter fuzzing mode, use the target URL directly as an endpoint
            if self.config.fuzzing.parameters.enabled:
                from modules.fuzzing.orchestrator import Endpoint
                
                # Create a synthetic endpoint from the target URL
                target_endpoint = Endpoint(
                    url=target,
                    method="GET",
                    status_code=200,  # Assume it's valid for parameter testing
                    response_size=0,
                    response_time=0.0,
                    discovered_via="target",
                    endpoint_type="parameter_target"
                )
                
                self.discovered_endpoints = [target_endpoint]
                
                self.logger.info("Using target URL for parameter fuzzing", 
                                target=target,
                                endpoints_found=1)
            else:
                self.discovered_endpoints = []
    
    async def _execute_fuzzing_phase(self) -> Any:
        """Execute traditional fuzzing phase"""
        self.logger.debug("Executing traditional fuzzing phase")
        
        # Get fuzzing orchestrator (should be initialized from discovery phase)
        if not hasattr(self, 'fuzzing_orchestrator'):
            self.logger.warning("Fuzzing orchestrator not initialized, skipping fuzzing phase")
            return {
                "endpoints_tested": 0,
                "parameters_tested": 0,
                "headers_tested": 0,
                "findings": []
            }
        
        try:
            # Execute parameter fuzzing
            parameter_findings = []
            if self.config.fuzzing.parameters.enabled:
                parameter_findings = await self.fuzzing_orchestrator.fuzz_parameters(self.discovered_endpoints)
            
            # Execute header fuzzing
            header_findings = []
            if self.config.fuzzing.headers.enabled:
                header_findings = await self.fuzzing_orchestrator.fuzz_headers(self.discovered_endpoints)
            
            # Get statistics
            stats = self.fuzzing_orchestrator.get_fuzzing_statistics()
            
            # Get parameter details if parameter fuzzing was enabled
            parameter_details = []
            if self.config.fuzzing.parameters.enabled and hasattr(self.fuzzing_orchestrator, 'parameter_fuzzer'):
                parameter_details = getattr(self.fuzzing_orchestrator.parameter_fuzzer, 'parameter_test_details', [])
            
            fuzzing_results = {
                "endpoints_tested": stats.endpoints_tested,
                "endpoints_discovered": stats.endpoints_discovered,
                "parameters_tested": stats.parameters_tested,
                "headers_tested": stats.headers_tested,
                "total_requests": stats.total_requests,
                "success_rate": stats.success_rate,
                "findings": parameter_findings + header_findings,
                "parameter_details": parameter_details
            }
            
            self.logger.info("Traditional fuzzing phase completed",
                            endpoints_tested=stats.endpoints_tested,
                            total_requests=stats.total_requests,
                            findings=len(fuzzing_results["findings"]))
            
            return fuzzing_results
            
        except Exception as e:
            self.logger.error("Fuzzing phase failed", error=str(e))
            return {
                "endpoints_tested": 0,
                "parameters_tested": 0,
                "headers_tested": 0,
                "findings": []
            }
    
    async def _execute_owasp_phase(self) -> Any:
        """Execute OWASP specialized testing phase"""
        self.logger.debug("Executing OWASP testing phase")
        
        owasp_results = {
            "modules_executed": [],
            "coverage_by_category": {},
            "findings": []
        }
        
        # Initialize OWASP modules if not already done
        if not self.owasp_modules:
            await self._initialize_owasp_modules()
        
        # Execute enabled OWASP modules
        enabled_modules = self.config.owasp_testing.enabled_modules
        
        for module_name in enabled_modules:
            if module_name in self.owasp_modules:
                try:
                    self.logger.debug("Executing OWASP module", module=module_name)
                    
                    # Execute the module
                    module = self.owasp_modules[module_name]
                    module_findings = await module.execute_tests(self.discovered_endpoints)
                    
                    # Add findings to results
                    owasp_results["findings"].extend(module_findings)
                    owasp_results["modules_executed"].append(module_name)
                    
                    # Add findings to collector
                    if module_findings:
                        self.findings_collector.add_findings(module_findings)
                    
                    self.logger.info("OWASP module completed",
                                   module=module_name,
                                   findings_count=len(module_findings))
                    
                except Exception as e:
                    self.logger.error("OWASP module execution failed",
                                    module=module_name,
                                    error=str(e))
            else:
                self.logger.warning("OWASP module not registered", module=module_name)
        
        # Execute Advanced Discovery if enabled
        if self.config.advanced_discovery.enabled:
            try:
                self.logger.info("Executing Advanced Discovery phase")
                await self._execute_advanced_discovery_phase()
                owasp_results["modules_executed"].append("advanced_discovery")
            except Exception as e:
                self.logger.error("Advanced Discovery execution failed", error=str(e))
        
        self.logger.info("OWASP testing phase completed",
                        modules_executed=len(owasp_results["modules_executed"]),
                        total_findings=len(owasp_results["findings"]))
        
        return owasp_results
    
    async def _initialize_owasp_modules(self) -> None:
        """Initialize OWASP testing modules"""
        self.logger.debug("Initializing OWASP modules")
        
        try:
            # Import OWASP modules
            from modules.owasp import (
                BOLATestingModule, 
                AuthenticationTestingModule, 
                PropertyLevelAuthModule,
                FunctionLevelAuthModule,
                ResourceConsumptionModule
            )
            
            # Create HTTP client for OWASP modules
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, UserAgentRotator
            
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(
                max_attempts=3,
                backoff_factor=2.0,
                retry_on_status=[429, 502, 503, 504]
            )
            
            # Create user agent rotator based on configuration
            user_agent_rotator = None
            headers_config = self.config.fuzzing.headers
            
            if headers_config.random_user_agent:
                user_agent_rotator = UserAgentRotator(mode="random")
            elif headers_config.user_agent_rotation and headers_config.user_agent_list:
                user_agent_rotator = UserAgentRotator(mode="rotate", user_agent_list=headers_config.user_agent_list)
            elif headers_config.custom_headers.get('User-Agent'):
                custom_ua = headers_config.custom_headers['User-Agent']
                if custom_ua != 'APILeak/0.1.0':  # Only use custom if it's not the default
                    user_agent_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
            
            # Get status code filter for HTTP output
            status_code_filter = _get_status_code_filter(self.config)
            
            http_client = HTTPRequestEngine(rate_limiter, retry_config, user_agent_rotator=user_agent_rotator, status_code_filter=status_code_filter)
            
            # Get authentication contexts
            auth_contexts = self.config.authentication.contexts
            
            # Initialize modules with their specific configurations
            if "bola" not in self.owasp_modules:
                bola_module = BOLATestingModule(self.config.owasp_testing.bola_testing, http_client, auth_contexts)
                self.register_owasp_module("bola", bola_module)
            
            if "auth" not in self.owasp_modules:
                auth_module = AuthenticationTestingModule(self.config.owasp_testing.auth_testing, http_client, auth_contexts)
                self.register_owasp_module("auth", auth_module)
            
            if "property" not in self.owasp_modules:
                property_module = PropertyLevelAuthModule(self.config.owasp_testing.property_testing, http_client, auth_contexts)
                self.register_owasp_module("property", property_module)
            
            if "function_auth" not in self.owasp_modules:
                function_auth_module = FunctionLevelAuthModule(self.config.owasp_testing.function_auth_testing, http_client, auth_contexts)
                self.register_owasp_module("function_auth", function_auth_module)
            
            if "resource" not in self.owasp_modules:
                resource_module = ResourceConsumptionModule(self.config.owasp_testing.resource_testing, http_client, auth_contexts)
                self.register_owasp_module("resource", resource_module)
            
            # Initialize Advanced Discovery Engine if enabled
            if self.config.advanced_discovery.enabled and not hasattr(self, 'advanced_discovery_engine'):
                await self._initialize_advanced_discovery()
            
            self.logger.info("OWASP modules initialized",
                           modules_count=len(self.owasp_modules))
            
        except ImportError as e:
            self.logger.error("Failed to import OWASP modules", error=str(e))
        except Exception as e:
            self.logger.error("Failed to initialize OWASP modules", error=str(e))
    
    async def _initialize_advanced_discovery(self) -> None:
        """Initialize Advanced Discovery Engine"""
        try:
            from modules.advanced import AdvancedDiscoveryEngine
            from modules.advanced.subdomain_discovery import SubdomainDiscoveryConfig
            from modules.advanced.cors_analyzer import CORSAnalyzerConfig
            from modules.advanced.security_headers_analyzer import SecurityHeadersConfig
            from modules.advanced.advanced_discovery_engine import AdvancedDiscoveryConfig
            
            # Create HTTP client for advanced discovery
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, UserAgentRotator
            
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(
                max_attempts=3,
                backoff_factor=2.0,
                retry_on_status=[429, 502, 503, 504]
            )
            
            # Create user agent rotator
            user_agent_rotator = None
            headers_config = self.config.fuzzing.headers
            
            if headers_config.random_user_agent:
                user_agent_rotator = UserAgentRotator(mode="random")
            elif headers_config.user_agent_rotation and headers_config.user_agent_list:
                user_agent_rotator = UserAgentRotator(mode="rotate", user_agent_list=headers_config.user_agent_list)
            elif headers_config.custom_headers.get('User-Agent'):
                custom_ua = headers_config.custom_headers['User-Agent']
                if custom_ua != 'APILeak/0.1.0':
                    user_agent_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
            
            # Get status code filter for HTTP output
            status_code_filter = _get_status_code_filter(self.config)
            
            http_client = HTTPRequestEngine(rate_limiter, retry_config, user_agent_rotator=user_agent_rotator, status_code_filter=status_code_filter)
            
            # Create advanced discovery configuration
            subdomain_config = SubdomainDiscoveryConfig(
                enabled=self.config.advanced_discovery.subdomain_discovery,
                wordlist=self.config.advanced_discovery.subdomain_wordlist,
                timeout=self.config.advanced_discovery.timeout,
                max_concurrent=self.config.advanced_discovery.max_concurrent
            )
            
            cors_config = CORSAnalyzerConfig(
                enabled=self.config.advanced_discovery.cors_analysis,
                test_origins=self.config.advanced_discovery.cors_test_origins,
                timeout=self.config.advanced_discovery.timeout,
                max_concurrent=self.config.advanced_discovery.max_concurrent
            )
            
            security_headers_config = SecurityHeadersConfig(
                enabled=self.config.advanced_discovery.security_headers,
                timeout=self.config.advanced_discovery.timeout,
                max_concurrent=self.config.advanced_discovery.max_concurrent
            )
            
            advanced_config = AdvancedDiscoveryConfig(
                subdomain_discovery=subdomain_config,
                cors_analysis=cors_config,
                security_headers=security_headers_config,
                timeout=self.config.advanced_discovery.timeout
            )
            
            # Initialize Advanced Discovery Engine
            self.advanced_discovery_engine = AdvancedDiscoveryEngine(advanced_config, http_client)
            
            self.logger.info("Advanced Discovery Engine initialized")
            
        except ImportError as e:
            self.logger.error("Failed to import Advanced Discovery modules", error=str(e))
        except Exception as e:
            self.logger.error("Failed to initialize Advanced Discovery Engine", error=str(e))
    
    async def _execute_advanced_discovery_phase(self) -> None:
        """Execute Advanced Discovery phase"""
        if not hasattr(self, 'advanced_discovery_engine'):
            self.logger.warning("Advanced Discovery Engine not initialized")
            return
        
        try:
            # Collect additional endpoints from discovered endpoints
            additional_endpoints = [endpoint.url for endpoint in self.discovered_endpoints]
            
            # Map attack surface
            attack_surface = await self.advanced_discovery_engine.map_attack_surface(
                target=self.config.target.base_url,
                additional_endpoints=additional_endpoints
            )
            
            # Get findings from advanced discovery
            advanced_findings = self.advanced_discovery_engine.get_findings()
            
            # Add findings to collector
            if advanced_findings:
                self.findings_collector.add_findings(advanced_findings)
            
            # Store attack surface in scan results
            if hasattr(self.scan_results, 'advanced_results'):
                self.scan_results.advanced_results = attack_surface
            else:
                # Add advanced_results attribute dynamically
                setattr(self.scan_results, 'advanced_results', attack_surface)
            
            self.logger.info("Advanced Discovery phase completed",
                           subdomains_found=len(attack_surface.discovered_subdomains),
                           total_findings=len(advanced_findings),
                           high_risk_findings=attack_surface.high_risk_findings)
            
        except Exception as e:
            self.logger.error("Advanced Discovery phase failed", error=str(e))
    
    async def _aggregate_results(self) -> None:
        """Aggregate results from all phases using enhanced findings collector"""
        self.logger.debug("Aggregating scan results with enhanced classification")
        
        # Aggregate findings from fuzzing and OWASP phases into findings collector
        if self.scan_results.fuzzing_results:
            fuzzing_findings = self.scan_results.fuzzing_results.get("findings", [])
            if fuzzing_findings:
                self.findings_collector.add_findings(fuzzing_findings)
        
        if self.scan_results.owasp_results:
            owasp_findings = self.scan_results.owasp_results.get("findings", [])
            if owasp_findings:
                self.findings_collector.add_findings(owasp_findings)
        
        # Update legacy findings list for backward compatibility
        self.scan_results.findings = self.findings_collector.findings
        
        # Add discovered endpoints to scan results
        self.scan_results.discovered_endpoints = self.discovered_endpoints
        
        # Update statistics with enhanced metrics
        collector_stats = self.findings_collector.get_statistics()
        self.scan_results.statistics.findings_count = collector_stats["total_findings"]
        self.scan_results.statistics.critical_findings = collector_stats["critical_findings"]
        self.scan_results.statistics.high_findings = collector_stats["high_findings"]
        self.scan_results.statistics.medium_findings = collector_stats["medium_findings"]
        self.scan_results.statistics.low_findings = collector_stats["low_findings"]
        self.scan_results.statistics.info_findings = collector_stats["info_findings"]
        self.scan_results.statistics.endpoints_discovered = len(self.discovered_endpoints)
        
        # Update fuzzing statistics from fuzzing results
        if self.scan_results.fuzzing_results:
            fuzzing_stats = self.scan_results.fuzzing_results
            self.scan_results.statistics.total_requests = fuzzing_stats.get("total_requests", 0)
            # Add parameters_tested to statistics if not already there
            if hasattr(self.scan_results.statistics, 'parameters_tested'):
                self.scan_results.statistics.parameters_tested = fuzzing_stats.get("parameters_tested", 0)
            else:
                # Add the attribute dynamically
                setattr(self.scan_results.statistics, 'parameters_tested', fuzzing_stats.get("parameters_tested", 0))
            
            # Add endpoints_tested to statistics
            if hasattr(self.scan_results.statistics, 'endpoints_tested'):
                self.scan_results.statistics.endpoints_tested = fuzzing_stats.get("endpoints_tested", 0)
            else:
                # Add the attribute dynamically
                setattr(self.scan_results.statistics, 'endpoints_tested', fuzzing_stats.get("endpoints_tested", 0))
        
        # Log OWASP coverage information
        owasp_coverage = self.findings_collector.get_owasp_coverage()
        self.logger.info("OWASP coverage analysis completed",
                        tested_categories=owasp_coverage["tested_categories"],
                        coverage_percentage=owasp_coverage["coverage_percentage"],
                        most_critical=collector_stats.get("most_critical_category"))
        
        self.logger.debug("Results aggregation completed",
                         total_findings=collector_stats["total_findings"],
                         unique_endpoints=collector_stats["unique_endpoints"],
                         owasp_categories=collector_stats["owasp_categories_tested"])
    
    def register_fuzzing_module(self, module_name: str, module: Any) -> None:
        """
        Register a fuzzing module
        
        Args:
            module_name: Name of the module
            module: Module instance
        """
        self.fuzzing_modules[module_name] = module
        self.logger.debug("Fuzzing module registered", module=module_name)
    
    def register_owasp_module(self, module_name: str, module: Any) -> None:
        """
        Register an OWASP testing module
        
        Args:
            module_name: Name of the module
            module: Module instance
        """
        self.owasp_modules[module_name] = module
        self.logger.debug("OWASP module registered", module=module_name)
    
    def get_findings_collector(self) -> FindingsCollector:
        """
        Get the findings collector instance
        
        Returns:
            FindingsCollector instance
        """
        return self.findings_collector
    
    def add_finding(self, category: str, severity: Optional[Any], endpoint: str, 
                   method: str, evidence: str, recommendation: str, **kwargs) -> Finding:
        """
        Add a finding directly to the collector
        
        Args:
            category: Finding category
            severity: Finding severity (auto-classified if None)
            endpoint: Affected endpoint
            method: HTTP method
            evidence: Evidence of the finding
            recommendation: Remediation recommendation
            **kwargs: Additional finding attributes
            
        Returns:
            Created finding
        """
        return self.findings_collector.add_finding(
            category=category,
            severity=severity,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            recommendation=recommendation,
            **kwargs
        )
    
    def get_discovered_endpoints(self) -> List[Any]:
        """
        Get list of discovered endpoints
        
        Returns:
            List of discovered endpoints
        """
        return self.discovered_endpoints.copy()
    
    def get_scan_status(self) -> Dict[str, Any]:
        """
        Get current scan status
        
        Returns:
            Dictionary with scan status information
        """
        status = {
            "scan_id": self.scan_id,
            "is_running": self.is_running,
            "target": self.config.target.base_url,
            "registered_fuzzing_modules": list(self.fuzzing_modules.keys()),
            "registered_owasp_modules": list(self.owasp_modules.keys()),
            "enabled_owasp_modules": self.config.owasp_testing.enabled_modules,
            "endpoints_discovered": len(self.discovered_endpoints),
            "findings_statistics": self.findings_collector.get_statistics()
        }
        
        if self.scan_results:
            status.update({
                "scan_start_time": self.scan_results.timestamp.isoformat(),
                "total_findings": self.scan_results.statistics.findings_count,
                "critical_findings": self.scan_results.statistics.critical_findings
            })
        
        return status
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the core engine
        
        Returns:
            Health check results
        """
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "scan_id": self.scan_id,
            "configuration_loaded": self.config is not None,
            "fuzzing_modules_count": len(self.fuzzing_modules),
            "owasp_modules_count": len(self.owasp_modules),
            "is_scan_running": self.is_running
        }
        
        # Check configuration validity
        config_manager = ConfigurationManager()
        config_manager.config = self.config
        validation_errors = config_manager.validate_configuration()
        
        if validation_errors:
            health_status["status"] = "degraded"
            health_status["configuration_errors"] = validation_errors
        
        self.logger.debug("Health check completed", status=health_status["status"])
        
        return health_status