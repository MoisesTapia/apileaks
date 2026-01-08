"""
Subdomain Discovery Module
Discovers subdomains related to the target API for comprehensive attack surface mapping
"""

import asyncio
import socket
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from datetime import datetime
from uuid import uuid4

from core.logging import get_logger
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, Severity


@dataclass
class SubdomainResult:
    """Result of subdomain discovery"""
    subdomain: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    is_accessible: bool = False
    error: Optional[str] = None
    discovered_via: str = "wordlist"
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SubdomainDiscoveryConfig:
    """Configuration for subdomain discovery"""
    enabled: bool = True
    wordlist: List[str] = field(default_factory=lambda: [
        "api", "dev", "staging", "test", "qa", "uat", "prod", "production",
        "www", "admin", "management", "dashboard", "portal", "app", "mobile",
        "v1", "v2", "v3", "beta", "alpha", "demo", "sandbox", "internal"
    ])
    timeout: float = 5.0
    max_concurrent: int = 10
    verify_ssl: bool = False
    follow_redirects: bool = True
    dns_resolution: bool = True


class SubdomainDiscovery:
    """
    Subdomain Discovery Module
    
    Discovers subdomains related to the target API to map the complete attack surface.
    Supports common subdomain patterns and DNS resolution verification.
    
    Requirements: 18.3, 18.4
    """
    
    def __init__(self, config: SubdomainDiscoveryConfig, http_client: HTTPRequestEngine):
        """
        Initialize Subdomain Discovery
        
        Args:
            config: Subdomain discovery configuration
            http_client: HTTP client for making requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__).bind(component="subdomain_discovery")
        
        # Discovery results
        self.discovered_subdomains: List[SubdomainResult] = []
        self.accessible_subdomains: List[str] = []
        
        self.logger.info("Subdomain Discovery initialized",
                        wordlist_size=len(config.wordlist),
                        timeout=config.timeout,
                        max_concurrent=config.max_concurrent)
    
    async def discover_subdomains(self, target_domain: str) -> List[SubdomainResult]:
        """
        Discover subdomains for the target domain
        
        Args:
            target_domain: Target domain to discover subdomains for
            
        Returns:
            List of subdomain discovery results
        """
        if not self.config.enabled:
            self.logger.info("Subdomain discovery disabled")
            return []
        
        self.logger.info("Starting subdomain discovery", target=target_domain)
        
        # Parse domain from URL if needed
        if target_domain.startswith(('http://', 'https://')):
            parsed = urlparse(target_domain)
            domain = parsed.netloc
        else:
            domain = target_domain
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Generate subdomain candidates
        subdomain_candidates = self._generate_subdomain_candidates(domain)
        
        self.logger.info("Generated subdomain candidates", 
                        count=len(subdomain_candidates),
                        domain=domain)
        
        # Test subdomains concurrently
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        tasks = [
            self._test_subdomain(semaphore, subdomain, domain)
            for subdomain in subdomain_candidates
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and collect valid results
        valid_results = []
        for result in results:
            if isinstance(result, SubdomainResult):
                valid_results.append(result)
                if result.is_accessible:
                    self.accessible_subdomains.append(result.subdomain)
            elif isinstance(result, Exception):
                self.logger.warning("Subdomain test failed", error=str(result))
        
        self.discovered_subdomains = valid_results
        
        self.logger.info("Subdomain discovery completed",
                        total_tested=len(subdomain_candidates),
                        accessible_found=len(self.accessible_subdomains),
                        total_results=len(valid_results))
        
        return valid_results
    
    def _generate_subdomain_candidates(self, domain: str) -> List[str]:
        """
        Generate subdomain candidates based on wordlist
        
        Args:
            domain: Base domain
            
        Returns:
            List of subdomain candidates
        """
        candidates = []
        
        for prefix in self.config.wordlist:
            subdomain = f"{prefix}.{domain}"
            candidates.append(subdomain)
        
        return candidates
    
    async def _test_subdomain(self, semaphore: asyncio.Semaphore, 
                            subdomain: str, base_domain: str) -> SubdomainResult:
        """
        Test if a subdomain is accessible
        
        Args:
            semaphore: Concurrency control semaphore
            subdomain: Subdomain to test
            base_domain: Base domain for context
            
        Returns:
            SubdomainResult with test results
        """
        async with semaphore:
            result = SubdomainResult(subdomain=subdomain)
            
            try:
                # DNS resolution check if enabled
                if self.config.dns_resolution:
                    try:
                        ip_address = socket.gethostbyname(subdomain)
                        result.ip_address = ip_address
                        self.logger.debug("DNS resolution successful", 
                                        subdomain=subdomain, 
                                        ip=ip_address)
                    except socket.gaierror:
                        result.error = "DNS resolution failed"
                        self.logger.debug("DNS resolution failed", subdomain=subdomain)
                        return result
                
                # HTTP accessibility check
                test_urls = [f"https://{subdomain}", f"http://{subdomain}"]
                
                for url in test_urls:
                    try:
                        response = await self.http_client.request(
                            method="GET",
                            url=url,
                            timeout=self.config.timeout
                        )
                        
                        result.status_code = response.status_code
                        result.response_time = response.elapsed
                        
                        # Consider subdomain accessible if we get any response
                        # (including 4xx errors, as they indicate the server exists)
                        if response.status_code > 0:
                            result.is_accessible = True
                            
                            self.logger.info("Accessible subdomain found",
                                           subdomain=subdomain,
                                           status_code=response.status_code,
                                           response_time=response.elapsed)
                            break
                    
                    except Exception as e:
                        self.logger.debug("HTTP test failed", 
                                        subdomain=subdomain, 
                                        url=url, 
                                        error=str(e))
                        continue
                
                if not result.is_accessible:
                    result.error = "HTTP connection failed"
            
            except Exception as e:
                result.error = f"Test failed: {str(e)}"
                self.logger.error("Subdomain test error", 
                                subdomain=subdomain, 
                                error=str(e))
            
            return result
    
    def get_accessible_subdomains(self) -> List[str]:
        """
        Get list of accessible subdomains
        
        Returns:
            List of accessible subdomain URLs
        """
        return self.accessible_subdomains.copy()
    
    def get_discovery_results(self) -> List[SubdomainResult]:
        """
        Get complete discovery results
        
        Returns:
            List of all subdomain discovery results
        """
        return self.discovered_subdomains.copy()
    
    def generate_findings(self) -> List[Finding]:
        """
        Generate findings from subdomain discovery results
        
        Returns:
            List of findings related to subdomain discovery
        """
        findings = []
        
        if not self.accessible_subdomains:
            return findings
        
        # Generate finding for discovered subdomains
        accessible_count = len(self.accessible_subdomains)
        
        if accessible_count > 0:
            evidence = f"Discovered {accessible_count} accessible subdomains: {', '.join(self.accessible_subdomains[:5])}"
            if accessible_count > 5:
                evidence += f" and {accessible_count - 5} more"
            
            finding = Finding(
                id=str(uuid4()),
                scan_id="subdomain_discovery",
                category="SUBDOMAIN_DISCOVERY",
                owasp_category=None,
                severity=Severity.INFO,
                endpoint=self.accessible_subdomains[0] if self.accessible_subdomains else "",
                method="GET",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=evidence,
                recommendation="Review discovered subdomains for additional attack surface. "
                             "Ensure all subdomains are properly secured and monitored.",
                payload=None,
                response_snippet=f"Total subdomains found: {accessible_count}",
                headers={}
            )
            findings.append(finding)
        
        # Check for potentially sensitive subdomains
        sensitive_patterns = ["dev", "staging", "test", "qa", "admin", "internal", "beta", "alpha"]
        sensitive_found = []
        
        for subdomain in self.accessible_subdomains:
            for pattern in sensitive_patterns:
                if pattern in subdomain.lower():
                    sensitive_found.append(subdomain)
                    break
        
        if sensitive_found:
            finding = Finding(
                id=str(uuid4()),
                scan_id="subdomain_discovery",
                category="SENSITIVE_SUBDOMAIN_EXPOSURE",
                owasp_category="API9",  # Improper Assets Management
                severity=Severity.MEDIUM,
                endpoint=sensitive_found[0],
                method="GET",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=f"Found potentially sensitive subdomains: {', '.join(sensitive_found)}",
                recommendation="Review sensitive subdomains for proper access controls. "
                             "Development and staging environments should not be publicly accessible.",
                payload=None,
                response_snippet=f"Sensitive subdomains: {len(sensitive_found)}",
                headers={}
            )
            findings.append(finding)
        
        return findings
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get subdomain discovery statistics
        
        Returns:
            Dictionary with discovery statistics
        """
        total_tested = len(self.discovered_subdomains)
        accessible = len(self.accessible_subdomains)
        
        return {
            "total_tested": total_tested,
            "accessible_found": accessible,
            "success_rate": (accessible / total_tested * 100) if total_tested > 0 else 0,
            "dns_resolved": len([r for r in self.discovered_subdomains if r.ip_address]),
            "http_accessible": accessible,
            "average_response_time": sum(
                r.response_time for r in self.discovered_subdomains 
                if r.response_time
            ) / max(1, len([r for r in self.discovered_subdomains if r.response_time]))
        }