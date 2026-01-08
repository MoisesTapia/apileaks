"""
Findings Collector
Aggregates and manages security findings from all modules
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4
import hashlib

from core.logging import get_logger
from core.config import Severity


@dataclass
class Finding:
    """Security finding data model"""
    id: str
    scan_id: str
    category: str
    owasp_category: Optional[str]
    severity: Severity
    endpoint: str
    method: str
    status_code: int
    response_size: int
    response_time: float
    evidence: str
    recommendation: str
    payload: Optional[str] = None
    response_snippet: Optional[str] = None
    headers: Dict[str, str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.timestamp is None:
            self.timestamp = datetime.now()


class FindingsCollector:
    """
    Findings Collector for aggregating security findings
    
    Manages collection, deduplication, and classification of findings
    from fuzzing and OWASP testing modules with advanced classification
    and prioritization based on OWASP API Security Top 10
    """
    
    # OWASP API Security Top 10 2023 mapping
    OWASP_CATEGORIES = {
        "API1": "Broken Object Level Authorization",
        "API2": "Broken Authentication", 
        "API3": "Broken Object Property Level Authorization",
        "API4": "Unrestricted Resource Consumption",
        "API5": "Broken Function Level Authorization",
        "API6": "Unrestricted Access to Sensitive Business Flows",
        "API7": "Server Side Request Forgery",
        "API8": "Security Misconfiguration",
        "API9": "Improper Inventory Management",
        "API10": "Unsafe Consumption of APIs"
    }
    
    # Severity classification rules based on vulnerability types
    SEVERITY_RULES = {
        # Critical vulnerabilities - immediate security risk
        "BOLA_ANONYMOUS_ACCESS": Severity.CRITICAL,
        "AUTH_BYPASS": Severity.CRITICAL,
        "PRIVILEGE_ESCALATION": Severity.CRITICAL,
        "SSRF_INTERNAL_ACCESS": Severity.CRITICAL,
        "ADMIN_ACCESS_ANONYMOUS": Severity.CRITICAL,
        "SENSITIVE_DATA_EXPOSURE": Severity.CRITICAL,
        
        # High severity - significant security risk
        "WEAK_JWT_ALGORITHM": Severity.HIGH,
        "TOKEN_NOT_EXPIRED": Severity.HIGH,
        "MASS_ASSIGNMENT": Severity.HIGH,
        "FUNCTION_LEVEL_BYPASS": Severity.HIGH,
        "CORS_MISCONFIGURATION": Severity.HIGH,
        
        # Medium severity - moderate security risk
        "MISSING_RATE_LIMITING": Severity.MEDIUM,
        "LARGE_PAYLOAD_ACCEPTED": Severity.MEDIUM,
        "MISSING_SECURITY_HEADERS": Severity.MEDIUM,
        "UNDOCUMENTED_ENDPOINT": Severity.MEDIUM,
        "PARAMETER_POLLUTION": Severity.MEDIUM,
        
        # Low severity - minor security concerns
        "INFORMATION_DISCLOSURE": Severity.LOW,
        "VERBOSE_ERROR_MESSAGES": Severity.LOW,
        "DEPRECATED_API_VERSION": Severity.LOW,
        
        # Info - informational findings
        "ENDPOINT_DISCOVERED": Severity.INFO,
        "FRAMEWORK_DETECTED": Severity.INFO,
        "API_VERSION_FOUND": Severity.INFO
    }
    
    # Category to OWASP mapping
    CATEGORY_TO_OWASP = {
        "BOLA_ANONYMOUS_ACCESS": "API1",
        "BOLA_HORIZONTAL_ESCALATION": "API1", 
        "BOLA_OBJECT_ACCESS": "API1",
        "AUTH_BYPASS": "API2",
        "WEAK_JWT_ALGORITHM": "API2",
        "TOKEN_NOT_EXPIRED": "API2",
        "SENSITIVE_DATA_EXPOSURE": "API3",
        "MASS_ASSIGNMENT": "API3",
        "UNDOCUMENTED_FIELD": "API3",
        "MISSING_RATE_LIMITING": "API4",
        "LARGE_PAYLOAD_ACCEPTED": "API4",
        "RESOURCE_EXHAUSTION": "API4",
        "ADMIN_ACCESS_ANONYMOUS": "API5",
        "FUNCTION_LEVEL_BYPASS": "API5",
        "HTTP_METHOD_BYPASS": "API5",
        "SSRF_INTERNAL_ACCESS": "API7",
        "SSRF_BLIND": "API7",
        "FILE_PROTOCOL_ACCESS": "API7",
        "CORS_MISCONFIGURATION": "API8",
        "MISSING_SECURITY_HEADERS": "API8",
        "ENDPOINT_DISCOVERED": "API9",
        "FRAMEWORK_DETECTED": "API9",
        "DEPRECATED_API_VERSION": "API9"
    }
    
    def __init__(self, scan_id: str):
        """
        Initialize Findings Collector
        
        Args:
            scan_id: Unique scan identifier
        """
        self.scan_id = scan_id
        self.findings: List[Finding] = []
        self.logger = get_logger(__name__).bind(scan_id=scan_id)
        self._deduplication_cache: Set[str] = set()
        
        self.logger.info("Findings Collector initialized with enhanced classification")
    
    def add_finding(self, 
                   category: str,
                   severity: Optional[Severity],
                   endpoint: str,
                   method: str,
                   evidence: str,
                   recommendation: str,
                   **kwargs) -> Finding:
        """
        Add a new finding with automatic classification
        
        Args:
            category: Finding category
            severity: Finding severity (if None, will be auto-classified)
            endpoint: Affected endpoint
            method: HTTP method
            evidence: Evidence of the finding
            recommendation: Remediation recommendation
            **kwargs: Additional finding attributes
            
        Returns:
            Created finding
        """
        # Auto-classify severity if not provided
        if severity is None:
            severity = self._classify_severity(category)
        
        # Auto-assign OWASP category
        owasp_category = self._get_owasp_category(category)
        
        finding = Finding(
            id=str(uuid4()),
            scan_id=self.scan_id,
            category=category,
            severity=severity,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            recommendation=recommendation,
            owasp_category=owasp_category or kwargs.get('owasp_category'),
            status_code=kwargs.get('status_code', 0),
            response_size=kwargs.get('response_size', 0),
            response_time=kwargs.get('response_time', 0.0),
            payload=kwargs.get('payload'),
            response_snippet=kwargs.get('response_snippet'),
            headers=kwargs.get('headers', {})
        )
        
        # Check for duplicates before adding
        if not self._is_duplicate(finding):
            self.findings.append(finding)
            self._add_to_deduplication_cache(finding)
            
            self.logger.info("Finding added",
                            category=category,
                            severity=severity.value,
                            endpoint=endpoint,
                            owasp_category=owasp_category)
        else:
            self.logger.debug("Duplicate finding ignored",
                             category=category,
                             endpoint=endpoint)
        
        return finding
    
    def add_findings(self, findings: List[Finding]) -> int:
        """
        Add multiple findings with deduplication
        
        Args:
            findings: List of findings to add
            
        Returns:
            Number of unique findings added
        """
        added_count = 0
        
        for finding in findings:
            finding.scan_id = self.scan_id
            
            # Auto-classify if needed
            if not finding.severity:
                finding.severity = self._classify_severity(finding.category)
            
            if not finding.owasp_category:
                finding.owasp_category = self._get_owasp_category(finding.category)
            
            # Check for duplicates
            if not self._is_duplicate(finding):
                self.findings.append(finding)
                self._add_to_deduplication_cache(finding)
                added_count += 1
        
        self.logger.info("Multiple findings processed", 
                        total_submitted=len(findings),
                        unique_added=added_count,
                        duplicates_ignored=len(findings) - added_count)
        
        return added_count
    
    def _classify_severity(self, category: str) -> Severity:
        """
        Automatically classify finding severity based on category
        
        Args:
            category: Finding category
            
        Returns:
            Classified severity level
        """
        return self.SEVERITY_RULES.get(category, Severity.MEDIUM)
    
    def _get_owasp_category(self, category: str) -> Optional[str]:
        """
        Get OWASP API Security Top 10 category for finding
        
        Args:
            category: Finding category
            
        Returns:
            OWASP category (API1-API10) or None
        """
        return self.CATEGORY_TO_OWASP.get(category)
    
    def _is_duplicate(self, finding: Finding) -> bool:
        """
        Check if finding is a duplicate
        
        Args:
            finding: Finding to check
            
        Returns:
            True if duplicate, False otherwise
        """
        # Create deduplication key based on endpoint, method, category, and evidence hash
        evidence_hash = hashlib.md5(finding.evidence.encode()).hexdigest()[:8]
        dedup_key = f"{finding.endpoint}:{finding.method}:{finding.category}:{evidence_hash}"
        
        return dedup_key in self._deduplication_cache
    
    def _add_to_deduplication_cache(self, finding: Finding) -> None:
        """
        Add finding to deduplication cache
        
        Args:
            finding: Finding to add to cache
        """
        evidence_hash = hashlib.md5(finding.evidence.encode()).hexdigest()[:8]
        dedup_key = f"{finding.endpoint}:{finding.method}:{finding.category}:{evidence_hash}"
        self._deduplication_cache.add(dedup_key)
    
    def get_findings(self, 
                    severity: Optional[Severity] = None,
                    category: Optional[str] = None,
                    owasp_category: Optional[str] = None) -> List[Finding]:
        """
        Get findings with optional filtering
        
        Args:
            severity: Filter by severity
            category: Filter by category
            owasp_category: Filter by OWASP category
            
        Returns:
            Filtered list of findings
        """
        filtered_findings = self.findings
        
        if severity:
            filtered_findings = [f for f in filtered_findings if f.severity == severity]
        
        if category:
            filtered_findings = [f for f in filtered_findings if f.category == category]
        
        if owasp_category:
            filtered_findings = [f for f in filtered_findings if f.owasp_category == owasp_category]
        
        return filtered_findings
    
    def get_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """
        Get findings grouped by severity with prioritization
        
        Returns:
            Dictionary mapping severity to findings (ordered by priority)
        """
        findings_by_severity = {
            Severity.CRITICAL.value: [],
            Severity.HIGH.value: [],
            Severity.MEDIUM.value: [],
            Severity.LOW.value: [],
            Severity.INFO.value: []
        }
        
        for finding in self.findings:
            findings_by_severity[finding.severity.value].append(finding)
        
        # Sort findings within each severity by OWASP category priority
        for severity_level in findings_by_severity:
            findings_by_severity[severity_level].sort(
                key=lambda f: self._get_owasp_priority(f.owasp_category)
            )
        
        return findings_by_severity
    
    def get_findings_by_owasp_category(self) -> Dict[str, List[Finding]]:
        """
        Get findings grouped by OWASP API Security Top 10 category
        
        Returns:
            Dictionary mapping OWASP category to findings
        """
        findings_by_owasp = {}
        
        for finding in self.findings:
            if finding.owasp_category:
                if finding.owasp_category not in findings_by_owasp:
                    findings_by_owasp[finding.owasp_category] = []
                findings_by_owasp[finding.owasp_category].append(finding)
        
        # Sort by OWASP category priority (API1 first, API10 last)
        sorted_owasp = {}
        for category in sorted(findings_by_owasp.keys(), key=self._get_owasp_priority):
            sorted_owasp[category] = findings_by_owasp[category]
        
        return sorted_owasp
    
    def _get_owasp_priority(self, owasp_category: Optional[str]) -> int:
        """
        Get priority order for OWASP categories (lower number = higher priority)
        
        Args:
            owasp_category: OWASP category (API1-API10)
            
        Returns:
            Priority number (1-10, or 99 for unknown)
        """
        if not owasp_category:
            return 99
        
        try:
            return int(owasp_category.replace("API", ""))
        except (ValueError, AttributeError):
            return 99
    
    def get_prioritized_findings(self, limit: Optional[int] = None) -> List[Finding]:
        """
        Get findings prioritized by severity and OWASP category
        
        Args:
            limit: Maximum number of findings to return
            
        Returns:
            List of findings ordered by priority (most critical first)
        """
        # Define severity priority (lower number = higher priority)
        severity_priority = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5
        }
        
        # Sort findings by severity priority, then OWASP priority
        prioritized = sorted(
            self.findings,
            key=lambda f: (
                severity_priority.get(f.severity, 99),
                self._get_owasp_priority(f.owasp_category)
            )
        )
        
        if limit:
            prioritized = prioritized[:limit]
        
        return prioritized
    
    def deduplicate_findings(self) -> int:
        """
        Remove duplicate findings (legacy method for compatibility)
        
        Returns:
            Number of duplicates removed (always 0 since deduplication is automatic)
        """
        # Deduplication is now automatic during add_finding
        # This method is kept for backward compatibility
        self.logger.debug("Deduplication called - automatic deduplication already active")
        return 0
    
    def get_owasp_coverage(self) -> Dict[str, Any]:
        """
        Get OWASP API Security Top 10 coverage analysis
        
        Returns:
            Dictionary with coverage statistics and gaps
        """
        findings_by_owasp = self.get_findings_by_owasp_category()
        
        coverage = {}
        for category, description in self.OWASP_CATEGORIES.items():
            findings_count = len(findings_by_owasp.get(category, []))
            critical_count = len([f for f in findings_by_owasp.get(category, []) 
                                if f.severity == Severity.CRITICAL])
            high_count = len([f for f in findings_by_owasp.get(category, []) 
                            if f.severity == Severity.HIGH])
            
            coverage[category] = {
                "description": description,
                "findings_count": findings_count,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "tested": findings_count > 0,
                "risk_level": self._calculate_risk_level(critical_count, high_count, findings_count)
            }
        
        # Calculate overall coverage
        tested_categories = sum(1 for cat in coverage.values() if cat["tested"])
        coverage_percentage = (tested_categories / len(self.OWASP_CATEGORIES)) * 100
        
        return {
            "categories": coverage,
            "total_categories": len(self.OWASP_CATEGORIES),
            "tested_categories": tested_categories,
            "coverage_percentage": coverage_percentage,
            "untested_categories": [cat for cat, data in coverage.items() if not data["tested"]]
        }
    
    def _calculate_risk_level(self, critical: int, high: int, total: int) -> str:
        """
        Calculate risk level for an OWASP category
        
        Args:
            critical: Number of critical findings
            high: Number of high findings
            total: Total findings
            
        Returns:
            Risk level string
        """
        if critical > 0:
            return "CRITICAL"
        elif high > 0:
            return "HIGH"
        elif total > 0:
            return "MEDIUM"
        else:
            return "NONE"
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive findings statistics
        
        Returns:
            Enhanced statistics dictionary
        """
        findings_by_severity = self.get_findings_by_severity()
        owasp_coverage = self.get_owasp_coverage()
        
        return {
            "total_findings": len(self.findings),
            "critical_findings": len(findings_by_severity[Severity.CRITICAL.value]),
            "high_findings": len(findings_by_severity[Severity.HIGH.value]),
            "medium_findings": len(findings_by_severity[Severity.MEDIUM.value]),
            "low_findings": len(findings_by_severity[Severity.LOW.value]),
            "info_findings": len(findings_by_severity[Severity.INFO.value]),
            "unique_endpoints": len(set(f.endpoint for f in self.findings)),
            "unique_categories": len(set(f.category for f in self.findings)),
            "owasp_categories_tested": owasp_coverage["tested_categories"],
            "owasp_coverage_percentage": owasp_coverage["coverage_percentage"],
            "most_critical_category": self._get_most_critical_category(),
            "deduplication_cache_size": len(self._deduplication_cache)
        }
    
    def _get_most_critical_category(self) -> Optional[str]:
        """
        Get the OWASP category with the most critical findings
        
        Returns:
            OWASP category with highest risk or None
        """
        findings_by_owasp = self.get_findings_by_owasp_category()
        
        max_critical = 0
        most_critical = None
        
        for category, findings in findings_by_owasp.items():
            critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
            if critical_count > max_critical:
                max_critical = critical_count
                most_critical = category
        
        return most_critical
    
    def export_findings_summary(self) -> Dict[str, Any]:
        """
        Export a comprehensive findings summary for reporting
        
        Returns:
            Dictionary suitable for report generation
        """
        statistics = self.get_statistics()
        owasp_coverage = self.get_owasp_coverage()
        prioritized_findings = self.get_prioritized_findings(limit=10)
        
        return {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_findings": statistics["total_findings"],
                "risk_distribution": {
                    "critical": statistics["critical_findings"],
                    "high": statistics["high_findings"], 
                    "medium": statistics["medium_findings"],
                    "low": statistics["low_findings"],
                    "info": statistics["info_findings"]
                },
                "owasp_coverage": {
                    "tested_categories": owasp_coverage["tested_categories"],
                    "total_categories": owasp_coverage["total_categories"],
                    "coverage_percentage": owasp_coverage["coverage_percentage"]
                }
            },
            "top_findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "owasp_category": f.owasp_category,
                    "severity": f.severity.value,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "evidence": f.evidence[:200] + "..." if len(f.evidence) > 200 else f.evidence
                }
                for f in prioritized_findings
            ],
            "owasp_breakdown": owasp_coverage["categories"]
        }