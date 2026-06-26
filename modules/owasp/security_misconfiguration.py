"""
Security Misconfiguration Testing Module
Implements OWASP API8 - Security Misconfiguration testing

This module detects security misconfigurations such as permissive CORS policies
and missing security headers. It reuses the existing advanced CORS analyzer and
security headers analyzer via composition rather than duplicating their logic.

Because it issues only read-style requests (GET / OPTIONS), it is inherently
Safe-Mode compatible and performs no state-changing operations against the target.
"""

from typing import List, Dict, Any

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine
from core.config import SecurityMisconfigConfig, AuthContext, Severity
from core.logging import get_logger

from modules.advanced.cors_analyzer import CORSAnalyzer, CORSAnalyzerConfig, CORSAnalysis
from modules.advanced.security_headers_analyzer import (
    SecurityHeadersAnalyzer,
    SecurityHeadersConfig,
    SecurityHeadersAnalysis,
)


class SecurityMisconfigModule(OWASPModule):
    """
    Security Misconfiguration Testing Module for detecting OWASP API8:2023 issues.

    This module implements detection for:
    - Permissive CORS policies (wildcard origins, credentials with wildcard,
      dangerous methods) -> CORS_MISCONFIGURATION findings (API8, HIGH).
    - Missing required security headers -> MISSING_SECURITY_HEADERS findings
      (API8, MEDIUM).

    It reuses the existing CORS analysis component
    (`modules/advanced/cors_analyzer.py`) and security headers analysis component
    (`modules/advanced/security_headers_analyzer.py`) through composition, sharing
    the same HTTP client. It only performs read/GET/OPTIONS requests, making it
    inherently Safe-Mode compatible.
    """

    def __init__(self, config: SecurityMisconfigConfig, http_client: HTTPRequestEngine,
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="security_misconfig")

        # Reuse the existing advanced analyzers via composition (no logic duplication).
        # The CORS analyzer performs OPTIONS preflight probes; the security headers
        # analyzer performs GET requests. Both are non-destructive (Safe-Mode safe).
        self.cors_analyzer = CORSAnalyzer(CORSAnalyzerConfig(), self.http_client)
        self.security_headers_analyzer = SecurityHeadersAnalyzer(
            self._build_security_headers_config(), self.http_client
        )

        self.logger.info("Security Misconfiguration Testing Module initialized",
                         required_headers=len(getattr(config, "required_headers", []) or []))

    def get_module_name(self) -> str:
        """Get module name"""
        return "security_misconfig"

    def _build_security_headers_config(self) -> SecurityHeadersConfig:
        """
        Build a security headers analyzer configuration whose `required` flags
        reflect the headers configured in `SecurityMisconfigConfig.required_headers`.

        Returns:
            SecurityHeadersConfig with required flags aligned to module config.
        """
        required = set(getattr(self.config, "required_headers", []) or [])

        # Start from the analyzer defaults so we keep its secure-value/pattern checks,
        # then align which headers are treated as required to our module configuration.
        default_config = SecurityHeadersConfig()
        check_headers: Dict[str, Dict[str, Any]] = {}

        for header_name, header_config in default_config.check_headers.items():
            merged = dict(header_config)
            if required:
                merged["required"] = header_name in required
            check_headers[header_name] = merged

        # Ensure any required header missing from the analyzer defaults is still checked.
        for header_name in required:
            if header_name not in check_headers:
                check_headers[header_name] = {"required": True, "weight": 10}

        return SecurityHeadersConfig(check_headers=check_headers)

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute security misconfiguration tests on discovered endpoints.

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of security misconfiguration findings
        """
        # Empty endpoint list -> no work, no HTTP requests (Requirement 3.6).
        if not endpoints:
            self.logger.info("No endpoints provided, skipping security misconfiguration testing")
            return []

        self.logger.info("Starting security misconfiguration testing",
                         endpoints_count=len(endpoints))

        endpoint_urls = self._extract_endpoint_urls(endpoints)

        findings: List[Finding] = []

        try:
            # Step 1: Analyze CORS policies (Requirement 3.3)
            cors_findings = await self._test_cors(endpoint_urls)
            findings.extend(cors_findings)
            self.logger.debug("CORS analysis completed", findings=len(cors_findings))

            # Step 2: Analyze security headers (Requirement 3.4)
            header_findings = await self._test_security_headers(endpoint_urls)
            findings.extend(header_findings)
            self.logger.debug("Security headers analysis completed", findings=len(header_findings))

        except Exception as e:
            self.logger.error("Security misconfiguration testing failed", error=str(e))
            raise

        self.logger.info("Security misconfiguration testing completed",
                         total_findings=len(findings))

        return findings

    @staticmethod
    def _extract_endpoint_urls(endpoints: List[Any]) -> List[str]:
        """
        Extract endpoint URL strings from endpoint objects.

        Args:
            endpoints: List of endpoint objects or URL strings

        Returns:
            De-duplicated list of endpoint URLs (order preserved)
        """
        urls: List[str] = []
        seen = set()
        for endpoint in endpoints:
            url = endpoint.url if hasattr(endpoint, "url") else str(endpoint)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    async def _test_cors(self, endpoint_urls: List[str]) -> List[Finding]:
        """
        Detect permissive CORS policies and emit CORS_MISCONFIGURATION findings.

        Args:
            endpoint_urls: List of endpoint URLs to analyze

        Returns:
            List of CORS_MISCONFIGURATION findings
        """
        findings: List[Finding] = []

        cors_results: Dict[str, CORSAnalysis] = await self.cors_analyzer.analyze_cors_policy(
            endpoint_urls
        )

        for endpoint, analysis in cors_results.items():
            if not self._is_permissive_cors(analysis):
                continue

            severity = self._cors_severity(analysis)
            evidence = self._cors_evidence(analysis)

            finding = Finding(
                id="",  # Will be set by findings collector
                scan_id="",
                category="CORS_MISCONFIGURATION",
                owasp_category="API8",
                severity=severity,
                endpoint=endpoint,
                method="OPTIONS",
                status_code=200,
                response_size=0,
                response_time=0.0,
                evidence=evidence,
                recommendation="Restrict the CORS policy to explicitly trusted origins. "
                               "Avoid wildcard origins (*), never combine a wildcard origin with "
                               "Access-Control-Allow-Credentials: true, and only expose the HTTP "
                               "methods that the API genuinely requires.",
                payload="Origin probing via OPTIONS preflight",
                response_snippet=evidence,
            )
            findings.append(finding)

            self.logger.warning("Permissive CORS policy detected",
                                endpoint=endpoint,
                                security_risk=analysis.security_risk,
                                wildcard_origin=analysis.wildcard_origin)

        return findings

    @staticmethod
    def _is_permissive_cors(analysis: CORSAnalysis) -> bool:
        """
        Determine whether a CORS analysis represents a permissive policy.

        A policy is considered permissive if it allows a wildcard origin, allows
        credentials together with a wildcard origin, exposes dangerous methods, or
        the analyzer rated its security risk above LOW.

        Args:
            analysis: CORS analysis result for an endpoint

        Returns:
            True if the CORS policy is permissive
        """
        return bool(
            analysis.wildcard_origin
            or analysis.credentials_allowed
            or analysis.dangerous_methods
            or analysis.security_risk in ("MEDIUM", "HIGH", "CRITICAL")
        )

    @staticmethod
    def _cors_severity(analysis: CORSAnalysis) -> Severity:
        """Map the CORS analysis risk to a finding severity (default HIGH for API8)."""
        if analysis.security_risk == "CRITICAL":
            return Severity.CRITICAL
        if analysis.security_risk == "MEDIUM":
            return Severity.MEDIUM
        # Permissive CORS misconfigurations default to HIGH (per API8 mapping).
        return Severity.HIGH

    @staticmethod
    def _cors_evidence(analysis: CORSAnalysis) -> str:
        """Build a human-readable evidence string from a CORS analysis."""
        parts = [f"Permissive CORS policy detected (risk: {analysis.security_risk})."]
        if analysis.wildcard_origin:
            parts.append("Wildcard origin (*) is allowed.")
        if analysis.credentials_allowed:
            parts.append("Credentials are allowed with a wildcard origin.")
        if analysis.dangerous_methods:
            parts.append(f"Dangerous methods allowed: {', '.join(sorted(analysis.dangerous_methods))}.")
        if analysis.allowed_origins:
            parts.append(f"Allowed origins: {', '.join(sorted(analysis.allowed_origins))}.")
        return " ".join(parts)

    async def _test_security_headers(self, endpoint_urls: List[str]) -> List[Finding]:
        """
        Detect missing required security headers and emit MISSING_SECURITY_HEADERS findings.

        Args:
            endpoint_urls: List of endpoint URLs to analyze

        Returns:
            List of MISSING_SECURITY_HEADERS findings
        """
        findings: List[Finding] = []

        header_results: Dict[str, SecurityHeadersAnalysis] = (
            await self.security_headers_analyzer.analyze_security_headers(endpoint_urls)
        )

        for endpoint, analysis in header_results.items():
            if not analysis.missing_headers:
                continue

            missing = analysis.missing_headers
            evidence = (f"Missing required security headers: {', '.join(missing)}. "
                        f"Security headers score: {analysis.security_score}%.")

            finding = Finding(
                id="",  # Will be set by findings collector
                scan_id="",
                category="MISSING_SECURITY_HEADERS",
                owasp_category="API8",
                severity=Severity.MEDIUM,
                endpoint=endpoint,
                method="GET",
                status_code=analysis.status_code,
                response_size=0,
                response_time=analysis.response_time,
                evidence=evidence,
                recommendation="Add the missing security response headers to protect against "
                               "common web vulnerabilities (e.g., Strict-Transport-Security, "
                               "X-Content-Type-Options, X-Frame-Options, Content-Security-Policy). "
                               "Refer to the OWASP Secure Headers Project for recommended values.",
                payload=None,
                response_snippet=evidence,
            )
            findings.append(finding)

            self.logger.warning("Missing security headers detected",
                                endpoint=endpoint,
                                missing_headers=missing)

        return findings
