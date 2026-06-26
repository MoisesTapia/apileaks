"""
Business Flows Testing Module
Implements OWASP API6 - Unrestricted Access to Sensitive Business Flows testing
"""

from typing import List, Dict, Any, Optional

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import BusinessFlowConfig, AuthContext, Severity
from core.logging import get_logger


# HTTP methods that change server state. In safe mode these are skipped so the
# module only issues non-state-changing probes (GET/HEAD/OPTIONS).
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Methods considered safe to probe with when safe mode is enabled.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Response headers that indicate rate limiting / anti-automation controls are
# present on an endpoint. If any of these are observed the flow is considered
# protected and no finding is emitted.
ANTI_AUTOMATION_HEADERS = [
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
]


class BusinessFlowsTestingModule(OWASPModule):
    """
    Business Flows Testing Module for detecting Unrestricted Access to Sensitive
    Business Flows (OWASP API6).

    The module identifies sensitive-flow endpoints (checkout, purchase, transfer,
    registration, coupon redemption, etc.) by matching their URL against the
    configured ``sensitive_flow_patterns``. For each identified flow it issues
    repeated requests up to ``repetition_limit``. If the repeated requests
    complete WITHOUT any rate limiting or anti-automation controls (no HTTP 429
    and no anti-automation headers such as Retry-After or X-RateLimit-*), it
    emits a ``BUSINESS_FLOW_NO_LIMIT`` (API6) finding.

    Safe Mode (config.safe_mode) restricts probing to non-state-changing methods
    (GET/HEAD/OPTIONS) and skips state-changing flow probes entirely.
    """

    def __init__(self, config: BusinessFlowConfig, http_client: HTTPRequestEngine,
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="business_flow")

        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}

        # Safe mode flag (optional attribute on config)
        self.safe_mode = getattr(self.config, 'safe_mode', False)

        self.logger.info("Business Flows Testing Module initialized",
                         sensitive_flow_patterns=len(getattr(config, 'sensitive_flow_patterns', [])),
                         repetition_limit=getattr(config, 'repetition_limit', 0),
                         safe_mode=self.safe_mode)

    def get_module_name(self) -> str:
        """Get module name"""
        return "business_flow"

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute business-flow tests on discovered endpoints.

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of business-flow findings. Returns [] (with no HTTP requests)
            for an empty endpoint list.
        """
        # Empty-input safety: no endpoints -> no work, no requests.
        if not endpoints:
            self.logger.info("No endpoints provided for business flow testing")
            return []

        self.logger.info("Starting business flow testing",
                         endpoints_count=len(endpoints),
                         safe_mode=self.safe_mode)

        findings: List[Finding] = []

        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])

        patterns = list(getattr(self.config, 'sensitive_flow_patterns', []) or [])
        repetition_limit = max(1, int(getattr(self.config, 'repetition_limit', 1)))

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'

            # Only test endpoints that look like a sensitive business flow.
            if not self._is_sensitive_flow(endpoint_url, patterns):
                continue

            # Honor safe mode: skip state-changing methods entirely and only
            # probe with non-state-changing methods.
            if self.safe_mode:
                if method.upper() in STATE_CHANGING_METHODS:
                    self.logger.debug("Skipping state-changing flow in safe mode",
                                      endpoint=endpoint_url, method=method)
                    continue
                if method.upper() not in SAFE_METHODS:
                    method = "GET"

            try:
                finding = await self._test_flow(endpoint_url, method, repetition_limit)
                if finding:
                    findings.append(finding)
            except Exception as e:
                self.logger.debug("Business flow endpoint test failed",
                                  endpoint=endpoint_url,
                                  error=str(e))

        self.logger.info("Business flow testing completed",
                         total_findings=len(findings),
                         high_findings=len([f for f in findings
                                            if f.severity == Severity.HIGH]))

        return findings

    def _is_sensitive_flow(self, endpoint_url: str, patterns: List[str]) -> bool:
        """Return True if the endpoint URL matches a sensitive-flow pattern."""
        if not patterns:
            return False
        lowered = endpoint_url.lower()
        return any(pattern.lower() in lowered for pattern in patterns)

    async def _test_flow(self, endpoint_url: str, method: str,
                         repetition_limit: int) -> Optional[Finding]:
        """
        Issue repeated requests against a sensitive-flow endpoint and emit a
        finding if no rate limiting / anti-automation control is observed.
        """
        successful_requests = 0
        rate_limited = False
        last_response: Optional[Response] = None

        for attempt in range(repetition_limit):
            response = await self.http_client.request(method, endpoint_url)
            last_response = response

            # HTTP 429 indicates rate limiting.
            if response.status_code == 429:
                rate_limited = True
                break

            # Anti-automation headers (Retry-After, X-RateLimit-*) indicate the
            # presence of automation controls.
            if self._has_anti_automation_headers(response.headers):
                rate_limited = True
                break

            successful_requests += 1

        if rate_limited or last_response is None:
            self.logger.debug("Rate limiting / anti-automation observed",
                              endpoint=endpoint_url,
                              successful_requests=successful_requests)
            return None

        self.logger.warning("Unrestricted sensitive business flow detected",
                            endpoint=endpoint_url,
                            method=method,
                            successful_requests=successful_requests)

        return Finding(
            id="",
            scan_id="",
            category="BUSINESS_FLOW_NO_LIMIT",
            owasp_category="API6",
            severity=Severity.HIGH,
            endpoint=endpoint_url,
            method=method,
            status_code=last_response.status_code,
            response_size=len(last_response.content) if last_response.content is not None else 0,
            response_time=last_response.elapsed,
            evidence=(f"Sensitive business flow accepted {successful_requests} repeated "
                      f"requests without rate limiting or anti-automation controls "
                      f"(no HTTP 429, no Retry-After / X-RateLimit-* headers). "
                      f"Final status: {last_response.status_code}."),
            recommendation="Protect sensitive business flows against automated abuse. Implement "
                           "rate limiting, anti-automation challenges (e.g. CAPTCHA), device "
                           "fingerprinting, or human-interaction detection on flows such as "
                           "checkout, purchase, transfer, registration, and coupon redemption.",
            payload=f"Repeated {successful_requests} requests (limit={repetition_limit})"
        )

    @staticmethod
    def _has_anti_automation_headers(headers: Optional[Dict[str, str]]) -> bool:
        """Return True if any anti-automation/rate-limit header is present."""
        if not headers:
            return False
        lowered = {str(k).lower() for k in headers.keys()}
        return any(h in lowered for h in ANTI_AUTOMATION_HEADERS)
