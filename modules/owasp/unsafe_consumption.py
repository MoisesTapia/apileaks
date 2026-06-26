"""
Unsafe Consumption Testing Module
Implements OWASP API10 - Unsafe Consumption of APIs testing
"""

from typing import List, Dict, Any, Optional, Tuple

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import UnsafeConsumptionConfig, AuthContext, Severity
from core.logging import get_logger


# HTTP methods that change server state. In safe mode these are skipped so the
# module only issues non-state-changing probes (GET/HEAD/OPTIONS).
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Methods considered safe to probe with when safe mode is enabled.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Query parameter names frequently used to carry data that originates from, or
# is forwarded to, an upstream/third-party API. Malformed values are injected
# into these parameters.
INJECTION_QUERY_PARAMS = ["q", "data", "input", "query", "search", "value", "url"]


class UnsafeConsumptionModule(OWASPModule):
    """
    Unsafe Consumption Testing Module for detecting Unsafe Consumption of APIs
    (OWASP API10).

    The module first identifies endpoints whose responses indicate they return
    data sourced from an upstream/third-party API. Identification is based on
    the configured ``upstream_indicators`` (e.g. ``proxy``, ``upstream``,
    ``external``, ``aggregate``) matched against the endpoint URL, the baseline
    response body, and response headers.

    For each endpoint identified as upstream-sourced, the module submits the
    configured ``malformed_payloads`` (e.g. prototype-pollution, XSS, SQLi, and
    null-byte values). If the endpoint reflects an unvalidated malformed payload
    verbatim in its response, it emits an ``UNSAFE_UPSTREAM_DATA`` (API10)
    finding.

    Safe Mode (config.safe_mode) restricts probing to non-state-changing methods
    (GET/HEAD/OPTIONS); state-changing endpoints are skipped and malformed input
    is only submitted via query parameters.
    """

    def __init__(self, config: UnsafeConsumptionConfig, http_client: HTTPRequestEngine,
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="unsafe_consumption")

        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}

        # Safe mode flag (optional attribute on config)
        self.safe_mode = getattr(self.config, 'safe_mode', False)

        self.logger.info("Unsafe Consumption Testing Module initialized",
                         upstream_indicators=len(getattr(config, 'upstream_indicators', [])),
                         malformed_payloads=len(getattr(config, 'malformed_payloads', [])),
                         safe_mode=self.safe_mode)

    def get_module_name(self) -> str:
        """Get module name"""
        return "unsafe_consumption"

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute unsafe-consumption tests on discovered endpoints.

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of unsafe-consumption findings. Returns [] (with no HTTP
            requests) for an empty endpoint list.
        """
        # Empty-input safety: no endpoints -> no work, no requests.
        if not endpoints:
            self.logger.info("No endpoints provided for unsafe consumption testing")
            return []

        self.logger.info("Starting unsafe consumption testing",
                         endpoints_count=len(endpoints),
                         safe_mode=self.safe_mode)

        findings: List[Finding] = []

        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])

        upstream_indicators = list(getattr(self.config, 'upstream_indicators', []) or [])
        malformed_payloads = list(getattr(self.config, 'malformed_payloads', []) or [])

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'

            # Honor safe mode: skip state-changing methods entirely and only
            # probe with non-state-changing methods.
            if self.safe_mode:
                if method.upper() in STATE_CHANGING_METHODS:
                    self.logger.debug("Skipping state-changing endpoint in safe mode",
                                      endpoint=endpoint_url, method=method)
                    continue
                if method.upper() not in SAFE_METHODS:
                    method = "GET"

            try:
                endpoint_findings = await self._test_endpoint(
                    endpoint_url, method, upstream_indicators, malformed_payloads
                )
                findings.extend(endpoint_findings)
            except Exception as e:
                self.logger.debug("Unsafe consumption endpoint test failed",
                                  endpoint=endpoint_url,
                                  error=str(e))

        self.logger.info("Unsafe consumption testing completed",
                         total_findings=len(findings),
                         high_findings=len([f for f in findings
                                            if f.severity == Severity.HIGH]))

        return findings

    async def _test_endpoint(self, endpoint_url: str, method: str,
                             upstream_indicators: List[str],
                             malformed_payloads: List[str]) -> List[Finding]:
        """
        Test a single endpoint: confirm it returns upstream-sourced data, then
        submit malformed payloads and look for unvalidated reflection.
        """
        findings: List[Finding] = []

        # Step 1: Establish a baseline response to determine whether the
        # endpoint returns data sourced from an upstream/third-party API.
        baseline = await self._probe(endpoint_url, method)
        is_upstream, indicator = self._is_upstream_sourced(
            endpoint_url, baseline, upstream_indicators
        )

        if not is_upstream:
            self.logger.debug("Endpoint not identified as upstream-sourced; skipping",
                              endpoint=endpoint_url)
            return findings

        self.logger.debug("Endpoint identified as upstream-sourced",
                          endpoint=endpoint_url, indicator=indicator)

        # Step 2: Submit malformed/unexpected input for the upstream data and
        # detect unvalidated reflection.
        state_changing = method.upper() in STATE_CHANGING_METHODS

        for payload in malformed_payloads:
            # Inject via query parameters (always available, safe for any mode).
            response = await self._probe(
                endpoint_url, method,
                params={p: payload for p in INJECTION_QUERY_PARAMS}
            )
            finding = self._analyze_reflection(
                endpoint_url, method, payload, response, indicator, "query"
            )
            if finding:
                findings.append(finding)
                # One finding per payload is sufficient evidence for this endpoint.
                continue

            # Inject via request body for state-changing methods, but only when
            # Safe Mode is disabled (state-changing probes are not allowed in
            # safe mode).
            if state_changing and not self.safe_mode:
                response = await self._probe(
                    endpoint_url, method,
                    json={"data": payload}
                )
                finding = self._analyze_reflection(
                    endpoint_url, method, payload, response, indicator, "body"
                )
                if finding:
                    findings.append(finding)

        return findings

    def _is_upstream_sourced(self, endpoint_url: str, response: Optional[Response],
                             upstream_indicators: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Determine whether an endpoint returns data sourced from an upstream API.

        An endpoint is considered upstream-sourced when any configured indicator
        appears in the endpoint URL, the baseline response body, or the response
        headers (case-insensitive).
        """
        if not upstream_indicators:
            return False, None

        # Check the endpoint URL itself.
        lowered_url = endpoint_url.lower()
        for indicator in upstream_indicators:
            if indicator.lower() in lowered_url:
                return True, indicator

        if response is None:
            return False, None

        # Check the baseline response body.
        body = self._response_text(response).lower()
        for indicator in upstream_indicators:
            if indicator.lower() in body:
                return True, indicator

        # Check response headers (keys and values).
        headers = getattr(response, 'headers', None) or {}
        header_blob = " ".join(
            f"{k} {v}" for k, v in headers.items()
        ).lower()
        for indicator in upstream_indicators:
            if indicator.lower() in header_blob:
                return True, indicator

        return False, None

    def _analyze_reflection(self, endpoint_url: str, method: str, payload: str,
                            response: Optional[Response], indicator: Optional[str],
                            injection_point: str) -> Optional[Finding]:
        """
        Emit an UNSAFE_UPSTREAM_DATA finding when a malformed payload is
        reflected verbatim (unvalidated/unsanitized) in the response body.
        """
        if response is None or not payload:
            return None

        body = self._response_text(response)
        if not body:
            return None

        # Verbatim reflection of an unsanitized malformed payload indicates the
        # upstream data was consumed and reflected without validation.
        if payload not in body:
            return None

        self.logger.warning("Unvalidated upstream data reflection detected",
                            endpoint=endpoint_url,
                            injection_point=injection_point,
                            indicator=indicator)

        indicator_note = f" (upstream indicator: '{indicator}')" if indicator else ""

        return Finding(
            id="",
            scan_id="",
            category="UNSAFE_UPSTREAM_DATA",
            owasp_category="API10",
            severity=Severity.HIGH,
            endpoint=endpoint_url,
            method=method,
            status_code=response.status_code,
            response_size=len(response.content) if response.content is not None else 0,
            response_time=response.elapsed,
            evidence=(f"Endpoint returns upstream-sourced data{indicator_note} and reflected an "
                      f"unvalidated malformed payload verbatim via {injection_point} injection. "
                      f"Reflected payload: '{payload}'. Status: {response.status_code}."),
            recommendation="Validate, sanitize, and strictly type-check all data consumed from "
                           "upstream/third-party APIs before forwarding or reflecting it. Apply "
                           "schema validation and output encoding, and do not trust data returned "
                           "by integrated services.",
            payload=f"{injection_point}={payload}"
        )

    async def _probe(self, endpoint_url: str, method: str,
                     params: Optional[Dict[str, str]] = None,
                     headers: Optional[Dict[str, str]] = None,
                     json: Optional[Dict[str, Any]] = None) -> Optional[Response]:
        """
        Issue a single probe request. Returns the Response or None on failure.
        Per-probe exceptions are logged at debug and swallowed so they do not
        abort the whole module.
        """
        try:
            kwargs: Dict[str, Any] = {}
            if params:
                kwargs['params'] = params
            if headers:
                kwargs['headers'] = headers
            if json is not None:
                kwargs['json'] = json
            return await self.http_client.request(method, endpoint_url, **kwargs)
        except Exception as e:
            self.logger.debug("Unsafe consumption probe request failed",
                              endpoint=endpoint_url,
                              method=method,
                              error=str(e))
            return None

    @staticmethod
    def _response_text(response: Response) -> str:
        """Safely extract text content from a response for matching."""
        if getattr(response, 'text', None):
            return response.text
        content = getattr(response, 'content', None)
        if content:
            try:
                return content.decode('utf-8', errors='ignore')
            except Exception:
                return ""
        return ""
