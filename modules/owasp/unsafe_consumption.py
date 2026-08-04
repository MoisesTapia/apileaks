"""
Unsafe Consumption Testing Module
Implements OWASP API10 - Unsafe Consumption of APIs testing

Detectors implemented
---------------------
1. UNSAFE_UPSTREAM_DATA  — unvalidated reflection of malformed payloads
   sourced from upstream/third-party APIs (verbatim reflection detection).

2. UNSAFE_BLIND_REDIRECT — API blindly follows a synthetic redirect injected
   via an upstream-sourced parameter without validating the Location target
   (OWASP API10 Scenario #2).

3. UNSAFE_CLEARTEXT_UPSTREAM — the endpoint URL uses the ``http://`` scheme,
   meaning integrations with upstream services happen over an unencrypted
   channel (OWASP API10 vector 3).
"""

from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

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

# Query parameter names that carry URL values — used for redirect-probe injection.
URL_QUERY_PARAMS = ["url", "redirect", "callback", "next", "location",
                    "target", "dest", "destination", "return", "returnUrl",
                    "redirectUrl", "forward", "link", "src", "source", "fetch"]

# HTTP redirect status codes that indicate a server-side redirect.
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# Signature fragments present in AWS IMDSv1 responses — used to detect that
# the server actually fetched and returned content from the injected URL.
REDIRECT_RESPONSE_SIGNATURES = [
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "latest/meta-data",
    "computeMetadata",
    "metadata/instance",
]


class UnsafeConsumptionModule(OWASPModule):
    """
    Unsafe Consumption Testing Module for detecting Unsafe Consumption of APIs
    (OWASP API10).

    **Detector 1 — Unvalidated upstream data reflection**
    The module first identifies endpoints whose responses indicate they return
    data sourced from an upstream/third-party API. Identification is based on
    the configured ``upstream_indicators`` (e.g. ``proxy``, ``upstream``,
    ``external``, ``aggregate``) matched against the endpoint URL, the baseline
    response body, and response headers.

    For each endpoint identified as upstream-sourced, the module submits the
    configured ``malformed_payloads`` (e.g. prototype-pollution, XSS, SQLi, and
    null-byte values). If the endpoint reflects an unvalidated malformed payload
    verbatim in its response, it emits an ``UNSAFE_UPSTREAM_DATA`` (API10 / HIGH)
    finding.

    **Detector 2 — Blind redirect following**
    For upstream-sourced endpoints that accept URL-like parameters, the module
    injects a synthetic redirect target (``config.redirect_test_url``). If the
    server issues a 3xx redirect whose Location header points at the injected
    URL, or if the response body contains a known IMDS signature (indicating the
    server fetched the injected URL), the module emits an
    ``UNSAFE_BLIND_REDIRECT`` (API10 / HIGH) finding.

    **Detector 3 — Cleartext upstream channel**
    Endpoints whose URL starts with ``http://`` (plain HTTP, no TLS) are
    flagged as ``UNSAFE_CLEARTEXT_UPSTREAM`` (API10 / MEDIUM) because
    integrations with upstream services happen over an unencrypted channel,
    enabling man-in-the-middle attacks against the aggregated data.

    **Safe Mode** (``config.safe_mode``) restricts probing to non-state-changing
    methods (GET/HEAD/OPTIONS); state-changing endpoints are skipped and
    malformed input is only submitted via query parameters.
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

        # Feature flags read from config with safe fallbacks so older config
        # objects that lack the new fields still work without crashing.
        self.check_redirects = getattr(self.config, 'check_redirects', True)
        self.redirect_test_url = getattr(
            self.config, 'redirect_test_url',
            "http://169.254.169.254/latest/meta-data/"
        )
        self.check_cleartext_upstream = getattr(
            self.config, 'check_cleartext_upstream', True
        )

        self.logger.info(
            "Unsafe Consumption Testing Module initialized",
            upstream_indicators=len(getattr(config, 'upstream_indicators', [])),
            malformed_payloads=len(getattr(config, 'malformed_payloads', [])),
            check_redirects=self.check_redirects,
            check_cleartext_upstream=self.check_cleartext_upstream,
            safe_mode=self.safe_mode,
        )

    def get_module_name(self) -> str:
        """Get module name"""
        return "unsafe_consumption"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute unsafe-consumption tests on discovered endpoints.

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of unsafe-consumption findings. Returns [] (with no HTTP
            requests) for an empty endpoint list.
        """
        if not endpoints:
            self.logger.info("No endpoints provided for unsafe consumption testing")
            return []

        self.logger.info(
            "Starting unsafe consumption testing",
            endpoints_count=len(endpoints),
            safe_mode=self.safe_mode,
        )

        findings: List[Finding] = []

        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])

        upstream_indicators = list(getattr(self.config, 'upstream_indicators', []) or [])
        malformed_payloads = list(getattr(self.config, 'malformed_payloads', []) or [])

        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'

            # ── Detector 3: cleartext upstream channel ─────────────────
            # Checked regardless of upstream-sourced status or safe mode —
            # the plain-HTTP signal comes from the URL itself, not a probe.
            if self.check_cleartext_upstream:
                cleartext_finding = self._check_cleartext_channel(endpoint_url, method)
                if cleartext_finding:
                    findings.append(cleartext_finding)

            # Honor safe mode: skip state-changing methods entirely and only
            # probe with non-state-changing methods.
            if self.safe_mode:
                if method.upper() in STATE_CHANGING_METHODS:
                    self.logger.debug(
                        "Skipping state-changing endpoint in safe mode",
                        endpoint=endpoint_url, method=method,
                    )
                    continue
                if method.upper() not in SAFE_METHODS:
                    method = "GET"

            try:
                endpoint_findings = await self._test_endpoint(
                    endpoint_url, method, upstream_indicators, malformed_payloads
                )
                findings.extend(endpoint_findings)
            except Exception as e:
                self.logger.debug(
                    "Unsafe consumption endpoint test failed",
                    endpoint=endpoint_url,
                    error=str(e),
                )

        self.logger.info(
            "Unsafe consumption testing completed",
            total_findings=len(findings),
            high_findings=len([f for f in findings if f.severity == Severity.HIGH]),
        )

        return findings

    # ------------------------------------------------------------------
    # Per-endpoint orchestration
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        endpoint_url: str,
        method: str,
        upstream_indicators: List[str],
        malformed_payloads: List[str],
    ) -> List[Finding]:
        """
        Test a single endpoint:
          1. Confirm it returns upstream-sourced data (baseline probe).
          2. Submit malformed payloads and look for unvalidated reflection
             (Detector 1).
          3. Inject a synthetic redirect URL and detect blind following
             (Detector 2).
        """
        findings: List[Finding] = []

        # ── Step 1: baseline to establish upstream-sourced status ──────
        baseline = await self._probe(endpoint_url, method)
        is_upstream, indicator = self._is_upstream_sourced(
            endpoint_url, baseline, upstream_indicators
        )

        if not is_upstream:
            self.logger.debug(
                "Endpoint not identified as upstream-sourced; skipping",
                endpoint=endpoint_url,
            )
            return findings

        self.logger.debug(
            "Endpoint identified as upstream-sourced",
            endpoint=endpoint_url, indicator=indicator,
        )

        state_changing = method.upper() in STATE_CHANGING_METHODS

        # ── Step 2: Detector 1 — unvalidated reflection ────────────────
        for payload in malformed_payloads:
            response = await self._probe(
                endpoint_url, method,
                params={p: payload for p in INJECTION_QUERY_PARAMS},
            )
            finding = self._analyze_reflection(
                endpoint_url, method, payload, response, indicator, "query"
            )
            if finding:
                findings.append(finding)
                continue

            if state_changing and not self.safe_mode:
                response = await self._probe(
                    endpoint_url, method,
                    json={"data": payload},
                )
                finding = self._analyze_reflection(
                    endpoint_url, method, payload, response, indicator, "body"
                )
                if finding:
                    findings.append(finding)

        # ── Step 3: Detector 2 — blind redirect following ──────────────
        if self.check_redirects:
            redirect_finding = await self._test_blind_redirect(
                endpoint_url, method, indicator
            )
            if redirect_finding:
                findings.append(redirect_finding)

        return findings

    # ------------------------------------------------------------------
    # Detector 1 helpers — unvalidated upstream data reflection
    # ------------------------------------------------------------------

    def _is_upstream_sourced(
        self,
        endpoint_url: str,
        response: Optional[Response],
        upstream_indicators: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine whether an endpoint returns data sourced from an upstream API.

        An endpoint is considered upstream-sourced when any configured indicator
        appears in the endpoint URL, the baseline response body, or the response
        headers (case-insensitive).
        """
        if not upstream_indicators:
            return False, None

        lowered_url = endpoint_url.lower()
        for indicator in upstream_indicators:
            if indicator.lower() in lowered_url:
                return True, indicator

        if response is None:
            return False, None

        body = self._response_text(response).lower()
        for indicator in upstream_indicators:
            if indicator.lower() in body:
                return True, indicator

        headers = getattr(response, 'headers', None) or {}
        header_blob = " ".join(f"{k} {v}" for k, v in headers.items()).lower()
        for indicator in upstream_indicators:
            if indicator.lower() in header_blob:
                return True, indicator

        return False, None

    def _analyze_reflection(
        self,
        endpoint_url: str,
        method: str,
        payload: str,
        response: Optional[Response],
        indicator: Optional[str],
        injection_point: str,
    ) -> Optional[Finding]:
        """
        Emit an UNSAFE_UPSTREAM_DATA finding when a malformed payload is
        reflected verbatim (unvalidated/unsanitized) in the response body.
        """
        if response is None or not payload:
            return None

        body = self._response_text(response)
        if not body:
            return None

        if payload not in body:
            return None

        self.logger.warning(
            "Unvalidated upstream data reflection detected",
            endpoint=endpoint_url,
            injection_point=injection_point,
            indicator=indicator,
        )

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
            evidence=(
                f"Endpoint returns upstream-sourced data{indicator_note} and reflected an "
                f"unvalidated malformed payload verbatim via {injection_point} injection. "
                f"Reflected payload: '{payload}'. Status: {response.status_code}."
            ),
            recommendation=(
                "Validate, sanitize, and strictly type-check all data consumed from "
                "upstream/third-party APIs before forwarding or reflecting it. Apply "
                "schema validation and output encoding, and do not trust data returned "
                "by integrated services."
            ),
            payload=f"{injection_point}={payload}",
        )

    # ------------------------------------------------------------------
    # Detector 2 — blind redirect following (OWASP API10 Scenario #2)
    # ------------------------------------------------------------------

    async def _test_blind_redirect(
        self,
        endpoint_url: str,
        method: str,
        indicator: Optional[str],
    ) -> Optional[Finding]:
        """
        Detect whether the endpoint blindly follows a synthetic redirect
        injected into URL-carrying query parameters.

        The probe injects ``self.redirect_test_url`` into each URL-like query
        parameter in turn. A finding is emitted when:
          - the server responds with a 3xx status whose ``Location`` header
            points at the injected URL (the server is issuing the redirect
            itself, meaning it passed the URL through), **or**
          - the response body contains a known IMDS/cloud-metadata signature
            (indicating the server fetched the injected URL and returned its
            content).
        """
        if not self.redirect_test_url:
            return None

        for param in URL_QUERY_PARAMS:
            response = await self._probe(
                endpoint_url, method,
                params={param: self.redirect_test_url},
            )
            if response is None:
                continue

            finding = self._analyze_blind_redirect(
                endpoint_url, method, param, response, indicator
            )
            if finding:
                return finding

        return None

    def _analyze_blind_redirect(
        self,
        endpoint_url: str,
        method: str,
        param: str,
        response: Response,
        indicator: Optional[str],
    ) -> Optional[Finding]:
        """
        Analyse a single redirect-probe response and emit
        ``UNSAFE_BLIND_REDIRECT`` when evidence of blind following is found.

        Two signals are checked:
        1. 3xx status with a ``Location`` header that contains the injected URL.
        2. Response body contains a known IMDS/cloud-metadata content signature
           (the server fetched the injected resource and returned its body).
        """
        evidence_signal: Optional[str] = None

        # Signal 1: server issued a redirect whose Location echoes our payload.
        if response.status_code in REDIRECT_STATUS_CODES:
            headers = getattr(response, 'headers', None) or {}
            location = headers.get('location') or headers.get('Location') or ""
            if self.redirect_test_url in location:
                evidence_signal = (
                    f"Server responded with HTTP {response.status_code} and "
                    f"Location: {location} — the injected redirect target was "
                    f"forwarded without validation."
                )

        # Signal 2: response body reveals the server fetched the injected URL.
        if evidence_signal is None:
            body = self._response_text(response).lower()
            for sig in REDIRECT_RESPONSE_SIGNATURES:
                if sig.lower() in body:
                    evidence_signal = (
                        f"Response body contains '{sig}' — the server appears to have "
                        f"fetched the injected redirect target "
                        f"({self.redirect_test_url}) and returned its content."
                    )
                    break

        if evidence_signal is None:
            return None

        self.logger.warning(
            "Blind redirect following detected",
            endpoint=endpoint_url,
            param=param,
            redirect_url=self.redirect_test_url,
        )

        indicator_note = f" (upstream indicator: '{indicator}')" if indicator else ""

        return Finding(
            id="",
            scan_id="",
            category="UNSAFE_BLIND_REDIRECT",
            owasp_category="API10",
            severity=Severity.HIGH,
            endpoint=endpoint_url,
            method=method,
            status_code=response.status_code,
            response_size=len(response.content) if response.content is not None else 0,
            response_time=response.elapsed,
            evidence=(
                f"Endpoint{indicator_note} blindly follows redirects injected via "
                f"the '{param}' parameter without validating the redirect target. "
                f"{evidence_signal}"
            ),
            recommendation=(
                "Do not blindly follow redirects from upstream APIs or user-supplied URLs. "
                "Maintain an allowlist of permitted redirect destinations and reject any "
                "Location target that is not on the list. Log and alert on unexpected "
                "redirect attempts."
            ),
            payload=f"{param}={self.redirect_test_url}",
        )

    # ------------------------------------------------------------------
    # Detector 3 — cleartext upstream channel (no TLS)
    # ------------------------------------------------------------------

    def _check_cleartext_channel(
        self, endpoint_url: str, method: str
    ) -> Optional[Finding]:
        """
        Flag the endpoint as ``UNSAFE_CLEARTEXT_UPSTREAM`` when its URL uses
        the plain ``http://`` scheme, meaning all traffic with the upstream
        service is transmitted in the clear (susceptible to MitM).

        This is a static check — no HTTP probe is needed.
        """
        if not endpoint_url:
            return None

        parsed = urlparse(endpoint_url)
        if parsed.scheme.lower() != "http":
            return None

        self.logger.warning(
            "Cleartext upstream channel detected",
            endpoint=endpoint_url,
            scheme=parsed.scheme,
        )

        return Finding(
            id="",
            scan_id="",
            category="UNSAFE_CLEARTEXT_UPSTREAM",
            owasp_category="API10",
            severity=Severity.MEDIUM,
            endpoint=endpoint_url,
            method=method,
            status_code=0,
            response_size=0,
            response_time=0.0,
            evidence=(
                f"Endpoint '{endpoint_url}' communicates with an upstream/third-party "
                f"service over an unencrypted HTTP channel (scheme: '{parsed.scheme}'). "
                f"Data exchanged with the upstream service is exposed to interception "
                f"and tampering by network-layer attackers."
            ),
            recommendation=(
                "Ensure all interactions with upstream/third-party APIs use HTTPS (TLS). "
                "Replace http:// with https:// and verify the upstream service's TLS "
                "certificate. Do not disable certificate verification."
            ),
            payload=None,
        )

    # ------------------------------------------------------------------
    # Shared probe helper
    # ------------------------------------------------------------------

    async def _probe(
        self,
        endpoint_url: str,
        method: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Optional[Response]:
        """
        Issue a single probe request. Returns the Response or None on failure.
        Per-probe exceptions are logged at debug level and swallowed so they do
        not abort the whole module.
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
            self.logger.debug(
                "Unsafe consumption probe request failed",
                endpoint=endpoint_url,
                method=method,
                error=str(e),
            )
            return None

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

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
