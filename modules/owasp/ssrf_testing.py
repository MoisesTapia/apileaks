"""
SSRF Testing Module
Implements OWASP API7 - Server Side Request Forgery testing
"""

import re
from typing import List, Dict, Any, Optional, Tuple

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import SSRFConfig, AuthContext, Severity
from core.logging import get_logger


# HTTP methods that change server state. In safe mode these are skipped so that
# the module only issues non-state-changing probes (GET/HEAD).
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Methods considered safe to probe with when safe mode is enabled.
SAFE_METHODS = {"GET", "HEAD"}

# Headers commonly used by servers to determine an upstream/forwarded host and
# therefore prone to SSRF when reflected into outbound requests.
SSRF_PRONE_HEADERS = [
    "X-Forwarded-For",
    "Referer",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
]

# Query parameter names that frequently carry a URL/host the server will fetch.
SSRF_QUERY_PARAMS = ["url", "uri", "target", "dest", "redirect", "host"]

# Signatures that indicate cloud metadata or internal-host content was reached.
INTERNAL_TARGET_SIGNATURES = [
    "ami-id",
    "instance-id",
    "instance-action",
    "iam/security-credentials",
    "meta-data",
    "computeMetadata",
    "metadata.google.internal",
    "access_token",
    "security-credentials",
    "local-hostname",
    "public-ipv4",
]

# Signatures that indicate file-system content was returned (e.g. /etc/passwd,
# directory listings) via a file:// or ftp:// payload.
FILE_PROTOCOL_SIGNATURES = [
    "root:x:",
    "root:",
    "daemon:",
    "bin:x:",
    "nobody:",
    "/bin/bash",
    "/usr/sbin/nologin",
    "Index of /",
    "Directory listing for",
]


class SSRFTestingModule(OWASPModule):
    """
    SSRF Testing Module for detecting Server Side Request Forgery (OWASP API7).

    For each endpoint the module injects internal targets (e.g. cloud metadata
    endpoints, loopback hosts) and file-protocol payloads into query parameters
    and SSRF-prone request headers. It emits:
      - SSRF_INTERNAL_ACCESS when internal/metadata content is reachable.
      - FILE_PROTOCOL_ACCESS when file-system content is returned.

    Safe Mode (config.safe_mode) restricts probing to non-state-changing
    methods (GET/HEAD) and skips state-changing methods entirely.
    """

    def __init__(self, config: SSRFConfig, http_client: HTTPRequestEngine,
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="ssrf")

        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}

        # Safe mode flag (optional attribute on config)
        self.safe_mode = getattr(self.config, 'safe_mode', False)

        self.logger.info("SSRF Testing Module initialized",
                         internal_targets=len(getattr(config, 'internal_targets', [])),
                         file_protocols=len(getattr(config, 'file_protocols', [])),
                         safe_mode=self.safe_mode)

    def get_module_name(self) -> str:
        """Get module name"""
        return "ssrf"

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute SSRF tests on discovered endpoints.

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of SSRF findings. Returns [] (with no HTTP requests) for an
            empty endpoint list.
        """
        # Empty-input safety: no endpoints -> no work, no requests.
        if not endpoints:
            self.logger.info("No endpoints provided for SSRF testing")
            return []

        self.logger.info("Starting SSRF testing",
                         endpoints_count=len(endpoints),
                         safe_mode=self.safe_mode)

        findings: List[Finding] = []

        # Use first available auth context for testing
        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])

        internal_targets = list(getattr(self.config, 'internal_targets', []) or [])
        file_protocols = list(getattr(self.config, 'file_protocols', []) or [])

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
                    endpoint_url, method, internal_targets, file_protocols
                )
                findings.extend(endpoint_findings)
            except Exception as e:
                self.logger.debug("SSRF endpoint test failed",
                                  endpoint=endpoint_url,
                                  error=str(e))

        self.logger.info("SSRF testing completed",
                         total_findings=len(findings),
                         critical_findings=len([f for f in findings
                                                if f.severity == Severity.CRITICAL]))

        return findings

    async def _test_endpoint(self, endpoint_url: str, method: str,
                             internal_targets: List[str],
                             file_protocols: List[str]) -> List[Finding]:
        """
        Test a single endpoint by injecting internal targets and file protocols
        into query parameters and SSRF-prone headers.
        """
        findings: List[Finding] = []

        # 1. Internal-target injection (query params + headers)
        for target in internal_targets:
            payload = self._build_internal_payload(target)

            # Inject via query parameters
            result = await self._probe(endpoint_url, method, params={p: payload for p in SSRF_QUERY_PARAMS})
            finding = self._analyze_internal_response(endpoint_url, method, payload, result, "query")
            if finding:
                findings.append(finding)

            # Inject via SSRF-prone headers
            result = await self._probe(endpoint_url, method,
                                       headers={h: payload for h in SSRF_PRONE_HEADERS})
            finding = self._analyze_internal_response(endpoint_url, method, payload, result, "header")
            if finding:
                findings.append(finding)

        # 2. File-protocol injection (query params + headers)
        for protocol in file_protocols:
            payload = self._build_file_payload(protocol)

            # Inject via query parameters
            result = await self._probe(endpoint_url, method, params={p: payload for p in SSRF_QUERY_PARAMS})
            finding = self._analyze_file_response(endpoint_url, method, payload, result, "query")
            if finding:
                findings.append(finding)

            # Inject via SSRF-prone headers
            result = await self._probe(endpoint_url, method,
                                       headers={h: payload for h in SSRF_PRONE_HEADERS})
            finding = self._analyze_file_response(endpoint_url, method, payload, result, "header")
            if finding:
                findings.append(finding)

        return findings

    def _build_internal_payload(self, target: str) -> str:
        """Build a URL payload for an internal target."""
        if "://" in target:
            return target
        # Cloud-metadata hosts are typically reached over plain HTTP.
        return f"http://{target}/"

    def _build_file_payload(self, protocol: str) -> str:
        """Build a file/ftp-protocol payload pointing at a sensitive resource."""
        protocol = protocol.rstrip("/")
        if protocol.startswith("file:"):
            return f"{protocol}//etc/passwd"
        # ftp:// or other protocols
        return f"{protocol}//127.0.0.1/etc/passwd"

    async def _probe(self, endpoint_url: str, method: str,
                     params: Optional[Dict[str, str]] = None,
                     headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
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
            return await self.http_client.request(method, endpoint_url, **kwargs)
        except Exception as e:
            self.logger.debug("SSRF probe request failed",
                              endpoint=endpoint_url,
                              method=method,
                              error=str(e))
            return None

    def _analyze_internal_response(self, endpoint_url: str, method: str, payload: str,
                                   response: Optional[Response],
                                   injection_point: str) -> Optional[Finding]:
        """
        Detect internal/metadata access. A finding is emitted when the response
        body contains internal-host/metadata signatures, or when an injected
        internal target yields a successful 2xx response.
        """
        if response is None:
            return None

        body = self._response_text(response)
        matched = self._match_signature(body, INTERNAL_TARGET_SIGNATURES)

        signature_hit = matched is not None
        success_hit = 200 <= response.status_code < 300

        if not (signature_hit or success_hit):
            return None

        if signature_hit:
            evidence = (f"Internal target content reached via {injection_point} injection. "
                        f"Signature matched: '{matched}'. Status: {response.status_code}.")
        else:
            evidence = (f"Injected internal target returned a successful response "
                        f"({response.status_code}) via {injection_point} injection, "
                        f"indicating the server fetched the supplied target.")

        self.logger.warning("Potential SSRF internal access detected",
                            endpoint=endpoint_url,
                            injection_point=injection_point,
                            payload=payload)

        return Finding(
            id="",
            scan_id="",
            category="SSRF_INTERNAL_ACCESS",
            owasp_category="API7",
            severity=Severity.CRITICAL,
            endpoint=endpoint_url,
            method=method,
            status_code=response.status_code,
            response_size=len(response.content) if response.content is not None else 0,
            response_time=response.elapsed,
            evidence=evidence,
            recommendation="Validate and allow-list outbound request targets. Block access to "
                           "internal/loopback and cloud-metadata addresses, disable unused URL "
                           "fetch features, and do not reflect user-controlled hosts/headers into "
                           "server-side requests.",
            payload=f"{injection_point}={payload}"
        )

    def _analyze_file_response(self, endpoint_url: str, method: str, payload: str,
                               response: Optional[Response],
                               injection_point: str) -> Optional[Finding]:
        """
        Detect file-protocol access by matching file-system content signatures
        (e.g. /etc/passwd markers, directory listings) in the response body.
        """
        if response is None:
            return None

        body = self._response_text(response)
        matched = self._match_signature(body, FILE_PROTOCOL_SIGNATURES)

        if matched is None:
            return None

        self.logger.warning("Potential file-protocol access detected",
                            endpoint=endpoint_url,
                            injection_point=injection_point,
                            payload=payload)

        return Finding(
            id="",
            scan_id="",
            category="FILE_PROTOCOL_ACCESS",
            owasp_category="API7",
            severity=Severity.CRITICAL,
            endpoint=endpoint_url,
            method=method,
            status_code=response.status_code,
            response_size=len(response.content) if response.content is not None else 0,
            response_time=response.elapsed,
            evidence=(f"File-system content returned via {injection_point} injection of a "
                      f"file/ftp-protocol payload. Signature matched: '{matched}'. "
                      f"Status: {response.status_code}."),
            recommendation="Disable support for dangerous URL schemes (file://, ftp://, gopher://, "
                           "etc.) in server-side fetchers. Allow-list permitted schemes/hosts and "
                           "reject user-supplied protocol handlers.",
            payload=f"{injection_point}={payload}"
        )

    @staticmethod
    def _response_text(response: Response) -> str:
        """Safely extract text content from a response for signature matching."""
        if getattr(response, 'text', None):
            return response.text
        content = getattr(response, 'content', None)
        if content:
            try:
                return content.decode('utf-8', errors='ignore')
            except Exception:
                return ""
        return ""

    @staticmethod
    def _match_signature(body: str, signatures: List[str]) -> Optional[str]:
        """Return the first signature found in the body (case-insensitive)."""
        if not body:
            return None
        lowered = body.lower()
        for sig in signatures:
            if sig.lower() in lowered:
                return sig
        return None
