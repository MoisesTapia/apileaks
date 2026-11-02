"""
HTTP Parameter Pollution (HPP) Testing Module

Detects inconsistent or unsafe server-side handling of duplicate request
parameters — the classic HTTP Parameter Pollution class of bugs, where
supplying the same parameter name twice (query string) or wrapped in an
array (JSON body) causes the backend to resolve it differently than either
single-valued request alone, or lets an otherwise-rejected value through.

Two independent probe sources feed this module, so it is useful with or
without live discovery:

1. **Discovered endpoints** — any GET endpoint whose URL already carries a
   query string is a candidate: each query parameter is polluted in turn.
2. **Captured traffic (Burp Suite XML / Caido or any other tool's HAR
   export)** — reuses :class:`utils.import_sources.BurpXmlImporter` and
   :class:`utils.import_sources.HarImporter`, the SAME importers
   ``modules/owasp/ssrf_testing.py`` uses for its Full_Replay_Mode. Unlike
   the SSRF module, this module is NOT restricted to "URL-like" fields: EVERY
   query parameter and EVERY JSON/form body field of a captured request is a
   pollution candidate, because parameter pollution is not SSRF-specific —
   generalizing the capture-replay mechanism beyond SSRF is the whole point
   of this module existing separately (see
   technical-debt/code-quality-audit.md "qué sigue" discussion).

Original headers, cookies, and the HTTP method of a captured request are
preserved untouched; only the one parameter under test is duplicated per
probe, exactly as SSRF's Full_Replay_Mode preserves everything except the
injected field.
"""

from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from core.config import AuthContext, ParameterPollutionConfig, Severity
from core.logging import get_logger
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Response
from utils.parameter_pollution import (
    build_form_body_pollution_variants,
    build_json_array_pollution_variants,
    build_query_pollution_variants,
    classify_pollution_response,
)
from utils.safe_mode import SafeModeGuard

from .registry import OWASPModule

# Two innocuous-looking but distinguishable values used to pollute each
# candidate parameter. Deliberately NOT payload-like (no injection strings)
# because this module tests *parameter resolution behavior*, not injection —
# the signal is purely "did the backend treat A, B, and A+B consistently?".
_VALUE_A = "apileak_pp_a"
_VALUE_B = "apileak_pp_b"

# Hard ceiling on probes issued per run, independent of how many candidate
# parameters are found, so a large discovery set or a large capture file
# cannot runaway the request count. Each candidate costs 3 requests
# (baseline A, baseline B, polluted).
_DEFAULT_MAX_CANDIDATES = 40


class ParameterPollutionModule(OWASPModule, SafeModeGuard):
    """HTTP Parameter Pollution testing across discovered and captured requests."""

    def __init__(
        self,
        config: ParameterPollutionConfig,
        http_client: HTTPRequestEngine,
        auth_contexts: list[AuthContext],
    ):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="parameter_pollution")
        self._init_safe_mode(config)

        self.max_candidates = getattr(config, "max_candidates", _DEFAULT_MAX_CANDIDATES)

        self.logger.info(
            "Parameter Pollution Testing Module initialized",
            safe_mode=self.safe_mode,
            burp_xml_path=getattr(config, "burp_xml_path", None),
            har_path=getattr(config, "har_path", None),
            max_candidates=self.max_candidates,
        )

    def get_module_name(self) -> str:
        return "parameter_pollution"

    async def execute_tests(self, endpoints: list[Any]) -> list[Finding]:
        """Run HPP probes against discovered endpoints and any imported capture.

        Args:
            endpoints: Discovered endpoints (from the fuzzing/discovery phase).

        Returns:
            List of ``HTTP_PARAMETER_POLLUTION`` findings.
        """
        self.logger.info("Starting parameter pollution testing", endpoints_count=len(endpoints))

        findings: list[Finding] = []
        probes_issued = 0

        try:
            probes_issued = await self._test_discovered_endpoints(endpoints, findings, probes_issued)
            probes_issued = await self._test_imported_requests(endpoints, findings, probes_issued)
        except Exception as e:
            self.logger.error("Parameter pollution testing failed", error=str(e))
            raise

        self.logger.info(
            "Parameter pollution testing completed",
            total_findings=len(findings),
            probes_issued=probes_issued,
        )
        return findings

    # ------------------------------------------------------------------
    # Source 1: discovered endpoints with an existing query string
    # ------------------------------------------------------------------

    async def _test_discovered_endpoints(
        self, endpoints: list[Any], findings: list[Finding], probes_issued: int
    ) -> int:
        for endpoint in endpoints:
            if probes_issued >= self.max_candidates:
                break
            url = endpoint.url if hasattr(endpoint, "url") else str(endpoint)
            method = endpoint.method if hasattr(endpoint, "method") else "GET"

            if self.skip_if_state_changing(method, "parameter_pollution_discovered"):
                continue

            query = urlsplit(url).query
            if not query:
                continue

            param_names = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
            for param in param_names:
                if probes_issued >= self.max_candidates:
                    break
                probes_issued += 1
                finding = await self._probe_query_pollution(url, method, param)
                if finding is not None:
                    findings.append(finding)

        return probes_issued

    # ------------------------------------------------------------------
    # Source 2: captured traffic (Burp Suite XML / Caido/any tool's HAR)
    # ------------------------------------------------------------------

    def _load_imported_requests(self) -> list[Any]:
        """Load captured requests from ``--burp-xml``/``--har``, if configured."""
        imported: list[Any] = []

        burp_xml_path = getattr(self.config, "burp_xml_path", None)
        if burp_xml_path:
            from utils.import_sources import BurpXmlImporter

            self.logger.info("Loading Burp XML import source", path=burp_xml_path)
            imported.extend(BurpXmlImporter(burp_xml_path).parse())

        har_path = getattr(self.config, "har_path", None)
        if har_path:
            from utils.import_sources import HarImporter

            self.logger.info("Loading HAR import source (Caido, Burp Logger, Hetty, "
                              "DevTools, Firefox all export this format)", path=har_path)
            imported.extend(HarImporter(har_path).parse())

        return imported

    async def _test_imported_requests(
        self, endpoints: list[Any], findings: list[Finding], probes_issued: int
    ) -> int:
        imported_requests = self._load_imported_requests()
        if not imported_requests:
            return probes_issued

        base_url = self._infer_base_url(endpoints)
        if not base_url:
            self.logger.warning(
                "Captured requests loaded but no base URL could be inferred "
                "(no discovered endpoints and no --target-derived base); "
                "skipping imported-request pollution probes",
                count=len(imported_requests),
            )
            return probes_issued

        for imported_req in imported_requests:
            if probes_issued >= self.max_candidates:
                break
            if self.skip_if_state_changing(imported_req.method, "parameter_pollution_imported"):
                continue

            probe_url = self._resolve_probe_url(base_url, imported_req.path)

            # Every query parameter on the captured request is a candidate —
            # not just the "URL-like" subset SSRF restricts itself to.
            query = urlsplit(probe_url).query
            if query:
                for param, _ in parse_qsl(query, keep_blank_values=True):
                    if probes_issued >= self.max_candidates:
                        break
                    probes_issued += 1
                    finding = await self._probe_query_pollution(
                        probe_url, imported_req.method, param, headers=imported_req.headers
                    )
                    if finding is not None:
                        findings.append(finding)

            # Every JSON body field is a candidate too (array-wrap probe).
            if isinstance(imported_req.body, dict):
                for field_name in list(imported_req.body.keys()):
                    if probes_issued >= self.max_candidates:
                        break
                    probes_issued += 1
                    finding = await self._probe_json_body_pollution(
                        probe_url, imported_req.method, imported_req.body, field_name,
                        headers=imported_req.headers,
                    )
                    if finding is not None:
                        findings.append(finding)
            elif imported_req.raw_body and self._is_form_urlencoded(imported_req.headers):
                # Not JSON: if the captured request carries a real
                # application/x-www-form-urlencoded body, the wire format
                # genuinely supports a duplicate key (a=1&a=2), so this is a
                # true duplicate-key HPP probe rather than the array-wrap
                # approximation JSON bodies need above.
                form_fields = dict(parse_qsl(imported_req.raw_body, keep_blank_values=True))
                for field_name in list(form_fields.keys()):
                    if probes_issued >= self.max_candidates:
                        break
                    probes_issued += 1
                    finding = await self._probe_form_body_pollution(
                        probe_url, imported_req.method, form_fields, field_name,
                        headers=imported_req.headers,
                    )
                    if finding is not None:
                        findings.append(finding)

        return probes_issued

    @staticmethod
    def _infer_base_url(endpoints: list[Any]) -> str | None:
        """Derive ``scheme://host`` from the first discovered endpoint, if any."""
        if not endpoints:
            return None
        first = endpoints[0]
        raw = first.url if hasattr(first, "url") else str(first)
        parts = urlsplit(raw)
        if not parts.scheme or not parts.netloc:
            return None
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    @staticmethod
    def _is_form_urlencoded(headers: dict[str, str]) -> bool:
        content_type = next(
            (v for k, v in headers.items() if k.lower() == "content-type"), ""
        )
        return "application/x-www-form-urlencoded" in content_type.lower()

    @staticmethod
    def _resolve_probe_url(base_url: str, path: str) -> str:
        """Join ``base_url`` with a captured request's path (which may itself
        be a full URL if the capture tool recorded it that way)."""
        parts = urlsplit(path)
        if parts.scheme and parts.netloc:
            raw_path = urlunsplit(("", "", parts.path, parts.query, ""))
        else:
            raw_path = path
        return base_url.rstrip("/") + "/" + raw_path.lstrip("/")

    # ------------------------------------------------------------------
    # Probe + analysis
    # ------------------------------------------------------------------

    async def _probe_query_pollution(
        self, url: str, method: str, param: str, headers: dict[str, str] | None = None
    ) -> Finding | None:
        url_a, url_b, url_polluted = build_query_pollution_variants(url, param, _VALUE_A, _VALUE_B)
        try:
            resp_a = await self.http_client.request(method, url_a, headers=headers or {})
            resp_b = await self.http_client.request(method, url_b, headers=headers or {})
            resp_polluted = await self.http_client.request(
                method, url_polluted, headers=headers or {}
            )
        except Exception as exc:
            self.logger.debug(
                "Query pollution probe failed", url=url, param=param, error=str(exc)
            )
            return None

        return self._build_finding_if_anomalous(
            url_polluted, method, param, "query", resp_a, resp_b, resp_polluted
        )

    async def _probe_json_body_pollution(
        self,
        url: str,
        method: str,
        body: dict[str, Any],
        field_name: str,
        headers: dict[str, str] | None = None,
    ) -> Finding | None:
        value = body.get(field_name)
        if not isinstance(value, (str, int, float, bool)) or isinstance(value, dict):
            return None  # only scalar fields make sense to pollute this way

        value_str = str(value)
        body_a, body_b, body_polluted = build_json_array_pollution_variants(
            body, field_name, value_str, _VALUE_B
        )
        req_headers = dict(headers or {})
        req_headers.setdefault("Content-Type", "application/json")

        try:
            resp_a = await self.http_client.request(method, url, headers=req_headers, json=body_a)
            resp_b = await self.http_client.request(method, url, headers=req_headers, json=body_b)
            resp_polluted = await self.http_client.request(
                method, url, headers=req_headers, json=body_polluted
            )
        except Exception as exc:
            self.logger.debug(
                "JSON body pollution probe failed", url=url, field=field_name, error=str(exc)
            )
            return None

        return self._build_finding_if_anomalous(
            url, method, field_name, "body", resp_a, resp_b, resp_polluted
        )

    async def _probe_form_body_pollution(
        self,
        url: str,
        method: str,
        form_fields: dict[str, str],
        field_name: str,
        headers: dict[str, str] | None = None,
    ) -> Finding | None:
        other_fields = {k: v for k, v in form_fields.items() if k != field_name}
        body_a, body_b, body_polluted = build_form_body_pollution_variants(
            other_fields, field_name, _VALUE_A, _VALUE_B
        )
        req_headers = dict(headers or {})
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        try:
            resp_a = await self.http_client.request(method, url, headers=req_headers, data=body_a)
            resp_b = await self.http_client.request(method, url, headers=req_headers, data=body_b)
            resp_polluted = await self.http_client.request(
                method, url, headers=req_headers, data=body_polluted
            )
        except Exception as exc:
            self.logger.debug(
                "Form body pollution probe failed", url=url, field=field_name, error=str(exc)
            )
            return None

        return self._build_finding_if_anomalous(
            url, method, field_name, "body", resp_a, resp_b, resp_polluted
        )

    def _build_finding_if_anomalous(
        self,
        endpoint: str,
        method: str,
        param: str,
        location: str,
        resp_a: Response,
        resp_b: Response,
        resp_polluted: Response,
    ) -> Finding | None:
        classification = classify_pollution_response(
            resp_a.status_code, resp_b.status_code, resp_polluted.status_code
        )
        if classification is None:
            return None

        if classification == "bypass_via_pollution":
            severity = Severity.HIGH
            evidence = (
                f"Parameter '{param}' ({location}) alone with value '{_VALUE_B}' was "
                f"rejected (status {resp_b.status_code}), but supplying it duplicated/"
                f"array-wrapped alongside '{_VALUE_A}' succeeded (status "
                f"{resp_polluted.status_code}) — the backend's parameter-pollution "
                "handling let an otherwise-rejected value through."
            )
            recommendation = (
                "Validate every occurrence of a duplicated or array-wrapped parameter, "
                "not just the first/last value the framework happens to bind to the "
                "application variable. Reject requests that supply a parameter more "
                "than once unless the API explicitly declares it as an array."
            )
        else:
            severity = Severity.MEDIUM
            evidence = (
                f"Parameter '{param}' ({location}) resolved inconsistently when "
                f"duplicated/array-wrapped: single value A -> status {resp_a.status_code}, "
                f"single value B -> status {resp_b.status_code}, both values together -> "
                f"status {resp_polluted.status_code} (matches neither baseline)."
            )
            recommendation = (
                "Define and enforce one explicit parameter-resolution policy "
                "(reject duplicates, or always use the first/last occurrence) so "
                "request parsing is deterministic and cannot be abused to desynchronize "
                "client- and server-side validation of the same input."
            )

        return Finding(
            id="",
            scan_id="",
            category="HTTP_PARAMETER_POLLUTION",
            owasp_category="API8",
            severity=severity,
            endpoint=endpoint,
            method=method,
            status_code=resp_polluted.status_code,
            response_size=len(resp_polluted.content) if resp_polluted.content else 0,
            response_time=resp_polluted.elapsed,
            evidence=evidence,
            recommendation=recommendation,
            payload=f"{location}:{param}={_VALUE_A}+{_VALUE_B}",
        )
