"""
Business Flows Testing Module
Implements OWASP API6 - Unrestricted Access to Sensitive Business Flows

Detectors implemented
---------------------
1. BUSINESS_FLOW_NO_LIMIT            — sensitive endpoint accepts N repeated
   requests with no HTTP 429 and no anti-automation headers.

2. BUSINESS_FLOW_QUOTA_NOT_ENFORCED  — a resource-scarcity field (stock, seats,
   remaining, credits…) does not decrease across N repeated requests, meaning
   the quota or inventory check is not enforced server-side.

3. BUSINESS_FLOW_MULTI_STEP_BYPASS   — a complete multi-step business transaction
   (e.g. add-to-cart → checkout → confirm) can be executed end-to-end N times
   without any rate-limiting or anti-automation control being observed.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Response
from core.config import BusinessFlowConfig, AuthContext, Severity
from core.logging import get_logger


# HTTP methods that change server state. In safe mode these are skipped.
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Methods considered safe to probe with when safe mode is enabled.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Response headers that indicate rate limiting / anti-automation controls.
ANTI_AUTOMATION_HEADERS = frozenset({
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "x-request-limit",
    "x-quota-remaining",
})


class BusinessFlowsTestingModule(OWASPModule):
    """
    Business Flows Testing Module for detecting Unrestricted Access to Sensitive
    Business Flows (OWASP API6).

    **Detector 1 — Rate-limit absence (BUSINESS_FLOW_NO_LIMIT)**
    Identifies sensitive-flow endpoints (checkout, purchase, transfer, booking…)
    by URL pattern matching. Issues ``repetition_limit`` repeated requests. If
    none trigger HTTP 429 or an anti-automation header, emits
    ``BUSINESS_FLOW_NO_LIMIT`` (API6 / HIGH).

    **Detector 2 — Quota / resource decrement (BUSINESS_FLOW_QUOTA_NOT_ENFORCED)**
    When ``config.check_quota_decrement`` is True, compares ``quota_fields``
    (stock, remaining, seats…) between the first and last response. If the value
    does not change across all repetitions the server is not enforcing inventory,
    emitting ``BUSINESS_FLOW_QUOTA_NOT_ENFORCED`` (API6 / HIGH).

    **Detector 3 — Multi-step flow bypass (BUSINESS_FLOW_MULTI_STEP_BYPASS)**
    Executes each ``multi_step_flows`` sequence ``repetition_limit`` times. If the
    full sequence completes on every iteration with no controls, emits
    ``BUSINESS_FLOW_MULTI_STEP_BYPASS`` (API6 / HIGH).

    **Safe Mode** (``config.safe_mode``) skips state-changing method endpoints
    and state-changing steps in multi-step flows.
    """

    def __init__(self, config: BusinessFlowConfig, http_client: HTTPRequestEngine,
                 auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="business_flow")

        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        self.safe_mode = getattr(self.config, 'safe_mode', False)
        self.check_quota_decrement = getattr(self.config, 'check_quota_decrement', True)
        self.quota_fields = list(getattr(self.config, 'quota_fields', []) or [])
        self.multi_step_flows = list(getattr(self.config, 'multi_step_flows', []) or [])
        self.inter_request_delay_ms = int(getattr(self.config, 'inter_request_delay_ms', 0))

        self.logger.info(
            "Business Flows Testing Module initialized",
            sensitive_flow_patterns=len(getattr(config, 'sensitive_flow_patterns', [])),
            repetition_limit=getattr(config, 'repetition_limit', 0),
            check_quota_decrement=self.check_quota_decrement,
            multi_step_flows=len(self.multi_step_flows),
            safe_mode=self.safe_mode,
        )

    def get_module_name(self) -> str:
        return "business_flow"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute business-flow tests.

        Detectors 1 & 2 iterate over ``endpoints``.
        Detector 3 (multi-step flows) runs independently of the endpoint list
        and executes even when ``endpoints`` is empty.

        Returns [] immediately only when both the endpoint list AND the
        multi-step flow list are empty.
        """
        has_endpoints = bool(endpoints)
        has_flows = bool(self.multi_step_flows)

        if not has_endpoints and not has_flows:
            self.logger.info("No endpoints or multi-step flows to test; skipping")
            return []

        self.logger.info(
            "Starting business flow testing",
            endpoints_count=len(endpoints),
            multi_step_flows=len(self.multi_step_flows),
            safe_mode=self.safe_mode,
        )

        findings: List[Finding] = []

        if self.auth_contexts:
            self.http_client.set_auth_context(self.auth_contexts[0])

        patterns = list(getattr(self.config, 'sensitive_flow_patterns', []) or [])
        repetition_limit = max(1, int(getattr(self.config, 'repetition_limit', 1)))

        # ── Detectors 1 & 2: per-endpoint probes ───────────────────────
        for endpoint in endpoints:
            endpoint_url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)
            method = endpoint.method if hasattr(endpoint, 'method') else 'GET'

            if not self._is_sensitive_flow(endpoint_url, patterns):
                continue

            if self.safe_mode:
                if method.upper() in STATE_CHANGING_METHODS:
                    self.logger.debug(
                        "Skipping state-changing flow in safe mode",
                        endpoint=endpoint_url, method=method,
                    )
                    continue
                if method.upper() not in SAFE_METHODS:
                    method = "GET"

            try:
                endpoint_findings = await self._test_endpoint(
                    endpoint_url, method, repetition_limit
                )
                findings.extend(endpoint_findings)
            except Exception as e:
                self.logger.debug(
                    "Business flow endpoint test failed",
                    endpoint=endpoint_url, error=str(e),
                )

        # ── Detector 3: multi-step flow sequences ──────────────────────
        for flow in self.multi_step_flows:
            try:
                flow_finding = await self._test_multi_step_flow(flow, repetition_limit)
                if flow_finding:
                    findings.append(flow_finding)
            except Exception as e:
                flow_name = getattr(flow, 'name', str(flow))
                self.logger.debug(
                    "Multi-step flow test failed",
                    flow=flow_name, error=str(e),
                )

        self.logger.info(
            "Business flow testing completed",
            total_findings=len(findings),
            high_findings=len([f for f in findings if f.severity == Severity.HIGH]),
        )
        return findings

    # ------------------------------------------------------------------
    # Per-endpoint test (Detectors 1 + 2)
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        endpoint_url: str,
        method: str,
        repetition_limit: int,
    ) -> List[Finding]:
        """Run Detector 1 (rate-limit absence) and Detector 2 (quota decrement)
        against a single sensitive-flow endpoint."""
        findings: List[Finding] = []
        responses: List[Response] = []
        rate_limited = False

        for _attempt in range(repetition_limit):
            if self.inter_request_delay_ms > 0:
                await asyncio.sleep(self.inter_request_delay_ms / 1000.0)

            response = await self.http_client.request(method, endpoint_url)
            responses.append(response)

            if response.status_code == 429:
                rate_limited = True
                break

            if self._has_anti_automation_headers(response.headers):
                rate_limited = True
                break

        if not responses:
            return findings

        successful = len(responses) if not rate_limited else len(responses) - 1
        last_response = responses[-1]

        # ── Detector 1: no rate limit ───────────────────────────────────
        if not rate_limited:
            self.logger.warning(
                "Unrestricted sensitive business flow detected",
                endpoint=endpoint_url, method=method,
                successful_requests=successful,
            )
            findings.append(Finding(
                id="", scan_id="",
                category="BUSINESS_FLOW_NO_LIMIT",
                owasp_category="API6",
                severity=Severity.HIGH,
                endpoint=endpoint_url,
                method=method,
                status_code=last_response.status_code,
                response_size=(
                    len(last_response.content)
                    if last_response.content is not None else 0
                ),
                response_time=last_response.elapsed,
                evidence=(
                    f"Sensitive business flow accepted {successful} repeated "
                    f"requests without rate limiting or anti-automation controls "
                    f"(no HTTP 429, no Retry-After / X-RateLimit-* headers). "
                    f"Final status: {last_response.status_code}."
                ),
                recommendation=(
                    "Protect sensitive business flows against automated abuse. "
                    "Implement rate limiting, CAPTCHA, device fingerprinting, or "
                    "human-interaction detection on flows such as checkout, purchase, "
                    "transfer, registration, and coupon redemption."
                ),
                payload=f"Repeated {successful} requests (limit={repetition_limit})",
            ))

        # ── Detector 2: quota not enforced ──────────────────────────────
        if self.check_quota_decrement and len(responses) >= 2 and self.quota_fields:
            quota_finding = self._check_quota_decrement(
                endpoint_url, method,
                responses[0], responses[-1],
                successful, repetition_limit,
            )
            if quota_finding:
                findings.append(quota_finding)

        return findings

    # ------------------------------------------------------------------
    # Detector 2 helpers — quota / resource decrement
    # ------------------------------------------------------------------

    def _check_quota_decrement(
        self,
        endpoint_url: str,
        method: str,
        first_response: Response,
        last_response: Response,
        successful_requests: int,
        repetition_limit: int,
    ) -> Optional[Finding]:
        """Emit BUSINESS_FLOW_QUOTA_NOT_ENFORCED when a quota field has the same
        value in both the first and last response."""
        first_body = self._parse_json_body(first_response)
        last_body = self._parse_json_body(last_response)

        if not first_body or not last_body:
            return None

        unchanged_fields: Dict[str, Any] = {}
        for field in self.quota_fields:
            first_val = self._extract_field(first_body, field)
            last_val = self._extract_field(last_body, field)
            if first_val is None or last_val is None:
                continue
            if first_val == last_val:
                unchanged_fields[field] = first_val

        if not unchanged_fields:
            return None

        field_summary = ", ".join(f"'{k}'={v}" for k, v in unchanged_fields.items())

        self.logger.warning(
            "Quota / resource decrement not enforced",
            endpoint=endpoint_url,
            unchanged_fields=list(unchanged_fields.keys()),
        )

        return Finding(
            id="", scan_id="",
            category="BUSINESS_FLOW_QUOTA_NOT_ENFORCED",
            owasp_category="API6",
            severity=Severity.HIGH,
            endpoint=endpoint_url,
            method=method,
            status_code=last_response.status_code,
            response_size=(
                len(last_response.content)
                if last_response.content is not None else 0
            ),
            response_time=last_response.elapsed,
            evidence=(
                f"After {successful_requests} repeated requests to this sensitive "
                f"flow, the following resource fields remained unchanged between "
                f"the first and last response, indicating the server is not "
                f"enforcing quota or inventory limits: {field_summary}."
            ),
            recommendation=(
                "Ensure all quantity, stock, credit, and quota fields are decremented "
                "atomically on each successful transaction. Use database-level "
                "transactions with pessimistic locking (SELECT FOR UPDATE) or "
                "optimistic concurrency control (version fields) to prevent race "
                "conditions. Validate available inventory server-side before "
                "committing each operation."
            ),
            payload=f"quota_fields_unchanged={list(unchanged_fields.keys())}",
        )

    # ------------------------------------------------------------------
    # Detector 3 — multi-step flow bypass
    # ------------------------------------------------------------------

    async def _test_multi_step_flow(
        self,
        flow: Any,
        repetition_limit: int,
    ) -> Optional[Finding]:
        """Execute a multi-step flow sequence ``repetition_limit`` times.

        Emits BUSINESS_FLOW_MULTI_STEP_BYPASS when the complete sequence
        completes on every iteration with no 4xx/5xx or anti-automation controls.
        """
        flow_name = getattr(flow, 'name', str(flow))
        steps = list(getattr(flow, 'steps', []) or [])

        if not steps:
            self.logger.debug("Multi-step flow has no steps, skipping", flow=flow_name)
            return None

        self.logger.debug("Testing multi-step flow", flow=flow_name, steps=len(steps))

        successful_iterations = 0
        rate_limited = False

        for _iteration in range(repetition_limit):
            if self.inter_request_delay_ms > 0:
                await asyncio.sleep(self.inter_request_delay_ms / 1000.0)

            iteration_ok = True

            for step in steps:
                step_method = step.get('method', 'GET').upper()
                step_path = step.get('path', '/')
                step_body = step.get('body', None)

                if self.safe_mode and step_method in STATE_CHANGING_METHODS:
                    self.logger.debug(
                        "Skipping state-changing step in safe mode",
                        flow=flow_name, step=step_path, method=step_method,
                    )
                    iteration_ok = False
                    break

                kwargs: Dict[str, Any] = {}
                if step_body:
                    kwargs['json'] = step_body

                try:
                    response = await self.http_client.request(
                        step_method, step_path, **kwargs
                    )
                except Exception as e:
                    self.logger.debug(
                        "Multi-step flow step request failed",
                        flow=flow_name, step=step_path, error=str(e),
                    )
                    iteration_ok = False
                    break

                if response.status_code == 429 or \
                        self._has_anti_automation_headers(response.headers):
                    rate_limited = True
                    break

                if response.status_code >= 400:
                    iteration_ok = False
                    break

            if rate_limited:
                break

            if iteration_ok:
                successful_iterations += 1

        if rate_limited or successful_iterations == 0:
            self.logger.debug(
                "Multi-step flow is protected or always fails",
                flow=flow_name,
                successful_iterations=successful_iterations,
                rate_limited=rate_limited,
            )
            return None

        step_summary = " → ".join(
            f"{s.get('method','GET').upper()} {s.get('path','/')}"
            for s in steps
        )

        self.logger.warning(
            "Multi-step business flow bypass detected",
            flow=flow_name,
            successful_iterations=successful_iterations,
        )

        return Finding(
            id="", scan_id="",
            category="BUSINESS_FLOW_MULTI_STEP_BYPASS",
            owasp_category="API6",
            severity=Severity.HIGH,
            endpoint=steps[0].get('path', '/') if steps else '/',
            method=steps[0].get('method', 'GET').upper() if steps else 'GET',
            status_code=200,
            response_size=0,
            response_time=0.0,
            evidence=(
                f"Multi-step business flow '{flow_name}' completed "
                f"{successful_iterations} full iterations out of "
                f"{repetition_limit} attempts without triggering any "
                f"rate-limiting or anti-automation control. "
                f"Flow sequence: {step_summary}."
            ),
            recommendation=(
                "Protect multi-step business transactions end-to-end, not just "
                "individual endpoints. Implement flow-level rate limiting, "
                "session-bound quotas, and CAPTCHA gates at transaction initiation. "
                "Use workflow tokens or signed state transitions to prevent replay "
                "of intermediate steps."
            ),
            payload=(
                f"flow={flow_name}, steps={len(steps)}, "
                f"successful_iterations={successful_iterations}"
            ),
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _is_sensitive_flow(self, endpoint_url: str, patterns: List[str]) -> bool:
        """Return True if the endpoint URL matches any sensitive-flow pattern."""
        if not patterns:
            return False
        lowered = endpoint_url.lower()
        return any(pattern.lower() in lowered for pattern in patterns)

    @staticmethod
    def _has_anti_automation_headers(headers: Optional[Dict[str, str]]) -> bool:
        """Return True when any anti-automation/rate-limit header is present."""
        if not headers:
            return False
        lowered = {str(k).lower() for k in headers.keys()}
        return bool(lowered & ANTI_AUTOMATION_HEADERS)

    @staticmethod
    def _parse_json_body(response: Response) -> Optional[Dict[str, Any]]:
        """Safely parse the response body as JSON. Returns None on failure."""
        try:
            text = response.text if response.text else (
                response.content.decode('utf-8', errors='ignore')
                if response.content else ''
            )
            if not text:
                return None
            return json.loads(text)
        except Exception:
            return None

    @staticmethod
    def _extract_field(body: Dict[str, Any], field: str) -> Any:
        """Extract a field from a JSON body via case-insensitive key lookup.

        Searches top-level keys first, then one level of nesting, so that
        ``{"data": {"remaining": 10}}`` is matched by ``field="remaining"``.
        Returns None when the field is not found.
        """
        if field in body:
            return body[field]
        field_lower = field.lower()
        for k, v in body.items():
            if str(k).lower() == field_lower:
                return v
            if isinstance(v, dict):
                for nk, nv in v.items():
                    if str(nk).lower() == field_lower:
                        return nv
        return None
