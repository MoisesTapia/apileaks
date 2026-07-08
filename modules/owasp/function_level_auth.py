"""
Function Level Authorization Testing Module
OWASP API5:2023 – Broken Function Level Authorization (BFLA)

Four attack levels implemented:
  Level 1 – Basic: multi-token matrix replay (admin-discovered endpoints
             replayed with low-privilege / anonymous tokens).
  Level 2 – Intermediate: HTTP verb tampering + X-HTTP-Method-Override.
  Level 3 – Advanced: mass-assignment role injection in registration /
             profile-update flows.
  Level 4 – Expert: API version downgrade (replay admin endpoints against
             older API versions that may lack patched authorization).

Grey-box approach (two required roles):
  * HIGH-privilege auth context  → endpoint discovery
  * LOW-privilege / anonymous    → replay to confirm BFLA

All confirmed BFLA findings are persisted to ``config.bfla_output_file``
(JSON) when the path is configured, enabling downstream chained attacks.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type
from urllib.parse import urlparse

from core.config import AuthContext, AuthType, FunctionAuthConfig, Severity
from core.logging import get_logger
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Response
from utils.safe_mode import STATE_CHANGING_METHODS, SafeModeGuard

from .registry import OWASPModule


import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from .registry import OWASPModule
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Response
from utils.safe_mode import SafeModeGuard, STATE_CHANGING_METHODS, SAFE_METHODS
from core.config import FunctionAuthConfig, AuthContext, AuthType, Severity
from core.logging import get_logger


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BFLAProbeResult:
    """Result of a single BFLA replay attempt."""
    endpoint: str
    method: str
    probe_type: str            # "low_priv" | "anonymous" | "verb_tamper" | "mass_assign" | "version_downgrade"
    token_context: str         # name of the auth context used (or "anonymous")
    status_code: int
    response_size: int
    response_time: float
    is_confirmed: bool         # True → access was granted (BFLA confirmed)
    evidence: str
    payload: Optional[str] = None
    response_snippet: Optional[str] = None


@dataclass
class AdminEndpointRecord:
    """A high-privilege endpoint discovered during the mapping phase."""
    url: str
    method: str
    status_code: int           # observed with the high-priv token
    admin_score: float         # 0.0-1.0 heuristic confidence
    admin_indicators: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper: privilege-level ordering
# ---------------------------------------------------------------------------

def _privilege_level(ctx: AuthContext) -> int:
    """Return a numeric privilege level for an AuthContext.

    Uses ``ctx.privilege_level`` when set; falls back to heuristics on the
    context name so callers do not need to set the field explicitly.
    """
    if getattr(ctx, "privilege_level", None) is not None:
        return ctx.privilege_level
    name_lower = ctx.name.lower()
    for kw, level in [("admin", 100), ("super", 90), ("manager", 80),
                      ("staff", 60), ("user", 30), ("guest", 10),
                      ("anon", 0), ("public", 0)]:
        if kw in name_lower:
            return level
    return 50  # unknown → treat as medium


def _is_anonymous(ctx: AuthContext) -> bool:
    return not getattr(ctx, "token", None)


# ---------------------------------------------------------------------------
# Main module
# ---------------------------------------------------------------------------

class FunctionLevelAuthModule(OWASPModule, SafeModeGuard):
    """
    Broken Function Level Authorization (BFLA) – OWASP API5:2023

    Grey-box, multi-token approach:
    1. Map admin/privileged endpoints using the highest-privilege token.
    2. Replay each found endpoint with lower-privilege / anonymous tokens.
    3. Report BFLA whenever a protected function is accessible below its
       required privilege threshold.

    Four attack levels:
    • Level 1 – Multi-token matrix (admin-discovered → low-priv replay)
    • Level 2 – HTTP verb tampering & X-HTTP-Method-Override injection
    • Level 3 – Mass-assignment role injection (registration / profile update)
    • Level 4 – API version downgrade (replay on /v1/, /v2/ … after finding
                 the protected endpoint on /v3/ or later)
    """

    # -----------------------------------------------------------------------
    # Admin endpoint heuristics
    # -----------------------------------------------------------------------

    _ADMIN_PATH_KEYWORDS: List[str] = [
        "admin", "administrator", "management", "manage", "control",
        "dashboard", "panel", "console", "config", "configuration",
        "settings", "system", "internal", "private", "restricted",
        "privileged", "staff", "employee", "moderator", "supervisor",
        "operator", "maintenance", "debug", "backstage",
    ]

    _ADMIN_ACTION_KEYWORDS: List[str] = [
        "delete", "remove", "destroy", "purge", "clear", "reset",
        "create", "add", "insert", "generate", "approve", "reject",
        "ban", "unban", "block", "unblock", "enable", "disable",
        "activate", "deactivate", "suspend", "promote", "demote",
        "grant", "revoke", "assign", "unassign", "export", "import",
        "migrate", "backup", "restore", "sync",
    ]

    # HTTP methods that convey administrative intent
    _PRIVILEGED_METHODS: Set[str] = {"DELETE", "PUT", "PATCH", "POST"}

    # X-HTTP-Method-Override header name variants
    _METHOD_OVERRIDE_HEADERS: List[str] = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "_method",
    ]

    # -----------------------------------------------------------------------
    # Version pattern: captures the version segment in a URL path
    # e.g. /api/v3/users  →  group(1)="v3", group(2)="3"
    # -----------------------------------------------------------------------
    _VERSION_RE = re.compile(r"/(v)(\d+)/", re.IGNORECASE)

    def __init__(
        self,
        config: FunctionAuthConfig,
        http_client: HTTPRequestEngine,
        auth_contexts: List[AuthContext],
    ):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.logger = get_logger(__name__).bind(module="function_level_auth")

        self._init_safe_mode(config)

        # Sort contexts by privilege (descending) so index-0 is highest priv.
        self._sorted_contexts: List[AuthContext] = sorted(
            auth_contexts, key=_privilege_level, reverse=True
        )

        # Anonymous sentinel for unauthenticated probes.
        self._anonymous_ctx = AuthContext(
            name="anonymous",
            type=AuthType.BEARER,
            token="",
            privilege_level=0,
        )

        # Collected probe results (for output file).
        self._probe_results: List[BFLAProbeResult] = []

        self.logger.info(
            "FunctionLevelAuthModule initialized",
            contexts=len(auth_contexts),
            safe_mode=self.safe_mode,
        )

    def get_module_name(self) -> str:
        return "function_auth"

    # -----------------------------------------------------------------------
    # Entry point
    # -----------------------------------------------------------------------

    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """Run all four BFLA attack levels and return unified findings."""
        self.logger.info("Starting BFLA testing", endpoints=len(endpoints))
        findings: List[Finding] = []

        if not self._sorted_contexts:
            self.logger.warning("No auth contexts supplied; BFLA testing skipped")
            return findings

        # --- Phase 1: admin endpoint mapping (highest-priv token) ----------
        admin_records = await self._map_admin_endpoints(endpoints)
        self.logger.info("Admin endpoint mapping done", found=len(admin_records))

        # --- Level 1: multi-token replay -----------------------------------
        findings.extend(await self._level1_multi_token_replay(admin_records))

        # --- Level 2: verb tampering + method override ---------------------
        findings.extend(await self._level2_verb_tampering(endpoints, admin_records))

        # --- Level 3: mass-assignment role injection -----------------------
        findings.extend(await self._level3_mass_assignment_role(endpoints))

        # --- Level 4: API version downgrade --------------------------------
        findings.extend(await self._level4_version_downgrade(admin_records))

        self.logger.info("BFLA testing completed", findings=len(findings))

        # Persist results to output file when configured.
        self._persist_results()

        return findings

    # -----------------------------------------------------------------------
    # Phase 0: mapping with high-privilege token
    # -----------------------------------------------------------------------

    async def _map_admin_endpoints(self, endpoints: List[Any]) -> List[AdminEndpointRecord]:
        """Issue every discovered endpoint with the highest-privilege token.

        Returns AdminEndpointRecords for endpoints that:
        (a) look like administrative functions (heuristic score > 0), OR
        (b) are listed in ``config.admin_endpoints``.
        """
        high_ctx = self._sorted_contexts[0]
        self.http_client.set_auth_context(high_ctx)

        records: List[AdminEndpointRecord] = []

        # Seed from config.admin_endpoints (operator-declared known admin paths).
        config_admin_urls = set(getattr(self.config, "admin_endpoints", []) or [])

        for ep in endpoints:
            url = ep.url if hasattr(ep, "url") else str(ep)
            method = (ep.method if hasattr(ep, "method") else "GET").upper()

            score, indicators = self._admin_score(url, method)
            in_config = any(path in url for path in config_admin_urls)

            if score <= 0.0 and not in_config:
                continue

            # Probe with the high-priv token to confirm the endpoint exists.
            probe_method = method if not self.safe_mode else self.safe_read_method(method, "admin_map")
            try:
                resp = await self.http_client.request(probe_method, url)
            except Exception as e:
                self.logger.debug("Admin-map probe failed", url=url, error=str(e))
                continue

            # Only map endpoints that return a success response (not 404/405).
            if resp.status_code in (404, 405, 410):
                continue

            records.append(AdminEndpointRecord(
                url=url,
                method=probe_method,
                status_code=resp.status_code,
                admin_score=min(score + (0.3 if in_config else 0.0), 1.0),
                admin_indicators=indicators + (["config_listed"] if in_config else []),
            ))

        self.http_client.current_auth_context = None
        return records

    def _admin_score(self, url: str, method: str) -> Tuple[float, List[str]]:
        """Return a (score, indicators) tuple for a URL+method combination."""
        url_lower = url.lower()
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        score = 0.0
        indicators: List[str] = []

        for kw in self._ADMIN_PATH_KEYWORDS:
            if kw in path_lower:
                score += 0.35
                indicators.append(f"path:{kw}")
                break  # one admin keyword is enough

        for kw in self._ADMIN_ACTION_KEYWORDS:
            if kw in path_lower:
                score += 0.20
                indicators.append(f"action:{kw}")
                break

        if method in self._PRIVILEGED_METHODS:
            score += 0.15
            indicators.append(f"method:{method}")

        return score, indicators

    # -----------------------------------------------------------------------
    # Level 1 – Multi-token matrix replay
    # -----------------------------------------------------------------------

    async def _level1_multi_token_replay(
        self, admin_records: List[AdminEndpointRecord]
    ) -> List[Finding]:
        """Replay every mapped admin endpoint with each lower-privilege token.

        For each (admin_endpoint × lower-priv context) pair, replay the
        request.  If a 2xx/201/204 is returned → BFLA confirmed.

        Also probes anonymously (no token).  Finding categories:
        • BFLA_ANONYMOUS_ADMIN_ACCESS (CRITICAL) – anonymous access
        • BFLA_LOW_PRIV_ACCESS (CRITICAL) – low-priv context access
        • BFLA_ADMIN_ENDPOINT_EXPOSED (MEDIUM) – endpoint exists but
          access was 403/401 (informational exposure finding)
        """
        findings: List[Finding] = []
        high_level = _privilege_level(self._sorted_contexts[0])

        for record in admin_records:
            # Emit an informational finding just for exposing the admin surface.
            findings.append(self._make_finding(
                category="BFLA_ADMIN_ENDPOINT_EXPOSED",
                severity=Severity.MEDIUM,
                endpoint=record.url,
                method=record.method,
                status_code=record.status_code,
                response_size=0,
                response_time=0.0,
                evidence=(
                    f"Administrative endpoint '{record.url}' ({record.method}) "
                    f"was accessible with the highest-privilege token "
                    f"(HTTP {record.status_code}). "
                    f"Admin indicators: {record.admin_indicators}. "
                    f"Score: {record.admin_score:.2f}."
                ),
                recommendation=(
                    "Verify this endpoint requires the correct role. "
                    "Ensure authorization is checked at the function level, "
                    "not only at the API gateway."
                ),
            ))

            # Probe contexts below the high-priv level.
            lower_contexts: List[AuthContext] = [
                ctx for ctx in self._sorted_contexts
                if _privilege_level(ctx) < high_level
            ]
            # Always add an anonymous probe.
            all_probe_contexts = lower_contexts + [self._anonymous_ctx]

            for ctx in all_probe_contexts:
                if _is_anonymous(ctx):
                    self.http_client.current_auth_context = None
                else:
                    self.http_client.set_auth_context(ctx)

                probe_method = record.method
                if self.safe_mode:
                    probe_method = self.safe_read_method(record.method, "bfla_l1")

                try:
                    resp = await self.http_client.request(probe_method, record.url)
                except Exception as e:
                    self.logger.debug("L1 replay failed",
                                      url=record.url, ctx=ctx.name, error=str(e))
                    continue
                finally:
                    self.http_client.current_auth_context = None

                is_access = 200 <= resp.status_code < 300 or resp.status_code == 201

                result = BFLAProbeResult(
                    endpoint=record.url,
                    method=probe_method,
                    probe_type="anonymous" if _is_anonymous(ctx) else "low_priv",
                    token_context=ctx.name,
                    status_code=resp.status_code,
                    response_size=len(getattr(resp, "content", b"") or b""),
                    response_time=getattr(resp, "elapsed", 0.0) or 0.0,
                    is_confirmed=is_access,
                    evidence=self._build_l1_evidence(record, ctx, probe_method, resp),
                    response_snippet=(getattr(resp, "text", "") or "")[:500],
                )
                self._probe_results.append(result)

                if not is_access:
                    continue

                category = (
                    "BFLA_ANONYMOUS_ADMIN_ACCESS"
                    if _is_anonymous(ctx) else "BFLA_LOW_PRIV_ACCESS"
                )
                severity = Severity.CRITICAL
                findings.append(self._make_finding(
                    category=category,
                    severity=severity,
                    endpoint=record.url,
                    method=probe_method,
                    status_code=resp.status_code,
                    response_size=result.response_size,
                    response_time=result.response_time,
                    evidence=result.evidence,
                    recommendation=(
                        "Enforce role-based access control (RBAC) at the function "
                        "level for every endpoint. Do not rely solely on API gateway "
                        "or middleware-level checks. Verify the calling user's role "
                        "inside each controller/handler before executing the function."
                    ),
                    response_snippet=result.response_snippet,
                ))
                self.logger.warning("BFLA confirmed (L1)",
                                    url=record.url, ctx=ctx.name,
                                    status=resp.status_code)

        return findings

    def _build_l1_evidence(
        self,
        record: AdminEndpointRecord,
        ctx: AuthContext,
        method: str,
        resp: Response,
    ) -> str:
        ctx_label = "anonymous (no token)" if _is_anonymous(ctx) else f"'{ctx.name}'"
        return (
            f"Admin endpoint '{record.url}' ({method}) responded HTTP "
            f"{resp.status_code} when accessed with {ctx_label}. "
            f"The same endpoint returned HTTP {record.status_code} for the "
            f"high-privilege token. Admin indicators: {record.admin_indicators}."
        )

    # -----------------------------------------------------------------------
    # Level 2 – Verb tampering + X-HTTP-Method-Override
    # -----------------------------------------------------------------------

    async def _level2_verb_tampering(
        self,
        endpoints: List[Any],
        admin_records: List[AdminEndpointRecord],
    ) -> List[Finding]:
        """Two sub-probes:

        2a. Classic verb tampering: discover an endpoint via GET (no auth
            required), then try DELETE/PUT/PATCH with a low-priv token.
            If the low-priv attempt succeeds while the anonymous GET does NOT,
            the authorization check is tied only to the GET route.

        2b. X-HTTP-Method-Override: send GET/POST with an override header that
            claims DELETE/PATCH.  Some API Gateways route on the declared method
            (GET/POST → allowed) while the backend executes the override method.

        Findings: BFLA_VERB_TAMPERING, BFLA_METHOD_OVERRIDE.
        """
        findings: List[Finding] = []
        low_ctx = self._pick_low_priv_ctx()

        # ---- 2a: classic verb tampering ----
        for record in admin_records:
            original = record.method
            tamper_methods = [
                m for m in self.config.dangerous_methods
                if m.upper() != original.upper()
            ]
            for tmethod in tamper_methods:
                if self.safe_mode and tmethod.upper() in STATE_CHANGING_METHODS:
                    self.logger.info("Verb-tamper skipped in safe mode",
                                     method=tmethod, url=record.url)
                    continue

                self.http_client.set_auth_context(low_ctx) if low_ctx else None
                try:
                    resp = await self.http_client.request(tmethod, record.url)
                except Exception as e:
                    self.logger.debug("Verb-tamper probe failed", error=str(e))
                    continue
                finally:
                    self.http_client.current_auth_context = None

                if not (200 <= resp.status_code < 300):
                    continue

                result = BFLAProbeResult(
                    endpoint=record.url,
                    method=tmethod,
                    probe_type="verb_tamper",
                    token_context=low_ctx.name if low_ctx else "anonymous",
                    status_code=resp.status_code,
                    response_size=len(getattr(resp, "content", b"") or b""),
                    response_time=getattr(resp, "elapsed", 0.0) or 0.0,
                    is_confirmed=True,
                    evidence=(
                        f"Verb tampering: endpoint '{record.url}' (originally "
                        f"{original}) accepted {tmethod} with a low-privilege "
                        f"token (HTTP {resp.status_code}). The authorization "
                        f"check appears restricted to the original {original} "
                        f"method only."
                    ),
                )
                self._probe_results.append(result)
                findings.append(self._make_finding(
                    category="BFLA_VERB_TAMPERING",
                    severity=Severity.HIGH,
                    endpoint=record.url,
                    method=tmethod,
                    status_code=resp.status_code,
                    response_size=result.response_size,
                    response_time=result.response_time,
                    evidence=result.evidence,
                    recommendation=(
                        "Apply authorization checks independently of the HTTP method. "
                        "Never restrict protection to a single verb; validate the "
                        "caller's role for ALL methods on the same route pattern."
                    ),
                ))
                self.logger.warning("Verb tampering confirmed",
                                    url=record.url, method=tmethod)

        # ---- 2b: X-HTTP-Method-Override injection ----
        # Probe endpoints that returned 403/401 for a privileged method
        # via the low-priv token, but might be bypassed via override.
        test_records = admin_records[:20]  # bounded probe set
        for record in test_records:
            for override_method in ["DELETE", "PATCH", "PUT"]:
                if self.safe_mode:
                    self.logger.info("Method-override skipped in safe mode",
                                     override=override_method)
                    continue

                for header_name in self._METHOD_OVERRIDE_HEADERS:
                    override_headers = {
                        header_name: override_method,
                        "Content-Type": "application/json",
                    }
                    # Send as GET so the gateway doesn't block it on the method,
                    # but inject the override header so the backend executes the
                    # privileged method.
                    self.http_client.set_auth_context(low_ctx) if low_ctx else None
                    try:
                        resp = await self.http_client.request(
                            "GET", record.url, headers=override_headers
                        )
                    except Exception as e:
                        self.logger.debug("Method-override probe failed", error=str(e))
                        continue
                    finally:
                        self.http_client.current_auth_context = None

                    if not (200 <= resp.status_code < 300):
                        continue

                    result = BFLAProbeResult(
                        endpoint=record.url,
                        method=f"GET+{header_name}:{override_method}",
                        probe_type="method_override",
                        token_context=low_ctx.name if low_ctx else "anonymous",
                        status_code=resp.status_code,
                        response_size=len(getattr(resp, "content", b"") or b""),
                        response_time=getattr(resp, "elapsed", 0.0) or 0.0,
                        is_confirmed=True,
                        evidence=(
                            f"Method-override bypass: GET request to '{record.url}' "
                            f"with '{header_name}: {override_method}' returned HTTP "
                            f"{resp.status_code}. The API gateway authorized the "
                            f"request as GET while the backend executed {override_method}."
                        ),
                        payload=f"{header_name}: {override_method}",
                    )
                    self._probe_results.append(result)
                    findings.append(self._make_finding(
                        category="BFLA_METHOD_OVERRIDE",
                        severity=Severity.HIGH,
                        endpoint=record.url,
                        method=f"GET ({header_name}: {override_method})",
                        status_code=resp.status_code,
                        response_size=result.response_size,
                        response_time=result.response_time,
                        evidence=result.evidence,
                        recommendation=(
                            "Disable or strictly validate X-HTTP-Method-Override and "
                            "X-HTTP-Method headers. If these headers are needed for "
                            "legacy clients, ensure the backend applies the same "
                            "authorization checks for the overridden method."
                        ),
                        payload=result.payload,
                    ))
                    self.logger.warning("Method-override bypass confirmed",
                                        url=record.url, header=header_name,
                                        override=override_method)
                    break  # one confirmed override per record is sufficient

        return findings

    # -----------------------------------------------------------------------
    # Level 3 – Mass-assignment role injection
    # -----------------------------------------------------------------------

    # URL patterns that typically accept a user-creation / profile-update body.
    _REGISTRATION_PATH_RE = re.compile(
        r"/(register|signup|sign[\-_]?up|create[\-_]?user|users|profile|account)",
        re.IGNORECASE,
    )
    # Methods that carry a request body.
    _BODY_METHODS: Set[str] = {"POST", "PUT", "PATCH"}

    async def _level3_mass_assignment_role(
        self, endpoints: List[Any]
    ) -> List[Finding]:
        """Inject role/privilege fields into registration & profile-update flows.

        For every endpoint whose URL matches a registration/profile pattern and
        whose method carries a body (POST/PUT/PATCH), send a minimal JSON body
        that includes each combination of (role_field, role_value) from the
        config.  A 2xx response that echoes the injected role field back (or a
        different response from a baseline without the field) indicates that
        mass assignment elevated the account's role.

        Finding: BFLA_MASS_ASSIGNMENT_ROLE (CRITICAL).
        """
        findings: List[Finding] = []

        if self.safe_mode:
            self.logger.info("Mass-assignment probe skipped in safe mode")
            return findings

        role_fields: list[str] = getattr(self.config, "role_fields", []) or []
        role_values: list[str] = getattr(self.config, "role_values", []) or []
        role_fields: List[str] = getattr(self.config, "role_fields", []) or []
        role_values: List[str] = getattr(self.config, "role_values", []) or []

        if not role_fields or not role_values:
            return findings

        low_ctx = self._pick_low_priv_ctx()

        candidate_endpoints = [
            ep for ep in endpoints
            if self._REGISTRATION_PATH_RE.search(
                urlparse(ep.url if hasattr(ep, "url") else str(ep)).path
            )
            and (ep.method if hasattr(ep, "method") else "GET").upper()
            in self._BODY_METHODS
        ]

        if not candidate_endpoints:
            self.logger.info("No registration/profile endpoints found for L3")
            return findings

        for ep in candidate_endpoints[:10]:  # bounded
            url = ep.url if hasattr(ep, "url") else str(ep)
            method = (ep.method if hasattr(ep, "method") else "POST").upper()

            # Capture a baseline with a benign-but-minimal body (no role field).
            baseline_body: Dict[str, Any] = {
                "username": f"apileaks_probe_{uuid.uuid4().hex[:8]}",
                "email": f"probe_{uuid.uuid4().hex[:8]}@apileaks.invalid",
                "password": f"Probe!{uuid.uuid4().hex[:8]}",
            }
            self.http_client.set_auth_context(low_ctx) if low_ctx else None
            try:
                baseline_resp = await self.http_client.request(
                    method, url, json=baseline_body,
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:
                self.logger.debug("Mass-assign baseline failed", url=url, error=str(e))
                continue
            finally:
                self.http_client.current_auth_context = None

            for role_field in role_fields:
                for role_value in role_values:
                    inject_body = dict(baseline_body)
                    inject_body[role_field] = role_value

                    self.http_client.set_auth_context(low_ctx) if low_ctx else None
                    try:
                        resp = await self.http_client.request(
                            method, url, json=inject_body,
                            headers={"Content-Type": "application/json"},
                        )
                    except Exception as e:
                        self.logger.debug("Mass-assign probe failed", error=str(e))
                        continue
                    finally:
                        self.http_client.current_auth_context = None

                    # Confirm if:
                    # (a) response is 2xx, AND
                    # (b) injected field appears in the response body, OR
                    # (c) response code differs from the baseline (server
                    #     processed the field differently).
                    resp_text = getattr(resp, "text", "") or ""
                    is_confirmed = (
                        200 <= resp.status_code < 300
                        and (
                            role_value.lower() in resp_text.lower()
                            or role_field.lower() in resp_text.lower()
                            or resp.status_code != baseline_resp.status_code
                        )
                    )

                    result = BFLAProbeResult(
                        endpoint=url,
                        method=method,
                        probe_type="mass_assign",
                        token_context=low_ctx.name if low_ctx else "anonymous",
                        status_code=resp.status_code,
                        response_size=len(getattr(resp, "content", b"") or b""),
                        response_time=getattr(resp, "elapsed", 0.0) or 0.0,
                        is_confirmed=is_confirmed,
                        evidence=(
                            f"Mass-assignment role injection: '{role_field}={role_value}' "
                            f"injected into {method} {url}. Response: HTTP "
                            f"{resp.status_code}. Baseline (no role field): HTTP "
                            f"{baseline_resp.status_code}. "
                            f"Role value echoed in response: "
                            f"{role_value.lower() in resp_text.lower()}."
                        ),
                        payload=f"{role_field}={role_value}",
                        response_snippet=resp_text[:500],
                    )
                    self._probe_results.append(result)

                    if not is_confirmed:
                        continue

                    findings.append(self._make_finding(
                        category="BFLA_MASS_ASSIGNMENT_ROLE",
                        severity=Severity.CRITICAL,
                        endpoint=url,
                        method=method,
                        status_code=resp.status_code,
                        response_size=result.response_size,
                        response_time=result.response_time,
                        evidence=result.evidence,
                        recommendation=(
                            "Use an allowlist (DTO / request schema) to restrict which "
                            "fields the API accepts in the request body. Never bind the "
                            "raw request body to the user/account model. Explicitly block "
                            "role, admin, and privilege fields from being set by end users."
                        ),
                        payload=result.payload,
                        response_snippet=result.response_snippet,
                    ))
                    self.logger.warning(
                        "Mass-assignment role injection confirmed",
                        url=url, field=role_field, value=role_value,
                    )

        return findings

    # -----------------------------------------------------------------------
    # Level 4 – API version downgrade
    # -----------------------------------------------------------------------

    def _extract_version(self, url: str) -> Optional[Tuple[str, int]]:
        """Return (version_prefix, version_number) if the URL has a version segment."""
        m = self._VERSION_RE.search(url)
        if m:
            return m.group(1), int(m.group(2))
        return None

    def _substitute_version(self, url: str, new_version: int) -> str:
        """Replace the version segment in the URL with ``new_version``."""
        return self._VERSION_RE.sub(f"/v{new_version}/", url)

    async def _level4_version_downgrade(
        self, admin_records: List[AdminEndpointRecord]
    ) -> List[Finding]:
        """Replay each versioned admin endpoint against all lower API versions.

        If GET /api/v3/users/99/suspend returns 403 for low-priv, but
        GET /api/v1/users/99/suspend returns 200, the old version lacks
        the patch and BFLA is confirmed.

        Finding: BFLA_VERSION_DOWNGRADE (HIGH).
        """
        findings: list[Finding] = []
        low_ctx = self._pick_low_priv_ctx()
        configured_versions: list[str] = getattr(self.config, "api_versions", []) or []
        findings: List[Finding] = []
        low_ctx = self._pick_low_priv_ctx()
        configured_versions: List[str] = getattr(self.config, "api_versions", []) or []

        for record in admin_records:
            version_info = self._extract_version(record.url)
            if version_info is None:
                continue

            prefix, current_ver = version_info
            # Only downgrade (probe older versions).
            older_versions = [
                int(v.lstrip("vV"))
                for v in configured_versions
                if v.lstrip("vV").isdigit()
                and int(v.lstrip("vV")) < current_ver
            ]

            for older_ver in older_versions:
                downgraded_url = self._substitute_version(record.url, older_ver)

                probe_method = record.method
                if self.safe_mode:
                    probe_method = self.safe_read_method(record.method, "bfla_l4")

                self.http_client.set_auth_context(low_ctx) if low_ctx else None
                try:
                    resp = await self.http_client.request(probe_method, downgraded_url)
                except Exception as e:
                    self.logger.debug("Version-downgrade probe failed",
                                      url=downgraded_url, error=str(e))
                    continue
                finally:
                    self.http_client.current_auth_context = None

                # 404 = version doesn't exist; skip.
                if resp.status_code == 404:
                    continue

                is_confirmed = 200 <= resp.status_code < 300

                result = BFLAProbeResult(
                    endpoint=downgraded_url,
                    method=probe_method,
                    probe_type="version_downgrade",
                    token_context=low_ctx.name if low_ctx else "anonymous",
                    status_code=resp.status_code,
                    response_size=len(getattr(resp, "content", b"") or b""),
                    response_time=getattr(resp, "elapsed", 0.0) or 0.0,
                    is_confirmed=is_confirmed,
                    evidence=(
                        f"Version downgrade: the protected function at "
                        f"'{record.url}' (v{current_ver}, HTTP {record.status_code} "
                        f"with high-priv token) was replayed against the older "
                        f"v{older_ver} URL '{downgraded_url}'. Low-privilege token "
                        f"'{low_ctx.name if low_ctx else 'anonymous'}' received "
                        f"HTTP {resp.status_code}. "
                        f"{'BFLA confirmed: authorization patch missing in v' + str(older_ver) + '.' if is_confirmed else 'Endpoint exists but access was denied.'}"
                    ),
                )
                self._probe_results.append(result)

                if not is_confirmed:
                    continue

                findings.append(self._make_finding(
                    category="BFLA_VERSION_DOWNGRADE",
                    severity=Severity.HIGH,
                    endpoint=downgraded_url,
                    method=probe_method,
                    status_code=resp.status_code,
                    response_size=result.response_size,
                    response_time=result.response_time,
                    evidence=result.evidence,
                    recommendation=(
                        "Apply authorization patches to ALL active API versions "
                        "simultaneously. If older versions cannot be patched, "
                        "decommission them. Use a centralised authorization "
                        "library shared by every version's controllers."
                    ),
                ))
                self.logger.warning(
                    "Version-downgrade BFLA confirmed",
                    original=record.url,
                    downgraded=downgraded_url,
                    low_status=resp.status_code,
                )

        return findings

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _pick_low_priv_ctx(self) -> Optional[AuthContext]:
        """Return the lowest-privilege context that has a token (not anonymous)."""
        high_level = _privilege_level(self._sorted_contexts[0]) if self._sorted_contexts else 100
        candidates = [
            ctx for ctx in self._sorted_contexts
            if _privilege_level(ctx) < high_level and not _is_anonymous(ctx)
        ]
        return candidates[-1] if candidates else None

    def _make_finding(
        self,
        category: str,
        severity: Severity,
        endpoint: str,
        method: str,
        status_code: int,
        response_size: int,
        response_time: float,
        evidence: str,
        recommendation: str,
        payload: Optional[str] = None,
        response_snippet: Optional[str] = None,
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            scan_id="",
            category=category,
            owasp_category="API5",
            severity=severity,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_size=response_size,
            response_time=response_time,
            evidence=evidence,
            recommendation=recommendation,
            payload=payload,
            response_snippet=response_snippet,
        )

    # -----------------------------------------------------------------------
    # Output – persist BFLA matrix to JSON
    # -----------------------------------------------------------------------

    def _persist_results(self) -> None:
        """Write all probe results to ``config.bfla_output_file`` (JSON).

        The output file is a JSON array of BFLAProbeResult objects, intended
        for downstream analysis (e.g. feeding confirmed BFLA endpoints into
        further attack modules). The file is only written when
        ``config.bfla_output_file`` is set and at least one result was
        collected.
        """
        output_path_str = getattr(self.config, "bfla_output_file", None)
        if not output_path_str or not self._probe_results:
            return

        output_path = Path(output_path_str)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            confirmed = [r for r in self._probe_results if r.is_confirmed]
            all_records = [r for r in self._probe_results]
            payload = {
                "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                "total_probes": len(all_records),
                "confirmed_bfla": len(confirmed),
                "results": [asdict(r) for r in all_records],
            }
            output_path.write_text(
                json.dumps(payload, indent=2, default=str),
                encoding="utf-8",
            )
            self.logger.info(
                "BFLA results persisted",
                path=str(output_path),
                total=len(all_records),
                confirmed=len(confirmed),
            )
        except OSError as e:
            self.logger.error("Failed to write BFLA output file",
                              path=output_path_str, error=str(e))
