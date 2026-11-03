"""
modules.mcp_security.mcp_target_auditor — MCPTargetAuditor.

Connects as a generic MCP client to a third-party MCP server and runs an
offensive audit covering:

  * Tool discovery (Requirement 8.1)
  * Tool-poisoning detection (Requirement 8.2)
  * SSRF via URL-accepting tools (Requirement 8.3)
  * Destructive tool execution without confirmation (Requirement 8.4)
  * Credential leak detection in tool responses (Requirement 8.5)
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import shlex
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.config import Severity
from core.logging import get_logger
from modules.mcp_security.poisoning_detector import ToolPoisoningDetector
from modules.owasp.ssrf_testing import (
    BYPASS_PROBES,
    CLOUD_METADATA_PROBES,
    INTERNAL_TARGET_SIGNATURES,
    SSRF_SCHEMES,
)
from utils.findings import Finding

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Internal lightweight tool description model
# ---------------------------------------------------------------------------


@dataclass
class RemoteToolSpec:
    """Lightweight description of a tool discovered on a remote MCP server.

    This is intentionally decoupled from the internal
    :class:`~mcp_server.schemas.MCPToolSpec` so the auditor can work against
    any MCP server without importing the internal server package.
    """

    name: str
    description: str
    input_schema: dict[str, Any]

    # Derived property — cached after first evaluation.
    _url_params_cache: list[str] | None = None

    @property
    def url_param_names(self) -> list[str]:
        """Return a list of parameter names whose schema indicates a URL value."""
        if self._url_params_cache is None:
            self._url_params_cache = _extract_url_params(self.input_schema)
        return self._url_params_cache

    @property
    def appears_destructive(self) -> bool:
        """Return True when the description contains keywords that suggest the
        tool modifies state (delete, remove, overwrite, drop, wipe, purge,
        destroy, truncate, revoke)."""
        keywords = (
            r"\b(delet(e|es|ed|ing)|remov(e|es|ed|ing)|overwrite[sd]?|drop[ps]?|"
            r"wipes?|purge[sd]?|destroy[s]?|truncate[sd]?|revoke[sd]?|"
            r"format[s]?|reset[s]?|erase[sd]?|clear[s]?|disable[sd]?|terminate[sd]?)\b"
        )
        return bool(re.search(keywords, self.description, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_url_params(schema: dict[str, Any]) -> list[str]:
    """Return parameter names that are typed as URL/URI strings."""
    url_names: list[str] = []
    props: dict[str, Any] = schema.get("properties", {}) if isinstance(schema, dict) else {}
    for param_name, param_schema in props.items():
        if not isinstance(param_schema, dict):
            continue
        fmt = param_schema.get("format", "")
        title = param_schema.get("title", "").lower()
        description = param_schema.get("description", "").lower()
        if fmt in ("uri", "url"):
            url_names.append(param_name)
        elif any(
            kw in (param_name.lower() + " " + title + " " + description)
            for kw in ("url", "uri", "endpoint", "webhook", "callback", "target")
        ):
            url_names.append(param_name)
    return url_names


def _make_finding(
    *,
    category: str,
    severity: Severity,
    tool_name: str,
    evidence: str,
    recommendation: str,
    payload: str | None = None,
    response_snippet: str | None = None,
) -> Finding:
    """Create a Finding scoped to an MCP tool audit."""
    return Finding(
        id=str(uuid.uuid4()),
        scan_id="mcp_audit",
        category=category,
        owasp_category="API8",
        severity=severity,
        endpoint=f"mcp://tool/{tool_name}",
        method="INVOKE",
        status_code=0,
        response_size=len(response_snippet or ""),
        response_time=0.0,
        evidence=evidence,
        recommendation=recommendation,
        payload=payload,
        response_snippet=response_snippet,
        timestamp=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Secret / credential detection
# (mirrors PropertyLevelAuthModule._contains_sensitive_data logic — Req 8.5)
# ---------------------------------------------------------------------------

# Self-sufficient credential patterns
_CREDENTIAL_SUFFICIENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\d{3}-\d{2}-\d{4}"),                           # SSN
    re.compile(r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"),     # Credit card
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # Email
    re.compile(r"sk_[a-zA-Z0-9]{20,}"),                          # Stripe secret
]

# Credential prefixes (self-sufficient evidence)
_CREDENTIAL_PREFIXES: tuple[str, ...] = ("sk_", "pk_", "AKIA", "ghp_", "xoxb-")

# Credential-shape patterns (necessary but not sufficient alone)
_CREDENTIAL_SHAPE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[A-Za-z0-9]{32,}"),
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),
]

_CREDENTIAL_ENTROPY_THRESHOLD = 3.5

# Additional key/token field-name hints used for corroboration
_SENSITIVE_FIELD_KEYWORDS = (
    "key", "token", "secret", "password", "passwd", "credential",
    "api_key", "access_token", "auth", "bearer",
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _response_contains_secret(response_text: str) -> tuple[bool, str]:
    """Return (found, evidence_snippet) for the first credential match."""
    # Sufficient patterns
    for pattern in _CREDENTIAL_SUFFICIENT_PATTERNS:
        m = pattern.search(response_text)
        if m:
            return True, m.group(0)[:100]

    # Prefix check
    for prefix in _CREDENTIAL_PREFIXES:
        idx = response_text.find(prefix)
        if idx != -1:
            snippet = response_text[idx : idx + 60]
            return True, snippet

    # Shape + entropy corroboration
    for shape_pat in _CREDENTIAL_SHAPE_PATTERNS:
        for m in shape_pat.finditer(response_text):
            candidate = m.group(0)
            if _shannon_entropy(candidate) >= _CREDENTIAL_ENTROPY_THRESHOLD:
                return True, candidate[:80]

    return False, ""


# ---------------------------------------------------------------------------
# MCPTargetAuditor
# ---------------------------------------------------------------------------


class MCPTargetAuditor:
    """Offensive auditor for third-party MCP servers.

    Connects as a generic MCP client to the ``target`` server, enumerates its
    tools, and runs a suite of offensive checks covering:

    * **Tool-poisoning** — hidden prompt instructions in descriptions (Req 8.2)
    * **SSRF** — URL-accepting tools probed with internal/metadata payloads (Req 8.3)
    * **Missing confirmation gate** — destructive tools invoked without
      confirmation (Req 8.4)
    * **Credential leak** — secrets/tokens in tool responses (Req 8.5)

    The ``target`` may be:
      - A ``http://`` or ``https://`` URL for HTTP/SSE transport.
      - A shell command string (e.g. ``"node server.js"``) for stdio transport.

    Usage::

        auditor = MCPTargetAuditor("http://localhost:9000")
        tools = await auditor.discover()
        findings = await auditor.audit()
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self._poisoning_detector = ToolPoisoningDetector()
        self._logger = logger.bind(module="mcp_target_auditor", target=target)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def discover(self) -> list[RemoteToolSpec]:
        """Connect to the target MCP server and enumerate its tools.

        Returns a list of :class:`RemoteToolSpec` objects, one per tool
        advertised by the server.

        For HTTP targets the auditor performs an HTTP-based tool-list request.
        For stdio targets it launches the command and reads the tool list.

        Requirement 8.1
        """
        self._logger.info("mcp_audit_discover_start")
        try:
            tools = await self._fetch_tool_list()
            self._logger.info("mcp_audit_discover_done", tool_count=len(tools))
            return tools
        except Exception as exc:
            self._logger.error("mcp_audit_discover_error", error=str(exc))
            raise

    async def audit(self) -> list[Finding]:
        """Run all offensive audit checks and return the aggregated findings.

        Covers Requirement 8.2, 8.3, 8.4, 8.5.
        """
        self._logger.info("mcp_audit_start")
        tools = await self.discover()
        findings: list[Finding] = []

        for tool in tools:
            # 8.2 — Tool-poisoning
            poisoning_finding = self._poisoning_detector.scan_description(tool)
            if poisoning_finding is not None:
                poisoning_finding.scan_id = "mcp_audit"
                findings.append(poisoning_finding)

            # 8.4 — Missing confirmation for destructive tools
            if tool.appears_destructive:
                destructive_findings = await self._check_missing_confirmation(tool)
                findings.extend(destructive_findings)

        # 8.3 — SSRF via URL-accepting tools
        ssrf_findings = await self._check_ssrf(tools)
        findings.extend(ssrf_findings)

        # 8.5 — Credential leak in responses
        leak_findings = await self._check_credential_leak(tools)
        findings.extend(leak_findings)

        self._logger.info("mcp_audit_done", finding_count=len(findings))
        return findings

    # ------------------------------------------------------------------
    # Transport-level tool list fetch
    # ------------------------------------------------------------------

    async def _fetch_tool_list(self) -> list[RemoteToolSpec]:
        """Retrieve the tool list from the target server.

        Uses the MCP SDK client if available; falls back to a direct HTTP
        ``/tools/list`` probe for HTTP targets, or a stdio launch for
        command targets.
        """
        target = self.target.strip()
        if target.startswith(("http://", "https://")):
            return await self._fetch_via_http(target)
        else:
            return await self._fetch_via_stdio(target)

    async def _fetch_via_http(self, url: str) -> list[RemoteToolSpec]:
        """Fetch the tool list from an HTTP MCP server.

        First tries the MCP SDK client (preferred); falls back to a raw
        ``/tools/list`` POST if the SDK is not installed.
        """
        try:
            return await self._fetch_via_sdk_http(url)
        except ImportError:
            return await self._fetch_via_raw_http(url)

    async def _fetch_via_sdk_http(self, url: str) -> list[RemoteToolSpec]:
        """Use the official MCP Python SDK to list tools over HTTP."""
        import mcp.client.session as _mcp_session  # type: ignore[import]
        import mcp.client.sse as _mcp_sse  # type: ignore[import]

        tools: list[RemoteToolSpec] = []
        async with _mcp_sse.sse_client(url) as (read, write):
            async with _mcp_session.ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                for t in result.tools:
                    tools.append(
                        RemoteToolSpec(
                            name=t.name,
                            description=t.description or "",
                            input_schema=t.inputSchema or {},
                        )
                    )
        return tools

    async def _fetch_via_raw_http(self, base_url: str) -> list[RemoteToolSpec]:
        """POST to ``/tools/list`` directly (no MCP SDK dependency)."""
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "Neither the MCP SDK nor httpx is available; cannot connect to "
                f"HTTP target {base_url!r}."
            ) from exc

        endpoint = base_url.rstrip("/") + "/tools/list"
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()

        raw_tools: list[dict[str, Any]] = (
            data.get("result", {}).get("tools", [])
            if isinstance(data, dict)
            else []
        )
        return [
            RemoteToolSpec(
                name=t.get("name", "<unknown>"),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            )
            for t in raw_tools
            if isinstance(t, dict)
        ]

    async def _fetch_via_stdio(self, command: str) -> list[RemoteToolSpec]:
        """Launch the command as a stdio MCP server and list its tools.

        Parameters are passed as a list (never shell=True) to prevent command
        injection (Requirement 4.6 / Property 9).
        """
        try:
            return await self._fetch_via_sdk_stdio(command)
        except ImportError:
            return await self._fetch_via_raw_stdio(command)

    async def _fetch_via_sdk_stdio(self, command: str) -> list[RemoteToolSpec]:
        """Use the official MCP Python SDK stdio client."""
        import mcp.client.session as _mcp_session  # type: ignore[import]
        import mcp.client.stdio as _mcp_stdio  # type: ignore[import]

        args = shlex.split(command)
        tools: list[RemoteToolSpec] = []
        async with _mcp_stdio.stdio_client(_mcp_stdio.StdioServerParameters(
            command=args[0],
            args=args[1:],
        )) as (read, write):
            async with _mcp_session.ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                for t in result.tools:
                    tools.append(
                        RemoteToolSpec(
                            name=t.name,
                            description=t.description or "",
                            input_schema=t.inputSchema or {},
                        )
                    )
        return tools

    async def _fetch_via_raw_stdio(self, command: str) -> list[RemoteToolSpec]:
        """Send a raw JSON-RPC ``tools/list`` over stdio without the SDK."""
        args = shlex.split(command)
        if not args:
            return []

        # Safety: args is a list — never passed through shell=True.
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        init_msg = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
            '{"protocolVersion":"2024-11-05","capabilities":{},'
            '"clientInfo":{"name":"apileaks-auditor","version":"1.0"}}}\n'
        )
        list_msg = (
            '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
        )

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=(init_msg + list_msg).encode()),
                timeout=10.0,
            )
        except TimeoutError:
            proc.kill()
            return []

        tools: list[RemoteToolSpec] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw_tools = data.get("result", {}).get("tools", [])
            if raw_tools:
                for t in raw_tools:
                    if isinstance(t, dict):
                        tools.append(
                            RemoteToolSpec(
                                name=t.get("name", "<unknown>"),
                                description=t.get("description", ""),
                                input_schema=t.get("inputSchema", {}),
                            )
                        )
                break

        return tools

    # ------------------------------------------------------------------
    # Audit checks
    # ------------------------------------------------------------------

    async def _check_missing_confirmation(
        self, tool: RemoteToolSpec
    ) -> list[Finding]:
        """Verify whether a destructive-looking tool on the target server
        can be invoked without any confirmation mechanism (Requirement 8.4).

        Strategy: invoke the tool with minimal/empty parameters and observe
        whether the server returns a meaningful error demanding confirmation.
        A response that proceeds (HTTP 2xx / no confirmation error) signals
        the absence of a gate.
        """
        self._logger.debug(
            "mcp_audit_check_confirmation", tool_name=tool.name
        )
        try:
            response_text = await self._invoke_tool_minimal(tool)
        except Exception as exc:
            # Connection failures are not a missing-confirmation finding.
            self._logger.debug(
                "mcp_audit_confirmation_invoke_error",
                tool_name=tool.name,
                error=str(exc),
            )
            return []

        if response_text is None:
            return []

        # Look for confirmation-gate signals in the response.
        confirmation_keywords = (
            "confirmation", "confirm", "requires_confirmation",
            "CONFIRMATION_REQUIRED", "destructive", "consent",
        )
        response_lower = response_text.lower()
        gate_present = any(kw.lower() in response_lower for kw in confirmation_keywords)

        if gate_present:
            # Server asked for confirmation — no finding.
            return []

        # The server responded without requiring confirmation.
        return [
            _make_finding(
                category="MCP_MISSING_DESTRUCTIVE_CONFIRMATION",
                severity=Severity.HIGH,
                tool_name=tool.name,
                evidence=(
                    f"Tool '{tool.name}' appears destructive based on its description "
                    "but did not return a confirmation requirement when invoked with "
                    "minimal parameters.  A Destructive_Confirmation_Gate is absent "
                    "or can be bypassed."
                ),
                recommendation=(
                    "Implement a mandatory Destructive_Confirmation_Gate (e.g. "
                    "ConfirmationToken) for all state-modifying MCP tools.  The gate "
                    "must be enforced per-invocation, regardless of any process-level "
                    "flag (Requirement 4.1, 4.2)."
                ),
                response_snippet=response_text[:300],
            )
        ]

    async def _check_ssrf(self, tools: list[RemoteToolSpec]) -> list[Finding]:
        """Probe URL-accepting tools with SSRF payloads (Requirement 8.3).

        Reuses :data:`~modules.owasp.ssrf_testing.CLOUD_METADATA_PROBES` and
        :data:`~modules.owasp.ssrf_testing.BYPASS_PROBES` from the existing
        SSRF module (no code duplication).
        """
        findings: list[Finding] = []
        # Collect all SSRF probe URLs from the existing module constants.
        ssrf_payloads: list[str] = [p.payload for p in CLOUD_METADATA_PROBES]
        ssrf_payloads += [p.payload for p in BYPASS_PROBES]
        # Add a selection of dangerous-scheme probes.
        ssrf_payloads += [f"{scheme}127.0.0.1/" for scheme in SSRF_SCHEMES[:3]]

        url_tools = [t for t in tools if t.url_param_names]
        if not url_tools:
            return findings

        for tool in url_tools:
            for url_param in tool.url_param_names:
                for ssrf_url in ssrf_payloads[:6]:  # limit probes per tool
                    try:
                        response_text = await self._invoke_tool_with_param(
                            tool, url_param, ssrf_url
                        )
                    except Exception:
                        continue

                    if response_text and self._ssrf_signature_detected(response_text):
                        findings.append(
                            _make_finding(
                                category="MCP_SSRF_VIA_TOOL",
                                severity=Severity.CRITICAL,
                                tool_name=tool.name,
                                evidence=(
                                    f"Tool '{tool.name}' parameter '{url_param}' "
                                    f"triggered an SSRF response when injected with "
                                    f"payload '{ssrf_url}'.  Internal/metadata content "
                                    "was detected in the response."
                                ),
                                recommendation=(
                                    "Implement strict URL allowlisting before forwarding "
                                    "any user-supplied URL to an outbound HTTP client.  "
                                    "Block all RFC-1918 addresses, link-local ranges "
                                    "(169.254.0.0/16), and loopback addresses at the "
                                    "network layer (OWASP API7)."
                                ),
                                payload=ssrf_url,
                                response_snippet=response_text[:300],
                            )
                        )
                        break  # one finding per tool/param pair

        return findings

    async def _check_credential_leak(
        self, tools: list[RemoteToolSpec]
    ) -> list[Finding]:
        """Invoke each tool with minimal params and scan the response for
        leaked credentials/tokens (Requirement 8.5)."""
        findings: list[Finding] = []
        for tool in tools:
            try:
                response_text = await self._invoke_tool_minimal(tool)
            except Exception:
                continue
            if not response_text:
                continue

            found, evidence_snippet = _response_contains_secret(response_text)
            if found:
                findings.append(
                    _make_finding(
                        category="MCP_CREDENTIAL_LEAK",
                        severity=Severity.CRITICAL,
                        tool_name=tool.name,
                        evidence=(
                            f"Tool '{tool.name}' returned a response that contains "
                            f"what appears to be a credential/token.  Snippet: "
                            f"{evidence_snippet!r}"
                        ),
                        recommendation=(
                            "Ensure that MCP tool responses never include raw "
                            "credentials, API keys, or tokens.  Apply "
                            "``redact_secrets`` to all tool outputs before returning "
                            "them to the client (Requirement 8.5 / OWASP MCP01)."
                        ),
                        response_snippet=response_text[:300],
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Minimal invocation helpers
    # ------------------------------------------------------------------

    async def _invoke_tool_minimal(self, tool: RemoteToolSpec) -> str | None:
        """Invoke a tool with the minimum valid parameters (or empty params)
        and return the raw response as a string, or None on error."""
        minimal_params = self._build_minimal_params(tool.input_schema)
        return await self._invoke_tool_raw(tool.name, minimal_params)

    async def _invoke_tool_with_param(
        self, tool: RemoteToolSpec, param_name: str, param_value: str
    ) -> str | None:
        """Invoke a tool with a single overridden parameter value."""
        params = self._build_minimal_params(tool.input_schema)
        params[param_name] = param_value
        return await self._invoke_tool_raw(tool.name, params)

    async def _invoke_tool_raw(
        self, tool_name: str, params: dict[str, Any]
    ) -> str | None:
        """Send a tool invocation to the target server and return the raw
        response body as a string."""
        target = self.target.strip()
        if target.startswith(("http://", "https://")):
            return await self._invoke_via_http(target, tool_name, params)
        else:
            return await self._invoke_via_stdio(target, tool_name, params)

    async def _invoke_via_http(
        self, base_url: str, tool_name: str, params: dict[str, Any]
    ) -> str | None:
        try:
            import httpx
        except ImportError:
            return None

        endpoint = base_url.rstrip("/") + "/tools/call"
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": params},
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(endpoint, json=payload)
                return resp.text
        except Exception as exc:
            self._logger.debug("invoke_http_error", tool=tool_name, error=str(exc))
            return None

    async def _invoke_via_stdio(
        self, command: str, tool_name: str, params: dict[str, Any]
    ) -> str | None:
        args = shlex.split(command)
        if not args:
            return None

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        init_msg = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
            '{"protocolVersion":"2024-11-05","capabilities":{},'
            '"clientInfo":{"name":"apileaks-auditor","version":"1.0"}}}\n'
        )
        call_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": params},
        }) + "\n"

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=(init_msg + call_msg).encode()),
                timeout=10.0,
            )
        except TimeoutError:
            proc.kill()
            return None

        return stdout.decode(errors="replace")

    # ------------------------------------------------------------------
    # Parameter construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_minimal_params(schema: dict[str, Any]) -> dict[str, Any]:
        """Build a minimal parameter dict satisfying the required fields in
        the tool's input schema, using safe placeholder values."""
        if not isinstance(schema, dict):
            return {}
        props: dict[str, Any] = schema.get("properties", {})
        required: list[str] = schema.get("required", [])
        params: dict[str, Any] = {}
        for field_name in required:
            field_schema = props.get(field_name, {}) if isinstance(props, dict) else {}
            params[field_name] = _safe_placeholder(field_name, field_schema)
        return params

    # ------------------------------------------------------------------
    # SSRF signature detection
    # ------------------------------------------------------------------

    @staticmethod
    def _ssrf_signature_detected(response_text: str) -> bool:
        """Return True when the response contains internal metadata signatures."""
        return any(sig in response_text for sig in INTERNAL_TARGET_SIGNATURES)


def _safe_placeholder(field_name: str, field_schema: dict[str, Any]) -> Any:
    """Return a safe placeholder value for a required tool parameter."""
    name_lower = field_name.lower()
    fmt = field_schema.get("format", "") if isinstance(field_schema, dict) else ""
    type_ = field_schema.get("type", "string") if isinstance(field_schema, dict) else "string"

    if fmt in ("uri", "url") or any(
        kw in name_lower for kw in ("url", "uri", "endpoint", "webhook", "callback")
    ):
        return "http://audit-probe.invalid/"
    if type_ == "integer":
        return 0
    if type_ == "number":
        return 0.0
    if type_ == "boolean":
        return False
    if type_ == "array":
        return []
    if type_ == "object":
        return {}
    # Default: empty string for string/unknown types
    return ""
