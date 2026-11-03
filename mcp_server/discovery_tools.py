"""
mcp_server.discovery_tools — MCP tool specs for endpoint and parameter discovery.

Implements Task 2.3 (discovery portion): register MCP tools for the two
primary discovery commands exposed by the ``discovery_cmds.py`` CLI layer:

- ``apileak.discovery.dir`` — endpoint/directory fuzzing (maps to
  ``apileaks dir``).  Discovers hidden API endpoints and directories via
  wordlist-based HTTP fuzzing.
- ``apileak.discovery.par`` — parameter fuzzing (maps to ``apileaks par``).
  Discovers undocumented/hidden request parameters on known endpoints by
  fuzzing candidate names and watching for anomalous server behaviour.

Both handlers use :class:`~core.engine.APILeakCore` with
:class:`~core.ConfigurationManager` — the same infrastructure the CLI uses —
so option semantics are byte-identical.  There is no subprocess invocation
and no ``shell=True`` (Requirement 4.6 / OWASP MCP05).

Results are returned as :class:`~mcp_server.schemas.MCPToolResult` objects
with:
- ``findings`` — standard APILeak :class:`~utils.findings.Finding` objects
  produced during the discovery run (secret detections, parameter anomalies).
- ``metadata`` — rich discovery statistics including discovered endpoint
  summaries.
- ``untrusted_content=True`` — responses contain verbatim target data
  (Requirement 4.8 / OWASP MCP06).

Requirements: 1.2, 1.4
"""

from __future__ import annotations

import dataclasses
from typing import Any

from cli.config_builders import create_enhanced_config, resolve_max_depth
from core import ConfigurationManager
from core.engine import APILeakCore
from core.logging import get_logger
from mcp_server.schemas import MCPToolError, MCPToolResult, MCPToolSpec

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Shared JSON Schema property blocks
# ---------------------------------------------------------------------------

#: Network / budget properties shared by both dir and par tools.
_SHARED_NETWORK_PROPERTIES: dict[str, Any] = {
    "timeout": {
        "type": "number",
        "exclusiveMinimum": 0,
        "description": "Per-request HTTP timeout in seconds (default: 10).",
    },
    "retries": {
        "type": "integer",
        "minimum": 0,
        "description": "Retry attempts per failed request (default: 2).",
    },
    "rate_limit": {
        "type": "integer",
        "minimum": 1,
        "description": "Maximum requests per second sent to the target.",
    },
    "concurrency": {
        "type": "integer",
        "minimum": 1,
        "description": "Maximum concurrent in-flight requests (default: 50).",
    },
    "max_requests": {
        "type": "integer",
        "minimum": 1,
        "description": "Global request budget for this run (default: unbounded).",
    },
    "proxy": {
        "type": "string",
        "description": "Route all requests through this HTTP proxy (e.g. http://127.0.0.1:8080).",
    },
    "jwt": {
        "type": "string",
        "description": "JWT bearer token for authenticated requests.",
    },
}

# ---------------------------------------------------------------------------
# JSON Schema — apileak.discovery.dir
# ---------------------------------------------------------------------------

DIR_INPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["target"],
    "additionalProperties": False,
    "properties": {
        # --- Required -------------------------------------------------------
        "target": {
            "type": "string",
            "description": (
                "Target base URL to discover endpoints on "
                "(e.g. https://api.example.com). "
                "All discovered paths are relative to this URL."
            ),
        },
        # --- Discovery tuning -----------------------------------------------
        "depth": {
            "type": "integer",
            "minimum": 0,
            "description": (
                "Maximum recursion depth for endpoint discovery "
                "(0 = no recursion, default: 3)."
            ),
        },
        "recursive": {
            "type": "boolean",
            "description": "Enable recursive discovery (default: true).",
        },
        "extensions": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "File extensions to append to wordlist entries "
                "(e.g. ['json', 'xml']). Leading dots are optional."
            ),
        },
        "detect_secrets": {
            "type": "boolean",
            "default": False,
            "description": (
                "Scan response bodies for exposed secrets/credentials during "
                "discovery and include them as findings in the result."
            ),
        },
        # --- Shared network -------------------------------------------------
        **_SHARED_NETWORK_PROPERTIES,
    },
}

DIR_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["tool_name", "findings"],
    "properties": {
        "tool_name": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Security findings produced during discovery (e.g. exposed secrets).",
        },
        "metadata": {
            "type": "object",
            "description": (
                "Discovery statistics: target, endpoints_found, valid_endpoints, "
                "auth_required_endpoints, discovered_urls (list of found paths)."
            ),
        },
        "untrusted_content": {"type": "boolean"},
    },
}

# ---------------------------------------------------------------------------
# JSON Schema — apileak.discovery.par
# ---------------------------------------------------------------------------

PAR_INPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["target"],
    "additionalProperties": False,
    "properties": {
        # --- Required -------------------------------------------------------
        "target": {
            "type": "string",
            "description": (
                "Target endpoint URL to fuzz parameters on "
                "(e.g. https://api.example.com/users/123). "
                "A specific endpoint URL is preferred over a base URL for "
                "parameter fuzzing."
            ),
        },
        # --- Parameter fuzzing tuning ----------------------------------------
        "methods": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            },
            "description": (
                "HTTP methods to fuzz. GET/DELETE drive query-parameter injection; "
                "POST/PUT/PATCH drive body-parameter injection. "
                "Default: ['GET', 'POST']."
            ),
        },
        "boundary_testing": {
            "type": "boolean",
            "default": True,
            "description": (
                "Enable boundary-value testing (min/max/empty/null) on each "
                "discovered parameter (default: true)."
            ),
        },
        "depth": {
            "type": "integer",
            "minimum": 0,
            "description": (
                "Recursion depth for pre-fuzzing endpoint discovery "
                "(0 = no recursion, default: 0 for targeted par mode)."
            ),
        },
        # --- Shared network -------------------------------------------------
        **_SHARED_NETWORK_PROPERTIES,
    },
}

PAR_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["tool_name", "findings"],
    "properties": {
        "tool_name": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {"type": "object"},
            "description": (
                "Parameter fuzzing findings: reflected parameters, new JSON "
                "fields, anomalous server responses."
            ),
        },
        "metadata": {
            "type": "object",
            "description": (
                "Fuzzing statistics: target, finding_count, parameters_tested, "
                "requests_made."
            ),
        },
        "untrusted_content": {"type": "boolean"},
    },
}


# ---------------------------------------------------------------------------
# Shared config builder
# ---------------------------------------------------------------------------


def _build_discovery_config(
    params: dict[str, Any],
    *,
    enable_parameters: bool = False,
):
    """Build an :class:`~core.config.APILeakConfig` for a discovery or par run.

    Common base for both the ``dir`` and ``par`` handlers.  Sets
    ``enabled_modules = []`` so the OWASP phase is skipped entirely, and
    toggles ``parameters.enabled`` based on ``enable_parameters``.

    Args:
        params: Validated MCP input parameters.
        enable_parameters: When True, enables the parameter-fuzzing phase in
            the core engine (used by the ``par`` handler).

    Returns:
        A tuple ``(cfg, config_manager)``.
    """
    target = params["target"]

    config_dict = create_enhanced_config(
        target_url=target,
        wordlist_path=None,
        scan_type="full",
        user_agent_config=None,
        output_filename=None,
        advanced_config={
            "detect_framework": False,
            "fuzz_versions": False,
            "framework_confidence": 0.6,
            "enable_payload_encoding": False,
            "enable_waf_evasion": False,
            "enable_subdomain_discovery": False,
            "enable_cors_analysis": False,
        },
        status_code_filter=None,
        ci_mode=False,
        fail_on="high",
        safe_mode=False,
    )

    # --- Discovery / budget controls ----------------------------------------
    config_dict["fuzzing"]["max_depth"] = resolve_max_depth(params.get("depth"))
    if params.get("recursive") is not None:
        config_dict["fuzzing"]["recursive"] = params["recursive"]
    if params.get("max_requests") is not None:
        config_dict["fuzzing"]["max_requests"] = params["max_requests"]
    if params.get("concurrency") is not None:
        config_dict["fuzzing"]["concurrency"] = params["concurrency"]
    if params.get("timeout") is not None:
        config_dict["target"]["timeout"] = params["timeout"]
    if params.get("retries") is not None:
        config_dict["fuzzing"]["retries"] = params["retries"]
    if params.get("depth") == 0:
        config_dict["fuzzing"]["recursive"] = False

    # --- Extensions ----------------------------------------------------------
    raw_extensions = params.get("extensions") or []
    if raw_extensions:
        from modules.fuzzing.orchestrator import normalize_extensions
        config_dict["fuzzing"].setdefault("endpoints", {})
        config_dict["fuzzing"]["endpoints"]["extensions"] = normalize_extensions(
            raw_extensions
        )

    # --- Rate limit / proxy --------------------------------------------------
    if params.get("rate_limit"):
        config_dict.setdefault("rate_limiting", {})
        config_dict["rate_limiting"]["requests_per_second"] = params["rate_limit"]
    if params.get("proxy"):
        config_dict["proxy"] = params["proxy"]

    # --- JWT authentication --------------------------------------------------
    if params.get("jwt"):
        config_dict.setdefault("authentication", {})
        config_dict["authentication"]["jwt_token"] = params["jwt"]

    # Load + validate
    config_manager = ConfigurationManager()
    cfg = config_manager.load_config_from_dict(config_dict)

    # --- Disable all OWASP modules (discovery / par only) -------------------
    cfg.owasp_testing.enabled_modules = []

    # --- Parameter fuzzing toggle ------------------------------------------
    cfg.fuzzing.parameters.enabled = enable_parameters
    cfg.fuzzing.headers.enabled = False  # headers fuzzing not exposed here

    # --- Par: apply methods override ----------------------------------------
    if enable_parameters and params.get("methods"):
        cfg.fuzzing.parameters.methods = [m.upper() for m in params["methods"]]

    # --- Par: boundary testing toggle ---------------------------------------
    if enable_parameters and params.get("boundary_testing") is not None:
        cfg.fuzzing.parameters.boundary_testing = params["boundary_testing"]

    return cfg, config_manager


# ---------------------------------------------------------------------------
# Shared findings serialiser
# ---------------------------------------------------------------------------


def _serialise_findings(raw_findings: list[Any], tool_name: str) -> list[dict[str, Any]]:
    """Convert a list of :class:`~utils.findings.Finding` to plain dicts.

    Handles Severity enum → string and datetime → ISO-8601 conversions.
    Logs a warning (but never raises) when a single finding fails to serialise.
    """
    serialised: list[dict[str, Any]] = []
    for f in raw_findings:
        try:
            d = dataclasses.asdict(f)
            if hasattr(d.get("severity"), "value"):
                d["severity"] = d["severity"].value
            elif not isinstance(d.get("severity"), str):
                from core.config import Severity

                if isinstance(f.severity, Severity):
                    d["severity"] = f.severity.value
            if hasattr(d.get("timestamp"), "isoformat"):
                d["timestamp"] = d["timestamp"].isoformat()
            serialised.append(d)
        except Exception as exc:
            logger.warning(
                "mcp_discovery_finding_serialise_error",
                tool=tool_name,
                finding_id=getattr(f, "id", None),
                error=str(exc),
            )
    return serialised


# ---------------------------------------------------------------------------
# dir handler
# ---------------------------------------------------------------------------


async def _dir_handler(params: dict[str, Any]) -> MCPToolResult:
    """Discover endpoints via wordlist fuzzing and return structured findings.

    Uses :class:`~core.engine.APILeakCore` with no OWASP modules enabled so
    only the endpoint-discovery phase runs.  Discovered endpoints are returned
    in ``metadata``; any security findings from optional secret detection are
    returned in ``findings``.

    Requirements: 1.2, 1.4
    """
    target = params["target"]
    logger.info("mcp_discovery_dir_starting", target=target)

    cfg, config_manager = _build_discovery_config(params, enable_parameters=False)

    validation_errors = config_manager.validate_configuration()
    if validation_errors:
        raise MCPToolError(
            f"Discovery configuration is invalid: {'; '.join(validation_errors)}",
            error_code="INVALID_CONFIG",
        )

    core = APILeakCore(cfg)
    try:
        await core.health_check()
        await core.run_scan(target, scope_endpoints=None)
    except Exception as exc:
        raise MCPToolError(
            f"Endpoint discovery failed: {exc}",
            error_code="DISCOVERY_ERROR",
        ) from exc

    # Collect security findings (e.g. exposed secrets when detect_secrets=True)
    collector = core.get_findings_collector()
    raw_findings = collector.get_findings()
    serialised = _serialise_findings(raw_findings, "apileak.discovery.dir")

    # Collect discovered endpoints for metadata
    discovered_endpoints = core.get_discovered_endpoints()
    endpoint_summaries = [
        {
            "url": getattr(ep, "url", str(ep)),
            "status": ep.status.value  # type: ignore[union-attr]
            if hasattr(getattr(ep, "status", None), "value")
            else str(getattr(ep, "status", "unknown")),
            "auth_required": getattr(ep, "auth_required", False),
            "method": getattr(ep, "method", "GET"),
        }
        for ep in discovered_endpoints
    ]

    valid_count = sum(
        1
        for ep in discovered_endpoints
        if str(getattr(getattr(ep, "status", None), "value", "")) == "valid"
    )
    auth_count = sum(1 for ep in discovered_endpoints if getattr(ep, "auth_required", False))

    stats = collector.get_statistics()
    logger.info(
        "mcp_discovery_dir_completed",
        target=target,
        endpoints_found=len(discovered_endpoints),
        finding_count=len(serialised),
    )

    return MCPToolResult(
        tool_name="apileak.discovery.dir",
        findings=serialised,
        metadata={
            "target": target,
            "endpoints_found": len(discovered_endpoints),
            "valid_endpoints": valid_count,
            "auth_required_endpoints": auth_count,
            "discovered_urls": [ep["url"] for ep in endpoint_summaries],
            "endpoint_details": endpoint_summaries,
            "finding_count": len(serialised),
            "statistics": stats,
        },
        # Responses contain verbatim target data (Requirement 4.8 / OWASP MCP06)
        untrusted_content=True,
    )


# ---------------------------------------------------------------------------
# par handler
# ---------------------------------------------------------------------------


async def _par_handler(params: dict[str, Any]) -> MCPToolResult:
    """Fuzz parameters on discovered endpoints and return structured findings.

    Uses :class:`~core.engine.APILeakCore` with the parameter-fuzzing phase
    enabled and no OWASP modules.  The engine first runs endpoint discovery
    (with zero recursion by default so it targets the supplied URL directly),
    then runs :class:`~modules.fuzzing.orchestrator.ParameterFuzzer` on each
    endpoint to discover undocumented parameters.

    Requirements: 1.2, 1.4
    """
    target = params["target"]

    # Default par mode: target the specific URL directly (depth=0)
    effective_params = dict(params)
    if "depth" not in effective_params:
        effective_params["depth"] = 0

    logger.info("mcp_discovery_par_starting", target=target)

    cfg, config_manager = _build_discovery_config(
        effective_params, enable_parameters=True
    )

    validation_errors = config_manager.validate_configuration()
    if validation_errors:
        raise MCPToolError(
            f"Parameter fuzzing configuration is invalid: {'; '.join(validation_errors)}",
            error_code="INVALID_CONFIG",
        )

    core = APILeakCore(cfg)
    try:
        await core.health_check()
        await core.run_scan(target, scope_endpoints=None)
    except Exception as exc:
        raise MCPToolError(
            f"Parameter fuzzing failed: {exc}",
            error_code="PAR_ERROR",
        ) from exc

    collector = core.get_findings_collector()
    raw_findings = collector.get_findings()
    serialised = _serialise_findings(raw_findings, "apileak.discovery.par")

    stats = collector.get_statistics()
    logger.info(
        "mcp_discovery_par_completed",
        target=target,
        finding_count=len(serialised),
    )

    return MCPToolResult(
        tool_name="apileak.discovery.par",
        findings=serialised,
        metadata={
            "target": target,
            "finding_count": len(serialised),
            "statistics": stats,
            "methods": effective_params.get("methods", ["GET", "POST"]),
        },
        # Responses contain verbatim target data (Requirement 4.8 / OWASP MCP06)
        untrusted_content=True,
    )


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def build_discovery_tool_specs() -> list[MCPToolSpec]:
    """Return :class:`MCPToolSpec` objects for all discovery tools.

    Exposes two tools:

    - ``apileak.discovery.dir``: endpoint / directory fuzzing (maps to
      ``apileaks dir``).
    - ``apileak.discovery.par``: parameter fuzzing (maps to
      ``apileaks par``).

    Called by
    :meth:`~mcp_server.server.APILeakMCPServer._register_default_tools` to
    register both tools with the
    :class:`~mcp_server.tool_registry.MCPToolRegistry`.

    Note on ``is_destructive``:
        Both tools are marked ``is_destructive=False``.  Discovery and
        parameter fuzzing are read-only probes; the destructive-confirmation
        gate (Task 6.1) is not needed here.

    Requirements: 1.2, 1.4
    """
    return [
        MCPToolSpec(
            name="apileak.discovery.dir",
            description=(
                "Discover hidden API endpoints and directories via wordlist-based "
                "HTTP fuzzing against the target base URL. "
                "Performs recursive path enumeration, framework detection, and "
                "optional secret detection in responses. "
                "Returns discovered endpoints as metadata and any security "
                "findings (exposed secrets, misconfigurations) as structured findings. "
                "Maps to `apileaks dir` on the CLI."
            ),
            input_schema=DIR_INPUT_SCHEMA,
            output_schema=DIR_OUTPUT_SCHEMA,
            is_destructive=False,
            handler=_dir_handler,
            max_execution_seconds=300.0,
        ),
        MCPToolSpec(
            name="apileak.discovery.par",
            description=(
                "Discover undocumented or hidden request parameters on a target "
                "endpoint by fuzzing candidate parameter names and watching for "
                "anomalous server responses (reflection, new JSON fields, status "
                "changes, response-size differences). "
                "Supports query-parameter fuzzing (GET/DELETE) and body-parameter "
                "fuzzing (POST/PUT/PATCH) with optional boundary-value testing. "
                "Maps to `apileaks par` on the CLI."
            ),
            input_schema=PAR_INPUT_SCHEMA,
            output_schema=PAR_OUTPUT_SCHEMA,
            is_destructive=False,
            handler=_par_handler,
            max_execution_seconds=300.0,
        ),
    ]
