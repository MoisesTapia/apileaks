"""
mcp_server.scan_handler — MCP tool spec for ``apileak.scan``.

Implements Task 2.1: register the ``apileak.scan`` tool that maps to the
existing ``cli/commands/scan_cmds.py::scan`` high-level command.

The handler runs the scan programmatically using the same core engine that
the CLI uses (``ConfigurationManager`` + ``APILeakCore``), avoiding any
dependency on Click context or ``sys.exit()`` calls.  Findings are collected
from :class:`~utils.findings.FindingsCollector` and returned in the standard
APILeak :class:`~utils.findings.Finding` format inside an
:class:`~mcp_server.schemas.MCPToolResult` (Requirements 1.2, 1.4).

Tool name: ``apileak.scan``
"""

from __future__ import annotations

import dataclasses
from typing import Any

from cli.config_builders import create_enhanced_config, resolve_max_depth
from cli.owasp_descriptors import all_keys as all_owasp_keys
from core import ConfigurationManager
from core.engine import APILeakCore
from core.logging import get_logger
from mcp_server.schemas import MCPToolResult, MCPToolSpec

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# JSON Schema — input parameters for apileak.scan
#
# Derived directly from the transversal options declared in
# ``cli/shared_options.py`` and the module-key list from
# ``cli/owasp_descriptors.py``.  Each property name uses snake_case to match
# the Click option dest names so the opts dict in ``_build_scan_config`` can
# be consumed without renaming.
# ---------------------------------------------------------------------------

#: All registered OWASP module keys — used to build the ``modules`` enum.
_ALL_MODULE_KEYS: list[str] = list(all_owasp_keys())

SCAN_INPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["target"],
    "additionalProperties": False,
    "properties": {
        # --- Required -------------------------------------------------------
        "target": {
            "type": "string",
            "description": (
                "Target base URL to scan (e.g. https://api.example.com). "
                "Overrides any URL set in a config file."
            ),
        },
        # --- Module selection -----------------------------------------------
        "modules": {
            "type": "array",
            "items": {"type": "string", "enum": _ALL_MODULE_KEYS},
            "uniqueItems": True,
            "description": (
                "OWASP module keys to enable for this scan. "
                "When omitted all registered modules are run. "
                f"Valid values: {', '.join(_ALL_MODULE_KEYS)}."
            ),
        },
        # --- Discovery -------------------------------------------------------
        "depth": {
            "type": "integer",
            "minimum": 0,
            "description": (
                "Maximum recursion depth for endpoint discovery "
                "(0 = no recursion). Defaults to 3 when not specified."
            ),
        },
        "recursive": {
            "type": "boolean",
            "description": "Enable recursive discovery (default: true).",
        },
        "max_requests": {
            "type": "integer",
            "minimum": 1,
            "description": "Global request budget for discovery (default: unbounded).",
        },
        "concurrency": {
            "type": "integer",
            "minimum": 1,
            "description": "Maximum concurrent in-flight requests (default: 50).",
        },
        "extensions": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "File extensions to append to wordlist entries during discovery "
                "(e.g. ['json', 'xml']). Leading dots are optional."
            ),
        },
        # --- Network --------------------------------------------------------
        "rate_limit": {
            "type": "integer",
            "minimum": 1,
            "description": "Maximum requests per second sent to the target.",
        },
        "timeout": {
            "type": "number",
            "exclusiveMinimum": 0,
            "description": "Per-request timeout in seconds (default: 10).",
        },
        "retries": {
            "type": "integer",
            "minimum": 0,
            "description": "Number of retry attempts per failed request (default: 2).",
        },
        "proxy": {
            "type": "string",
            "description": (
                "Route all requests through this HTTP proxy "
                "(e.g. http://127.0.0.1:8080)."
            ),
        },
        # --- Authentication -------------------------------------------------
        "auth_context": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": "^[^:]+:.+$",
                "description": "user:token[:privilege] triple.",
            },
            "description": (
                "List of authenticated identities for multi-user authorization "
                "tests. Each entry has the format user:token or user:token:privilege."
            ),
        },
        "jwt": {
            "type": "string",
            "description": "JWT bearer token for authentication.",
        },
        # --- Safety ---------------------------------------------------------
        "safe_mode": {
            "type": "boolean",
            "default": False,
            "description": (
                "Skip all state-changing probes (POST/PUT/PATCH/DELETE) — "
                "non-destructive, read-only scan."
            ),
        },
        # --- Severity gate --------------------------------------------------
        "fail_on": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "default": "high",
            "description": (
                "Severity threshold at which the scan is considered failed "
                "from a CI perspective. Returned in result metadata."
            ),
        },
        # --- Output ---------------------------------------------------------
        "output": {
            "type": "string",
            "description": (
                "Output filename stem for disk reports "
                "(saved under reports/ directory)."
            ),
        },
        "ci_mode": {
            "type": "boolean",
            "default": False,
            "description": "Emit CI-friendly exit-code semantics in result metadata.",
        },
    },
}

#: JSON Schema for the scan tool's structured output.
SCAN_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["tool_name", "findings"],
    "properties": {
        "tool_name": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "description": "APILeak Finding in standard format.",
            },
        },
        "metadata": {
            "type": "object",
            "description": "Scan statistics and severity-gate outcome.",
        },
        "untrusted_content": {
            "type": "boolean",
            "description": (
                "True when findings contain raw data obtained from the target "
                "(response bodies, headers). Clients SHOULD apply prompt-injection "
                "defences on those values (OWASP MCP06)."
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Config builder — maps MCP params dict → APILeakConfig
# ---------------------------------------------------------------------------


def _build_scan_config(params: dict[str, Any]):
    """Build an :class:`~core.config.APILeakConfig` from MCP ``params``.

    Uses :func:`~cli.config_builders.create_enhanced_config` and
    :class:`~core.ConfigurationManager` — the same path the CLI ``scan``
    command uses — so option semantics are byte-identical.

    Args:
        params: Validated input parameters from the MCP client (already
                passed through JSON Schema validation by the registry).

    Returns:
        A ready-to-use :class:`~core.config.APILeakConfig` instance.
    """
    target = params["target"]

    # Build the config dict using the same helper as the CLI
    config_dict = create_enhanced_config(
        target_url=target,
        wordlist_path=None,
        scan_type="full",
        user_agent_config=None,
        output_filename=params.get("output"),
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
        ci_mode=params.get("ci_mode", False),
        fail_on=params.get("fail_on", "high"),
        safe_mode=params.get("safe_mode", False),
    )

    # --- Discovery / budget controls (mirrors _build_and_run) ---------------
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

    # --- Extensions ---------------------------------------------------------
    raw_extensions = params.get("extensions") or []
    if raw_extensions:
        from modules.fuzzing.orchestrator import normalize_extensions
        config_dict["fuzzing"].setdefault("endpoints", {})
        config_dict["fuzzing"]["endpoints"]["extensions"] = normalize_extensions(
            raw_extensions
        )

    # --- Rate limit / proxy -------------------------------------------------
    if params.get("rate_limit"):
        config_dict.setdefault("rate_limiting", {})
        config_dict["rate_limiting"]["requests_per_second"] = params["rate_limit"]
    if params.get("proxy"):
        config_dict["proxy"] = params["proxy"]

    # Load + validate
    config_manager = ConfigurationManager()
    cfg = config_manager.load_config_from_dict(config_dict)

    # --- Module selection ---------------------------------------------------
    selected_keys = params.get("modules") or list(all_owasp_keys())
    cfg.owasp_testing.enabled_modules = selected_keys

    return cfg, config_manager


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


async def _scan_handler(params: dict[str, Any]) -> MCPToolResult:
    """Execute an APILeak scan and return findings in structured MCP format.

    This is the ``handler`` for the ``apileak.scan`` :class:`MCPToolSpec`.
    It is called by :meth:`~mcp_server.tool_registry.MCPToolRegistry.invoke`
    after schema validation and (if applicable) destructive-confirmation
    gating.

    Requirements: 1.2, 1.4
    """
    target = params["target"]
    logger.info("mcp_scan_starting", target=target, params_keys=list(params.keys()))

    # Build configuration
    cfg, config_manager = _build_scan_config(params)

    # Validate configuration
    validation_errors = config_manager.validate_configuration()
    if validation_errors:
        from mcp_server.schemas import MCPToolError
        raise MCPToolError(
            f"Scan configuration is invalid: {'; '.join(validation_errors)}",
            error_code="INVALID_CONFIG",
        )

    # Run the scan
    core = APILeakCore(cfg)
    try:
        await core.health_check()
        await core.run_scan(target, scope_endpoints=None)
    except Exception as exc:
        from mcp_server.schemas import MCPToolError
        raise MCPToolError(
            f"Scan execution failed: {exc}",
            error_code="SCAN_ERROR",
        ) from exc

    # Collect findings
    collector = core.get_findings_collector()
    raw_findings: list[Any] = collector.get_findings()

    # Serialise findings to plain dicts so the result is JSON-serialisable
    # and follows the standard Finding format (Requirement 1.4).
    serialised: list[dict[str, Any]] = []
    for f in raw_findings:
        try:
            d = dataclasses.asdict(f)
            # Severity is an enum — convert to its string value
            if hasattr(d.get("severity"), "value"):
                d["severity"] = d["severity"].value
            elif isinstance(d.get("severity"), str):
                pass  # already a string
            else:
                from core.config import Severity
                if isinstance(f.severity, Severity):
                    d["severity"] = f.severity.value
            # datetime → ISO string
            if hasattr(d.get("timestamp"), "isoformat"):
                d["timestamp"] = d["timestamp"].isoformat()
            serialised.append(d)
        except Exception as exc:
            logger.warning(
                "mcp_scan_finding_serialise_error",
                finding_id=getattr(f, "id", None),
                error=str(exc),
            )

    stats = collector.get_statistics()
    logger.info(
        "mcp_scan_completed",
        target=target,
        finding_count=len(serialised),
    )

    return MCPToolResult(
        tool_name="apileak.scan",
        findings=serialised,
        metadata={
            "target": target,
            "finding_count": len(serialised),
            "statistics": stats,
            "modules_run": params.get("modules") or list(all_owasp_keys()),
            "safe_mode": params.get("safe_mode", False),
            "ci_mode": params.get("ci_mode", False),
            "fail_on": params.get("fail_on", "high"),
        },
        # Evidence in findings may contain verbatim target response data
        # → mark untrusted so the MCP client applies prompt-injection defences
        # (Requirement 4.8 / OWASP MCP06).
        untrusted_content=True,
    )


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def build_scan_tool_spec() -> MCPToolSpec:
    """Return the fully configured :class:`MCPToolSpec` for ``apileak.scan``.

    Called by :meth:`~mcp_server.server.APILeakMCPServer._register_default_tools`
    to register the tool with the :class:`~mcp_server.tool_registry.MCPToolRegistry`.

    The tool is **not** marked destructive by default: safe-mode scans and
    read-only OWASP modules are non-destructive.  The destructive flag and
    confirmation gate for ``--allow-write-bola`` / ``--allow-destructive-bfla``
    variants are handled in Task 6.1.
    """
    return MCPToolSpec(
        name="apileak.scan",
        description=(
            "Run a full OWASP API Security Top 10 scan against the target URL. "
            "Performs endpoint discovery followed by the selected OWASP test modules "
            "(BOLA, Auth, Property, Resource, BFLA, Business Flow, SSRF, "
            "Security Misconfiguration, Inventory, Unsafe Consumption, "
            "Parameter Pollution, Spec-Driven Testing). "
            "Returns structured findings in APILeak's standard Finding format. "
            "Maps to `apileaks scan` on the CLI."
        ),
        input_schema=SCAN_INPUT_SCHEMA,
        output_schema=SCAN_OUTPUT_SCHEMA,
        is_destructive=False,
        handler=_scan_handler,
        max_execution_seconds=600.0,  # Full scans can be long
    )
