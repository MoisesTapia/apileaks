"""
mcp_server.cloud_audit_tool — MCP tool spec for ``apileak.cloud_audit``.

Implements Task 2.4: register the ``apileak.cloud_audit`` tool that maps to
``core/cloud_audit.py::CloudAuditOrchestrator``.

**Stub note:** This tool is a *documented stub* while the
``cloud-gateway-security-audit`` spec is in progress.  The tool is fully
registered with a correct JSON Schema, security flags, and description so that
MCP clients can discover and inspect it.  When a client actually invokes the
handler without the underlying orchestrator being available (e.g. missing cloud
provider SDK dependencies), it raises a structured :class:`MCPToolError` with
code ``NOT_IMPLEMENTED`` and a clear message explaining the dependency.

If the orchestrator *is* available (all cloud provider dependencies installed
and ``CloudAuditOrchestrator`` importable), the handler will delegate to it
and return structured :class:`MCPToolResult` output.

Tool name: ``apileak.cloud_audit``

Cloud providers supported (once fully implemented):
  - AWS API Gateway (REST / HTTP / WebSocket APIs)
  - GCP API Gateway / Cloud Endpoints
  - Azure API Management (APIM)

Security flags:
  - ``is_destructive = True`` — the ``--allow-destructive-cloud-audit`` flag
    can enable write/mutate operations on the cloud management plane.
  - ``untrusted_content = True`` in results — raw cloud resource data (API
    configurations, policy documents) is returned verbatim from the target
    and must be treated as untrusted by the MCP client (Req 4.8 / OWASP MCP06).

Requirements: 1.2, 1.4
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from mcp_server.schemas import MCPToolError, MCPToolResult, MCPToolSpec

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# JSON Schema — input parameters for apileak.cloud_audit
#
# Derived from the options accepted by ``cloud-audit`` in
# ``cli/commands/cloud_audit_cmds.py``.
# ---------------------------------------------------------------------------

CLOUD_AUDIT_INPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "apileak.cloud_audit input",
    "description": (
        "Parameters for auditing cloud API gateway security configurations "
        "(AWS API Gateway, GCP API Gateway / Cloud Endpoints, Azure APIM)."
    ),
    "required": ["target"],
    "additionalProperties": False,
    "properties": {
        # ----------------------------------------------------------------
        # Core scope
        # ----------------------------------------------------------------
        "target": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Human-readable label or ARN/resource-ID identifying the audit "
                "scope (e.g. an AWS API Gateway ID, a GCP project ID, or an "
                "Azure subscription ID).  Used to populate the scan report's "
                "target field and as a key for result isolation."
            ),
        },
        "provider": {
            "type": "string",
            "enum": ["aws", "azure", "gcp"],
            "description": (
                "Cloud provider to audit.  Must be one of 'aws', 'azure', or "
                "'gcp'.  To audit multiple providers, invoke the tool once per "
                "provider or use the CLI 'all' shorthand via the CLI directly."
            ),
        },
        # ----------------------------------------------------------------
        # AWS-specific
        # ----------------------------------------------------------------
        "aws_profile": {
            "type": "string",
            "description": "AWS named credential profile (~/.aws/credentials).",
        },
        "aws_role_arn": {
            "type": "string",
            "description": "IAM role ARN to assume before auditing.",
        },
        "aws_regions": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
            "default": ["us-east-1"],
            "description": "AWS region(s) to include in the audit.",
        },
        # ----------------------------------------------------------------
        # GCP-specific
        # ----------------------------------------------------------------
        "gcp_project_id": {
            "type": "string",
            "description": "GCP project ID to audit.",
        },
        "gcp_service_account_file": {
            "type": "string",
            "description": (
                "Path to a GCP service account JSON key file.  Falls back to "
                "Application Default Credentials (ADC) when omitted."
            ),
        },
        # ----------------------------------------------------------------
        # Azure-specific
        # ----------------------------------------------------------------
        "azure_subscription_id": {
            "type": "string",
            "description": "Azure subscription ID to audit.",
        },
        "azure_resource_group": {
            "type": "string",
            "description": "Azure resource group containing APIM instance(s).",
        },
        "azure_tenant_id": {
            "type": "string",
            "description": "Azure tenant ID (overrides AZURE_TENANT_ID env var).",
        },
        "azure_client_id": {
            "type": "string",
            "description": "Azure service principal client ID.",
        },
        # Note: azure_client_secret is intentionally *not* accepted as an MCP
        # parameter — secrets must be passed via environment variable
        # (AZURE_CLIENT_SECRET) or vault, never through the MCP parameter
        # channel (Requirement 7.3 / OWASP MCP01).
        # ----------------------------------------------------------------
        # Safety
        # ----------------------------------------------------------------
        "allow_destructive_cloud_audit": {
            "type": "boolean",
            "default": False,
            "description": (
                "Allow write/mutate operations on the cloud management plane.  "
                "Currently no write operations are implemented; this flag is a "
                "safety knob for future extensibility.  All audits are "
                "read-only by default.  Requires a ConfirmationToken when True "
                "(Requirement 4.1, 4.2)."
            ),
        },
        # ----------------------------------------------------------------
        # Output
        # ----------------------------------------------------------------
        "output_dir": {
            "type": "string",
            "default": "reports",
            "description": "Directory to write the JSON findings report.",
        },
    },
}

CLOUD_AUDIT_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "apileak.cloud_audit output",
    "description": "Structured result from a cloud API gateway security audit.",
    "properties": {
        "findings": {
            "type": "array",
            "description": (
                "Normalised APILeak Finding objects (OWASP API8 — Security "
                "Misconfiguration) produced by the cloud auditors."
            ),
        },
        "metadata": {
            "type": "object",
            "properties": {
                "providers_audited": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "auditors_succeeded": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "auditors_failed": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "auditors_skipped_no_credentials": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "finding_count": {"type": "integer"},
                "untrusted_content": {
                    "type": "boolean",
                    "description": (
                        "Always true — raw cloud resource data from the target "
                        "is included in findings (Req 4.8 / OWASP MCP06)."
                    ),
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


async def _cloud_audit_handler(params: dict[str, Any]) -> MCPToolResult:
    """Invoke CloudAuditOrchestrator or raise NOT_IMPLEMENTED if unavailable.

    Delegates to :class:`~core.cloud_audit.CloudAuditOrchestrator` when the
    ``cloud-gateway-security-audit`` spec implementation is fully available
    (i.e. when ``core.cloud_audit`` and the cloud provider SDKs can be
    imported).

    If the orchestrator cannot be imported — either because the optional cloud
    SDK extras are not installed or because the spec is not yet complete — this
    handler raises a structured :class:`MCPToolError` with code
    ``NOT_IMPLEMENTED`` rather than crashing with an uncontrolled ImportError.

    Args:
        params: Validated input parameters (already passed through JSON Schema
                validation by :class:`~mcp_server.tool_registry.MCPToolRegistry`).

    Returns:
        :class:`MCPToolResult` with structured :class:`~utils.findings.Finding`
        objects and cloud-audit metadata.

    Raises:
        MCPToolError: With ``error_code='NOT_IMPLEMENTED'`` when
            ``CloudAuditOrchestrator`` is not available (stub behaviour).
        MCPToolError: With ``error_code='CLOUD_AUDIT_ERROR'`` for runtime
            failures during an actual audit run.
    """
    # -----------------------------------------------------------------------
    # Attempt to import CloudAuditOrchestrator.
    # The try/except here is intentional: the orchestrator depends on optional
    # cloud SDK packages that may not be installed in all environments.
    # This is the documented stub boundary for the cloud-gateway-security-audit
    # spec dependency (see module docstring).
    # -----------------------------------------------------------------------
    try:
        from core.cloud_audit import CloudAuditOrchestrator  # noqa: PLC0415
        from core.config import CloudAuditConfig  # noqa: PLC0415
    except ImportError as exc:
        raise MCPToolError(
            "The 'apileak.cloud_audit' tool depends on the "
            "'cloud-gateway-security-audit' spec implementation and optional "
            "cloud provider SDK packages (boto3, google-cloud-*, azure-mgmt-*). "
            "Install the 'apileaks[cloud]' extra and ensure the "
            "cloud-gateway-security-audit spec is complete before invoking this "
            f"tool.  Import error: {exc}",
            error_code="NOT_IMPLEMENTED",
        ) from exc

    # -----------------------------------------------------------------------
    # Build CloudAuditConfig from MCP params.
    # The provider field from the schema (aws | azure | gcp) is expanded to
    # the list format expected by CloudAuditConfig.
    # -----------------------------------------------------------------------
    provider = params.get("provider")
    providers = [provider] if provider else ["aws"]

    try:
        config = CloudAuditConfig(
            providers=providers,
            aws_profiles=[params["aws_profile"]] if params.get("aws_profile") else [],
            aws_role_arns=[params["aws_role_arn"]] if params.get("aws_role_arn") else [],
            aws_regions=params.get("aws_regions") or ["us-east-1"],
            gcp_project_ids=(
                [params["gcp_project_id"]] if params.get("gcp_project_id") else []
            ),
            gcp_service_account_file=params.get("gcp_service_account_file"),
            azure_subscription_ids=(
                [params["azure_subscription_id"]]
                if params.get("azure_subscription_id")
                else []
            ),
            azure_resource_groups=(
                [params["azure_resource_group"]]
                if params.get("azure_resource_group")
                else []
            ),
            azure_tenant_id=params.get("azure_tenant_id"),
            azure_client_id=params.get("azure_client_id"),
            # azure_client_secret must come from the environment variable
            # AZURE_CLIENT_SECRET — it is never accepted as an MCP parameter
            # (Requirement 7.3 / OWASP MCP01).
            azure_client_secret=None,
            allow_destructive=params.get("allow_destructive_cloud_audit", False),
        )
    except Exception as exc:
        raise MCPToolError(
            f"Failed to build cloud audit configuration: {exc}",
            error_code="CLOUD_AUDIT_CONFIG_ERROR",
        ) from exc

    # -----------------------------------------------------------------------
    # Run the audit.
    # -----------------------------------------------------------------------
    logger.info(
        "mcp_cloud_audit_start",
        target=params["target"],
        providers=providers,
        allow_destructive=config.allow_destructive,
    )

    try:
        orchestrator = CloudAuditOrchestrator(config)
        summary = await orchestrator.run()
    except Exception as exc:
        logger.error(
            "mcp_cloud_audit_error",
            target=params["target"],
            exc_type=type(exc).__name__,
            exc_message=str(exc),
        )
        raise MCPToolError(
            f"Cloud audit failed for target '{params['target']}': {exc}",
            error_code="CLOUD_AUDIT_ERROR",
        ) from exc

    logger.info(
        "mcp_cloud_audit_complete",
        target=params["target"],
        finding_count=len(summary.findings),
        auditors_succeeded=summary.auditors_succeeded,
        auditors_failed=summary.auditors_failed,
    )

    return MCPToolResult(
        tool_name="apileak.cloud_audit",
        findings=summary.findings,
        metadata={
            "target": params["target"],
            "providers_audited": providers,
            "auditors_succeeded": summary.auditors_succeeded,
            "auditors_failed": summary.auditors_failed,
            "auditors_skipped_no_credentials": summary.auditors_skipped_no_credentials,
            "finding_count": len(summary.findings),
            # Raw cloud resource data returned by cloud provider APIs must be
            # treated as untrusted by the MCP client (Requirement 4.8 / OWASP MCP06).
            "untrusted_content": True,
        },
        raw_output=(
            f"Cloud audit of '{params['target']}' ({', '.join(providers)}) "
            f"complete: {len(summary.findings)} finding(s) across "
            f"{len(summary.auditors_succeeded)} auditor(s)."
        ),
        # Mark the entire result as untrusted_content because raw cloud API
        # response data is embedded in the findings (Requirement 4.8).
        untrusted_content=True,
    )


# ---------------------------------------------------------------------------
# Spec builder
# ---------------------------------------------------------------------------


def build_cloud_audit_tool_spec() -> MCPToolSpec:
    """Return the :class:`MCPToolSpec` for the ``apileak.cloud_audit`` tool.

    The spec is registered in :class:`~mcp_server.server.APILeakMCPServer`
    during ``_register_default_tools()`` (Task 2.4).

    Key characteristics:

    - ``is_destructive = True``: cloud audits may include write/mutate
      operations when ``allow_destructive_cloud_audit`` is True; the
      :class:`~mcp_server.confirmation_gate.DestructiveConfirmationGate`
      always requires an explicit :class:`~mcp_server.schemas.ConfirmationToken`
      (Requirements 4.1, 4.2).
    - ``untrusted_content = True`` on results: raw cloud resource
      configurations returned verbatim from cloud provider APIs must be
      treated as untrusted data by the MCP client (Requirement 4.8 / OWASP MCP06).
    - The handler is a documented stub: it raises ``NOT_IMPLEMENTED`` when
      ``CloudAuditOrchestrator`` cannot be imported, and delegates to the
      orchestrator otherwise.  This allows the server to start and register
      the tool even before the ``cloud-gateway-security-audit`` spec is
      complete (per spec notes in tasks.md).

    Returns:
        Fully configured :class:`MCPToolSpec` for ``apileak.cloud_audit``.
    """
    return MCPToolSpec(
        name="apileak.cloud_audit",
        description=(
            "Audit the security configuration of cloud API gateways "
            "(AWS API Gateway, GCP API Gateway / Cloud Endpoints, Azure APIM). "
            "Performs read-only inspection of the management-plane configuration "
            "and reports Security Misconfiguration findings (OWASP API8). "
            "Destructive (write/mutate) operations are disabled by default and "
            "require explicit confirmation. "
            "\n\n"
            "DEPENDENCY NOTE: This tool requires the 'cloud-gateway-security-audit' "
            "spec implementation and the 'apileaks[cloud]' optional extra to be "
            "installed.  Until that spec is complete, invocations will return a "
            "NOT_IMPLEMENTED error with a clear explanation."
        ),
        input_schema=CLOUD_AUDIT_INPUT_SCHEMA,
        output_schema=CLOUD_AUDIT_OUTPUT_SCHEMA,
        is_destructive=True,
        handler=_cloud_audit_handler,
        # Cloud audits enumerate potentially many API gateways across multiple
        # regions; a generous timeout is appropriate (10 minutes).
        max_execution_seconds=600.0,
    )
