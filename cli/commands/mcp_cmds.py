"""
cli.commands.mcp_cmds — MCP server and audit CLI commands.

Adds two top-level commands to the ``apileaks`` CLI:

* ``apileaks mcp-server``  — Starts the APILeak MCP server (Requirement 2.1, 2.2).
* ``apileaks mcp-audit``   — Audits a third-party MCP server (Requirement 8.1, Task 11.7).

Task 3.1 implements ``mcp-server`` with ``--transport stdio`` only.
HTTP transport (``--transport http``), ``--mcp-auth-token``, TLS flags,
and ``mcp-audit`` arrive in Tasks 3.2 and 11.7 respectively.
"""

from __future__ import annotations

import asyncio
import json
import sys

import click

from core.logging import get_logger

logger = get_logger(__name__)


@click.command("mcp-server")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"], case_sensitive=False),
    default="stdio",
    show_default=True,
    help="Transport to use for the MCP server.",
)
@click.option(
    "--port",
    type=int,
    default=None,
    show_default=False,
    help="TCP port for HTTP transport (ignored for stdio). [default: 8080]",
)
@click.option(
    "--mcp-auth-token",
    envvar="APILEAKS_MCP_AUTH_TOKEN",
    default=None,
    help=(
        "Bearer token required by HTTP clients (Requirement 2.3). "
        "Can also be set via the APILEAKS_MCP_AUTH_TOKEN environment variable."
    ),
)
@click.option(
    "--tls-cert",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    default=None,
    help="Path to TLS certificate file (HTTP transport, Requirement 2.5).",
)
@click.option(
    "--tls-key",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    default=None,
    help="Path to TLS private-key file (HTTP transport, Requirement 2.5).",
)
@click.option(
    "--mcp-rate-limit",
    type=int,
    default=60,
    show_default=True,
    help="Maximum tool invocations per client per minute (Requirement 15.2).",
)
@click.option(
    "--allow-destructive-mcp",
    is_flag=True,
    default=False,
    help=(
        "Enable process-level opt-in for destructive tool execution. "
        "Individual invocations still require an explicit ConfirmationToken "
        "(Requirement 4.1)."
    ),
)
@click.option(
    "--audit-log",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Path for the append-only JSON-Lines audit log (Requirement 12.1).",
)
def mcp_server_cmd(
    transport: str,
    port: int | None,
    mcp_auth_token: str | None,
    tls_cert: str | None,
    tls_key: str | None,
    mcp_rate_limit: int,
    allow_destructive_mcp: bool,
    audit_log: str | None,
) -> None:
    """Start the APILeak MCP server.

    Exposes all APILeak scan capabilities (scan, OWASP modules, JWT testing,
    discovery, cloud audit) as MCP tools invocable by an AI agent such as
    Claude or Kiro.

    \b
    Examples:

      # stdio transport — suitable for local AI clients (Claude Desktop, Kiro):
      apileaks mcp-server --transport stdio

      # HTTP transport (Task 3.2 — not yet available):
      apileaks mcp-server --transport http --port 8080

    \b
    Security notes:
      - Destructive tools require an explicit ConfirmationToken per invocation
        even when --allow-destructive-mcp is set.
      - HTTP transport enforces TLS; deploy behind a reverse proxy if no cert
        is provided (Requirement 2.5).
      - stdio transport trusts the parent process implicitly; only use when
        the MCP client is run by the same OS user (Requirement 2.6).
    """
    # Lazy import avoids making mcp_server a hard dependency for the base CLI.
    try:
        from mcp_server.schemas import MCPServerConfig
        from mcp_server.server import APILeakMCPServer
    except ImportError as exc:  # pragma: no cover
        raise click.ClickException(
            "The 'mcp' extra is not installed.  "
            "Install it with:  pip install 'apileaks[mcp]'"
        ) from exc

    transport = transport.lower()

    if transport == "http" and not mcp_auth_token:
        raise click.ClickException(
            "HTTP transport requires an authentication token.  "
            "Set --mcp-auth-token or the APILEAKS_MCP_AUTH_TOKEN environment "
            "variable (Requirement 2.3)."
        )

    config = MCPServerConfig(
        transport=transport,
        port=port,
        auth_token=mcp_auth_token,
        allow_destructive=allow_destructive_mcp,
        tls_cert=tls_cert,
        tls_key=tls_key,
        rate_limit_per_minute=mcp_rate_limit,
        audit_log_path=audit_log,
    )

    server = APILeakMCPServer(transport=transport, config=config)

    logger.info(
        "mcp_server_cmd_launch",
        transport=transport,
        allow_destructive=allow_destructive_mcp,
        rate_limit_per_minute=mcp_rate_limit,
    )

    asyncio.run(server.serve())


# ---------------------------------------------------------------------------
# mcp-audit command (Task 11.7 / Requirement 8.1)
# ---------------------------------------------------------------------------


@click.command("mcp-audit")
@click.option(
    "--target",
    required=True,
    metavar="<url-or-command>",
    help=(
        "Target MCP server to audit.  "
        "Accepts a URL (http:// or https://) for HTTP/SSE transport, "
        "or a shell command string (e.g. 'node server.js') for stdio transport."
    ),
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format for the audit findings.",
)
@click.option(
    "--fail-on-findings",
    is_flag=True,
    default=False,
    help=(
        "Exit with a non-zero status code when any finding of HIGH or CRITICAL "
        "severity is reported (useful for CI pipelines, Requirement 9.2)."
    ),
)
def mcp_audit_cmd(
    target: str,
    output: str,
    fail_on_findings: bool,
) -> None:
    """Audit a third-party MCP server as an attack surface.

    Connects as a generic MCP client to the target server, enumerates its
    tools, and runs the following offensive checks:

    \b
      - Tool-poisoning: hidden prompt instructions in tool descriptions (Req 8.2)
      - SSRF: URL-accepting tools probed with internal/metadata payloads (Req 8.3)
      - Missing confirmation: destructive tools that execute without a gate (Req 8.4)
      - Credential leak: tokens/keys in tool responses (Req 8.5)

    \b
    Examples:

      # Audit an HTTP MCP server:
      apileaks mcp-audit --target http://localhost:9000

      # Audit a stdio MCP server (shell command):
      apileaks mcp-audit --target "node /path/to/server.js"

      # JSON output + fail CI on findings:
      apileaks mcp-audit --target http://mcp.example.com --output json --fail-on-findings

    \b
    Requirements: 8.1 – 8.5, 9.1 – 9.2
    """
    try:
        from modules.mcp_security.mcp_target_auditor import MCPTargetAuditor
    except ImportError as exc:  # pragma: no cover
        raise click.ClickException(
            "The modules.mcp_security package could not be loaded.  "
            "Ensure the package is installed correctly."
        ) from exc

    auditor = MCPTargetAuditor(target)

    logger.info("mcp_audit_cmd_start", target=target)

    findings = asyncio.run(auditor.audit())

    if output.lower() == "json":
        _print_findings_json(findings)
    else:
        _print_findings_text(findings)

    if fail_on_findings:
        from core.config import Severity

        high_or_critical = [
            f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        if high_or_critical:
            logger.warning(
                "mcp_audit_cmd_findings_gate_triggered",
                count=len(high_or_critical),
            )
            sys.exit(1)


def _print_findings_text(findings: list) -> None:
    """Print findings in human-readable text format."""
    if not findings:
        click.echo("✓  No findings detected.")
        return

    click.echo(f"\n{'=' * 60}")
    click.echo(f"  MCP Audit — {len(findings)} finding(s) detected")
    click.echo(f"{'=' * 60}\n")

    for i, f in enumerate(findings, 1):
        severity_label = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        click.echo(f"  [{i}] {f.category}  [{severity_label.upper()}]")
        click.echo(f"      Tool : {f.endpoint}")
        click.echo(f"      Evidence : {f.evidence[:150]}")
        click.echo(f"      Recommendation : {f.recommendation[:200]}")
        if f.response_snippet:
            click.echo(f"      Response snippet : {f.response_snippet[:100]}")
        click.echo()


def _print_findings_json(findings: list) -> None:
    """Print findings as a JSON array."""
    output_data = []
    for f in findings:
        output_data.append(
            {
                "id": f.id,
                "category": f.category,
                "severity": (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity)
                ),
                "endpoint": f.endpoint,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "response_snippet": f.response_snippet,
                "payload": f.payload,
            }
        )
    click.echo(json.dumps(output_data, indent=2))
