"""
CLI command: apileaks cloud-audit

Audits the configuration of cloud API gateways (AWS API Gateway, GCP API
Gateway / Cloud Endpoints, Azure API Management) using read-only management-
plane SDK calls.  Findings are normalised to standard APILeak Finding objects
under OWASP API8 (Security Misconfiguration) and written to the output
directory alongside any other scan results.

All cloud operations are read-only by default.  Use
--allow-destructive-cloud-audit to enable write operations (none are
currently implemented — the flag exists for future extensibility and as an
explicit safety knob).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from core.cloud_audit import CloudAuditOrchestrator
from core.config import CloudAuditConfig
from core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------


@click.command("cloud-audit")
@click.option(
    "--provider",
    "providers",
    multiple=True,
    default=["aws"],
    show_default=True,
    type=click.Choice(["aws", "gcp", "azure", "all"], case_sensitive=False),
    help="Cloud provider(s) to audit. Pass multiple times for several providers "
    "or use 'all' to audit all configured providers.",
)
# --- AWS options ---
@click.option(
    "--aws-profile",
    "aws_profiles",
    multiple=True,
    default=[],
    metavar="PROFILE",
    help="AWS named credential profile (~/.aws/credentials).",
)
@click.option(
    "--aws-role-arn",
    "aws_role_arns",
    multiple=True,
    default=[],
    metavar="ARN",
    help="IAM role ARN to assume before auditing.",
)
@click.option(
    "--aws-region",
    "aws_regions",
    multiple=True,
    default=["us-east-1"],
    show_default=True,
    metavar="REGION",
    help="AWS region(s) to audit (repeatable).",
)
# --- GCP options ---
@click.option(
    "--gcp-project-id",
    "gcp_project_ids",
    multiple=True,
    default=[],
    metavar="PROJECT_ID",
    help="GCP project ID(s) to audit (repeatable).",
)
@click.option(
    "--gcp-service-account-file",
    "gcp_service_account_file",
    default=None,
    metavar="PATH",
    help="Path to a GCP service account JSON key file. "
    "Falls back to Application Default Credentials when omitted.",
)
# --- Azure options ---
@click.option(
    "--azure-subscription-id",
    "azure_subscription_ids",
    multiple=True,
    default=[],
    metavar="SUB_ID",
    help="Azure subscription ID(s) to audit (repeatable).",
)
@click.option(
    "--azure-resource-group",
    "azure_resource_groups",
    multiple=True,
    default=[],
    metavar="RG",
    help="Azure resource group(s) containing APIM instances (repeatable).",
)
@click.option("--azure-tenant-id", "azure_tenant_id", default=None, envvar="AZURE_TENANT_ID")
@click.option("--azure-client-id", "azure_client_id", default=None, envvar="AZURE_CLIENT_ID")
@click.option(
    "--azure-client-secret",
    "azure_client_secret",
    default=None,
    envvar="AZURE_CLIENT_SECRET",
    help="Azure service principal client secret. "
    "Read from AZURE_CLIENT_SECRET env var when not provided.",
)
# --- Safety ---
@click.option(
    "--allow-destructive-cloud-audit",
    "allow_destructive",
    is_flag=True,
    default=False,
    help="Allow write/mutate operations against the cloud management API "
    "(currently no write operations are implemented; this flag is a "
    "safety knob for future extensibility). Read-only by default.",
)
# --- Output ---
@click.option(
    "--output-dir",
    "output_dir",
    default="reports",
    show_default=True,
    metavar="DIR",
    help="Directory to write the JSON findings report.",
)
@click.option(
    "--output-format",
    "output_format",
    type=click.Choice(["json", "text"], case_sensitive=False),
    default="json",
    show_default=True,
)
def cloud_audit_cmd(
    providers: tuple[str, ...],
    aws_profiles: tuple[str, ...],
    aws_role_arns: tuple[str, ...],
    aws_regions: tuple[str, ...],
    gcp_project_ids: tuple[str, ...],
    gcp_service_account_file: str | None,
    azure_subscription_ids: tuple[str, ...],
    azure_resource_groups: tuple[str, ...],
    azure_tenant_id: str | None,
    azure_client_id: str | None,
    azure_client_secret: str | None,
    allow_destructive: bool,
    output_dir: str,
    output_format: str,
) -> None:
    """
    Audit cloud API gateway configurations (AWS / GCP / Azure).

    Reads the management-plane configuration of API Gateway services using
    the cloud provider's SDK and credential chain, then reports
    Security Misconfiguration findings (OWASP API8).

    Examples:

      # Audit AWS API Gateway using the default credential chain:\n
      apileaks cloud-audit --provider aws\n

      # Audit a specific AWS profile and region:\n
      apileaks cloud-audit --provider aws --aws-profile prod --aws-region eu-west-1\n

      # Audit GCP + Azure in one run:\n
      apileaks cloud-audit --provider gcp --provider azure \\
        --gcp-project-id my-project \\
        --azure-subscription-id 00000000-1111-2222-3333-444444444444 \\
        --azure-resource-group my-rg
    """
    # Expand "all" shorthand
    resolved_providers = list(providers)
    if "all" in resolved_providers:
        resolved_providers = ["aws", "gcp", "azure"]

    config = CloudAuditConfig(
        providers=resolved_providers,
        aws_profiles=list(aws_profiles),
        aws_role_arns=list(aws_role_arns),
        aws_regions=list(aws_regions) or ["us-east-1"],
        gcp_project_ids=list(gcp_project_ids),
        gcp_service_account_file=gcp_service_account_file,
        azure_subscription_ids=list(azure_subscription_ids),
        azure_resource_groups=list(azure_resource_groups),
        azure_tenant_id=azure_tenant_id,
        azure_client_id=azure_client_id,
        azure_client_secret=azure_client_secret,
        allow_destructive=allow_destructive,
    )

    click.echo(f"[cloud-audit] Starting audit: providers={resolved_providers}")
    if allow_destructive:
        click.echo(
            "[cloud-audit] WARNING: destructive mode enabled — write operations permitted.",
            err=True,
        )

    orchestrator = CloudAuditOrchestrator(config)
    summary = asyncio.run(orchestrator.run())

    # --- Report ---
    click.echo(
        f"\n[cloud-audit] {len(summary.findings)} finding(s) across "
        f"{len(summary.auditors_succeeded)} auditor(s)."
    )
    if summary.auditors_failed:
        click.echo(f"[cloud-audit] FAILED auditors: {summary.auditors_failed}", err=True)
    if summary.auditors_skipped_no_credentials:
        click.echo(
            f"[cloud-audit] SKIPPED (no credentials): {summary.auditors_skipped_no_credentials}",
            err=True,
        )

    # Write output
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    findings_file = output_path / "cloud_audit_findings.json"

    serializable = [
        {
            "id": f.id,
            "category": f.category,
            "owasp_category": f.owasp_category,
            "severity": f.severity.value,
            "endpoint": f.endpoint,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        }
        for f in summary.findings
    ]

    with open(findings_file, "w", encoding="utf-8") as fh:
        json.dump(serializable, fh, indent=2, ensure_ascii=False)

    click.echo(f"[cloud-audit] Findings written to: {findings_file}")

    if output_format == "text":
        for f in summary.findings:
            click.echo(
                f"  [{f.severity.value}] {f.category} — {f.endpoint}\n"
                f"    {f.evidence[:120] if isinstance(f.evidence, str) else f.evidence}"
            )

    # Exit non-zero if any critical/high findings were found
    high_plus = [f for f in summary.findings if f.severity.value in ("CRITICAL", "HIGH")]
    if high_plus:
        sys.exit(1)
