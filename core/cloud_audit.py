"""
Cloud Audit Orchestrator

Builds and runs the appropriate CloudGatewayAuditor instances for each
provider/account combination specified in CloudAuditConfig, handles
per-auditor errors (CredentialResolutionError, InsufficientPermissionsError,
ProviderThrottledError) without aborting the entire run, and returns a flat
list of normalised Finding objects ready for the existing ReportGenerator.

This implements the resilience requirements of spec Requirement 9: a failure
on one provider/account is logged and skipped; the findings from the remaining
providers are still returned.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from core.config import CloudAuditConfig
from core.logging import get_logger
from modules.cloud.base import (
    CloudGatewayAuditor,
    CredentialResolutionError,
    GatewayFinding,
    InsufficientPermissionsError,
    ProviderThrottledError,
)
from modules.cloud.normalizer import GatewayFindingNormalizer
from utils.findings import Finding

logger = get_logger(__name__)

_MAX_THROTTLE_RETRIES = 3
_THROTTLE_INITIAL_WAIT = 2.0  # seconds


@dataclass
class AuditSummary:
    """Summary produced by CloudAuditOrchestrator.run()."""

    findings: list[Finding] = field(default_factory=list)
    gateway_findings: list[GatewayFinding] = field(default_factory=list)
    auditors_succeeded: list[str] = field(default_factory=list)
    auditors_failed: list[str] = field(default_factory=list)
    auditors_skipped_no_credentials: list[str] = field(default_factory=list)


class CloudAuditOrchestrator:
    """
    Builds and runs CloudGatewayAuditor instances, collecting findings.

    Parameters
    ----------
    config:     CloudAuditConfig specifying providers, credentials, and scope.
    scan_id:    Optional scan ID propagated to normalised Finding objects.
    """

    def __init__(
        self,
        config: CloudAuditConfig,
        scan_id: str | None = None,
    ) -> None:
        self._config = config
        self._scan_id = scan_id or str(uuid4())
        self._normalizer = GatewayFindingNormalizer()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> AuditSummary:
        """
        Build all configured auditors, run each one, collect findings.

        Exceptions from a single auditor are caught and recorded in the
        summary without propagating (Requirement 9).
        """
        summary = AuditSummary()
        auditors = self._build_auditors()

        for label, auditor in auditors:
            gateway_findings = await self._run_auditor_safely(label, auditor, summary)
            if gateway_findings is not None:
                findings = self._normalizer.to_findings(gateway_findings, self._scan_id)
                summary.gateway_findings.extend(gateway_findings)
                summary.findings.extend(findings)
                summary.auditors_succeeded.append(label)

        logger.info(
            "Cloud audit run complete",
            total_findings=len(summary.findings),
            succeeded=summary.auditors_succeeded,
            failed=summary.auditors_failed,
            skipped=summary.auditors_skipped_no_credentials,
        )
        return summary

    # ------------------------------------------------------------------
    # Auditor construction
    # ------------------------------------------------------------------

    def _build_auditors(self) -> list[tuple[str, CloudGatewayAuditor]]:
        """
        Instantiate one auditor per provider × account/profile/project.
        """
        from utils.cloud.readonly_guard import CloudReadOnlyGuard

        guard = CloudReadOnlyGuard(allow_destructive=self._config.allow_destructive)
        auditors: list[tuple[str, CloudGatewayAuditor]] = []

        providers = {p.lower() for p in self._config.providers}

        if "aws" in providers:
            auditors.extend(self._build_aws_auditors(guard))

        if "gcp" in providers:
            auditors.extend(self._build_gcp_auditors(guard))

        if "azure" in providers:
            auditors.extend(self._build_azure_auditors(guard))

        return auditors

    def _build_aws_auditors(self, guard: Any) -> list[tuple[str, CloudGatewayAuditor]]:
        from modules.cloud.aws_api_gateway import AWSGatewayAuditor
        from utils.cloud.aws_client import AWSGatewayClient

        auditors: list[tuple[str, CloudGatewayAuditor]] = []

        # One auditor per profile
        profiles = self._config.aws_profiles or [None]  # type: ignore[list-item]
        for profile in profiles:
            for region in self._config.aws_regions:
                label = f"aws:{profile or 'default'}:{region}"
                client = AWSGatewayClient(profile=profile, region=region)
                auditor = AWSGatewayAuditor(client=client, guard=guard, account_context=label)
                auditors.append((label, auditor))

        # One additional auditor per role ARN (role assumption takes precedence
        # over profiles, so we use a separate client per ARN)
        for role_arn in self._config.aws_role_arns:
            for region in self._config.aws_regions:
                label = f"aws:assumed:{role_arn.split('/')[-1]}:{region}"
                client = AWSGatewayClient(role_arn=role_arn, region=region)
                auditor = AWSGatewayAuditor(client=client, guard=guard, account_context=label)
                auditors.append((label, auditor))

        return auditors

    def _build_gcp_auditors(self, guard: Any) -> list[tuple[str, CloudGatewayAuditor]]:
        from modules.cloud.gcp_api_gateway import GCPGatewayAuditor
        from utils.cloud.gcp_client import GCPGatewayClient

        auditors: list[tuple[str, CloudGatewayAuditor]] = []
        for project_id in self._config.gcp_project_ids or []:
            label = f"gcp:{project_id}"
            client = GCPGatewayClient(
                project_id=project_id,
                service_account_file=self._config.gcp_service_account_file,
            )
            auditor = GCPGatewayAuditor(client=client, guard=guard, account_context=label)
            auditors.append((label, auditor))
        return auditors

    def _build_azure_auditors(self, guard: Any) -> list[tuple[str, CloudGatewayAuditor]]:
        from modules.cloud.azure_apim import AzureAPIMAuditor
        from utils.cloud.azure_client import AzureAPIMClient

        auditors: list[tuple[str, CloudGatewayAuditor]] = []
        for sub_id in self._config.azure_subscription_ids or []:
            client = AzureAPIMClient(
                subscription_id=sub_id,
                tenant_id=self._config.azure_tenant_id,
                client_id=self._config.azure_client_id,
                client_secret=self._config.azure_client_secret,
            )
            for rg in self._config.azure_resource_groups or []:
                label = f"azure:{sub_id}:{rg}"
                auditor = AzureAPIMAuditor(
                    client=client, resource_group=rg, guard=guard, account_context=label
                )
                auditors.append((label, auditor))
        return auditors

    # ------------------------------------------------------------------
    # Resilient execution
    # ------------------------------------------------------------------

    async def _run_auditor_safely(
        self,
        label: str,
        auditor: CloudGatewayAuditor,
        summary: AuditSummary,
    ) -> list[GatewayFinding] | None:
        """
        Run a single auditor, handling all expected exceptions gracefully.
        Returns the list of GatewayFindings on success, or None on failure.
        """
        wait = _THROTTLE_INITIAL_WAIT
        for attempt in range(1, _MAX_THROTTLE_RETRIES + 1):
            try:
                logger.info("Starting cloud audit", auditor=label)
                return await auditor.audit()

            except CredentialResolutionError as exc:
                logger.warning(
                    "Cloud audit skipped — no valid credentials",
                    auditor=label,
                    error=str(exc),
                )
                summary.auditors_skipped_no_credentials.append(label)
                return None

            except ProviderThrottledError as exc:
                if attempt < _MAX_THROTTLE_RETRIES:
                    logger.warning(
                        "Provider throttled; retrying after backoff",
                        auditor=label,
                        attempt=attempt,
                        wait_seconds=wait,
                    )
                    await asyncio.sleep(wait)
                    wait *= 2
                else:
                    logger.warning(
                        "Provider throttled; max retries exceeded",
                        auditor=label,
                        error=str(exc),
                    )
                    summary.auditors_failed.append(label)
                    return None

            except InsufficientPermissionsError as exc:
                logger.warning(
                    "Insufficient permissions for cloud audit",
                    auditor=label,
                    error=str(exc),
                )
                summary.auditors_failed.append(label)
                return None

            except Exception as exc:
                logger.warning(
                    "Cloud auditor failed with unexpected error",
                    auditor=label,
                    error=str(exc),
                )
                summary.auditors_failed.append(label)
                return None

        summary.auditors_failed.append(label)
        return None
