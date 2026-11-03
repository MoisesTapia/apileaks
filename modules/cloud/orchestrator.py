"""
Cloud Audit Orchestrator

Builds the full set of provider-specific auditors from a ``CloudAuditConfig``
(one auditor per provider × account/project/subscription combination) and
runs them in sequence, normalizing all ``GatewayFinding``s to the standard
``Finding`` model via ``GatewayFindingNormalizer``.

Supports Multi_Account_Scan (Requirement 8.2): when the config lists multiple
profiles, role ARNs, project IDs, or subscription IDs, a separate auditor
instance is created for each, each tagged with its own ``account_context``
label so findings can be traced back to their origin.

Error handling strategy (Requirement 9) is minimal at this stage — individual
auditor failures are caught and logged, and the orchestrator continues with
the remaining auditors so partial results are always returned.  Full
resilience logic (backoff, per-resource permission findings, etc.) is
implemented inside the individual auditors themselves.
"""

from __future__ import annotations

from uuid import uuid4

from core.config import CloudAuditConfig
from core.logging import get_logger
from modules.cloud.aws_api_gateway import AWSGatewayAuditor
from modules.cloud.azure_apim import AzureAPIMAuditor
from modules.cloud.base import (
    CloudGatewayAuditor,
    CredentialResolutionError,
    GatewayFinding,
    InsufficientPermissionsError,
    ProviderThrottledError,
    create_permission_denied_finding,
)
from modules.cloud.gcp_api_gateway import GCPGatewayAuditor
from modules.cloud.normalizer import GatewayFindingNormalizer
from utils.cloud.aws_client import AWSGatewayClient
from utils.cloud.azure_client import AzureAPIMClient
from utils.cloud.gcp_client import GCPGatewayClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard
from utils.findings import Finding

logger = get_logger(__name__)


class CloudAuditOrchestrator:
    """
    Orchestrates cloud API gateway security audits across multiple
    providers and accounts/projects/subscriptions.

    Parameters
    ----------
    config:
        ``CloudAuditConfig`` that defines which providers to audit and
        how to resolve credentials for each one.

    Usage
    -----
    ::

        config = CloudAuditConfig(providers=["aws", "gcp"], gcp_project_ids=["my-project"])
        orchestrator = CloudAuditOrchestrator(config)
        findings = asyncio.run(orchestrator.run())
    """

    def __init__(self, config: CloudAuditConfig) -> None:
        self._config = config
        self._normalizer = GatewayFindingNormalizer()
        self.auditors: list[CloudGatewayAuditor] = self._build_auditors(config)
        # Populated by each call to run(); reset at the start of every run.
        self._skipped_providers: list[str] = []
        self._not_audited_resources: list[str] = []

    # ------------------------------------------------------------------
    # Auditor construction
    # ------------------------------------------------------------------

    def _build_auditors(self, config: CloudAuditConfig) -> list[CloudGatewayAuditor]:
        """
        Instantiate one auditor per provider × account context combination.

        For AWS the cross-product is:
          - profiles × regions  (or default session × regions when no profiles)
          - role_arns × regions (additional auditors when role ARNs are given)
        For GCP: one auditor per project_id.
        For Azure: one auditor per subscription_id × resource_group.

        Any ``CredentialResolutionError`` raised at construction time (e.g.
        missing SDK) is caught and logged as a warning so the orchestrator can
        still build auditors for the other providers.
        """
        guard = CloudReadOnlyGuard(allow_destructive=config.allow_destructive)
        auditors: list[CloudGatewayAuditor] = []

        for provider in config.providers:
            if provider == "aws":
                auditors.extend(self._build_aws_auditors(config, guard))
            elif provider == "gcp":
                auditors.extend(self._build_gcp_auditors(config, guard))
            elif provider == "azure":
                auditors.extend(self._build_azure_auditors(config, guard))
            else:
                logger.warning("Unknown provider in CloudAuditConfig — skipping", provider=provider)

        logger.info(
            "CloudAuditOrchestrator: auditors built",
            total_auditors=len(auditors),
            providers=config.providers,
        )
        return auditors

    # ------------------------------------------------------------------
    # AWS auditor factory
    # ------------------------------------------------------------------

    def _build_aws_auditors(
        self,
        config: CloudAuditConfig,
        guard: CloudReadOnlyGuard,
    ) -> list[CloudGatewayAuditor]:
        """
        Build one ``AWSGatewayAuditor`` per (profile OR role_arn) × region.

        When neither profiles nor role ARNs are configured, a single auditor
        is created per region using the boto3 default credential chain.
        """
        regions = config.aws_regions or [None]  # type: ignore[list-item]
        auditors: list[CloudGatewayAuditor] = []

        # Profile-based auditors
        if config.aws_profiles:
            for profile in config.aws_profiles:
                for region in regions:
                    account_ctx = f"aws:{profile}" + (f"/{region}" if region else "")
                    try:
                        client = AWSGatewayClient(profile=profile, region=region)
                        auditors.append(
                            AWSGatewayAuditor(
                                client=client,
                                guard=guard,
                                account_context=account_ctx,
                            )
                        )
                        logger.debug(
                            "Built AWS auditor",
                            profile=profile,
                            region=region,
                            account_context=account_ctx,
                        )
                    except CredentialResolutionError as exc:
                        logger.warning(
                            "Could not build AWS auditor for profile",
                            profile=profile,
                            region=region,
                            error=str(exc),
                        )

        # Role ARN-based auditors (may coexist with profile-based ones)
        if config.aws_role_arns:
            for role_arn in config.aws_role_arns:
                for region in regions:
                    account_ctx = f"aws:role:{role_arn.split('/')[-1]}" + (
                        f"/{region}" if region else ""
                    )
                    try:
                        client = AWSGatewayClient(role_arn=role_arn, region=region)
                        auditors.append(
                            AWSGatewayAuditor(
                                client=client,
                                guard=guard,
                                account_context=account_ctx,
                            )
                        )
                        logger.debug(
                            "Built AWS auditor via role assumption",
                            role_arn=role_arn,
                            region=region,
                            account_context=account_ctx,
                        )
                    except CredentialResolutionError as exc:
                        logger.warning(
                            "Could not build AWS auditor for role ARN",
                            role_arn=role_arn,
                            region=region,
                            error=str(exc),
                        )

        # Default credential chain (no profile, no role) — one per region
        if not config.aws_profiles and not config.aws_role_arns:
            for region in regions:
                account_ctx = "aws:default" + (f"/{region}" if region else "")
                try:
                    client = AWSGatewayClient(region=region)
                    auditors.append(
                        AWSGatewayAuditor(
                            client=client,
                            guard=guard,
                            account_context=account_ctx,
                        )
                    )
                    logger.debug(
                        "Built AWS auditor using default credential chain",
                        region=region,
                        account_context=account_ctx,
                    )
                except CredentialResolutionError as exc:
                    logger.warning(
                        "Could not build default AWS auditor",
                        region=region,
                        error=str(exc),
                    )

        return auditors

    # ------------------------------------------------------------------
    # GCP auditor factory
    # ------------------------------------------------------------------

    def _build_gcp_auditors(
        self,
        config: CloudAuditConfig,
        guard: CloudReadOnlyGuard,
    ) -> list[CloudGatewayAuditor]:
        """
        Build one ``GCPGatewayAuditor`` per project_id.

        When no project IDs are configured and the ``gcp`` provider is requested,
        a warning is logged and no GCP auditors are created (the GCP SDK has no
        equivalent to boto3's "default profile").
        """
        if not config.gcp_project_ids:
            logger.warning(
                "Provider 'gcp' requested but no gcp_project_ids configured — "
                "skipping GCP auditors"
            )
            return []

        auditors: list[CloudGatewayAuditor] = []
        for project_id in config.gcp_project_ids:
            account_ctx = f"gcp:{project_id}"
            try:
                client = GCPGatewayClient(
                    project_id=project_id,
                    service_account_file=config.gcp_service_account_file,
                )
                auditors.append(
                    GCPGatewayAuditor(
                        client=client,
                        guard=guard,
                        account_context=account_ctx,
                    )
                )
                logger.debug(
                    "Built GCP auditor",
                    project_id=project_id,
                    account_context=account_ctx,
                )
            except CredentialResolutionError as exc:
                logger.warning(
                    "Could not build GCP auditor for project",
                    project_id=project_id,
                    error=str(exc),
                )

        return auditors

    # ------------------------------------------------------------------
    # Azure auditor factory
    # ------------------------------------------------------------------

    def _build_azure_auditors(
        self,
        config: CloudAuditConfig,
        guard: CloudReadOnlyGuard,
    ) -> list[CloudGatewayAuditor]:
        """
        Build one ``AzureAPIMAuditor`` per subscription_id × resource_group.

        When no subscription IDs are configured, a warning is logged and no
        Azure auditors are created.  When no resource groups are configured,
        a single ``"default"`` resource group label is used (the auditor
        will list APIM services across the subscription from there).
        """
        if not config.azure_subscription_ids:
            logger.warning(
                "Provider 'azure' requested but no azure_subscription_ids configured — "
                "skipping Azure auditors"
            )
            return []

        resource_groups = config.azure_resource_groups or ["default"]
        auditors: list[CloudGatewayAuditor] = []

        for subscription_id in config.azure_subscription_ids:
            for resource_group in resource_groups:
                account_ctx = f"azure:{subscription_id}/{resource_group}"
                try:
                    client = AzureAPIMClient(
                        subscription_id=subscription_id,
                        tenant_id=config.azure_tenant_id,
                        client_id=config.azure_client_id,
                        client_secret=config.azure_client_secret,
                    )
                    auditors.append(
                        AzureAPIMAuditor(
                            client=client,
                            resource_group=resource_group,
                            guard=guard,
                            account_context=account_ctx,
                        )
                    )
                    logger.debug(
                        "Built Azure APIM auditor",
                        subscription_id=subscription_id,
                        resource_group=resource_group,
                        account_context=account_ctx,
                    )
                except CredentialResolutionError as exc:
                    logger.warning(
                        "Could not build Azure auditor for subscription",
                        subscription_id=subscription_id,
                        resource_group=resource_group,
                        error=str(exc),
                    )

        return auditors

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(self, scan_id: str | None = None) -> list[Finding]:
        """
        Execute all auditors and return normalized ``Finding`` objects.

        Each auditor is run independently; exceptions are caught per auditor
        so a failure in one provider does not prevent results from the others
        from being returned (Requirement 9).

        Error handling strategy (design doc, Requirement 9):

        * ``CredentialResolutionError`` — provider is skipped with a warning;
          added to ``_skipped_providers``.  No finding is generated (we never
          had usable credentials).
        * ``InsufficientPermissionsError`` — a scope-level INFO ``GatewayFinding``
          is created for the auditor's account context and the error is counted
          in ``_not_audited_resources``.
        * ``ProviderThrottledError`` — per-resource backoff is handled inside
          the auditors themselves; if a ``ProviderThrottledError`` still bubbles
          up here it means the whole auditor scope was exhausted.  Logged as a
          warning; added to ``_not_audited_resources``.
        * Any other ``Exception`` — logged as an unhandled warning (same as the
          original behaviour); auditor is skipped.

        Parameters
        ----------
        scan_id:
            Optional scan identifier threaded into every ``Finding`` produced
            during this run.  A new UUID is generated when not provided.

        Returns
        -------
        list[Finding]
            All normalized findings from all auditors, in the order auditors
            were built (provider × account context).
        """
        _scan_id = scan_id or str(uuid4())
        all_gateway_findings: list[GatewayFinding] = []

        # Reset run-level summary tracking
        self._skipped_providers = []
        self._not_audited_resources = []

        for auditor in self.auditors:
            provider = auditor.get_provider_name()
            account_context: str = getattr(auditor, "_account_context", provider)
            try:
                logger.info(
                    "Running cloud auditor",
                    provider=provider,
                    account_context=account_context,
                )
                gateway_findings = await auditor.audit()
                all_gateway_findings.extend(gateway_findings)
                logger.info(
                    "Cloud auditor complete",
                    provider=provider,
                    account_context=account_context,
                    finding_count=len(gateway_findings),
                )

            except CredentialResolutionError as exc:
                # Credentials missing or invalid — skip this provider context entirely.
                self._skipped_providers.append(account_context)
                logger.warning(
                    "Skipping cloud auditor — credentials could not be resolved",
                    provider=provider,
                    account_context=account_context,
                    error=str(exc),
                )

            except InsufficientPermissionsError as exc:
                # The auditor scope is unreadable; generate an INFO finding so the
                # fact of the failure is visible in reports.
                self._not_audited_resources.append(account_context)
                perm_finding = create_permission_denied_finding(
                    resource_id=account_context,
                    resource_type=f"{provider}_gateway_scope",
                    provider=provider,
                    account_context=account_context,
                    operation="audit",
                )
                all_gateway_findings.append(perm_finding)
                logger.warning(
                    "Cloud auditor scope inaccessible — insufficient permissions",
                    provider=provider,
                    account_context=account_context,
                    error=str(exc),
                )

            except ProviderThrottledError as exc:
                # Backoff inside the auditor was exhausted; mark scope as not audited.
                self._not_audited_resources.append(account_context)
                logger.warning(
                    "Cloud auditor throttled after retries — scope not fully audited",
                    provider=provider,
                    account_context=account_context,
                    error=str(exc),
                )

            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Cloud auditor raised an unhandled exception — skipping",
                    provider=provider,
                    account_context=account_context,
                    error=str(exc),
                    exc_info=True,
                )

        findings = self._normalizer.to_findings(all_gateway_findings, scan_id=_scan_id)

        # --- Run summary ---
        logger.info(
            "CloudAuditOrchestrator run complete",
            total_gateway_findings=len(all_gateway_findings),
            total_findings=len(findings),
            skipped_providers=self._skipped_providers,
            skipped_provider_count=len(self._skipped_providers),
            not_audited_resources=self._not_audited_resources,
            not_audited_resource_count=len(self._not_audited_resources),
        )

        if self._skipped_providers:
            logger.warning(
                "Some provider contexts were skipped due to missing credentials",
                skipped=self._skipped_providers,
            )
        if self._not_audited_resources:
            logger.warning(
                "Some resources could not be audited (permissions / throttling)",
                not_audited=self._not_audited_resources,
            )

        return findings
