"""
Unit tests for CloudAuditOrchestrator.

Covers:
- _build_auditors creates the correct number of auditors per provider x context
- Multi_Account_Scan: multiple profiles / project IDs / subscriptions each get
  their own auditor instance (Requirement 8.2)
- ``run()`` collects findings from all auditors and normalizes them
- A failing auditor does not prevent results from the other auditors
- Providers with no configured accounts/projects produce warnings but no
  auditors
- Unknown providers are skipped with a warning

No real AWS/GCP/Azure credentials or network access are used — all provider
clients and auditors are mocked via unittest.mock.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.config import CloudAuditConfig
from modules.cloud.base import GatewayFinding, GatewaySeverity
from modules.cloud.orchestrator import CloudAuditOrchestrator
from utils.findings import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(provider: str, account_ctx: str) -> GatewayFinding:
    """Return a minimal GatewayFinding for testing."""
    return GatewayFinding(
        provider=provider,
        resource_id=f"arn::{provider}::test-resource",
        resource_type="rest_api",
        check_id="test_check",
        title="Test finding",
        severity=GatewaySeverity.MEDIUM,
        evidence={"key": "value"},
        remediation="Fix it.",
        account_context=account_ctx,
    )


def _make_mock_auditor(provider: str, account_ctx: str, findings: list[GatewayFinding]) -> MagicMock:
    """Return a mock CloudGatewayAuditor that returns ``findings`` from ``audit()``."""
    mock = MagicMock()
    mock.get_provider_name.return_value = provider
    mock.audit = AsyncMock(return_value=findings)
    return mock


# ---------------------------------------------------------------------------
# _build_auditors — AWS
# ---------------------------------------------------------------------------


class TestBuildAuditorsAWS:
    def test_default_credential_chain_creates_one_auditor_per_region(self):
        """No profiles, no role ARNs → one auditor per configured region."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_regions=["us-east-1", "eu-west-1"],
        )
        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient") as MockClient,
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 2

    def test_profiles_create_one_auditor_per_profile_per_region(self):
        """Two profiles × two regions → four AWS auditors."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_profiles=["dev", "prod"],
            aws_regions=["us-east-1", "eu-west-1"],
        )
        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient") as MockClient,
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 4

    def test_role_arns_create_one_auditor_per_arn_per_region(self):
        """Two role ARNs × one region → two AWS auditors."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_role_arns=[
                "arn:aws:iam::111111111111:role/AuditRole",
                "arn:aws:iam::222222222222:role/AuditRole",
            ],
            aws_regions=["us-east-1"],
        )
        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient") as MockClient,
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 2

    def test_profiles_and_role_arns_are_additive(self):
        """One profile + one role ARN × one region → two AWS auditors."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_profiles=["myprofile"],
            aws_role_arns=["arn:aws:iam::123456789012:role/AuditRole"],
            aws_regions=["us-east-1"],
        )
        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient") as MockClient,
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 2

    def test_account_context_label_contains_profile_name(self):
        """Each AWS auditor's account_context should embed the profile name."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_profiles=["sec-audit"],
            aws_regions=["us-east-1"],
        )
        captured_contexts: list[str] = []

        def capture(**kwargs):
            captured_contexts.append(kwargs.get("account_context", ""))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert any("sec-audit" in ctx for ctx in captured_contexts)

    def test_default_region_used_when_no_regions_configured(self):
        """When aws_regions is empty the default CloudAuditConfig region is used."""
        # The CloudAuditConfig default is ["us-east-1"]
        config = CloudAuditConfig(providers=["aws"])
        assert config.aws_regions == ["us-east-1"]

        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        # One default auditor for the default region
        assert len(orch.auditors) == 1


# ---------------------------------------------------------------------------
# _build_auditors — GCP
# ---------------------------------------------------------------------------


class TestBuildAuditorsGCP:
    def test_one_auditor_per_project_id(self):
        """Three project IDs → three GCP auditors (Multi_Account_Scan)."""
        config = CloudAuditConfig(
            providers=["gcp"],
            gcp_project_ids=["proj-a", "proj-b", "proj-c"],
        )
        with (
            patch("modules.cloud.orchestrator.GCPGatewayClient"),
            patch("modules.cloud.orchestrator.GCPGatewayAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 3

    def test_no_project_ids_yields_zero_gcp_auditors(self):
        """GCP without project IDs → zero auditors (warning logged)."""
        config = CloudAuditConfig(providers=["gcp"])
        with (
            patch("modules.cloud.orchestrator.GCPGatewayClient"),
            patch("modules.cloud.orchestrator.GCPGatewayAuditor"),
        ):
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 0

    def test_account_context_contains_project_id(self):
        """GCP auditor account_context should include the project ID."""
        config = CloudAuditConfig(
            providers=["gcp"],
            gcp_project_ids=["my-gcp-project"],
        )
        captured_contexts: list[str] = []

        def capture(**kwargs):
            captured_contexts.append(kwargs.get("account_context", ""))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.GCPGatewayClient"),
            patch("modules.cloud.orchestrator.GCPGatewayAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert any("my-gcp-project" in ctx for ctx in captured_contexts)


# ---------------------------------------------------------------------------
# _build_auditors — Azure
# ---------------------------------------------------------------------------


class TestBuildAuditorsAzure:
    def test_one_auditor_per_subscription_per_resource_group(self):
        """2 subscriptions × 2 resource groups → 4 Azure auditors."""
        config = CloudAuditConfig(
            providers=["azure"],
            azure_subscription_ids=["sub-111", "sub-222"],
            azure_resource_groups=["rg-a", "rg-b"],
        )
        with (
            patch("modules.cloud.orchestrator.AzureAPIMClient"),
            patch("modules.cloud.orchestrator.AzureAPIMAuditor") as MockAuditor,
        ):
            MockAuditor.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 4

    def test_no_subscription_ids_yields_zero_azure_auditors(self):
        """Azure without subscription IDs → zero auditors."""
        config = CloudAuditConfig(providers=["azure"])
        with (
            patch("modules.cloud.orchestrator.AzureAPIMClient"),
            patch("modules.cloud.orchestrator.AzureAPIMAuditor"),
        ):
            orch = CloudAuditOrchestrator(config)

        assert len(orch.auditors) == 0

    def test_default_resource_group_used_when_none_configured(self):
        """When no resource groups are configured, 'default' is used."""
        config = CloudAuditConfig(
            providers=["azure"],
            azure_subscription_ids=["sub-abc"],
        )
        captured_rg: list[str] = []

        def capture(client, resource_group, **kwargs):
            captured_rg.append(resource_group)
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AzureAPIMClient"),
            patch("modules.cloud.orchestrator.AzureAPIMAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert "default" in captured_rg

    def test_account_context_contains_subscription_and_resource_group(self):
        """Azure auditor context should embed subscription_id and resource_group."""
        config = CloudAuditConfig(
            providers=["azure"],
            azure_subscription_ids=["my-sub"],
            azure_resource_groups=["my-rg"],
        )
        captured_contexts: list[str] = []

        def capture(client, resource_group, **kwargs):
            captured_contexts.append(kwargs.get("account_context", ""))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AzureAPIMClient"),
            patch("modules.cloud.orchestrator.AzureAPIMAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert any("my-sub" in ctx and "my-rg" in ctx for ctx in captured_contexts)


# ---------------------------------------------------------------------------
# _build_auditors — multi-provider
# ---------------------------------------------------------------------------


class TestBuildAuditorsMultiProvider:
    def test_all_providers_build_combined_auditor_list(self):
        """AWS + GCP + Azure → auditors from all three providers combined."""
        config = CloudAuditConfig(
            providers=["aws", "gcp", "azure"],
            aws_regions=["us-east-1"],
            gcp_project_ids=["proj-x"],
            azure_subscription_ids=["sub-x"],
            azure_resource_groups=["rg-x"],
        )
        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAWS,
            patch("modules.cloud.orchestrator.GCPGatewayClient"),
            patch("modules.cloud.orchestrator.GCPGatewayAuditor") as MockGCP,
            patch("modules.cloud.orchestrator.AzureAPIMClient"),
            patch("modules.cloud.orchestrator.AzureAPIMAuditor") as MockAzure,
        ):
            MockAWS.return_value = MagicMock()
            MockGCP.return_value = MagicMock()
            MockAzure.return_value = MagicMock()
            orch = CloudAuditOrchestrator(config)

        # 1 AWS (default chain, 1 region) + 1 GCP + 1 Azure
        assert len(orch.auditors) == 3

    def test_unknown_provider_is_skipped(self):
        """An unknown provider name should not raise — it is skipped with a warning."""
        config = CloudAuditConfig.__new__(CloudAuditConfig)
        # Bypass __post_init__ validation by manually setting attributes
        object.__setattr__(config, "providers", ["aws", "unknown_cloud"])
        object.__setattr__(config, "aws_profiles", [])
        object.__setattr__(config, "aws_role_arns", [])
        object.__setattr__(config, "aws_regions", ["us-east-1"])
        object.__setattr__(config, "gcp_project_ids", [])
        object.__setattr__(config, "gcp_service_account_file", None)
        object.__setattr__(config, "azure_subscription_ids", [])
        object.__setattr__(config, "azure_resource_groups", [])
        object.__setattr__(config, "azure_tenant_id", None)
        object.__setattr__(config, "azure_client_id", None)
        object.__setattr__(config, "azure_client_secret", None)
        object.__setattr__(config, "allow_destructive", False)
        object.__setattr__(config, "_SENSITIVE_FIELDS", ("azure_client_secret",))

        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor") as MockAWS,
        ):
            MockAWS.return_value = MagicMock()
            # Should not raise
            orch = CloudAuditOrchestrator(config)

        # Only the valid "aws" provider should have produced an auditor
        assert len(orch.auditors) == 1


# ---------------------------------------------------------------------------
# run() — finding collection and normalization
# ---------------------------------------------------------------------------


class TestOrchestratorRun:
    def test_run_returns_empty_list_when_no_auditors(self):
        """With no auditors, run() returns an empty list without errors."""
        config = CloudAuditConfig(providers=["gcp"])  # no project IDs → 0 auditors
        with (
            patch("modules.cloud.orchestrator.GCPGatewayClient"),
            patch("modules.cloud.orchestrator.GCPGatewayAuditor"),
        ):
            orch = CloudAuditOrchestrator(config)

        findings = asyncio.run(orch.run())
        assert findings == []

    def test_run_collects_and_normalizes_findings_from_all_auditors(self):
        """Findings from multiple auditors are combined into a single Finding list."""
        aws_finding = _make_finding("aws", "aws:dev")
        gcp_finding = _make_finding("gcp", "gcp:my-project")

        aws_auditor = _make_mock_auditor("aws", "aws:dev", [aws_finding])
        gcp_auditor = _make_mock_auditor("gcp", "gcp:my-project", [gcp_finding])

        config = CloudAuditConfig(providers=["aws", "gcp"])
        orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
        orch._config = config
        orch._normalizer = __import__(
            "modules.cloud.normalizer", fromlist=["GatewayFindingNormalizer"]
        ).GatewayFindingNormalizer()
        orch.auditors = [aws_auditor, gcp_auditor]

        findings = asyncio.run(orch.run())

        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)

    def test_run_findings_have_api8_owasp_category(self):
        """All normalized findings should carry owasp_category='API8'."""
        gf = _make_finding("aws", "aws:default")
        auditor = _make_mock_auditor("aws", "aws:default", [gf])

        config = CloudAuditConfig(providers=["aws"])
        orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
        orch._config = config
        orch._normalizer = __import__(
            "modules.cloud.normalizer", fromlist=["GatewayFindingNormalizer"]
        ).GatewayFindingNormalizer()
        orch.auditors = [auditor]

        findings = asyncio.run(orch.run())
        assert all(f.owasp_category == "API8" for f in findings)

    def test_run_uses_same_scan_id_for_all_findings(self):
        """All findings from a single run() call share the same scan_id."""
        findings_batch = [
            _make_finding("aws", "aws:default"),
            _make_finding("aws", "aws:default"),
        ]
        auditor = _make_mock_auditor("aws", "aws:default", findings_batch)

        config = CloudAuditConfig(providers=["aws"])
        orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
        orch._config = config
        orch._normalizer = __import__(
            "modules.cloud.normalizer", fromlist=["GatewayFindingNormalizer"]
        ).GatewayFindingNormalizer()
        orch.auditors = [auditor]

        findings = asyncio.run(orch.run(scan_id="test-scan-123"))
        scan_ids = {f.scan_id for f in findings}
        assert scan_ids == {"test-scan-123"}

    def test_run_continues_after_auditor_exception(self):
        """An exception from one auditor does not prevent findings from others."""
        bad_auditor = MagicMock()
        bad_auditor.get_provider_name.return_value = "aws"
        bad_auditor.audit = AsyncMock(side_effect=RuntimeError("Boom!"))

        good_finding = _make_finding("gcp", "gcp:my-project")
        good_auditor = _make_mock_auditor("gcp", "gcp:my-project", [good_finding])

        config = CloudAuditConfig(providers=["aws", "gcp"])
        orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
        orch._config = config
        orch._normalizer = __import__(
            "modules.cloud.normalizer", fromlist=["GatewayFindingNormalizer"]
        ).GatewayFindingNormalizer()
        orch.auditors = [bad_auditor, good_auditor]

        # Should not raise
        findings = asyncio.run(orch.run())

        # The good auditor's finding should still be returned
        assert len(findings) == 1
        assert findings[0].owasp_category == "API8"

    def test_run_with_zero_findings_auditor_is_fine(self):
        """An auditor that returns an empty list is not an error."""
        auditor = _make_mock_auditor("aws", "aws:default", [])

        config = CloudAuditConfig(providers=["aws"])
        orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
        orch._config = config
        orch._normalizer = __import__(
            "modules.cloud.normalizer", fromlist=["GatewayFindingNormalizer"]
        ).GatewayFindingNormalizer()
        orch.auditors = [auditor]

        findings = asyncio.run(orch.run())
        assert findings == []


# ---------------------------------------------------------------------------
# Multi_Account_Scan label uniqueness (Requirement 8.2)
# ---------------------------------------------------------------------------


class TestMultiAccountScanLabels:
    def test_each_aws_profile_gets_unique_account_context(self):
        """
        Multi_Account_Scan: each AWS profile should produce an auditor with a
        distinct account_context label so findings can be traced to their origin.
        """
        config = CloudAuditConfig(
            providers=["aws"],
            aws_profiles=["profile-alpha", "profile-beta"],
            aws_regions=["us-east-1"],
        )
        contexts: list[str] = []

        def capture(**kwargs):
            contexts.append(kwargs.get("account_context", ""))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        # All account_context values should be unique
        assert len(set(contexts)) == len(contexts)

    def test_each_gcp_project_gets_unique_account_context(self):
        """Each GCP project should produce a distinct account_context label."""
        config = CloudAuditConfig(
            providers=["gcp"],
            gcp_project_ids=["proj-1", "proj-2", "proj-3"],
        )
        contexts: list[str] = []

        def capture(**kwargs):
            contexts.append(kwargs.get("account_context", ""))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.GCPGatewayClient"),
            patch("modules.cloud.orchestrator.GCPGatewayAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert len(set(contexts)) == 3

    def test_each_azure_subscription_rg_gets_unique_account_context(self):
        """Each Azure sub × rg pair produces a distinct account_context."""
        config = CloudAuditConfig(
            providers=["azure"],
            azure_subscription_ids=["sub-1", "sub-2"],
            azure_resource_groups=["rg-a"],
        )
        contexts: list[str] = []

        def capture(client, resource_group, **kwargs):
            contexts.append(kwargs.get("account_context", ""))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AzureAPIMClient"),
            patch("modules.cloud.orchestrator.AzureAPIMAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert len(set(contexts)) == 2


# ---------------------------------------------------------------------------
# CloudReadOnlyGuard propagation
# ---------------------------------------------------------------------------


class TestReadOnlyGuardPropagation:
    def test_guard_allow_destructive_false_by_default(self):
        """Without --allow-destructive, the guard must be in read-only mode."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_regions=["us-east-1"],
            allow_destructive=False,
        )
        guards_seen: list = []

        def capture(**kwargs):
            guards_seen.append(kwargs.get("guard"))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert len(guards_seen) == 1
        guard = guards_seen[0]
        assert guard is not None
        assert guard.allow_destructive is False

    def test_guard_allow_destructive_true_when_configured(self):
        """With allow_destructive=True the guard should permit write operations."""
        config = CloudAuditConfig(
            providers=["aws"],
            aws_regions=["us-east-1"],
            allow_destructive=True,
        )
        guards_seen: list = []

        def capture(**kwargs):
            guards_seen.append(kwargs.get("guard"))
            return MagicMock()

        with (
            patch("modules.cloud.orchestrator.AWSGatewayClient"),
            patch("modules.cloud.orchestrator.AWSGatewayAuditor", side_effect=capture),
        ):
            CloudAuditOrchestrator(config)

        assert guards_seen[0].allow_destructive is True
