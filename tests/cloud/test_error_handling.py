"""
Unit tests for task 7.2: per-auditor error handling.

Covers:
- create_permission_denied_finding helper produces correct INFO GatewayFinding
- with_exponential_backoff retries on ProviderThrottledError and raises after
  max_retries is exhausted
- with_exponential_backoff propagates other exceptions immediately
- AWSGatewayAuditor.audit() converts InsufficientPermissionsError to an INFO
  GatewayFinding and continues auditing other APIs
- AWSGatewayAuditor.audit() uses backoff on ProviderThrottledError and generates
  a finding when retries are exhausted
- CloudAuditOrchestrator.run() catches CredentialResolutionError without crashing
  and records the provider in _skipped_providers
- CloudAuditOrchestrator.run() catches InsufficientPermissionsError, generates an
  INFO finding, and records the resource in _not_audited_resources
- CloudAuditOrchestrator.run() catches ProviderThrottledError and records the
  resource in _not_audited_resources
- Run summary (skipped providers, not-audited resources) is populated correctly

No real AWS/GCP/Azure credentials or network access are used.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules.cloud.base import (
    GatewayFinding,
    GatewaySeverity,
    InsufficientPermissionsError,
    ProviderThrottledError,
    CredentialResolutionError,
    create_permission_denied_finding,
)
from utils.cloud.backoff import with_exponential_backoff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(provider: str = "aws", account_ctx: str = "aws:test") -> GatewayFinding:
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


def _make_mock_auditor(
    provider: str,
    account_ctx: str,
    findings: list[GatewayFinding],
) -> MagicMock:
    mock = MagicMock()
    mock.get_provider_name.return_value = provider
    mock._account_context = account_ctx
    mock.audit = AsyncMock(return_value=findings)
    return mock


# ===========================================================================
# 1. create_permission_denied_finding
# ===========================================================================


class TestCreatePermissionDeniedFinding:
    def test_returns_gateway_finding_instance(self):
        finding = create_permission_denied_finding(
            resource_id="arn::aws::my-resource",
            resource_type="rest_api",
            provider="aws",
            account_context="aws:default",
            operation="get_rest_apis",
        )
        assert isinstance(finding, GatewayFinding)

    def test_severity_is_info(self):
        finding = create_permission_denied_finding(
            resource_id="r",
            resource_type="t",
            provider="aws",
            account_context="ctx",
            operation="op",
        )
        assert finding.severity == GatewaySeverity.INFO

    def test_check_id_is_cloud_resource_not_auditable(self):
        finding = create_permission_denied_finding(
            resource_id="r",
            resource_type="t",
            provider="gcp",
            account_context="ctx",
            operation="list_api_configs",
        )
        assert finding.check_id == "cloud_resource_not_auditable"

    def test_title_contains_operation_name(self):
        finding = create_permission_denied_finding(
            resource_id="r",
            resource_type="t",
            provider="azure",
            account_context="ctx",
            operation="list_by_resource_group",
        )
        assert "list_by_resource_group" in finding.title

    def test_provider_field_set_correctly(self):
        finding = create_permission_denied_finding(
            resource_id="r",
            resource_type="t",
            provider="gcp",
            account_context="gcp:proj",
            operation="op",
        )
        assert finding.provider == "gcp"

    def test_account_context_field_set(self):
        finding = create_permission_denied_finding(
            resource_id="r",
            resource_type="t",
            provider="aws",
            account_context="aws:my-profile",
            operation="op",
        )
        assert finding.account_context == "aws:my-profile"

    def test_evidence_contains_operation(self):
        finding = create_permission_denied_finding(
            resource_id="r",
            resource_type="t",
            provider="aws",
            account_context="ctx",
            operation="get_resources",
        )
        assert "operation" in finding.evidence
        assert finding.evidence["operation"] == "get_resources"


# ===========================================================================
# 2. with_exponential_backoff
# ===========================================================================


class TestWithExponentialBackoff:
    def test_returns_result_on_success(self):
        def _fn():
            return 42

        result = asyncio.run(with_exponential_backoff(_fn))
        assert result == 42

    def test_retries_on_retry_on_exception(self):
        call_count = 0

        def _fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ProviderThrottledError("throttled")
            return "ok"

        # Override delay to 0 so tests run instantly
        result = asyncio.run(
            with_exponential_backoff(
                _fn,
                max_retries=3,
                base_delay=0.0,
                retry_on=ProviderThrottledError,
            )
        )
        assert result == "ok"
        assert call_count == 3  # failed twice, succeeded on 3rd attempt

    def test_raises_after_max_retries_exhausted(self):
        def _always_throttle():
            raise ProviderThrottledError("always throttled")

        with pytest.raises(ProviderThrottledError):
            asyncio.run(
                with_exponential_backoff(
                    _always_throttle,
                    max_retries=2,
                    base_delay=0.0,
                    retry_on=ProviderThrottledError,
                )
            )

    def test_attempt_count_equals_max_retries_plus_one(self):
        """Total attempts == max_retries + 1."""
        call_count = 0

        def _fn():
            nonlocal call_count
            call_count += 1
            raise ProviderThrottledError("throttled")

        with pytest.raises(ProviderThrottledError):
            asyncio.run(
                with_exponential_backoff(
                    _fn,
                    max_retries=3,
                    base_delay=0.0,
                    retry_on=ProviderThrottledError,
                )
            )
        assert call_count == 4  # 1 initial + 3 retries

    def test_non_retry_exception_propagates_immediately(self):
        """Exceptions NOT in retry_on propagate without retrying."""
        call_count = 0

        def _fn():
            nonlocal call_count
            call_count += 1
            raise InsufficientPermissionsError("denied")

        with pytest.raises(InsufficientPermissionsError):
            asyncio.run(
                with_exponential_backoff(
                    _fn,
                    max_retries=5,
                    base_delay=0.0,
                    retry_on=ProviderThrottledError,
                )
            )
        # Should only have been called once — no retry for a non-retry exception
        assert call_count == 1

    def test_works_with_async_function(self):
        async def _async_fn():
            return "async result"

        result = asyncio.run(with_exponential_backoff(_async_fn))
        assert result == "async result"

    def test_async_fn_retried_on_throttle(self):
        call_count = 0

        async def _async_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ProviderThrottledError("throttled")
            return "ok"

        result = asyncio.run(
            with_exponential_backoff(
                _async_fn,
                max_retries=2,
                base_delay=0.0,
                retry_on=ProviderThrottledError,
            )
        )
        assert result == "ok"
        assert call_count == 2

    def test_kwargs_forwarded_to_function(self):
        def _fn(x, y=0):
            return x + y

        result = asyncio.run(with_exponential_backoff(_fn, 3, y=4))
        assert result == 7


# ===========================================================================
# 3. AWSGatewayAuditor — per-resource error handling
# ===========================================================================


class TestAWSAuditorErrorHandling:
    """Test that the AWS auditor turns resource-level errors into INFO findings
    and continues auditing other resources rather than aborting."""

    def _make_aws_auditor(self, client_mock: MagicMock) -> "AWSGatewayAuditor":
        from modules.cloud.aws_api_gateway import AWSGatewayAuditor
        from utils.cloud.readonly_guard import CloudReadOnlyGuard

        guard = CloudReadOnlyGuard(allow_destructive=False)
        return AWSGatewayAuditor(
            client=client_mock,
            guard=guard,
            account_context="aws:test-profile",
        )

    def test_insufficient_permissions_on_rest_apis_yields_info_finding(self):
        """When get_rest_apis is denied, an INFO finding is generated and audit() does not raise."""
        from botocore.exceptions import ClientError

        access_denied = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "get_rest_apis",
        )

        def _paginate_v1_side_effect(op, key, **kw):
            if op == "get_rest_apis":
                raise access_denied
            return []  # all other calls (get_domain_names, usage plans, etc.) succeed

        client = MagicMock()
        client.paginate_v1.side_effect = _paginate_v1_side_effect
        client.paginate_v2.return_value = []

        auditor = self._make_aws_auditor(client)
        findings = asyncio.run(auditor.audit())

        # There should be an INFO finding for the denied operation
        assert any(
            f.check_id == "cloud_resource_not_auditable" and f.severity == GatewaySeverity.INFO
            for f in findings
        ), f"Expected INFO finding, got: {[f.check_id for f in findings]}"

    def test_audit_continues_after_per_api_permission_error(self):
        """An InsufficientPermissionsError on one API's resources doesn't skip other APIs."""
        from botocore.exceptions import ClientError

        api_a = {"id": "api-a", "name": "API A", "policy": None}
        api_b = {"id": "api-b", "name": "API B", "policy": None}

        client = MagicMock()
        # get_rest_apis returns two APIs
        client.paginate_v1.side_effect = lambda op, key, **kw: {
            ("get_rest_apis", "items"): [api_a, api_b],
            ("get_resources", "items"): (
                # api-a is denied, api-b succeeds with empty resources
                (_ for _ in ()).throw(
                    ClientError(
                        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                        "get_resources",
                    )
                )
                if kw.get("restApiId") == "api-a"
                else []
            ),
        }.get((op, key), [])

        def _paginate_v1(op, key, **kw):
            if op == "get_rest_apis":
                return [api_a, api_b]
            if op == "get_resources" and kw.get("restApiId") == "api-a":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "get_resources",
                )
            if op in ("get_usage_plans", "get_api_keys", "get_domain_names"):
                return []
            return []

        client.paginate_v1.side_effect = _paginate_v1
        client.paginate_v2.return_value = []
        client.apigateway.get_stages.return_value = {"item": []}

        auditor = self._make_aws_auditor(client)
        # Should not raise, and should produce a permission finding for api-a
        findings = asyncio.run(auditor.audit())

        permission_findings = [
            f for f in findings if f.check_id == "cloud_resource_not_auditable"
        ]
        assert len(permission_findings) >= 1, (
            "Expected at least one permission-denied finding for api-a"
        )

    def test_throttled_rest_apis_yields_info_finding(self):
        """When get_rest_apis is throttled and retries exhausted, INFO finding is generated."""
        from botocore.exceptions import ClientError

        throttle_error = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "get_rest_apis",
        )

        def _paginate_v1_side_effect(op, key, **kw):
            if op == "get_rest_apis":
                raise throttle_error
            return []  # other calls succeed

        client = MagicMock()
        client.paginate_v1.side_effect = _paginate_v1_side_effect
        client.paginate_v2.return_value = []

        auditor = self._make_aws_auditor(client)
        # Disable actual sleep during retries to keep tests fast
        import unittest.mock as mock_lib
        with mock_lib.patch("utils.cloud.backoff.asyncio.sleep"):
            findings = asyncio.run(auditor.audit())

        assert any(f.check_id == "cloud_resource_not_auditable" for f in findings), (
            f"Expected throttle finding, got: {[f.check_id for f in findings]}"
        )

    def test_handle_aws_error_maps_limit_exceeded_to_throttled(self):
        """LimitExceededException is now treated as a throttle error."""
        from botocore.exceptions import ClientError

        client = MagicMock()
        auditor = self._make_aws_auditor(client)

        error_response = {
            "Error": {"Code": "LimitExceededException", "Message": "Limit exceeded"}
        }
        exc = ClientError(error_response, "operation")

        with pytest.raises(ProviderThrottledError):
            auditor._handle_aws_error("operation", exc)

    def test_handle_aws_error_maps_unauthorized_to_permissions(self):
        """UnauthorizedException → InsufficientPermissionsError."""
        from botocore.exceptions import ClientError

        client = MagicMock()
        auditor = self._make_aws_auditor(client)

        error_response = {
            "Error": {"Code": "UnauthorizedException", "Message": "Unauthorized"}
        }
        exc = ClientError(error_response, "operation")

        with pytest.raises(InsufficientPermissionsError):
            auditor._handle_aws_error("operation", exc)


# ===========================================================================
# 4. CloudAuditOrchestrator.run() — exception handling & summary
# ===========================================================================


class TestOrchestratorErrorHandlingRun:
    def _make_orch_with_mock_auditors(self, auditors):
        """Build an orchestrator bypassing __init__ and inject mock auditors."""
        from core.config import CloudAuditConfig
        from modules.cloud.orchestrator import CloudAuditOrchestrator
        from modules.cloud.normalizer import GatewayFindingNormalizer

        config = CloudAuditConfig(providers=["aws"])
        orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
        orch._config = config
        orch._normalizer = GatewayFindingNormalizer()
        orch.auditors = auditors
        orch._skipped_providers = []
        orch._not_audited_resources = []
        return orch

    def test_credential_resolution_error_does_not_crash(self):
        """CredentialResolutionError is caught; run() returns an empty list."""
        bad_auditor = MagicMock()
        bad_auditor.get_provider_name.return_value = "aws"
        bad_auditor._account_context = "aws:bad-profile"
        bad_auditor.audit = AsyncMock(
            side_effect=CredentialResolutionError("No credentials found")
        )

        orch = self._make_orch_with_mock_auditors([bad_auditor])
        findings = asyncio.run(orch.run())

        assert findings == []

    def test_credential_resolution_error_populates_skipped_providers(self):
        """_skipped_providers is updated when CredentialResolutionError is raised."""
        bad_auditor = MagicMock()
        bad_auditor.get_provider_name.return_value = "aws"
        bad_auditor._account_context = "aws:no-creds"
        bad_auditor.audit = AsyncMock(
            side_effect=CredentialResolutionError("Missing credentials")
        )

        orch = self._make_orch_with_mock_auditors([bad_auditor])
        asyncio.run(orch.run())

        assert "aws:no-creds" in orch._skipped_providers

    def test_insufficient_permissions_generates_info_finding(self):
        """InsufficientPermissionsError → INFO GatewayFinding in the result set."""
        perm_auditor = MagicMock()
        perm_auditor.get_provider_name.return_value = "gcp"
        perm_auditor._account_context = "gcp:my-project"
        perm_auditor.audit = AsyncMock(
            side_effect=InsufficientPermissionsError("roles/apigateway.viewer not granted")
        )

        orch = self._make_orch_with_mock_auditors([perm_auditor])
        findings = asyncio.run(orch.run())

        # Should include an INFO finding
        assert len(findings) >= 1
        assert all(f.owasp_category == "API8" for f in findings)
        assert any(f.severity.upper() == "INFO" for f in findings)

    def test_insufficient_permissions_populates_not_audited_resources(self):
        perm_auditor = MagicMock()
        perm_auditor.get_provider_name.return_value = "gcp"
        perm_auditor._account_context = "gcp:proj-x"
        perm_auditor.audit = AsyncMock(
            side_effect=InsufficientPermissionsError("denied")
        )

        orch = self._make_orch_with_mock_auditors([perm_auditor])
        asyncio.run(orch.run())

        assert "gcp:proj-x" in orch._not_audited_resources

    def test_provider_throttled_does_not_crash(self):
        """ProviderThrottledError is caught; run() returns without raising."""
        throttled_auditor = MagicMock()
        throttled_auditor.get_provider_name.return_value = "azure"
        throttled_auditor._account_context = "azure:sub-123/rg-a"
        throttled_auditor.audit = AsyncMock(
            side_effect=ProviderThrottledError("429 Too Many Requests")
        )

        orch = self._make_orch_with_mock_auditors([throttled_auditor])
        # Should not raise
        findings = asyncio.run(orch.run())
        assert isinstance(findings, list)

    def test_provider_throttled_populates_not_audited_resources(self):
        throttled_auditor = MagicMock()
        throttled_auditor.get_provider_name.return_value = "azure"
        throttled_auditor._account_context = "azure:sub-xyz/rg-b"
        throttled_auditor.audit = AsyncMock(
            side_effect=ProviderThrottledError("rate limit exceeded")
        )

        orch = self._make_orch_with_mock_auditors([throttled_auditor])
        asyncio.run(orch.run())

        assert "azure:sub-xyz/rg-b" in orch._not_audited_resources

    def test_run_summary_tracks_multiple_errors(self):
        """Mixed errors across auditors produce correct summary counts."""
        cred_auditor = MagicMock()
        cred_auditor.get_provider_name.return_value = "aws"
        cred_auditor._account_context = "aws:no-creds"
        cred_auditor.audit = AsyncMock(
            side_effect=CredentialResolutionError("no credentials")
        )

        perm_auditor = MagicMock()
        perm_auditor.get_provider_name.return_value = "gcp"
        perm_auditor._account_context = "gcp:no-perms"
        perm_auditor.audit = AsyncMock(
            side_effect=InsufficientPermissionsError("denied")
        )

        ok_finding = _make_finding("azure", "azure:sub-ok/rg")
        ok_auditor = _make_mock_auditor("azure", "azure:sub-ok/rg", [ok_finding])

        orch = self._make_orch_with_mock_auditors(
            [cred_auditor, perm_auditor, ok_auditor]
        )
        findings = asyncio.run(orch.run())

        # cred error → skipped_providers
        assert len(orch._skipped_providers) == 1
        assert "aws:no-creds" in orch._skipped_providers

        # perm error → not_audited_resources
        assert len(orch._not_audited_resources) == 1
        assert "gcp:no-perms" in orch._not_audited_resources

        # ok auditor → findings returned
        assert any(f.owasp_category == "API8" for f in findings)

    def test_run_resets_summary_between_calls(self):
        """Each call to run() resets _skipped_providers and _not_audited_resources."""
        bad_auditor = MagicMock()
        bad_auditor.get_provider_name.return_value = "aws"
        bad_auditor._account_context = "aws:bad"
        bad_auditor.audit = AsyncMock(
            side_effect=CredentialResolutionError("no creds")
        )

        orch = self._make_orch_with_mock_auditors([bad_auditor])

        asyncio.run(orch.run())
        assert len(orch._skipped_providers) == 1

        # Second run: replace auditor with a successful one and re-run
        good_finding = _make_finding("aws", "aws:good")
        good_auditor = _make_mock_auditor("aws", "aws:good", [good_finding])
        orch.auditors = [good_auditor]

        asyncio.run(orch.run())
        # Summary should be reset — no carryover from first run
        assert orch._skipped_providers == []
        assert orch._not_audited_resources == []

    def test_good_auditor_results_survive_alongside_errors(self):
        """Findings from successful auditors are returned even when other auditors fail."""
        bad_auditor = MagicMock()
        bad_auditor.get_provider_name.return_value = "aws"
        bad_auditor._account_context = "aws:bad"
        bad_auditor.audit = AsyncMock(
            side_effect=CredentialResolutionError("no creds")
        )

        good_finding = _make_finding("gcp", "gcp:ok-project")
        good_auditor = _make_mock_auditor("gcp", "gcp:ok-project", [good_finding])

        orch = self._make_orch_with_mock_auditors([bad_auditor, good_auditor])
        findings = asyncio.run(orch.run())

        assert len(findings) == 1
        assert findings[0].owasp_category == "API8"


# ===========================================================================
# 5. GCP / Azure _handle_*_error enhancements
# ===========================================================================


class TestGCPErrorHandling:
    def _make_gcp_auditor(self) -> "GCPGatewayAuditor":
        from modules.cloud.gcp_api_gateway import GCPGatewayAuditor
        from utils.cloud.readonly_guard import CloudReadOnlyGuard

        client = MagicMock()
        client.project_id = "test-project"
        client.location = "global"
        guard = CloudReadOnlyGuard(allow_destructive=False)
        return GCPGatewayAuditor(
            client=client, guard=guard, account_context="gcp:test-project"
        )

    def test_handle_gcp_error_maps_resource_exhausted_to_throttled(self):
        """ResourceExhausted-style exception → ProviderThrottledError."""
        auditor = self._make_gcp_auditor()

        class FakeResourceExhausted(Exception):
            pass

        FakeResourceExhausted.__name__ = "ResourceExhausted"

        with pytest.raises(ProviderThrottledError):
            auditor._handle_gcp_error(
                "list_api_configs", FakeResourceExhausted("quota exceeded")
            )

    def test_handle_gcp_error_maps_429_string_to_throttled(self):
        auditor = self._make_gcp_auditor()

        with pytest.raises(ProviderThrottledError):
            auditor._handle_gcp_error("list_apis", Exception("HTTP 429 rate limit exceeded"))

    def test_handle_gcp_error_maps_permission_denied_to_insufficient(self):
        auditor = self._make_gcp_auditor()

        with pytest.raises(InsufficientPermissionsError):
            auditor._handle_gcp_error(
                "list_api_configs", Exception("403 PERMISSION_DENIED")
            )


class TestAzureErrorHandling:
    def _make_azure_auditor(self) -> "AzureAPIMAuditor":
        from modules.cloud.azure_apim import AzureAPIMAuditor
        from utils.cloud.readonly_guard import CloudReadOnlyGuard

        client = MagicMock()
        client.subscription_id = "sub-test"
        guard = CloudReadOnlyGuard(allow_destructive=False)
        return AzureAPIMAuditor(
            client=client,
            resource_group="rg-test",
            guard=guard,
            account_context="azure:sub-test/rg-test",
        )

    def test_handle_azure_error_maps_429_to_throttled(self):
        """HTTP 429 response → ProviderThrottledError."""
        auditor = self._make_azure_auditor()

        with pytest.raises(ProviderThrottledError):
            auditor._handle_azure_error(
                "list_by_resource_group",
                Exception("429 Too Many Requests — throttling"),
            )

    def test_handle_azure_error_maps_403_to_insufficient_permissions(self):
        auditor = self._make_azure_auditor()

        with pytest.raises(InsufficientPermissionsError):
            auditor._handle_azure_error(
                "list_products",
                Exception("403 Forbidden — AuthorizationFailed"),
            )

    def test_handle_azure_error_non_fatal_does_not_raise(self):
        """A generic error that is not 403/429 should log but not raise."""
        auditor = self._make_azure_auditor()

        # Should not raise
        auditor._handle_azure_error("some_operation", Exception("ServiceUnavailable 503"))
