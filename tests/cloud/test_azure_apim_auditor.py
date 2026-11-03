"""
tests/cloud/test_azure_apim_auditor.py
Unit tests for AzureAPIMAuditor individual checks.

Coverage (per spec Requirements 6.1 – 6.5, 10.1, 10.2):
  - _check_product_subscription_required   (Requirement 6.1)
  - _check_api_validate_jwt                (Requirement 6.2)
  - _check_backend_mtls                    (Requirement 6.3)
  - _check_cors_wildcard_credentials       (Requirement 6.4)
  - _check_subscription_expiration         (Requirement 6.5)
  - discover_resources                     (async, Requirement 10.1)
  - audit                                  (async, Requirement 10.1)

All Azure SDK calls are mocked with unittest.mock.MagicMock — no real
credentials or network access are needed.  The entire module is skipped
gracefully when azure-mgmt-apimanagement is not installed (Requirement 10.2).
"""

from __future__ import annotations

import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Azure SDK is an optional extra; skip this entire module if not installed.
pytest.importorskip("azure.mgmt.apimanagement")

from modules.cloud.base import GatewaySeverity
from modules.cloud.azure_apim import AzureAPIMAuditor
from utils.cloud.azure_client import AzureAPIMClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUBSCRIPTION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_RESOURCE_GROUP = "rg-test"
_SERVICE_NAME = "apim-test"
_ACCOUNT_CTX = f"{_SUBSCRIPTION_ID}/{_RESOURCE_GROUP}/{_SERVICE_NAME}"


def _make_auditor() -> tuple[AzureAPIMAuditor, MagicMock]:
    """Return an AzureAPIMAuditor with a fully mocked AzureAPIMClient."""
    mock_client = MagicMock(spec=AzureAPIMClient)
    mock_client.subscription_id = _SUBSCRIPTION_ID

    # Prevent the `client` property from attempting real SDK calls
    mock_client.client = MagicMock()

    guard = CloudReadOnlyGuard(allow_destructive=False)
    auditor = AzureAPIMAuditor(
        client=mock_client,
        resource_group=_RESOURCE_GROUP,
        guard=guard,
        account_context=_ACCOUNT_CTX,
    )
    return auditor, mock_client


def _make_product(name: str, subscription_required: bool) -> MagicMock:
    """Build a mock APIM Product SDK object."""
    product = MagicMock()
    product.name = name
    product.subscription_required = subscription_required
    return product


def _make_api(name: str, display_name: str = "") -> MagicMock:
    """Build a mock APIM API SDK object."""
    api = MagicMock()
    api.name = name
    api.display_name = display_name or name
    return api


def _make_policy_response(xml: str) -> MagicMock:
    """Build a mock policy response with a 'value' attribute."""
    resp = MagicMock()
    resp.value = xml
    return resp


def _make_backend(
    name: str,
    url: str,
    certificate_thumbprints: list[str] | None = None,
) -> MagicMock:
    """Build a mock APIM Backend SDK object."""
    backend = MagicMock()
    backend.name = name
    backend.url = url

    if certificate_thumbprints is not None:
        credentials = MagicMock()
        credentials.certificate = certificate_thumbprints
        backend.credentials = credentials
    else:
        backend.credentials = None

    return backend


def _make_subscription(
    name: str,
    state: str,
    expiration_date: datetime.datetime | None = None,
) -> MagicMock:
    """Build a mock APIM Subscription SDK object."""
    sub = MagicMock()
    sub.name = name
    sub.state = state
    sub.expiration_date = expiration_date
    return sub


# ---------------------------------------------------------------------------
# Check 6.1 — _check_product_subscription_required
# ---------------------------------------------------------------------------


class TestCheckProductSubscriptionRequired:
    """AzureAPIMAuditor._check_product_subscription_required (Requirement 6.1)."""

    def test_vulnerable_subscription_required_false_emits_high(self):
        """product.subscription_required=False → HIGH finding."""
        auditor, _ = _make_auditor()
        product = _make_product("starter", subscription_required=False)

        finding = auditor._check_product_subscription_required(
            _SERVICE_NAME, product, _ACCOUNT_CTX
        )

        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "azure_apim_product_no_subscription_required"
        assert finding.provider == "azure"
        assert finding.evidence["subscription_required"] is False
        assert finding.evidence["product"] == "starter"

    def test_clean_subscription_required_true_returns_none(self):
        """product.subscription_required=True → no finding."""
        auditor, _ = _make_auditor()
        product = _make_product("premium", subscription_required=True)

        finding = auditor._check_product_subscription_required(
            _SERVICE_NAME, product, _ACCOUNT_CTX
        )

        assert finding is None

    def test_finding_resource_id_contains_product_name(self):
        """The resource_id of the finding encodes the product name in the Azure path."""
        auditor, _ = _make_auditor()
        product = _make_product("my-product", subscription_required=False)

        finding = auditor._check_product_subscription_required(
            _SERVICE_NAME, product, _ACCOUNT_CTX
        )

        assert finding is not None
        assert "my-product" in finding.resource_id
        assert "products" in finding.resource_id

    def test_finding_account_context_matches(self):
        """The finding's account_context is propagated correctly."""
        auditor, _ = _make_auditor()
        product = _make_product("free", subscription_required=False)

        finding = auditor._check_product_subscription_required(
            _SERVICE_NAME, product, _ACCOUNT_CTX
        )

        assert finding is not None
        assert finding.account_context == _ACCOUNT_CTX


# ---------------------------------------------------------------------------
# Check 6.2 — _check_api_validate_jwt
# ---------------------------------------------------------------------------


class TestCheckApiValidateJwt:
    """AzureAPIMAuditor._check_api_validate_jwt (Requirement 6.2)."""

    # ------------------------------------------------------------------ clean

    def test_clean_validate_jwt_in_inbound_returns_none(self):
        """Policy with <validate-jwt> in <inbound> → no finding."""
        auditor, _ = _make_auditor()
        xml = (
            "<policies><inbound>"
            "<validate-jwt header-name='Authorization'>"
            "<issuer-signing-keys><key>secret</key></issuer-signing-keys>"
            "</validate-jwt>"
            "</inbound></policies>"
        )
        api = _make_api("my-api")
        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_check_header_in_inbound_returns_none(self):
        """Policy with <check-header> in <inbound> (subscription key check) → no finding."""
        auditor, _ = _make_auditor()
        xml = (
            "<policies><inbound>"
            "<check-header name='Ocp-Apim-Subscription-Key' failed-check-httpcode='401' "
            "failed-check-error-message='Not authorized' />"
            "</inbound></policies>"
        )
        api = _make_api("key-api")
        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_authentication_basic_returns_none(self):
        """Policy with <authentication-basic> → no finding."""
        auditor, _ = _make_auditor()
        xml = (
            "<policies><inbound>"
            "<authentication-basic username='user' password='pass' />"
            "</inbound></policies>"
        )
        api = _make_api("basic-api")
        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)
        assert finding is None

    # --------------------------------------------------------------- vulnerable

    def test_vulnerable_no_auth_element_emits_high(self):
        """Policy XML with no auth element in inbound → HIGH finding."""
        auditor, _ = _make_auditor()
        xml = (
            "<policies><inbound>"
            "<rate-limit calls='100' renewal-period='60' />"
            "</inbound></policies>"
        )
        api = _make_api("open-api")
        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "azure_apim_api_no_auth_policy"
        assert finding.provider == "azure"

    def test_vulnerable_empty_policy_xml_emits_high(self):
        """Effectively empty policy XML → HIGH finding."""
        auditor, _ = _make_auditor()
        xml = "<policies><inbound><base /></inbound></policies>"
        api = _make_api("empty-policy-api")
        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH

    def test_finding_includes_api_name_in_evidence(self):
        """Finding evidence contains the api_id from the API object."""
        auditor, _ = _make_auditor()
        xml = "<policies><inbound></inbound></policies>"
        api = _make_api("insecure-api", display_name="Insecure API")

        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.evidence["api_id"] == "insecure-api"

    def test_finding_resource_id_contains_api_name(self):
        """The resource_id of the finding includes the api name in the Azure path."""
        auditor, _ = _make_auditor()
        xml = "<policies><inbound></inbound></policies>"
        api = _make_api("no-auth-api")

        finding = auditor._check_api_validate_jwt(_SERVICE_NAME, api, xml, _ACCOUNT_CTX)

        assert finding is not None
        assert "no-auth-api" in finding.resource_id
        assert "apis" in finding.resource_id


# ---------------------------------------------------------------------------
# Check 6.3 — _check_backend_mtls
# ---------------------------------------------------------------------------


class TestCheckBackendMTLS:
    """AzureAPIMAuditor._check_backend_mtls (Requirement 6.3)."""

    # ------------------------------------------------------------------ clean

    def test_clean_https_with_certificate_thumbprints_returns_none(self):
        """HTTPS backend with certificate thumbprints → no finding."""
        auditor, _ = _make_auditor()
        backend = _make_backend(
            "secure-backend",
            url="https://secure.internal.example.com",
            certificate_thumbprints=["AABBCC112233"],
        )
        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_http_backend_no_tls_returns_none(self):
        """HTTP backend (no TLS) → mTLS not applicable → no finding."""
        auditor, _ = _make_auditor()
        backend = _make_backend(
            "plain-backend",
            url="http://internal.example.com",
            certificate_thumbprints=None,
        )
        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_https_empty_url_no_finding(self):
        """Backend with empty URL → treated as non-HTTPS → no finding."""
        auditor, _ = _make_auditor()
        backend = _make_backend("no-url-backend", url="")
        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)
        assert finding is None

    # --------------------------------------------------------------- vulnerable

    def test_vulnerable_https_no_credentials_emits_info(self):
        """HTTPS backend with no credentials object → INFO finding."""
        auditor, _ = _make_auditor()
        backend = _make_backend(
            "tls-no-mtls",
            url="https://backend.example.com/api",
            certificate_thumbprints=None,
        )
        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.severity == GatewaySeverity.INFO
        assert finding.check_id == "azure_apim_backend_no_mtls"
        assert finding.provider == "azure"

    def test_vulnerable_https_empty_certificate_list_emits_info(self):
        """HTTPS backend with an empty certificates list → INFO finding."""
        auditor, _ = _make_auditor()
        backend = _make_backend(
            "empty-cert-backend",
            url="https://backend.example.com",
            certificate_thumbprints=[],
        )
        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.severity == GatewaySeverity.INFO

    def test_finding_evidence_includes_url(self):
        """The finding's evidence includes the backend URL."""
        auditor, _ = _make_auditor()
        backend_url = "https://api.example.com/v1"
        backend = _make_backend("b1", url=backend_url, certificate_thumbprints=None)

        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.evidence["url"] == backend_url
        assert finding.evidence["client_certificate_configured"] is False

    def test_finding_resource_id_contains_backend_name(self):
        """The resource_id of the finding encodes the backend name."""
        auditor, _ = _make_auditor()
        backend = _make_backend("b-secure", url="https://x.example.com")

        finding = auditor._check_backend_mtls(_SERVICE_NAME, backend, _ACCOUNT_CTX)

        assert finding is not None
        assert "b-secure" in finding.resource_id
        assert "backends" in finding.resource_id


# ---------------------------------------------------------------------------
# Check 6.4 — _check_cors_wildcard_credentials
# ---------------------------------------------------------------------------


class TestCheckCorsWildcardCredentials:
    """AzureAPIMAuditor._check_cors_wildcard_credentials (Requirement 6.4)."""

    # ------------------------------------------------------------------ clean

    def test_clean_cors_specific_origin_with_credentials_returns_none(self):
        """allow-credentials=true but origin is specific (not '*') → no finding."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "api1")
        xml = (
            "<policies><inbound>"
            '<cors allow-credentials="true">'
            "<allowed-origins>"
            "<origin>https://app.example.com</origin>"
            "</allowed-origins>"
            "</cors>"
            "</inbound></policies>"
        )
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )
        assert finding is None

    def test_clean_cors_wildcard_without_credentials_returns_none(self):
        """allow-credentials=false (default) with '*' origin → no finding."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "api1")
        xml = (
            "<policies><inbound>"
            '<cors allow-credentials="false">'
            "<allowed-origins><origin>*</origin></allowed-origins>"
            "</cors>"
            "</inbound></policies>"
        )
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )
        assert finding is None

    def test_clean_no_cors_element_returns_none(self):
        """Policy with no <cors> element → no finding."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "api1")
        xml = "<policies><inbound><rate-limit calls='100' renewal-period='60' /></inbound></policies>"
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )
        assert finding is None

    def test_clean_cors_no_allowed_origins_element_returns_none(self):
        """CORS element with credentials but no <allowed-origins> element → no finding."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "api1")
        xml = (
            "<policies><inbound>"
            '<cors allow-credentials="true">'
            "</cors>"
            "</inbound></policies>"
        )
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )
        assert finding is None

    # --------------------------------------------------------------- vulnerable

    def test_vulnerable_cors_wildcard_with_credentials_emits_high(self):
        """allow-credentials=true + origin='*' → HIGH finding."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "dangerous-api")
        xml = (
            "<policies><inbound>"
            '<cors allow-credentials="true">'
            "<allowed-origins><origin>*</origin></allowed-origins>"
            "</cors>"
            "</inbound></policies>"
        )
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )

        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "azure_apim_cors_wildcard_with_credentials"
        assert finding.provider == "azure"

    def test_vulnerable_finding_evidence_lists_wildcard_origin(self):
        """Finding evidence includes the wildcard origin in allowed_origins."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "api1")
        xml = (
            "<policies><inbound>"
            '<cors allow-credentials="true">'
            "<allowed-origins><origin>*</origin></allowed-origins>"
            "</cors>"
            "</inbound></policies>"
        )
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )

        assert finding is not None
        assert "*" in finding.evidence["allowed_origins"]
        assert finding.evidence["allow_credentials"] is True

    def test_vulnerable_mixed_origins_with_wildcard_emits_high(self):
        """allow-credentials=true with both specific and '*' origins → HIGH finding."""
        auditor, _ = _make_auditor()
        resource_id = auditor._build_resource_id(_SERVICE_NAME, "apis", "api1")
        xml = (
            "<policies><inbound>"
            '<cors allow-credentials="true">'
            "<allowed-origins>"
            "<origin>https://app.example.com</origin>"
            "<origin>*</origin>"
            "</allowed-origins>"
            "</cors>"
            "</inbound></policies>"
        )
        finding = auditor._check_cors_wildcard_credentials(
            _SERVICE_NAME, resource_id, xml, _ACCOUNT_CTX
        )
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH


# ---------------------------------------------------------------------------
# Check 6.5 — _check_subscription_expiration
# ---------------------------------------------------------------------------


class TestCheckSubscriptionExpiration:
    """AzureAPIMAuditor._check_subscription_expiration (Requirement 6.5)."""

    # ------------------------------------------------------------------ clean

    def test_clean_active_with_expiry_returns_none(self):
        """Active subscription with an expiration_date set → no finding."""
        auditor, _ = _make_auditor()
        sub = _make_subscription(
            "sub-001",
            state="active",
            expiration_date=datetime.datetime(2026, 1, 1),
        )
        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_suspended_without_expiry_returns_none(self):
        """Suspended subscription with no expiration_date → no finding."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("sub-002", state="suspended", expiration_date=None)
        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_cancelled_without_expiry_returns_none(self):
        """Cancelled subscription → no finding."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("sub-003", state="cancelled", expiration_date=None)
        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)
        assert finding is None

    def test_clean_expired_state_without_expiry_returns_none(self):
        """Subscription in 'expired' state → not 'active' → no finding."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("sub-004", state="expired", expiration_date=None)
        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)
        assert finding is None

    # --------------------------------------------------------------- vulnerable

    def test_vulnerable_active_without_expiry_emits_low(self):
        """Active subscription with expiration_date=None → LOW finding."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("sub-no-expiry", state="active", expiration_date=None)
        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.severity == GatewaySeverity.LOW
        assert finding.check_id == "azure_apim_subscription_no_expiry"
        assert finding.provider == "azure"

    def test_vulnerable_finding_evidence_includes_subscription_name(self):
        """Finding evidence contains the subscription name."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("my-key-sub", state="active", expiration_date=None)

        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.evidence["subscription_name"] == "my-key-sub"
        assert finding.evidence["state"] == "active"
        assert finding.evidence["expiration_date"] is None

    def test_vulnerable_finding_resource_id_contains_subscription_name(self):
        """The finding's resource_id encodes the subscription name."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("no-exp-sub", state="active", expiration_date=None)

        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)

        assert finding is not None
        assert "no-exp-sub" in finding.resource_id
        assert "subscriptions" in finding.resource_id

    def test_vulnerable_account_context_propagated(self):
        """Finding's account_context matches the context passed in."""
        auditor, _ = _make_auditor()
        sub = _make_subscription("sub-x", state="active", expiration_date=None)

        finding = auditor._check_subscription_expiration(_SERVICE_NAME, sub, _ACCOUNT_CTX)

        assert finding is not None
        assert finding.account_context == _ACCOUNT_CTX


# ---------------------------------------------------------------------------
# discover_resources (async)
# ---------------------------------------------------------------------------


class TestDiscoverResources:
    """AzureAPIMAuditor.discover_resources (async, Requirement 10.1)."""

    @pytest.mark.asyncio
    async def test_returns_services_products_and_apis(self):
        """discover_resources aggregates service, product, and api resource dicts."""
        auditor, mock_client = _make_auditor()

        svc = MagicMock()
        svc.name = _SERVICE_NAME
        svc.location = "eastus"
        mock_client.client.api_management_service.list_by_resource_group.return_value = [svc]

        product = _make_product("starter", subscription_required=True)
        mock_client.list_products.return_value = [product]

        api = _make_api("my-api")
        mock_client.list_apis.return_value = [api]

        resources = await auditor.discover_resources()

        types = {r["type"] for r in resources}
        assert "apim_service" in types
        assert "apim_product" in types
        assert "apim_api" in types

    @pytest.mark.asyncio
    async def test_service_resource_has_expected_fields(self):
        """Service resource dict contains name, location, type, and resource_group."""
        auditor, mock_client = _make_auditor()

        svc = MagicMock()
        svc.name = _SERVICE_NAME
        svc.location = "westeurope"
        mock_client.client.api_management_service.list_by_resource_group.return_value = [svc]
        mock_client.list_products.return_value = []
        mock_client.list_apis.return_value = []

        resources = await auditor.discover_resources()

        svc_resources = [r for r in resources if r["type"] == "apim_service"]
        assert len(svc_resources) == 1
        assert svc_resources[0]["name"] == _SERVICE_NAME
        assert svc_resources[0]["location"] == "westeurope"
        assert svc_resources[0]["resource_group"] == _RESOURCE_GROUP

    @pytest.mark.asyncio
    async def test_no_services_returns_empty_list(self):
        """When no APIM services exist, discover_resources returns an empty list."""
        auditor, mock_client = _make_auditor()
        mock_client.client.api_management_service.list_by_resource_group.return_value = []

        resources = await auditor.discover_resources()
        assert resources == []

    @pytest.mark.asyncio
    async def test_error_on_list_products_does_not_crash(self):
        """Exception during list_products is swallowed; service resource is still returned."""
        auditor, mock_client = _make_auditor()

        svc = MagicMock()
        svc.name = _SERVICE_NAME
        svc.location = "eastus"
        mock_client.client.api_management_service.list_by_resource_group.return_value = [svc]
        mock_client.list_products.side_effect = Exception("SDK error")
        mock_client.list_apis.return_value = []

        resources = await auditor.discover_resources()

        # Must not raise; at minimum the service itself should be recorded
        assert any(r["type"] == "apim_service" for r in resources)


# ---------------------------------------------------------------------------
# audit() — integration tests (async)
# ---------------------------------------------------------------------------


class TestAuditIntegration:
    """End-to-end audit() that drives through all checks per APIM service."""

    def _configure_service(self, mock_client: MagicMock) -> None:
        """Set up a single APIM service in the mock client."""
        svc = MagicMock()
        svc.name = _SERVICE_NAME
        mock_client.client.api_management_service.list_by_resource_group.return_value = [svc]

    # ------------------------------------------------------------------ clean

    @pytest.mark.asyncio
    async def test_clean_config_produces_no_findings(self):
        """Correctly configured APIM → zero findings."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        # Clean product
        mock_client.list_products.return_value = [
            _make_product("premium", subscription_required=True)
        ]
        # Clean API with validate-jwt
        api = _make_api("secure-api")
        mock_client.list_apis.return_value = [api]
        jwt_xml = (
            "<policies><inbound>"
            "<validate-jwt header-name='Authorization'>"
            "<issuer-signing-keys><key>s</key></issuer-signing-keys>"
            "</validate-jwt>"
            "</inbound></policies>"
        )
        mock_client.get_api_policy.return_value = _make_policy_response(jwt_xml)
        mock_client.get_service_policy.return_value = None
        # Clean backend (HTTPS + cert)
        mock_client.list_backends.return_value = [
            _make_backend("b1", "https://backend.example.com", ["AABB1122"])
        ]
        # Clean subscription (with expiry)
        mock_client.list_subscriptions.return_value = [
            _make_subscription("sub1", "active", datetime.datetime(2026, 12, 31))
        ]

        findings = await auditor.audit()
        assert findings == []

    # ------------------------------------------------------------------ vulnerable per check

    @pytest.mark.asyncio
    async def test_audit_detects_product_no_subscription_required(self):
        """audit() surfaces product with subscription_required=False → HIGH finding."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = [
            _make_product("open-product", subscription_required=False)
        ]
        mock_client.list_apis.return_value = []
        mock_client.get_service_policy.return_value = None
        mock_client.list_backends.return_value = []
        mock_client.list_subscriptions.return_value = []

        findings = await auditor.audit()
        check_ids = {f.check_id for f in findings}
        assert "azure_apim_product_no_subscription_required" in check_ids
        high_findings = [f for f in findings if f.severity == GatewaySeverity.HIGH]
        assert len(high_findings) >= 1

    @pytest.mark.asyncio
    async def test_audit_detects_api_without_auth_policy(self):
        """audit() surfaces API with no auth policy → HIGH finding."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = []
        api = _make_api("no-auth-api")
        mock_client.list_apis.return_value = [api]
        # Policy with no auth element
        no_auth_xml = "<policies><inbound><base /></inbound></policies>"
        mock_client.get_api_policy.return_value = _make_policy_response(no_auth_xml)
        mock_client.get_service_policy.return_value = None
        mock_client.list_backends.return_value = []
        mock_client.list_subscriptions.return_value = []

        findings = await auditor.audit()
        assert any(f.check_id == "azure_apim_api_no_auth_policy" for f in findings)

    @pytest.mark.asyncio
    async def test_audit_detects_backend_without_mtls(self):
        """audit() surfaces HTTPS backend with no client certificate → INFO finding."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = []
        mock_client.list_apis.return_value = []
        mock_client.get_service_policy.return_value = None
        mock_client.list_backends.return_value = [
            _make_backend("no-mtls", "https://api.example.com", certificate_thumbprints=None)
        ]
        mock_client.list_subscriptions.return_value = []

        findings = await auditor.audit()
        assert any(f.check_id == "azure_apim_backend_no_mtls" for f in findings)
        info = [f for f in findings if f.severity == GatewaySeverity.INFO]
        assert len(info) >= 1

    @pytest.mark.asyncio
    async def test_audit_detects_cors_wildcard_with_credentials(self):
        """audit() surfaces service-level CORS wildcard + credentials → HIGH finding."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = []
        mock_client.list_apis.return_value = []
        cors_xml = (
            "<policies><inbound>"
            '<cors allow-credentials="true">'
            "<allowed-origins><origin>*</origin></allowed-origins>"
            "</cors>"
            "</inbound></policies>"
        )
        mock_client.get_service_policy.return_value = _make_policy_response(cors_xml)
        mock_client.list_backends.return_value = []
        mock_client.list_subscriptions.return_value = []

        findings = await auditor.audit()
        assert any(
            f.check_id in (
                "azure_apim_cors_wildcard_with_credentials",
                "azure_apim_service_cors_wildcard_with_credentials",
            )
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_audit_detects_subscription_without_expiry(self):
        """audit() surfaces active subscription with no expiration_date → LOW finding."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = []
        mock_client.list_apis.return_value = []
        mock_client.get_service_policy.return_value = None
        mock_client.list_backends.return_value = []
        mock_client.list_subscriptions.return_value = [
            _make_subscription("never-expires", state="active", expiration_date=None)
        ]

        findings = await auditor.audit()
        assert any(f.check_id == "azure_apim_subscription_no_expiry" for f in findings)
        low_findings = [f for f in findings if f.severity == GatewaySeverity.LOW]
        assert len(low_findings) >= 1

    # ------------------------------------------------------------------ multi-issue

    @pytest.mark.asyncio
    async def test_audit_aggregates_findings_from_multiple_checks(self):
        """Multiple misconfigurations in one service → findings from each check."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = [
            _make_product("open", subscription_required=False)
        ]
        api = _make_api("bad-api")
        mock_client.list_apis.return_value = [api]
        no_auth_xml = "<policies><inbound></inbound></policies>"
        mock_client.get_api_policy.return_value = _make_policy_response(no_auth_xml)
        mock_client.get_service_policy.return_value = None
        mock_client.list_backends.return_value = [
            _make_backend("b1", "https://api.example.com", certificate_thumbprints=None)
        ]
        mock_client.list_subscriptions.return_value = [
            _make_subscription("s1", state="active", expiration_date=None)
        ]

        findings = await auditor.audit()
        check_ids = {f.check_id for f in findings}

        assert "azure_apim_product_no_subscription_required" in check_ids
        assert "azure_apim_api_no_auth_policy" in check_ids
        assert "azure_apim_backend_no_mtls" in check_ids
        assert "azure_apim_subscription_no_expiry" in check_ids

    @pytest.mark.asyncio
    async def test_audit_api_no_policy_at_all_emits_finding(self):
        """When get_api_policy returns None, a no-policy finding is still emitted."""
        auditor, mock_client = _make_auditor()
        self._configure_service(mock_client)

        mock_client.list_products.return_value = []
        api = _make_api("api-no-policy")
        mock_client.list_apis.return_value = [api]
        mock_client.get_api_policy.return_value = None
        mock_client.get_service_policy.return_value = None
        mock_client.list_backends.return_value = []
        mock_client.list_subscriptions.return_value = []

        findings = await auditor.audit()
        assert any(f.check_id == "azure_apim_api_no_auth_policy" for f in findings)
