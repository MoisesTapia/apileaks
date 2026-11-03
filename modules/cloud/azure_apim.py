"""
Azure API Management Security Auditor

Audits the configuration of Azure API Management instances using read-only
Azure SDK calls.

Checks implemented (mapped to spec Requirements 6.1 – 6.5):
  6.1  Products with subscriptionRequired = false
  6.2  APIs without a validate-jwt or key-validation policy
  6.3  Backends that support TLS but don't declare mTLS (clientCertificate)
  6.4  CORS configured with wildcard origin AND credentials enabled
  6.5  Active subscriptions with no expiry date (no rotation enforced)

All methods are read-only.  Policy XML documents are parsed with
``xml.etree.ElementTree`` rather than plain string matching.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from core.logging import get_logger
from modules.cloud.base import (
    CloudGatewayAuditor,
    GatewayFinding,
    GatewaySeverity,
    InsufficientPermissionsError,
    ProviderThrottledError,
    create_permission_denied_finding,
)
from utils.cloud.azure_client import AzureAPIMClient
from utils.cloud.backoff import with_exponential_backoff
from utils.cloud.readonly_guard import CloudReadOnlyGuard

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Remediation strings (stable, referenced from multiple places)
# ---------------------------------------------------------------------------

_REMEDIATION_SUBSCRIPTION_REQUIRED = (
    "In the Azure portal: API Management → Products → your product → Settings → "
    "enable 'Requires subscription'. "
    "ARM template: set subscriptionRequired: true on the product resource."
)
_REMEDIATION_AUTH_POLICY = (
    "Add a <validate-jwt> or <check-header> (Ocp-Apim-Subscription-Key) policy "
    "to the API's inbound policy or to the all-operations policy. "
    "Azure docs: https://learn.microsoft.com/azure/api-management/validate-jwt-policy"
)
_REMEDIATION_MTLS = (
    "Configure the backend to require client certificate authentication by setting "
    "the 'credentials.certificate' property on the Backend resource. "
    "Azure docs: https://learn.microsoft.com/azure/api-management/"
    "api-management-howto-mutual-certificates"
)
_REMEDIATION_CORS = (
    "Replace the wildcard CORS origin ('*') with an explicit list of allowed origins. "
    "Do not combine Access-Control-Allow-Origin: * with allow-credentials: true, "
    "as this is rejected by all modern browsers and indicates a misconfiguration."
)
_REMEDIATION_SUBSCRIPTION_EXPIRY = (
    "Set an expiry date on all active subscriptions or implement a key-rotation policy. "
    "Azure portal: API Management → Subscriptions → your subscription → edit."
)


class AzureAPIMAuditor(CloudGatewayAuditor):
    """
    Read-only auditor for Azure API Management instances.

    Parameters
    ----------
    client:
        ``AzureAPIMClient`` instance providing access to the Azure SDK.
    resource_group:
        Azure resource group that contains the APIM service(s) to audit.
    guard:
        ``CloudReadOnlyGuard`` — defaults to read-only if not supplied.
    account_context:
        Human-readable label for the subscription/resource-group being
        audited.  Defaults to ``"azure:<subscription_id>/<resource_group>"``.
    """

    def __init__(
        self,
        client: AzureAPIMClient,
        resource_group: str,
        guard: CloudReadOnlyGuard | None = None,
        account_context: str | None = None,
    ) -> None:
        self._client = client
        self._resource_group = resource_group
        self._guard = guard or CloudReadOnlyGuard(allow_destructive=False)
        self._account_context = (
            account_context
            or f"azure:{client.subscription_id}/{resource_group}"
        )

    # ------------------------------------------------------------------
    # CloudGatewayAuditor contract
    # ------------------------------------------------------------------

    def get_provider_name(self) -> str:
        return "azure"

    async def discover_resources(self) -> list[dict[str, Any]]:
        """
        Enumerate auditable APIM resources in ``self._resource_group``.

        Lists APIM service instances, products, and APIs for each service.
        """
        resources: list[dict[str, Any]] = []

        self._guard.guard_operation("list_by_resource_group")
        try:
            services = list(
                self._client.client.api_management_service.list_by_resource_group(
                    self._resource_group
                )
            )
        except ImportError:
            logger.warning(
                "azure-mgmt-apimanagement not installed — skipping Azure discovery. "
                "Install it with: pip install apileaks[azure]"
            )
            return resources
        except Exception as exc:
            self._handle_azure_error("list_by_resource_group", exc)
            return resources

        for service in services:
            service_name = service.name
            resources.append(
                {
                    "type": "apim_service",
                    "name": service_name,
                    "location": getattr(service, "location", None),
                    "resource_group": self._resource_group,
                }
            )

            # Products
            self._guard.guard_operation("list_products")
            try:
                for product in self._client.list_products(self._resource_group, service_name):
                    resources.append(
                        {
                            "type": "apim_product",
                            "service": service_name,
                            "name": product.name,
                        }
                    )
            except Exception as exc:
                logger.debug(
                    "Could not list products for service",
                    service=service_name,
                    error=str(exc),
                )

            # APIs
            self._guard.guard_operation("list_apis")
            try:
                for api in self._client.list_apis(self._resource_group, service_name):
                    resources.append(
                        {
                            "type": "apim_api",
                            "service": service_name,
                            "name": api.name,
                        }
                    )
            except Exception as exc:
                logger.debug(
                    "Could not list APIs for service",
                    service=service_name,
                    error=str(exc),
                )

        logger.info(
            "Azure APIM discovery complete",
            subscription=self._client.subscription_id,
            resource_group=self._resource_group,
            resource_count=len(resources),
        )
        return resources

    async def audit(self) -> list[GatewayFinding]:
        """Execute all Azure APIM security checks and return findings."""
        findings: list[GatewayFinding] = []

        self._guard.guard_operation("list_by_resource_group")
        try:
            services = await self._call_with_backoff(
                lambda: list(
                    self._client.client.api_management_service.list_by_resource_group(
                        self._resource_group
                    )
                ),
                operation="list_by_resource_group",
            )
            if services is None:
                services = []
        except ImportError:
            logger.warning(
                "azure-mgmt-apimanagement not installed — skipping Azure audit. "
                "Install it with: pip install apileaks[azure]"
            )
            return findings
        except InsufficientPermissionsError:
            findings.append(
                create_permission_denied_finding(
                    resource_id=(
                        f"/subscriptions/{self._client.subscription_id}"
                        f"/resourceGroups/{self._resource_group}"
                    ),
                    resource_type="apim_service_list",
                    provider="azure",
                    account_context=self._account_context,
                    operation="list_by_resource_group",
                )
            )
            return findings
        except ProviderThrottledError:
            findings.append(
                create_permission_denied_finding(
                    resource_id=(
                        f"/subscriptions/{self._client.subscription_id}"
                        f"/resourceGroups/{self._resource_group}"
                    ),
                    resource_type="apim_service_list",
                    provider="azure",
                    account_context=self._account_context,
                    operation="list_by_resource_group",
                )
            )
            return findings
        except Exception as exc:
            self._handle_azure_error("list_by_resource_group", exc)
            return findings

        for service in services:
            service_name = service.name
            account_ctx = (
                f"{self._client.subscription_id}"
                f"/{self._resource_group}"
                f"/{service_name}"
            )

            # --- Req 6.1: Products without subscriptionRequired ---
            self._guard.guard_operation("list_products")
            try:
                products = await self._call_with_backoff(
                    self._client.list_products,
                    self._resource_group, service_name,
                    operation=f"list_products({service_name})",
                )
                for product in (products or []):
                    f = self._check_product_subscription_required(
                        service_name, product, account_ctx
                    )
                    if f:
                        findings.append(f)
            except (InsufficientPermissionsError, ProviderThrottledError):
                findings.append(
                    create_permission_denied_finding(
                        resource_id=self._build_resource_id(service_name, None, None),
                        resource_type="apim_product_list",
                        provider="azure",
                        account_context=account_ctx,
                        operation=f"list_products({service_name})",
                    )
                )

            # --- Req 6.2 + 6.4: API policies (auth + CORS) ---
            self._guard.guard_operation("list_apis")
            try:
                apis = await self._call_with_backoff(
                    self._client.list_apis,
                    self._resource_group, service_name,
                    operation=f"list_apis({service_name})",
                )
                for api in (apis or []):
                    api_id = api.name

                    self._guard.guard_operation("get_api_policy")
                    policy_xml = self._fetch_api_policy_xml(service_name, api_id)
                    if policy_xml is not None:
                        api_resource_id = self._build_resource_id(
                            service_name, "apis", api_id
                        )

                        f = self._check_api_validate_jwt(
                            service_name, api, policy_xml, account_ctx
                        )
                        if f:
                            findings.append(f)

                        f = self._check_cors_wildcard_credentials(
                            service_name, api_resource_id, policy_xml, account_ctx
                        )
                        if f:
                            findings.append(f)
                    else:
                        # No policy at all → definitely no auth policy
                        api_resource_id = self._build_resource_id(
                            service_name, "apis", api_id
                        )
                        findings.append(
                            GatewayFinding(
                                provider="azure",
                                resource_id=api_resource_id,
                                resource_type="apim_api",
                                check_id="azure_apim_api_no_auth_policy",
                                title="Azure APIM API has no authentication/validation policy",
                                severity=GatewaySeverity.HIGH,
                                evidence={
                                    "service": service_name,
                                    "api_id": api_id,
                                    "api_name": getattr(api, "display_name", api_id),
                                    "policy_snippet": None,
                                },
                                remediation=_REMEDIATION_AUTH_POLICY,
                                account_context=account_ctx,
                            )
                        )
            except (InsufficientPermissionsError, ProviderThrottledError):
                findings.append(
                    create_permission_denied_finding(
                        resource_id=self._build_resource_id(service_name, None, None),
                        resource_type="apim_api_list",
                        provider="azure",
                        account_context=account_ctx,
                        operation=f"list_apis({service_name})",
                    )
                )
            except Exception as exc:
                self._handle_azure_error(f"list_apis({service_name})", exc)

            # --- Req 6.4 (service-level): CORS in service-level policy ---
            self._guard.guard_operation("get_service_policy")
            try:
                svc_policy_xml = self._fetch_service_policy_xml(service_name)
                if svc_policy_xml:
                    svc_resource_id = self._build_resource_id(service_name, None, None)
                    f = self._check_cors_wildcard_credentials(
                        service_name, svc_resource_id, svc_policy_xml, account_ctx
                    )
                    if f:
                        # tag it as service-level CORS finding
                        f.resource_type = "apim_service"
                        f.check_id = "azure_apim_service_cors_wildcard_with_credentials"
                        findings.append(f)
            except Exception as exc:
                logger.debug(
                    "Could not fetch service-level policy",
                    service=service_name,
                    error=str(exc),
                )

            # --- Req 6.3: Backends without mTLS ---
            self._guard.guard_operation("list_backends")
            try:
                backends = await self._call_with_backoff(
                    self._client.list_backends,
                    self._resource_group, service_name,
                    operation=f"list_backends({service_name})",
                )
                for backend in (backends or []):
                    f = self._check_backend_mtls(service_name, backend, account_ctx)
                    if f:
                        findings.append(f)
            except (InsufficientPermissionsError, ProviderThrottledError):
                findings.append(
                    create_permission_denied_finding(
                        resource_id=self._build_resource_id(service_name, None, None),
                        resource_type="apim_backend_list",
                        provider="azure",
                        account_context=account_ctx,
                        operation=f"list_backends({service_name})",
                    )
                )
            except Exception as exc:
                self._handle_azure_error(f"list_backends({service_name})", exc)

            # --- Req 6.5: Subscriptions without expiry ---
            self._guard.guard_operation("list_subscriptions")
            try:
                subscriptions = await self._call_with_backoff(
                    self._client.list_subscriptions,
                    self._resource_group, service_name,
                    operation=f"list_subscriptions({service_name})",
                )
                for sub in (subscriptions or []):
                    f = self._check_subscription_expiration(
                        service_name, sub, account_ctx
                    )
                    if f:
                        findings.append(f)
            except (InsufficientPermissionsError, ProviderThrottledError):
                findings.append(
                    create_permission_denied_finding(
                        resource_id=self._build_resource_id(service_name, None, None),
                        resource_type="apim_subscription_list",
                        provider="azure",
                        account_context=account_ctx,
                        operation=f"list_subscriptions({service_name})",
                    )
                )
            except Exception as exc:
                self._handle_azure_error(f"list_subscriptions({service_name})", exc)

        logger.info(
            "Azure APIM audit complete",
            subscription=self._client.subscription_id,
            resource_group=self._resource_group,
            finding_count=len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Check 6.1 — Products without subscriptionRequired
    # ------------------------------------------------------------------

    def _check_product_subscription_required(
        self,
        service_name: str,
        product: Any,
        account_ctx: str,
    ) -> GatewayFinding | None:
        """
        Return a HIGH finding when a product has ``subscriptionRequired = False``.

        Requirement 6.1.
        """
        subscription_required = getattr(product, "subscription_required", True)
        if subscription_required is False:
            resource_id = self._build_resource_id(service_name, "products", product.name)
            return GatewayFinding(
                provider="azure",
                resource_id=resource_id,
                resource_type="apim_product",
                check_id="azure_apim_product_no_subscription_required",
                title=(
                    "Azure APIM product exposes APIs without requiring a subscription"
                ),
                severity=GatewaySeverity.HIGH,
                evidence={
                    "service": service_name,
                    "product": product.name,
                    "subscription_required": False,
                },
                remediation=_REMEDIATION_SUBSCRIPTION_REQUIRED,
                account_context=account_ctx,
            )
        return None

    # ------------------------------------------------------------------
    # Check 6.2 — APIs without validate-jwt / API-key policy
    # ------------------------------------------------------------------

    def _check_api_validate_jwt(
        self,
        service_name: str,
        api: Any,
        policy_xml: str,
        account_ctx: str,
    ) -> GatewayFinding | None:
        """
        Return a HIGH finding when an API's policy has no ``<validate-jwt>``,
        ``<check-header>`` (Subscription-Key), or ``<authentication-*>`` element.

        Requirement 6.2.
        """
        root = self._parse_policy_xml(policy_xml)
        if root is None:
            # Unparseable XML — treat as no-policy
            has_auth = False
        else:
            inbound = root.find("inbound")
            search_root = inbound if inbound is not None else root

            has_validate_jwt = search_root.find(".//validate-jwt") is not None
            has_check_header = search_root.find(".//check-header") is not None
            # azure authentication policies: e.g. <authentication-basic>, <authentication-certificate>
            has_auth_policy = any(
                elem.tag.startswith("authentication-")
                for elem in search_root.iter()
            )
            has_auth = has_validate_jwt or has_check_header or has_auth_policy

        if not has_auth:
            api_id = api.name
            resource_id = self._build_resource_id(service_name, "apis", api_id)
            return GatewayFinding(
                provider="azure",
                resource_id=resource_id,
                resource_type="apim_api",
                check_id="azure_apim_api_no_auth_policy",
                title="Azure APIM API has no authentication/validation policy",
                severity=GatewaySeverity.HIGH,
                evidence={
                    "service": service_name,
                    "api_id": api_id,
                    "api_name": getattr(api, "display_name", api_id),
                    "policy_snippet": policy_xml[:300] if policy_xml else None,
                },
                remediation=_REMEDIATION_AUTH_POLICY,
                account_context=account_ctx,
            )
        return None

    # ------------------------------------------------------------------
    # Check 6.3 — Backends without mTLS
    # ------------------------------------------------------------------

    def _check_backend_mtls(
        self,
        service_name: str,
        backend: Any,
        account_ctx: str,
    ) -> GatewayFinding | None:
        """
        Return an INFO finding when a backend uses TLS (HTTPS URL) but does
        not declare a client certificate (mTLS).

        Requirement 6.3.
        """
        url: str = getattr(backend, "url", "") or ""
        uses_tls = url.startswith("https://")
        if not uses_tls:
            return None

        credentials = getattr(backend, "credentials", None)
        cert_thumbprints: list[Any] = []
        if credentials is not None:
            cert_thumbprints = getattr(credentials, "certificate", None) or []

        if not cert_thumbprints:
            resource_id = self._build_resource_id(
                service_name, "backends", backend.name
            )
            return GatewayFinding(
                provider="azure",
                resource_id=resource_id,
                resource_type="apim_backend",
                check_id="azure_apim_backend_no_mtls",
                title="Azure APIM backend uses TLS but has no client certificate (mTLS) configured",
                severity=GatewaySeverity.INFO,
                evidence={
                    "service": service_name,
                    "backend": backend.name,
                    "url": url,
                    "client_certificate_configured": False,
                },
                remediation=_REMEDIATION_MTLS,
                account_context=account_ctx,
            )
        return None

    # ------------------------------------------------------------------
    # Check 6.4 — CORS wildcard origin + credentials
    # ------------------------------------------------------------------

    def _check_cors_wildcard_credentials(
        self,
        service_name: str,
        resource_id: str,
        policy_xml: str,
        account_ctx: str,
    ) -> GatewayFinding | None:
        """
        Return a HIGH finding when the policy XML contains a ``<cors>`` element
        with a wildcard origin (``*``) **and** ``allow-credentials="true"``.

        Requirement 6.4.
        """
        root = self._parse_policy_xml(policy_xml)
        if root is None:
            return None

        for cors_elem in root.iter("cors"):
            allow_credentials_attr = cors_elem.get("allow-credentials", "false").lower()
            has_credentials = allow_credentials_attr == "true"
            if not has_credentials:
                continue

            # Look for a wildcard origin inside <allowed-origins>
            allowed_origins_elem = cors_elem.find("allowed-origins")
            if allowed_origins_elem is None:
                continue

            origins = [
                (o.text or "").strip()
                for o in allowed_origins_elem.findall("origin")
            ]
            if "*" in origins:
                return GatewayFinding(
                    provider="azure",
                    resource_id=resource_id,
                    resource_type="apim_api",
                    check_id="azure_apim_cors_wildcard_with_credentials",
                    title=(
                        "Azure APIM CORS policy allows wildcard origin "
                        "with credentials enabled"
                    ),
                    severity=GatewaySeverity.HIGH,
                    evidence={
                        "service": service_name,
                        "allow_credentials": True,
                        "allowed_origins": origins,
                    },
                    remediation=_REMEDIATION_CORS,
                    account_context=account_ctx,
                )
        return None

    # ------------------------------------------------------------------
    # Check 6.5 — Active subscriptions without expiry date
    # ------------------------------------------------------------------

    def _check_subscription_expiration(
        self,
        service_name: str,
        subscription: Any,
        account_ctx: str,
    ) -> GatewayFinding | None:
        """
        Return a LOW finding when an active subscription has no expiry date.

        Requirement 6.5.
        """
        state = str(getattr(subscription, "state", "")).lower()
        expiry = getattr(subscription, "expiration_date", None)

        if state == "active" and not expiry:
            resource_id = self._build_resource_id(
                service_name, "subscriptions", subscription.name
            )
            return GatewayFinding(
                provider="azure",
                resource_id=resource_id,
                resource_type="apim_subscription",
                check_id="azure_apim_subscription_no_expiry",
                title=(
                    "Azure APIM subscription is active with no expiration date"
                ),
                severity=GatewaySeverity.LOW,
                evidence={
                    "service": service_name,
                    "subscription_name": subscription.name,
                    "state": state,
                    "expiration_date": None,
                },
                remediation=_REMEDIATION_SUBSCRIPTION_EXPIRY,
                account_context=account_ctx,
            )
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_api_policy_xml(
        self, service_name: str, api_id: str
    ) -> str | None:
        """
        Fetch the policy XML for a specific API.

        Returns the XML string, an empty string when the policy exists but is
        blank, or ``None`` when no policy is configured.
        """
        try:
            policy_resp = self._client.get_api_policy(
                self._resource_group, service_name, api_id
            )
            if policy_resp is None:
                return None
            return getattr(policy_resp, "value", None) or ""
        except Exception as exc:
            logger.debug(
                "Could not fetch API policy",
                service=service_name,
                api_id=api_id,
                error=str(exc),
            )
            return None

    def _fetch_service_policy_xml(self, service_name: str) -> str | None:
        """
        Fetch the service-level (global) policy XML.

        Returns ``None`` when no service-level policy is configured.
        """
        try:
            policy_resp = self._client.get_service_policy(
                self._resource_group, service_name
            )
            if policy_resp is None:
                return None
            return getattr(policy_resp, "value", None) or ""
        except Exception as exc:
            logger.debug(
                "Could not fetch service-level policy",
                service=service_name,
                error=str(exc),
            )
            return None

    def _parse_policy_xml(self, policy_xml: str) -> ET.Element | None:
        """
        Parse a policy XML string and return the root ``Element``.

        Returns ``None`` when the XML is empty or malformed.
        """
        if not policy_xml or not policy_xml.strip():
            return None
        try:
            return ET.fromstring(policy_xml)
        except ET.ParseError as exc:
            logger.debug("Failed to parse policy XML", error=str(exc))
            return None

    def _build_resource_id(
        self,
        service_name: str,
        resource_type: str | None,
        resource_name: str | None,
    ) -> str:
        """
        Build a full Azure resource path for a finding's ``resource_id``.

        Examples
        --------
        Service: ``/subscriptions/<sub>/resourceGroups/<rg>/providers/
                    Microsoft.ApiManagement/service/<svc>``
        Product: ``…/products/<product>``
        """
        base = (
            f"/subscriptions/{self._client.subscription_id}"
            f"/resourceGroups/{self._resource_group}"
            f"/providers/Microsoft.ApiManagement/service/{service_name}"
        )
        if resource_type and resource_name:
            return f"{base}/{resource_type}/{resource_name}"
        return base

    def _handle_azure_error(self, operation: str, exc: Exception) -> None:
        """
        Translate Azure SDK exceptions to structured log entries or re-raise
        as ``InsufficientPermissionsError`` for permission-related failures or
        ``ProviderThrottledError`` for rate-limit failures.
        """
        exc_type = type(exc).__name__
        error_str = str(exc).lower()

        is_throttled = (
            exc_type in ("TooManyRequestsError", "HttpResponseError")
            and ("429" in error_str or "too many requests" in error_str or "throttl" in error_str)
        ) or "429" in error_str or "throttl" in error_str or "too many requests" in error_str

        is_permission_denied = (
            "authorization" in error_str
            or "forbidden" in error_str
            or "403" in error_str
            or "authorizationfailed" in error_str
        )

        if is_throttled:
            logger.warning(
                "Azure operation throttled — will retry with backoff",
                operation=operation,
                error=str(exc),
                subscription=self._client.subscription_id,
            )
            raise ProviderThrottledError(str(exc)) from exc

        if is_permission_denied:
            logger.warning(
                "Insufficient Azure permissions",
                operation=operation,
                error=str(exc),
                subscription=self._client.subscription_id,
            )
            raise InsufficientPermissionsError(str(exc)) from exc

        logger.warning(
            "Azure operation failed (non-fatal)",
            operation=operation,
            error=str(exc),
            subscription=self._client.subscription_id,
        )

    async def _call_with_backoff(
        self,
        fn: Any,
        *args: Any,
        operation: str,
        **kwargs: Any,
    ) -> Any:
        """
        Call *fn* with exponential backoff on :class:`ProviderThrottledError`.

        Converts Azure SDK exceptions to the appropriate
        :class:`InsufficientPermissionsError` or :class:`ProviderThrottledError`
        before retrying.

        Parameters
        ----------
        fn:        Sync callable.
        operation: Human-readable name used in log messages.
        """

        def _call() -> Any:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                self._handle_azure_error(operation, exc)
                return None  # only reached for non-fatal (logged) errors

        return await with_exponential_backoff(_call, retry_on=ProviderThrottledError)
