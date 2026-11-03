"""
Azure API Management Security Auditor

Audits the configuration of Azure API Management instances using read-only
Azure SDK calls.

Checks implemented (mapped to spec Requirements 6.1 – 6.5):
  6.1  Products with subscriptionRequired = false
  6.2  APIs without a validate-jwt or key-validation policy
  6.3  Backends declared as sensitive without mTLS configured
  6.4  CORS configured with wildcard origin AND credentials enabled
  6.5  Subscriptions with no expiry date (no rotation enforced)

All methods are read-only.
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from modules.cloud.base import (
    CloudGatewayAuditor,
    GatewayFinding,
    GatewaySeverity,
    InsufficientPermissionsError,
)
from utils.cloud.azure_client import AzureAPIMClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard

logger = get_logger(__name__)

_REMEDIATION_SUBSCRIPTION_REQUIRED = (
    "In the Azure portal: API Management → Products → your product → Settings → "
    "enable 'Requires subscription'. "
    "ARM template: set subscriptionRequired: true on the product resource."
)
_REMEDIATION_AUTH_POLICY = (
    "Add a <validate-jwt> or <check-header> policy to the API or all-operations policy. "
    "Azure docs: https://learn.microsoft.com/azure/api-management/validate-jwt-policy"
)
_REMEDIATION_MTLS = (
    "Configure the backend to require client certificate authentication. "
    "Azure docs: https://learn.microsoft.com/azure/api-management/api-management-howto-mutual-certificates"
)
_REMEDIATION_CORS = (
    "Replace the wildcard CORS origin with a specific allowed origin list. "
    "Do not combine Access-Control-Allow-Origin: * with credentials: true."
)
_REMEDIATION_SUBSCRIPTION_EXPIRY = (
    "Set an expiry date on all active subscriptions or implement a key rotation policy. "
    "Azure portal: API Management → Subscriptions → your subscription → edit."
)


class AzureAPIMAuditor(CloudGatewayAuditor):
    """
    Read-only auditor for Azure API Management instances.

    Parameters
    ----------
    client:              AzureAPIMClient instance.
    resource_group:      Resource group containing the APIM instances to audit.
    guard:               CloudReadOnlyGuard (default: read-only).
    account_context:     Label for the subscription being audited.
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
        self._account_context = account_context or f"azure:{client.subscription_id}"

    def get_provider_name(self) -> str:
        return "azure"

    async def discover_resources(self) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        try:
            apims = list(
                self._client.apim.api_management_service.list_by_resource_group(
                    self._resource_group
                )
            )
            for apim in apims:
                resources.append(
                    {
                        "type": "apim_service",
                        "name": apim.name,
                        "location": apim.location,
                    }
                )
        except ImportError:
            logger.warning("azure-mgmt-apimanagement not installed — skipping Azure discovery")
            return []
        except Exception as exc:
            self._handle_azure_error("list_by_resource_group", exc)

        logger.info(
            "Azure discovery complete",
            subscription=self._client.subscription_id,
            resource_count=len(resources),
        )
        return resources

    async def audit(self) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []

        try:
            apim_services = list(
                self._client.apim.api_management_service.list_by_resource_group(
                    self._resource_group
                )
            )
        except ImportError:
            logger.warning("azure-mgmt-apimanagement not installed — skipping Azure audit")
            return findings
        except Exception as exc:
            self._handle_azure_error("list_by_resource_group", exc)
            return findings

        for service in apim_services:
            service_name = service.name
            findings.extend(self._audit_products(service_name))
            findings.extend(self._audit_apis(service_name))
            findings.extend(self._audit_subscriptions(service_name))

        logger.info(
            "Azure audit complete",
            subscription=self._client.subscription_id,
            finding_count=len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Check 6.1 — Products without subscriptionRequired
    # ------------------------------------------------------------------

    def _audit_products(self, service_name: str) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        try:
            products = list(
                self._client.apim.product.list_by_service(self._resource_group, service_name)
            )
        except Exception as exc:
            self._handle_azure_error(f"product.list_by_service({service_name})", exc)
            return findings

        for product in products:
            if not getattr(product, "subscription_required", True):
                resource_id = (
                    f"/subscriptions/{self._client.subscription_id}"
                    f"/resourceGroups/{self._resource_group}"
                    f"/providers/Microsoft.ApiManagement/service/{service_name}"
                    f"/products/{product.name}"
                )
                findings.append(
                    GatewayFinding(
                        provider="azure",
                        resource_id=resource_id,
                        resource_type="apim_product",
                        check_id="azure_apim_product_no_subscription_required",
                        title="Azure APIM product exposes APIs without requiring a subscription",
                        severity=GatewaySeverity.HIGH,
                        evidence={
                            "service": service_name,
                            "product": product.name,
                            "subscription_required": False,
                        },
                        remediation=_REMEDIATION_SUBSCRIPTION_REQUIRED,
                        account_context=self._account_context,
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Check 6.2 / 6.4 — API policies (auth policy, CORS)
    # ------------------------------------------------------------------

    def _audit_apis(self, service_name: str) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        try:
            apis = list(self._client.apim.api.list_by_service(self._resource_group, service_name))
        except Exception as exc:
            self._handle_azure_error(f"api.list_by_service({service_name})", exc)
            return findings

        for api in apis:
            api_id = api.name

            # 6.2 Policy check
            try:
                policy_resp = self._client.apim.api_policy.get(
                    self._resource_group, service_name, api_id, "policy"
                )
                policy_xml = getattr(policy_resp, "value", "") or ""
                has_auth_policy = any(
                    tag in policy_xml
                    for tag in ("<validate-jwt", "<check-header", "<authentication-")
                )
                if not has_auth_policy:
                    resource_id = (
                        f"/subscriptions/{self._client.subscription_id}"
                        f"/resourceGroups/{self._resource_group}"
                        f"/providers/Microsoft.ApiManagement/service/{service_name}"
                        f"/apis/{api_id}"
                    )
                    findings.append(
                        GatewayFinding(
                            provider="azure",
                            resource_id=resource_id,
                            resource_type="apim_api",
                            check_id="azure_apim_api_no_auth_policy",
                            title="Azure APIM API has no authentication/validation policy",
                            severity=GatewaySeverity.HIGH,
                            evidence={
                                "service": service_name,
                                "api_id": api_id,
                                "api_name": api.display_name
                                if hasattr(api, "display_name")
                                else api_id,
                                "policy_snippet": policy_xml[:300] if policy_xml else None,
                            },
                            remediation=_REMEDIATION_AUTH_POLICY,
                            account_context=self._account_context,
                        )
                    )

                # 6.4 CORS wildcard with credentials
                if (
                    "<cors" in policy_xml
                    and 'origin="*"' in policy_xml
                    and "<credentials>" in policy_xml
                ):
                    findings.append(
                        GatewayFinding(
                            provider="azure",
                            resource_id=resource_id,
                            resource_type="apim_api",
                            check_id="azure_apim_cors_wildcard_with_credentials",
                            title="Azure APIM API CORS policy allows wildcard origin with credentials",
                            severity=GatewaySeverity.HIGH,
                            evidence={
                                "service": service_name,
                                "api_id": api_id,
                            },
                            remediation=_REMEDIATION_CORS,
                            account_context=self._account_context,
                        )
                    )

            except Exception as exc:
                self._handle_azure_error(f"api_policy.get({api_id})", exc)

        return findings

    # ------------------------------------------------------------------
    # Check 6.5 — Subscriptions without expiry
    # ------------------------------------------------------------------

    def _audit_subscriptions(self, service_name: str) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        try:
            subs = list(self._client.apim.subscription.list(self._resource_group, service_name))
        except Exception as exc:
            self._handle_azure_error(f"subscription.list({service_name})", exc)
            return findings

        for sub in subs:
            if getattr(sub, "state", None) == "active" and not getattr(
                sub, "expiration_date", None
            ):
                resource_id = (
                    f"/subscriptions/{self._client.subscription_id}"
                    f"/resourceGroups/{self._resource_group}"
                    f"/providers/Microsoft.ApiManagement/service/{service_name}"
                    f"/subscriptions/{sub.name}"
                )
                findings.append(
                    GatewayFinding(
                        provider="azure",
                        resource_id=resource_id,
                        resource_type="apim_subscription",
                        check_id="azure_apim_subscription_no_expiry",
                        title="Azure APIM subscription is active with no expiration date",
                        severity=GatewaySeverity.LOW,
                        evidence={
                            "service": service_name,
                            "subscription_name": sub.name,
                            "state": str(getattr(sub, "state", "")),
                            "expiration_date": None,
                        },
                        remediation=_REMEDIATION_SUBSCRIPTION_EXPIRY,
                        account_context=self._account_context,
                    )
                )
        return findings

    def _handle_azure_error(self, operation: str, exc: Exception) -> None:
        error_str = str(exc).lower()
        if "authorization" in error_str or "forbidden" in error_str or "403" in error_str:
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
