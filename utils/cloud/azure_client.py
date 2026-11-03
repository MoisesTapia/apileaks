"""
Azure API Management Client

Thin wrapper over ``azure-mgmt-apimanagement`` that resolves credentials via
``DefaultAzureCredential`` (env vars → managed identity → Azure CLI) or an
explicit service principal, then constructs the ``ApiManagementClient`` used
by ``AzureAPIMAuditor``.

Both ``azure-mgmt-apimanagement`` and ``azure-identity`` are optional extras.
This module degrades gracefully when they are absent — accessing any property
or method that requires them raises ``CredentialResolutionError`` with a clear
install hint instead of an ``ImportError`` at module-import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.logging import get_logger
from modules.cloud.base import CredentialResolutionError

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class AzureAPIMClient:
    """
    Manages the Azure SDK clients needed for the APIM auditor.

    Credentials are resolved lazily on first access following the same
    pattern as ``AWSGatewayClient`` and ``GCPGatewayClient`` — the
    constructor never performs a network call, so import-time failures
    due to a missing SDK are surfaced only when the caller actually uses
    the client.

    Parameters
    ----------
    subscription_id:
        Azure subscription ID to audit.
    tenant_id:
        Azure AD tenant ID for an explicit service principal (optional).
    client_id:
        Service principal application / client ID (optional).
    client_secret:
        Service principal client secret (optional).

    Credential resolution order
    ---------------------------
    * When *all three* of ``tenant_id``, ``client_id``, and
      ``client_secret`` are provided → ``ClientSecretCredential``.
    * Otherwise → ``DefaultAzureCredential`` (env vars, workload
      identity, managed identity, Azure CLI, etc.).
    """

    def __init__(
        self,
        subscription_id: str,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        self._subscription_id = subscription_id
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._cached_credential: Any | None = None
        self._apim_client: Any | None = None
        self._authz_client: Any | None = None

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    def _resolve_credential(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> Any:
        """
        Return an ``azure-identity`` credential object.

        Uses the parameters passed to this call first, then falls back to
        those set at construction time.

        Raises
        ------
        CredentialResolutionError
            When ``azure-identity`` is not installed, or when the explicit
            service principal values are incomplete.
        """
        effective_tenant = tenant_id or self._tenant_id
        effective_client = client_id or self._client_id
        effective_secret = client_secret or self._client_secret

        try:
            import azure.identity  # noqa: F401 — presence check
        except ImportError as exc:
            raise CredentialResolutionError(
                "azure-identity is not installed. "
                "Install it with: pip install apileaks[azure]"
            ) from exc

        if effective_tenant and effective_client and effective_secret:
            # Explicit service principal
            try:
                from azure.identity import ClientSecretCredential  # type: ignore[import]

                cred = ClientSecretCredential(
                    tenant_id=effective_tenant,
                    client_id=effective_client,
                    client_secret=effective_secret,
                )
                logger.info(
                    "Azure credentials resolved via ClientSecretCredential (service principal)",
                    tenant_id=effective_tenant,
                    client_id=effective_client,
                    subscription_id=self._subscription_id,
                )
                return cred
            except Exception as exc:
                raise CredentialResolutionError(
                    f"Failed to create Azure ClientSecretCredential: {exc}"
                ) from exc

        # Fall back to DefaultAzureCredential
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import]

            default_cred = DefaultAzureCredential()
            logger.info(
                "Azure credentials resolved via DefaultAzureCredential",
                subscription_id=self._subscription_id,
            )
            return default_cred
        except Exception as exc:
            raise CredentialResolutionError(
                f"Failed to create Azure DefaultAzureCredential: {exc}"
            ) from exc

    def _get_credential(self) -> Any:
        """Return (and cache) the resolved Azure credential."""
        if self._cached_credential is None:
            self._cached_credential = self._resolve_credential()
        return self._cached_credential

    # ------------------------------------------------------------------
    # SDK client access
    # ------------------------------------------------------------------

    @property
    def client(self) -> Any:
        """
        ``azure.mgmt.apimanagement.ApiManagementClient`` instance.

        Lazily initialised and cached on first access.
        """
        if self._apim_client is not None:
            return self._apim_client
        try:
            from azure.mgmt.apimanagement import ApiManagementClient  # type: ignore[import]
        except ImportError as exc:
            raise CredentialResolutionError(
                "azure-mgmt-apimanagement is not installed. "
                "Install it with: pip install apileaks[azure]"
            ) from exc
        cred = self._get_credential()
        self._apim_client = ApiManagementClient(cred, self._subscription_id)
        logger.info(
            "Azure ApiManagementClient initialised",
            subscription_id=self._subscription_id,
        )
        return self._apim_client

    @property
    def authz_client(self) -> Any:
        """
        ``azure.mgmt.authorization.AuthorizationManagementClient`` instance.

        Used to read IAM role assignments (Requirement 2.6).
        Lazily initialised and cached.
        """
        if self._authz_client is not None:
            return self._authz_client
        try:
            from azure.mgmt.authorization import (
                AuthorizationManagementClient,  # type: ignore[import]
            )
        except ImportError as exc:
            raise CredentialResolutionError(
                "azure-mgmt-authorization is not installed. "
                "Install it with: pip install apileaks[azure]"
            ) from exc
        cred = self._get_credential()
        self._authz_client = AuthorizationManagementClient(cred, self._subscription_id)
        return self._authz_client

    # ------------------------------------------------------------------
    # APIM service discovery
    # ------------------------------------------------------------------

    def list_services(self) -> list[Any]:
        """
        Return all APIM service instances in the subscription.

        Wraps ``ApiManagementClient.api_management_service.list()``.
        """
        return list(self.client.api_management_service.list())

    def get_service(self, resource_group: str, service_name: str) -> Any:
        """
        Return a single APIM service instance.

        Parameters
        ----------
        resource_group:
            Azure resource group name.
        service_name:
            APIM service name.
        """
        return self.client.api_management_service.get(resource_group, service_name)

    # ------------------------------------------------------------------
    # Products
    # ------------------------------------------------------------------

    def list_products(self, resource_group: str, service_name: str) -> list[Any]:
        """
        Return all products defined in an APIM service.

        Wraps ``ApiManagementClient.product.list_by_service()``.
        """
        return list(
            self.client.product.list_by_service(resource_group, service_name)
        )

    # ------------------------------------------------------------------
    # APIs
    # ------------------------------------------------------------------

    def list_apis(self, resource_group: str, service_name: str) -> list[Any]:
        """
        Return all APIs registered in an APIM service.

        Wraps ``ApiManagementClient.api.list_by_service()``.
        """
        return list(self.client.api.list_by_service(resource_group, service_name))

    # ------------------------------------------------------------------
    # API policies
    # ------------------------------------------------------------------

    def get_api_policy(
        self,
        resource_group: str,
        service_name: str,
        api_id: str,
        policy_id: str = "policy",
    ) -> Any | None:
        """
        Return the effective policy document for a specific API.

        Returns ``None`` when no policy is configured for the API.

        Parameters
        ----------
        resource_group:
            Azure resource group name.
        service_name:
            APIM service name.
        api_id:
            API identifier (short ID, not the full resource path).
        policy_id:
            Policy entity identifier, defaults to ``"policy"`` (the only
            valid value in the current Azure APIM API version).
        """
        try:
            return self.client.api_policy.get(
                resource_group, service_name, api_id, policy_id
            )
        except Exception as exc:  # noqa: BLE001
            # A 404-equivalent means no policy is set for this API.
            logger.debug(
                "No policy found for APIM API",
                resource_group=resource_group,
                service_name=service_name,
                api_id=api_id,
                error=str(exc),
            )
            return None

    def get_service_policy(
        self,
        resource_group: str,
        service_name: str,
        policy_id: str = "policy",
    ) -> Any | None:
        """
        Return the service-level (global) policy document.

        Service-level policies include CORS and other cross-cutting
        configurations.  Returns ``None`` when no policy is set.
        """
        try:
            return self.client.policy.get(resource_group, service_name, policy_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "No service-level policy found for APIM service",
                resource_group=resource_group,
                service_name=service_name,
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------
    # Backends
    # ------------------------------------------------------------------

    def list_backends(self, resource_group: str, service_name: str) -> list[Any]:
        """
        Return all backends configured in an APIM service.

        Wraps ``ApiManagementClient.backend.list_by_service()``.
        """
        return list(
            self.client.backend.list_by_service(resource_group, service_name)
        )

    # ------------------------------------------------------------------
    # CORS configuration
    # ------------------------------------------------------------------

    def get_cors_config(self, resource_group: str, service_name: str) -> Any | None:
        """
        Return the named-value or policy fragment containing CORS settings.

        CORS in APIM is controlled via inbound policies (``<cors>`` element)
        at the service or API level.  This method returns the service-level
        policy document — call ``get_api_policy`` for per-API CORS checks.

        Returns ``None`` when no service-level policy exists.
        """
        return self.get_service_policy(resource_group, service_name)

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def list_subscriptions(self, resource_group: str, service_name: str) -> list[Any]:
        """
        Return all APIM subscriptions in a service.

        Wraps ``ApiManagementClient.subscription.list()``.
        """
        return list(
            self.client.subscription.list(resource_group, service_name)
        )

    # ------------------------------------------------------------------
    # IAM bindings (role assignments)
    # ------------------------------------------------------------------

    def list_iam_bindings(self, resource_group: str, service_name: str) -> list[Any]:
        """
        Return Azure role assignments scoped to a specific APIM service.

        Uses ``AuthorizationManagementClient.role_assignments.list_for_resource()``.
        The ``authz_client`` requires ``azure-mgmt-authorization`` to be
        installed (included in the ``[azure]`` extra).

        Parameters
        ----------
        resource_group:
            Azure resource group name.
        service_name:
            APIM service name.
        """
        resource_scope = (
            f"/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.ApiManagement/service/{service_name}"
        )
        return list(
            self.authz_client.role_assignments.list_for_scope(resource_scope)
        )

    # ------------------------------------------------------------------
    # Read-only helper properties
    # ------------------------------------------------------------------

    @property
    def subscription_id(self) -> str:
        """The Azure subscription ID this client is scoped to."""
        return self._subscription_id
