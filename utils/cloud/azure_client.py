"""
Azure API Management Client

Thin wrapper over the Azure SDK (azure-mgmt-apimanagement + azure-identity)
that resolves credentials via DefaultAzureCredential (env vars, managed identity,
Azure CLI login) or an explicit service principal.
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
    Manages the Azure API Management SDK client.

    Parameters
    ----------
    subscription_id:  Azure subscription ID to audit.
    tenant_id:        Tenant ID for service-principal auth (optional).
    client_id:        Client ID for service-principal auth (optional).
    client_secret:    Client secret for service-principal auth (optional).
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
        self._apim_client: Any | None = None

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    def _resolve_credential(self) -> Any:
        try:
            from azure.identity import (  # type: ignore[import]
                ClientSecretCredential,
                DefaultAzureCredential,
            )
        except ImportError as exc:
            raise CredentialResolutionError(
                "azure-identity is not installed. Install it with: pip install apileaks[azure]"
            ) from exc

        if self._tenant_id and self._client_id and self._client_secret:
            logger.info("Using Azure service principal credentials")
            return ClientSecretCredential(
                tenant_id=self._tenant_id,
                client_id=self._client_id,
                client_secret=self._client_secret,
            )

        logger.info("Using Azure DefaultAzureCredential")
        return DefaultAzureCredential()

    # ------------------------------------------------------------------
    # APIM client
    # ------------------------------------------------------------------

    @property
    def apim(self) -> Any:
        """azure.mgmt.apimanagement.ApiManagementClient."""
        if self._apim_client is not None:
            return self._apim_client
        try:
            from azure.mgmt.apimanagement import ApiManagementClient  # type: ignore[import]
        except ImportError as exc:
            raise CredentialResolutionError(
                "azure-mgmt-apimanagement is not installed. "
                "Install it with: pip install apileaks[azure]"
            ) from exc
        credential = self._resolve_credential()
        self._apim_client = ApiManagementClient(credential, self._subscription_id)
        return self._apim_client

    @property
    def subscription_id(self) -> str:
        return self._subscription_id
