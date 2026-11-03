"""
GCP API Gateway Client

Thin wrapper that resolves credentials via Application Default Credentials
(ADC) or an explicit service account key file, then builds the client for
google-cloud-api-gateway.

The SDK (google-cloud-api-gateway) is an optional extra dependency.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.logging import get_logger
from modules.cloud.base import CredentialResolutionError

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class GCPGatewayClient:
    """
    Manages the Google Cloud API Gateway service client.

    Parameters
    ----------
    project_id:            GCP project ID to audit.
    service_account_file:  Path to a service account JSON key file (optional;
                           falls back to ADC when not supplied).
    location:              GCP location/region (defaults to "global").
    """

    def __init__(
        self,
        project_id: str,
        service_account_file: str | None = None,
        location: str = "global",
    ) -> None:
        self._project_id = project_id
        self._service_account_file = service_account_file
        self._location = location
        self._gateway_client: Any | None = None
        self._iam_client: Any | None = None

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    def _resolve_credentials(self) -> Any:
        """Return a google.oauth2 credentials object."""
        if self._service_account_file:
            try:
                from google.oauth2 import service_account  # type: ignore[import]

                creds = service_account.Credentials.from_service_account_file(
                    self._service_account_file,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                return creds
            except Exception as exc:
                raise CredentialResolutionError(
                    f"Failed to load GCP service account key: {exc}"
                ) from exc
        # Fall back to ADC
        try:
            import google.auth  # type: ignore[import]

            creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            return creds
        except Exception as exc:
            raise CredentialResolutionError(
                f"Failed to resolve GCP Application Default Credentials: {exc}. "
                "Run `gcloud auth application-default login` or set "
                "GOOGLE_APPLICATION_CREDENTIALS."
            ) from exc

    # ------------------------------------------------------------------
    # Clients
    # ------------------------------------------------------------------

    @property
    def gateway(self) -> Any:
        """google.cloud.apigateway_v1.ApiGatewayServiceClient."""
        if self._gateway_client is not None:
            return self._gateway_client
        try:
            from google.cloud import apigateway_v1  # type: ignore[import]
        except ImportError as exc:
            raise CredentialResolutionError(
                "google-cloud-api-gateway is not installed. "
                "Install it with: pip install apileaks[gcp]"
            ) from exc
        creds = self._resolve_credentials()
        self._gateway_client = apigateway_v1.ApiGatewayServiceClient(credentials=creds)
        return self._gateway_client

    @property
    def iam(self) -> Any:
        """googleapiclient.discovery resource for Cloud IAM."""
        if self._iam_client is not None:
            return self._iam_client
        try:
            from googleapiclient import discovery  # type: ignore[import]

            creds = self._resolve_credentials()
            self._iam_client = discovery.build("cloudresourcemanager", "v1", credentials=creds)
        except ImportError as exc:
            raise CredentialResolutionError(
                "google-api-python-client is not installed. "
                "Install it with: pip install apileaks[gcp]"
            ) from exc
        return self._iam_client

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def project_id(self) -> str:
        return self._project_id

    @property
    def location(self) -> str:
        return self._location

    def parent(self) -> str:
        return f"projects/{self._project_id}/locations/{self._location}"
