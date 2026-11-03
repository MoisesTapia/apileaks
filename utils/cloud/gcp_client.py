"""
GCP API Gateway Client

Thin wrapper that resolves credentials via Application Default Credentials
(ADC) or an explicit service account key file, then builds the client for
google-cloud-api-gateway.

The SDK (google-cloud-api-gateway) is an optional extra dependency; this
module degrades gracefully when it is not installed — any access to the
``gateway_client`` property raises ``CredentialResolutionError`` with a
helpful install hint instead of an ``ImportError`` at module-import time.
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

    Credentials are resolved lazily on first access, following the same
    pattern as ``AWSGatewayClient`` — the constructor never performs a
    network call so import-time errors for missing SDKs are surfaced only
    when the caller actually tries to use the client.

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
        self._cached_credentials: Any | None = None
        self._gateway_client: Any | None = None
        self._iam_client: Any | None = None

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    def _resolve_credentials(self, service_account_file: str | None = None) -> Any:
        """
        Return a google.oauth2 credentials object.

        Resolution order
        ----------------
        1. ``service_account_file`` parameter (if supplied).
        2. ``self._service_account_file`` set at construction time.
        3. Application Default Credentials (ADC) via ``google.auth.default()``.

        Raises
        ------
        CredentialResolutionError
            When the SDK is not installed, the key file is invalid, or ADC
            finds no valid credentials (``google.auth.exceptions.DefaultCredentialsError``).
        """
        file_path = service_account_file or self._service_account_file

        if file_path:
            try:
                from google.oauth2 import service_account  # type: ignore[import]

                creds = service_account.Credentials.from_service_account_file(
                    file_path,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                logger.info(
                    "GCP credentials resolved via service account file",
                    file=file_path,
                    project=self._project_id,
                )
                return creds
            except ImportError as exc:
                raise CredentialResolutionError(
                    "google-auth is not installed. "
                    "Install it with: pip install apileaks[gcp]"
                ) from exc
            except Exception as exc:
                raise CredentialResolutionError(
                    f"Failed to load GCP service account key from '{file_path}': {exc}"
                ) from exc

        # Fall back to Application Default Credentials
        try:
            import importlib
            _google_auth = importlib.import_module("google.auth")
            _google_auth_exceptions = importlib.import_module("google.auth.exceptions")
        except ImportError as exc:
            raise CredentialResolutionError(
                "google-auth is not installed. "
                "Install it with: pip install apileaks[gcp]"
            ) from exc

        try:
            creds, project = _google_auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            logger.info(
                "GCP credentials resolved via Application Default Credentials",
                detected_project=project,
                configured_project=self._project_id,
            )
            return creds
        except _google_auth_exceptions.DefaultCredentialsError as exc:
            raise CredentialResolutionError(
                "GCP Application Default Credentials (ADC) are not configured. "
                "Run `gcloud auth application-default login` or set the "
                "GOOGLE_APPLICATION_CREDENTIALS environment variable to a "
                "service account key file path."
            ) from exc

    def _get_credentials(self) -> Any:
        """Return (and cache) resolved credentials."""
        if self._cached_credentials is None:
            self._cached_credentials = self._resolve_credentials()
        return self._cached_credentials

    # ------------------------------------------------------------------
    # Service clients
    # ------------------------------------------------------------------

    @property
    def gateway_client(self) -> Any:
        """
        ``google.cloud.apigateway_v1.ApiGatewayServiceClient`` instance.

        Lazily initialised and cached on first access.
        """
        if self._gateway_client is not None:
            return self._gateway_client
        try:
            import importlib
            apigateway_v1 = importlib.import_module("google.cloud.apigateway_v1")
        except ImportError as exc:
            raise CredentialResolutionError(
                "google-cloud-api-gateway is not installed. "
                "Install it with: pip install apileaks[gcp]"
            ) from exc
        creds = self._get_credentials()
        self._gateway_client = apigateway_v1.ApiGatewayServiceClient(credentials=creds)
        logger.info(
            "GCP ApiGatewayServiceClient initialised", project=self._project_id
        )
        return self._gateway_client

    # Backward-compatible alias — the auditor module references .gateway
    @property
    def gateway(self) -> Any:
        """Alias for ``gateway_client`` (backward compatibility)."""
        return self.gateway_client

    @property
    def iam(self) -> Any:
        """
        ``googleapiclient.discovery`` resource for Cloud Resource Manager.

        Used to read project-level IAM policies (Requirement 5.4).
        Lazily initialised and cached.
        """
        if self._iam_client is not None:
            return self._iam_client
        try:
            from googleapiclient import discovery  # type: ignore[import]
        except ImportError as exc:
            raise CredentialResolutionError(
                "google-api-python-client is not installed. "
                "Install it with: pip install apileaks[gcp]"
            ) from exc
        creds = self._get_credentials()
        self._iam_client = discovery.build("cloudresourcemanager", "v1", credentials=creds)
        return self._iam_client

    # ------------------------------------------------------------------
    # Read-only helper properties
    # ------------------------------------------------------------------

    @property
    def project_id(self) -> str:
        """The GCP project ID this client is scoped to."""
        return self._project_id

    @property
    def location(self) -> str:
        """The GCP location/region (default: "global")."""
        return self._location

    def parent(self) -> str:
        """Return the canonical parent resource path for list calls."""
        return f"projects/{self._project_id}/locations/{self._location}"
