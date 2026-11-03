"""
tests/cloud/test_gcp_client.py
Unit tests for utils/cloud/gcp_client.py::GCPGatewayClient

Requirements: 2.4, 2.5, 10.1, 10.2
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# GCP SDK is an optional extra; skip this entire module if not installed.
pytest.importorskip("google.cloud.apigateway_v1")

from modules.cloud.base import CredentialResolutionError
from utils.cloud.gcp_client import GCPGatewayClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_credentials() -> MagicMock:
    """Return a mock credentials object (google.oauth2.Credentials-like)."""
    creds = MagicMock(name="FakeCredentials")
    return creds


def _fake_gateway_client() -> MagicMock:
    """Return a mock ApiGatewayServiceClient."""
    return MagicMock(name="ApiGatewayServiceClient")


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestDefaultInitialization:
    """Verify the client stores constructor args without triggering network calls."""

    def test_project_id_is_stored(self):
        client = GCPGatewayClient("my-project")
        assert client.project_id == "my-project"

    def test_default_location_is_global(self):
        client = GCPGatewayClient("my-project")
        assert client.location == "global"

    def test_custom_location_is_stored(self):
        client = GCPGatewayClient("my-project", location="us-central1")
        assert client.location == "us-central1"

    def test_gateway_client_is_lazily_created(self):
        """No SDK clients should be created at construction time."""
        client = GCPGatewayClient("my-project")
        assert client._gateway_client is None

    def test_iam_client_is_lazily_created(self):
        client = GCPGatewayClient("my-project")
        assert client._iam_client is None

    def test_cached_credentials_start_as_none(self):
        client = GCPGatewayClient("my-project")
        assert client._cached_credentials is None

    def test_service_account_file_is_stored(self):
        client = GCPGatewayClient("my-project", service_account_file="/tmp/sa.json")
        assert client._service_account_file == "/tmp/sa.json"


# ---------------------------------------------------------------------------
# parent() helper
# ---------------------------------------------------------------------------


class TestParentHelper:
    """parent() constructs the canonical resource path for list calls."""

    def test_parent_default_location(self):
        client = GCPGatewayClient("my-project")
        assert client.parent() == "projects/my-project/locations/global"

    def test_parent_custom_location(self):
        client = GCPGatewayClient("my-project", location="europe-west1")
        assert client.parent() == "projects/my-project/locations/europe-west1"


# ---------------------------------------------------------------------------
# Credential resolution — ADC path (Requirement 2.4)
# ---------------------------------------------------------------------------


class TestADCCredentialResolution:
    """When no service_account_file is provided, ADC chain is used."""

    def test_adc_called_when_no_sa_file(self):
        fake_creds = _fake_credentials()
        mock_google_auth = MagicMock()
        mock_google_auth.default.return_value = (fake_creds, "detected-project")
        mock_google_auth.exceptions = MagicMock()
        mock_google_auth.exceptions.DefaultCredentialsError = Exception

        with patch.dict(sys.modules, {"google.auth": mock_google_auth, "google.auth.exceptions": mock_google_auth.exceptions}):
            client = GCPGatewayClient("my-project")
            creds = client._resolve_credentials()

        mock_google_auth.default.assert_called_once_with(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        assert creds is fake_creds

    def test_credentials_cached_after_first_resolve(self):
        fake_creds = _fake_credentials()
        mock_google_auth = MagicMock()
        mock_google_auth.default.return_value = (fake_creds, "detected-project")
        mock_google_auth.exceptions = MagicMock()
        mock_google_auth.exceptions.DefaultCredentialsError = Exception

        with patch.dict(sys.modules, {"google.auth": mock_google_auth, "google.auth.exceptions": mock_google_auth.exceptions}):
            client = GCPGatewayClient("my-project")
            _ = client._get_credentials()
            _ = client._get_credentials()  # second call

        # google.auth.default should be called only once despite two _get_credentials calls
        assert mock_google_auth.default.call_count == 1

    def test_adc_default_credentials_error_raises_credential_resolution_error(self):
        """google.auth.exceptions.DefaultCredentialsError → CredentialResolutionError."""

        class _FakeDefaultCredentialsError(Exception):
            pass

        mock_exceptions = MagicMock()
        mock_exceptions.DefaultCredentialsError = _FakeDefaultCredentialsError

        mock_google_auth = MagicMock()
        mock_google_auth.default.side_effect = _FakeDefaultCredentialsError("No credentials")
        mock_google_auth.exceptions = mock_exceptions

        with patch.dict(sys.modules, {
            "google.auth": mock_google_auth,
            "google.auth.exceptions": mock_exceptions,
        }):
            client = GCPGatewayClient("my-project")
            with pytest.raises(CredentialResolutionError, match="Application Default Credentials"):
                client._resolve_credentials()


# ---------------------------------------------------------------------------
# Credential resolution — service account file path (Requirement 2.5)
# ---------------------------------------------------------------------------


class TestServiceAccountFileResolution:
    """When service_account_file is provided, it is loaded instead of ADC."""

    def test_sa_file_loaded_when_provided_at_construction(self):
        fake_creds = _fake_credentials()
        mock_sa = MagicMock()
        mock_sa.Credentials.from_service_account_file.return_value = fake_creds

        with patch.dict(sys.modules, {"google.oauth2": MagicMock(service_account=mock_sa),
                                      "google.oauth2.service_account": mock_sa}):
            client = GCPGatewayClient("my-project", service_account_file="/path/sa.json")
            creds = client._resolve_credentials()

        mock_sa.Credentials.from_service_account_file.assert_called_once_with(
            "/path/sa.json",
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        assert creds is fake_creds

    def test_sa_file_parameter_overrides_constructor_value(self):
        """Explicit parameter to _resolve_credentials takes precedence over stored value."""
        fake_creds = _fake_credentials()
        mock_sa = MagicMock()
        mock_sa.Credentials.from_service_account_file.return_value = fake_creds

        with patch.dict(sys.modules, {"google.oauth2": MagicMock(service_account=mock_sa),
                                      "google.oauth2.service_account": mock_sa}):
            client = GCPGatewayClient("my-project", service_account_file="/old/sa.json")
            client._resolve_credentials(service_account_file="/new/sa.json")

        mock_sa.Credentials.from_service_account_file.assert_called_once_with(
            "/new/sa.json",
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    def test_invalid_sa_file_raises_credential_resolution_error(self):
        mock_sa = MagicMock()
        mock_sa.Credentials.from_service_account_file.side_effect = Exception("File not found")

        with patch.dict(sys.modules, {"google.oauth2": MagicMock(service_account=mock_sa),
                                      "google.oauth2.service_account": mock_sa}):
            client = GCPGatewayClient("my-project", service_account_file="/bad/sa.json")
            with pytest.raises(CredentialResolutionError, match="service account key"):
                client._resolve_credentials()


# ---------------------------------------------------------------------------
# gateway_client property (Requirement 2.4, 10.1)
# ---------------------------------------------------------------------------


class TestGatewayClientProperty:
    """The gateway_client property returns an ApiGatewayServiceClient."""

    def _setup_mocks(self):
        """Return (fake_creds, mock_apigateway_v1 module, fake_service_client)."""
        fake_creds = _fake_credentials()
        fake_service_client = _fake_gateway_client()

        mock_apigateway_v1 = MagicMock()
        mock_apigateway_v1.ApiGatewayServiceClient.return_value = fake_service_client

        return fake_creds, mock_apigateway_v1, fake_service_client

    def test_gateway_client_returns_api_gateway_service_client(self):
        fake_creds, mock_apigw_v1, fake_svc = self._setup_mocks()

        with patch.dict(sys.modules, {"google.cloud.apigateway_v1": mock_apigw_v1}):
            client = GCPGatewayClient("my-project")
            client._cached_credentials = fake_creds  # inject pre-resolved creds
            svc = client.gateway_client

        mock_apigw_v1.ApiGatewayServiceClient.assert_called_once_with(credentials=fake_creds)
        assert svc is fake_svc

    def test_gateway_client_is_cached_after_first_access(self):
        fake_creds, mock_apigw_v1, fake_svc = self._setup_mocks()

        with patch.dict(sys.modules, {"google.cloud.apigateway_v1": mock_apigw_v1}):
            client = GCPGatewayClient("my-project")
            client._cached_credentials = fake_creds
            _ = client.gateway_client
            _ = client.gateway_client  # second access

        # ApiGatewayServiceClient should be constructed only once
        assert mock_apigw_v1.ApiGatewayServiceClient.call_count == 1

    def test_gateway_alias_returns_same_object_as_gateway_client(self):
        fake_creds, mock_apigw_v1, fake_svc = self._setup_mocks()

        with patch.dict(sys.modules, {"google.cloud.apigateway_v1": mock_apigw_v1}):
            client = GCPGatewayClient("my-project")
            client._cached_credentials = fake_creds
            via_primary = client.gateway_client
            via_alias = client.gateway

        assert via_primary is via_alias

    def test_missing_sdk_raises_credential_resolution_error(self):
        """When google-cloud-api-gateway is not installed, a clear error is raised."""
        with patch.dict(sys.modules, {"google.cloud.apigateway_v1": None}):
            client = GCPGatewayClient("my-project")
            with pytest.raises(CredentialResolutionError, match="google-cloud-api-gateway"):
                _ = client.gateway_client


# ---------------------------------------------------------------------------
# Error handling: missing google-auth
# ---------------------------------------------------------------------------


class TestMissingGoogleAuth:
    """CredentialResolutionError is raised when google-auth is not importable."""

    def test_import_error_on_adc_path(self):
        with patch.dict(sys.modules, {"google.auth": None, "google.auth.exceptions": None}):
            client = GCPGatewayClient("my-project")
            with pytest.raises(CredentialResolutionError, match="google-auth is not installed"):
                client._resolve_credentials()

    def test_import_error_on_sa_file_path(self):
        with patch.dict(sys.modules, {
            "google.oauth2": None,
            "google.oauth2.service_account": None,
        }):
            client = GCPGatewayClient("my-project", service_account_file="/path/sa.json")
            with pytest.raises(CredentialResolutionError, match="google-auth is not installed"):
                client._resolve_credentials()
