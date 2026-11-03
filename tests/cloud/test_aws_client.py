"""
tests/cloud/test_aws_client.py
Unit tests for utils/cloud/aws_client.py::AWSGatewayClient

Requirements: 2.1, 2.2, 2.3
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, call, patch

import pytest

# boto3 is a base dependency so no importorskip needed, but guard defensively.
pytest.importorskip("boto3")

from modules.cloud.base import CredentialResolutionError
from utils.cloud.aws_client import AWSGatewayClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_session(region: str | None = None) -> MagicMock:
    """Return a MagicMock that behaves like a boto3.Session."""
    session = MagicMock()
    session.client.side_effect = lambda svc, **kw: MagicMock(name=f"client:{svc}")
    return session


_FAKE_CREDS = {
    "Credentials": {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "AQoDYXdzEJr...",
    }
}


# ---------------------------------------------------------------------------
# Initialization — default (no profile, no role_arn, no region)
# ---------------------------------------------------------------------------


class TestDefaultInitialization:
    """Verify the client can be constructed with all optional parameters absent."""

    def test_no_args_sets_private_fields_to_none(self):
        with patch("boto3.Session", return_value=_fake_session()) as mock_session_cls:
            client = AWSGatewayClient()

        assert client._profile is None
        assert client._role_arn is None
        assert client._region is None

    def test_session_is_lazily_created(self):
        """_session must be None until a property is first accessed."""
        with patch("boto3.Session", return_value=_fake_session()):
            client = AWSGatewayClient()

        assert client._session is None

    def test_session_constructed_with_profile_and_region(self):
        """_get_session passes profile_name and region_name to boto3.Session."""
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess) as mock_cls:
            client = AWSGatewayClient(profile="my-profile", region="eu-west-1")
            _ = client.apigateway  # trigger session creation

        mock_cls.assert_called_once_with(profile_name="my-profile", region_name="eu-west-1")

    def test_session_constructed_without_profile_or_region(self):
        """When no profile/region, None values are still forwarded to boto3."""
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess) as mock_cls:
            client = AWSGatewayClient()
            _ = client.apigateway

        mock_cls.assert_called_once_with(profile_name=None, region_name=None)


# ---------------------------------------------------------------------------
# Named profile support (Requirement 2.2)
# ---------------------------------------------------------------------------


class TestNamedProfile:
    """Support for --aws-profile <name>."""

    def test_profile_forwarded_to_session(self):
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess) as mock_cls:
            client = AWSGatewayClient(profile="staging")
            _ = client.iam  # trigger session build

        mock_cls.assert_called_once_with(profile_name="staging", region_name=None)

    def test_session_cached_after_first_access(self):
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess) as mock_cls:
            client = AWSGatewayClient(profile="staging")
            _ = client.apigateway
            _ = client.apigatewayv2  # second access

        # boto3.Session should only be called once
        assert mock_cls.call_count == 1


# ---------------------------------------------------------------------------
# Role assumption via STS (Requirement 2.3)
# ---------------------------------------------------------------------------


class TestRoleAssumption:
    """Support for --aws-role-arn <arn>."""

    def _make_sts_base_session(self) -> MagicMock:
        """Return a base session whose STS client returns fake assumed-role creds."""
        sts_client = MagicMock()
        sts_client.assume_role.return_value = _FAKE_CREDS

        base_session = MagicMock()
        base_session.client.return_value = sts_client
        return base_session, sts_client

    def test_assume_role_called_with_correct_args(self):
        role_arn = "arn:aws:iam::123456789012:role/AuditRole"
        base_session, sts_client = self._make_sts_base_session()
        assumed_session = _fake_session()

        with patch("boto3.Session", side_effect=[base_session, assumed_session]):
            client = AWSGatewayClient(role_arn=role_arn)
            _ = client.apigateway  # trigger session build

        sts_client.assume_role.assert_called_once_with(
            RoleArn=role_arn,
            RoleSessionName="apileaks-cloud-audit",
        )

    def test_assumed_session_uses_temporary_credentials(self):
        role_arn = "arn:aws:iam::123456789012:role/AuditRole"
        base_session, _ = self._make_sts_base_session()
        assumed_session = _fake_session()

        with patch("boto3.Session", side_effect=[base_session, assumed_session]) as mock_cls:
            client = AWSGatewayClient(role_arn=role_arn)
            _ = client.apigateway

        # Second boto3.Session call must carry the temporary credentials
        second_call = mock_cls.call_args_list[1]
        kwargs = second_call[1]
        assert kwargs["aws_access_key_id"] == _FAKE_CREDS["Credentials"]["AccessKeyId"]
        assert kwargs["aws_secret_access_key"] == _FAKE_CREDS["Credentials"]["SecretAccessKey"]
        assert kwargs["aws_session_token"] == _FAKE_CREDS["Credentials"]["SessionToken"]

    def test_assumed_session_inherits_region(self):
        role_arn = "arn:aws:iam::123456789012:role/AuditRole"
        base_session, _ = self._make_sts_base_session()
        assumed_session = _fake_session()

        with patch("boto3.Session", side_effect=[base_session, assumed_session]) as mock_cls:
            client = AWSGatewayClient(role_arn=role_arn, region="ap-southeast-1")
            _ = client.apigateway

        second_call = mock_cls.call_args_list[1]
        assert second_call[1]["region_name"] == "ap-southeast-1"

    def test_no_role_arn_skips_sts(self):
        """Without a role_arn, assume_role must never be called."""
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess):
            client = AWSGatewayClient()
            _ = client.apigateway

        # session.client("sts") should not have been called at all
        for c in mock_sess.client.call_args_list:
            assert c[0][0] != "sts", "STS should not be called without role_arn"


# ---------------------------------------------------------------------------
# Service client properties (Requirement 2.1)
# ---------------------------------------------------------------------------


class TestServiceClients:
    """Each declared property returns a boto3 client for the correct service."""

    def _client_from(self, service: str) -> tuple[AWSGatewayClient, MagicMock]:
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess):
            client = AWSGatewayClient()
            svc_client = getattr(client, service)
        return client, mock_sess

    @pytest.mark.parametrize("service", ["apigateway", "apigatewayv2", "wafv2", "iam", "sts"])
    def test_property_creates_correct_client(self, service: str):
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess):
            client = AWSGatewayClient()
            _ = getattr(client, service)

        # Verify session.client was called with the right service name
        called_services = [c[0][0] for c in mock_sess.client.call_args_list]
        assert service in called_services, f"Expected session.client('{service}') to be called"

    def test_all_five_clients_available(self):
        """All five required clients must be accessible without raising."""
        mock_sess = _fake_session()
        with patch("boto3.Session", return_value=mock_sess):
            client = AWSGatewayClient()
            _ = client.apigateway
            _ = client.apigatewayv2
            _ = client.wafv2
            _ = client.iam
            _ = client.sts  # must not raise


# ---------------------------------------------------------------------------
# Error handling: missing boto3
# ---------------------------------------------------------------------------


class TestMissingBoto3:
    """CredentialResolutionError is raised when boto3 is not importable."""

    def test_import_error_raises_credential_resolution_error(self):
        with patch.dict(sys.modules, {"boto3": None}):
            client = AWSGatewayClient()
            with pytest.raises(CredentialResolutionError, match="boto3 is not installed"):
                _ = client.apigateway


# ---------------------------------------------------------------------------
# Error handling: boto3.Session raises
# ---------------------------------------------------------------------------


class TestSessionCreationFailure:
    """Wraps boto3 errors in CredentialResolutionError."""

    def test_boto3_session_exception_wrapped(self):
        with patch("boto3.Session", side_effect=Exception("No credentials")):
            client = AWSGatewayClient()
            with pytest.raises(CredentialResolutionError, match="Failed to resolve AWS credentials"):
                _ = client.apigateway

    def test_sts_assume_role_exception_wrapped(self):
        sts_client = MagicMock()
        sts_client.assume_role.side_effect = Exception("AccessDenied")

        base_session = MagicMock()
        base_session.client.return_value = sts_client

        with patch("boto3.Session", return_value=base_session):
            client = AWSGatewayClient(role_arn="arn:aws:iam::123:role/R")
            with pytest.raises(CredentialResolutionError, match="Failed to resolve AWS credentials"):
                _ = client.apigateway


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------


class TestPaginationHelpers:
    """paginate_v1 and paginate_v2 collect all pages correctly."""

    def _make_client_with_mock_session(self) -> tuple[AWSGatewayClient, MagicMock, MagicMock]:
        """Build an AWSGatewayClient with a pre-injected mock session.

        Bypasses the lazy _get_session() mechanism so that boto3 is never
        invoked; the mock session is injected directly into ``_session``.
        """
        gw_client = MagicMock()
        gw2_client = MagicMock()

        def session_client_factory(service, **kw):
            if service == "apigateway":
                return gw_client
            if service == "apigatewayv2":
                return gw2_client
            return MagicMock()

        mock_sess = MagicMock()
        mock_sess.client.side_effect = session_client_factory

        # Bypass __init__ entirely and inject the session directly so no real
        # boto3 credential resolution happens during pagination calls.
        client = object.__new__(AWSGatewayClient)
        client._profile = None
        client._role_arn = None
        client._region = None
        client._session = mock_sess

        return client, gw_client, gw2_client

    def test_paginate_v1_single_page(self):
        client, gw_client, _ = self._make_client_with_mock_session()
        gw_client.get_rest_apis.return_value = {
            "items": [{"id": "a1b2"}, {"id": "c3d4"}],
        }

        result = client.paginate_v1("get_rest_apis", "items")

        assert result == [{"id": "a1b2"}, {"id": "c3d4"}]

    def test_paginate_v1_multiple_pages(self):
        client, gw_client, _ = self._make_client_with_mock_session()
        gw_client.get_rest_apis.side_effect = [
            {"items": [{"id": "a1"}], "position": "tok1"},
            {"items": [{"id": "a2"}], "position": "tok2"},
            {"items": [{"id": "a3"}]},
        ]

        result = client.paginate_v1("get_rest_apis", "items")

        assert result == [{"id": "a1"}, {"id": "a2"}, {"id": "a3"}]
        assert gw_client.get_rest_apis.call_count == 3

    def test_paginate_v2_single_page(self):
        client, _, gw2_client = self._make_client_with_mock_session()
        gw2_client.get_apis.return_value = {
            "Items": [{"ApiId": "x1y2"}, {"ApiId": "z3w4"}],
        }

        result = client.paginate_v2("get_apis", "Items")

        assert result == [{"ApiId": "x1y2"}, {"ApiId": "z3w4"}]

    def test_paginate_v2_multiple_pages(self):
        client, _, gw2_client = self._make_client_with_mock_session()
        gw2_client.get_apis.side_effect = [
            {"Items": [{"ApiId": "x1"}], "NextToken": "nt1"},
            {"Items": [{"ApiId": "x2"}], "NextToken": "nt2"},
            {"Items": [{"ApiId": "x3"}]},
        ]

        result = client.paginate_v2("get_apis", "Items")

        assert result == [{"ApiId": "x1"}, {"ApiId": "x2"}, {"ApiId": "x3"}]
        assert gw2_client.get_apis.call_count == 3

    def test_paginate_v1_passes_position_on_subsequent_calls(self):
        client, gw_client, _ = self._make_client_with_mock_session()
        gw_client.get_rest_apis.side_effect = [
            {"items": [{"id": "a1"}], "position": "page2-token"},
            {"items": [{"id": "a2"}]},
        ]

        client.paginate_v1("get_rest_apis", "items")

        second_call_kwargs = gw_client.get_rest_apis.call_args_list[1][1]
        assert second_call_kwargs.get("position") == "page2-token"

    def test_paginate_v2_passes_next_token_on_subsequent_calls(self):
        client, _, gw2_client = self._make_client_with_mock_session()
        gw2_client.get_apis.side_effect = [
            {"Items": [{"ApiId": "x1"}], "NextToken": "page2"},
            {"Items": [{"ApiId": "x2"}]},
        ]

        client.paginate_v2("get_apis", "Items")

        second_call_kwargs = gw2_client.get_apis.call_args_list[1][1]
        assert second_call_kwargs.get("NextToken") == "page2"

    def test_paginate_v1_empty_result(self):
        client, gw_client, _ = self._make_client_with_mock_session()
        gw_client.get_rest_apis.return_value = {"items": []}

        result = client.paginate_v1("get_rest_apis", "items")

        assert result == []
