"""
AWS API Gateway Client

Thin wrapper over boto3 that resolves credentials via the standard chain
(env vars → ~/.aws/credentials → IAM role) and optionally assumes a role
before constructing the service clients used by AWSGatewayAuditor.

No credentials are ever read into memory beyond what boto3 already does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.logging import get_logger
from modules.cloud.base import CredentialResolutionError

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class AWSGatewayClient:
    """
    Manages boto3 service clients for the AWS API Gateway auditor.

    Parameters
    ----------
    profile:    AWS named profile from ~/.aws/credentials (optional).
    role_arn:   IAM role ARN to assume before auditing (optional).
    region:     AWS region override (optional; uses the profile/env default).

    All clients are constructed lazily on first access so that import-time
    failures (boto3 not installed) do not crash the whole module when the
    ``aws`` extra is not installed.
    """

    def __init__(
        self,
        profile: str | None = None,
        role_arn: str | None = None,
        region: str | None = None,
    ) -> None:
        self._profile = profile
        self._role_arn = role_arn
        self._region = region
        self._session: Any | None = None

    # ------------------------------------------------------------------
    # Session / credential resolution
    # ------------------------------------------------------------------

    def _get_session(self) -> Any:
        """Return (and cache) a boto3 Session, assuming a role when configured."""
        if self._session is not None:
            return self._session

        try:
            import boto3
        except ImportError as exc:
            raise CredentialResolutionError(
                "boto3 is not installed. Install it with: pip install apileaks[aws]"
            ) from exc

        try:
            base_session = boto3.Session(
                profile_name=self._profile,
                region_name=self._region,
            )

            if self._role_arn:
                sts = base_session.client("sts")
                assumed = sts.assume_role(
                    RoleArn=self._role_arn,
                    RoleSessionName="apileaks-cloud-audit",
                )
                creds = assumed["Credentials"]
                self._session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self._region,
                )
                logger.info("Assumed AWS IAM role for audit", role_arn=self._role_arn)
            else:
                self._session = base_session

        except Exception as exc:
            raise CredentialResolutionError(f"Failed to resolve AWS credentials: {exc}") from exc

        return self._session

    # ------------------------------------------------------------------
    # Service clients
    # ------------------------------------------------------------------

    def _client(self, service: str) -> Any:
        """Return a boto3 client for the given service."""
        return self._get_session().client(service)

    @property
    def apigateway(self) -> Any:
        """REST API (v1) client."""
        return self._client("apigateway")

    @property
    def apigatewayv2(self) -> Any:
        """HTTP API (v2) client."""
        return self._client("apigatewayv2")

    @property
    def wafv2(self) -> Any:
        return self._client("wafv2")

    @property
    def iam(self) -> Any:
        return self._client("iam")

    # ------------------------------------------------------------------
    # Pagination helpers
    # ------------------------------------------------------------------

    def paginate_v1(self, method_name: str, result_key: str, **kwargs: Any) -> list[dict]:
        """Paginate over a REST API (v1) list call and return all items."""
        client = self.apigateway
        method = getattr(client, method_name)
        items: list[dict] = []
        position: str | None = None

        while True:
            if position:
                kwargs["position"] = position
            response = method(**kwargs)
            items.extend(response.get(result_key, []))
            position = response.get("position")
            if not position:
                break

        return items

    def paginate_v2(self, method_name: str, result_key: str, **kwargs: Any) -> list[dict]:
        """Paginate over an HTTP API (v2) list call and return all items."""
        client = self.apigatewayv2
        method = getattr(client, method_name)
        items: list[dict] = []
        next_token: str | None = None

        while True:
            if next_token:
                kwargs["NextToken"] = next_token
            response = method(**kwargs)
            items.extend(response.get(result_key, []))
            next_token = response.get("NextToken")
            if not next_token:
                break

        return items
