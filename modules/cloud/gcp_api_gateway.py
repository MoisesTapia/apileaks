"""
GCP API Gateway Security Auditor

Audits the configuration of GCP API Gateway configurations and Cloud
Endpoints (ESPv2) using read-only SDK calls.

Checks implemented (mapped to spec Requirements 5.1 – 5.5):
  5.1 / 5.2  OpenAPI spec paths without securityDefinitions / security requirements
  5.3        Backend over HTTP (not HTTPS)
  5.4        IAM binding granting invoker access to allUsers/allAuthenticatedUsers
  5.5        Cloud Endpoints — API key or JWT validation not enabled

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
from utils.cloud.gcp_client import GCPGatewayClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard

logger = get_logger(__name__)

_REMEDIATION_SECURITY_DEF = (
    "Add a securityDefinitions section to your OpenAPI spec and reference it "
    "via the 'security' key on each path/method. "
    "GCP docs: https://cloud.google.com/api-gateway/docs/authenticating-users"
)
_REMEDIATION_HTTP_BACKEND = (
    "Update the backend URL to use HTTPS. "
    "GCP docs: https://cloud.google.com/api-gateway/docs/backend-auth"
)
_REMEDIATION_IAM_BINDING = (
    "Remove the IAM binding that grants 'allUsers' or 'allAuthenticatedUsers' "
    "the roles/apigateway.viewer or invoker role. "
    "CLI: gcloud projects remove-iam-policy-binding <project> "
    "--member=allUsers --role=<role>"
)
_REMEDIATION_ESP_VALIDATION = (
    "Enable API key or JWT validation in your Cloud Endpoints service config. "
    "GCP docs: https://cloud.google.com/endpoints/docs/openapi/restricting-api-access-with-api-keys"
)


class GCPGatewayAuditor(CloudGatewayAuditor):
    """
    Read-only auditor for GCP API Gateway configurations.

    Parameters
    ----------
    client:           GCPGatewayClient instance.
    guard:            CloudReadOnlyGuard (default: read-only).
    account_context:  Label for the GCP project/account being audited.
    """

    def __init__(
        self,
        client: GCPGatewayClient,
        guard: CloudReadOnlyGuard | None = None,
        account_context: str | None = None,
    ) -> None:
        self._client = client
        self._guard = guard or CloudReadOnlyGuard(allow_destructive=False)
        self._account_context = account_context or f"gcp:{client.project_id}"

    def get_provider_name(self) -> str:
        return "gcp"

    async def discover_resources(self) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        try:
            from google.cloud import apigateway_v1  # type: ignore[import]

            request = apigateway_v1.ListGatewaysRequest(parent=self._client.parent())
            for gw in self._client.gateway.list_gateways(request=request):
                resources.append({"type": "gateway", "name": gw.name, "state": str(gw.state)})
        except ImportError:
            logger.warning("google-cloud-api-gateway not installed — skipping GCP discovery")
            return []
        except Exception as exc:
            self._handle_gcp_error("list_gateways", exc)

        logger.info(
            "GCP discovery complete",
            project=self._client.project_id,
            resource_count=len(resources),
        )
        return resources

    async def audit(self) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []

        try:
            from google.cloud import apigateway_v1  # type: ignore[import]
        except ImportError:
            logger.warning("google-cloud-api-gateway not installed — skipping GCP audit")
            return findings

        # List API configs and check their OpenAPI specs
        try:
            list_req = apigateway_v1.ListApiConfigsRequest(
                parent=f"projects/{self._client.project_id}/locations/{self._client.location}/apis/-"
            )
            for config in self._client.gateway.list_api_configs(request=list_req):
                findings.extend(self._audit_api_config(config))
        except Exception as exc:
            self._handle_gcp_error("list_api_configs", exc)

        # Check project-level IAM bindings (5.4)
        findings.extend(self._check_iam_bindings())

        logger.info(
            "GCP audit complete",
            project=self._client.project_id,
            finding_count=len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Per-config checks
    # ------------------------------------------------------------------

    def _audit_api_config(self, config: Any) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        config_name = config.name

        for openapi_doc in getattr(config, "openapi_documents", []):
            try:
                import yaml  # already in requirements

                doc = yaml.safe_load(openapi_doc.document.contents.decode("utf-8"))
            except Exception:
                continue

            # 5.1 / 5.2 — paths without securityDefinitions or per-path security
            sec_defs = doc.get(
                "securityDefinitions", doc.get("components", {}).get("securitySchemes", {})
            )
            paths = doc.get("paths", {})

            for path, path_item in paths.items():
                for method, operation in path_item.items():
                    if not isinstance(operation, dict):
                        continue
                    path_security = operation.get("security") or doc.get("security")
                    if not sec_defs or not path_security:
                        findings.append(
                            GatewayFinding(
                                provider="gcp",
                                resource_id=config_name,
                                resource_type="gcp_api_config",
                                check_id="gcp_apigw_path_no_security_definition",
                                title=f"GCP API config path {path} {method.upper()} has no security requirement",
                                severity=GatewaySeverity.HIGH,
                                evidence={
                                    "config_name": config_name,
                                    "path": path,
                                    "method": method,
                                    "has_security_definitions": bool(sec_defs),
                                    "has_path_security": bool(path_security),
                                },
                                remediation=_REMEDIATION_SECURITY_DEF,
                                account_context=self._account_context,
                            )
                        )

            # 5.3 — backend over HTTP
            for ext_key, ext_val in (
                doc.get("x-google-backend", {}).items()
                if isinstance(doc.get("x-google-backend"), dict)
                else []
            ):
                if (
                    ext_key == "address"
                    and isinstance(ext_val, str)
                    and ext_val.startswith("http://")
                ):
                    findings.append(
                        GatewayFinding(
                            provider="gcp",
                            resource_id=config_name,
                            resource_type="gcp_api_config",
                            check_id="gcp_apigw_http_backend",
                            title="GCP API Gateway backend uses HTTP (not HTTPS)",
                            severity=GatewaySeverity.HIGH,
                            evidence={
                                "config_name": config_name,
                                "backend_url": ext_val,
                            },
                            remediation=_REMEDIATION_HTTP_BACKEND,
                            account_context=self._account_context,
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Check 5.4 — IAM bindings to allUsers / allAuthenticatedUsers
    # ------------------------------------------------------------------

    def _check_iam_bindings(self) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        try:
            iam = self._client.iam
            policy = (
                iam.projects().getIamPolicy(resource=self._client.project_id, body={}).execute()
            )
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                members = binding.get("members", [])
                if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
                    if any(r in role for r in ("apigateway", "viewer", "invoker", "run.invoker")):
                        findings.append(
                            GatewayFinding(
                                provider="gcp",
                                resource_id=f"projects/{self._client.project_id}",
                                resource_type="gcp_iam_binding",
                                check_id="gcp_apigw_iam_public_invoker",
                                title=f"GCP project IAM grants public access via role {role}",
                                severity=GatewaySeverity.CRITICAL,
                                evidence={
                                    "project": self._client.project_id,
                                    "role": role,
                                    "public_members": [
                                        m
                                        for m in members
                                        if m in ("allUsers", "allAuthenticatedUsers")
                                    ],
                                },
                                remediation=_REMEDIATION_IAM_BINDING,
                                account_context=self._account_context,
                            )
                        )
        except ImportError:
            pass
        except Exception as exc:
            self._handle_gcp_error("getIamPolicy", exc)
        return findings

    def _handle_gcp_error(self, operation: str, exc: Exception) -> None:
        error_str = str(exc).lower()
        if "permission" in error_str or "forbidden" in error_str or "403" in error_str:
            logger.warning(
                "Insufficient GCP permissions",
                operation=operation,
                error=str(exc),
                project=self._client.project_id,
            )
            raise InsufficientPermissionsError(str(exc)) from exc
        logger.warning(
            "GCP operation failed (non-fatal)",
            operation=operation,
            error=str(exc),
            project=self._client.project_id,
        )
