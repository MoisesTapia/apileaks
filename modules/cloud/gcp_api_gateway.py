"""
GCP API Gateway Security Auditor

Audits the configuration of GCP API Gateway configurations and Cloud
Endpoints (ESPv2) using read-only SDK calls.

Checks implemented (mapped to spec Requirements 5.1 – 5.5):
  5.1 / 5.2  OpenAPI spec missing securityDefinitions or paths lacking a
             security requirement
  5.3        Backend URL using HTTP (not HTTPS)
  5.4        IAM binding granting invoker access to allUsers/allAuthenticatedUsers
  5.5        Cloud Endpoints — no API key or JWT/OAuth2 security scheme defined

All operations are read-only.  The CloudReadOnlyGuard is injected at
construction time; guard_operation() is called before every SDK call to
document intent (all calls here are read-only and will always be allowed,
but the guard enforces the contract for any future write operations).
"""

from __future__ import annotations

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
from utils.cloud.backoff import with_exponential_backoff
from utils.cloud.gcp_client import GCPGatewayClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Remediation strings
# ---------------------------------------------------------------------------

_REMEDIATION_SECURITY_DEF = (
    "Add a securityDefinitions section to your OpenAPI spec and reference it "
    "via the 'security' key on each path/method. "
    "GCP docs: https://cloud.google.com/api-gateway/docs/authenticating-users"
)
_REMEDIATION_HTTP_BACKEND = (
    "Update the x-google-backend address to use HTTPS instead of HTTP. "
    "GCP docs: https://cloud.google.com/api-gateway/docs/backend-auth"
)
_REMEDIATION_IAM_BINDING = (
    "Remove the IAM binding that grants 'allUsers' or 'allAuthenticatedUsers' "
    "the apigateway viewer or invoker role. "
    "CLI: gcloud projects remove-iam-policy-binding <project> "
    "--member=allUsers --role=<role>"
)
_REMEDIATION_ESP_VALIDATION = (
    "Enable API key or JWT validation in your Cloud Endpoints service config "
    "by adding an apiKey or oauth2/openIdConnect securityDefinition and "
    "referencing it from each path's security field. "
    "GCP docs: https://cloud.google.com/endpoints/docs/openapi/"
    "restricting-api-access-with-api-keys"
)


# ---------------------------------------------------------------------------
# Roles that constitute invoker/viewer access on GCP API Gateway
# ---------------------------------------------------------------------------

_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

_SENSITIVE_ROLE_FRAGMENTS = (
    "apigateway",
    "run.invoker",
    "cloudfunctions.invoker",
    "iam.serviceAccountUser",
    "viewer",
    "invoker",
)

# Security scheme types that satisfy Req 5.5 (API key or JWT/OAuth2)
_VALID_AUTH_SCHEME_TYPES = frozenset({"apiKey", "oauth2", "openIdConnect"})


class GCPGatewayAuditor(CloudGatewayAuditor):
    """
    Read-only auditor for GCP API Gateway configurations.

    Parameters
    ----------
    client:           GCPGatewayClient instance.
    guard:            CloudReadOnlyGuard (default: read-only).
    account_context:  Label for the GCP context being audited.
                      Defaults to ``"<project>/<location>"``.
    """

    def __init__(
        self,
        client: GCPGatewayClient,
        guard: CloudReadOnlyGuard | None = None,
        account_context: str | None = None,
    ) -> None:
        self._client = client
        self._guard = guard or CloudReadOnlyGuard(allow_destructive=False)
        self._account_context = (
            account_context or f"{client.project_id}/{client.location}"
        )

    # ------------------------------------------------------------------
    # CloudGatewayAuditor contract
    # ------------------------------------------------------------------

    def get_provider_name(self) -> str:
        return "gcp"

    async def discover_resources(self) -> list[dict[str, Any]]:
        """
        Enumerate auditable GCP API Gateway resources.

        Calls (in order):
        - list_gateways — deployed gateway instances
        - list_apis     — API definition objects
        - list_api_configs — versioned API configs that contain the OpenAPI spec
        """
        resources: list[dict[str, Any]] = []

        try:
            from google.cloud import apigateway_v1  # type: ignore[import]
        except ImportError:
            logger.warning(
                "google-cloud-api-gateway is not installed — skipping GCP discovery. "
                "Install it with: pip install apileaks[gcp]"
            )
            return resources

        parent = self._client.parent()

        # --- list_gateways ---
        self._guard.guard_operation("list_gateways")
        try:
            request = apigateway_v1.ListGatewaysRequest(parent=parent)
            for gw in self._client.gateway.list_gateways(request=request):
                resources.append(
                    {
                        "type": "gateway",
                        "name": gw.name,
                        "state": str(gw.state),
                        "api_config": getattr(gw, "api_config", None),
                    }
                )
        except Exception as exc:
            self._handle_gcp_error("list_gateways", exc)

        # --- list_apis ---
        self._guard.guard_operation("list_apis")
        try:
            request = apigateway_v1.ListApisRequest(parent=parent)
            for api in self._client.gateway.list_apis(request=request):
                resources.append(
                    {
                        "type": "api",
                        "name": api.name,
                        "display_name": getattr(api, "display_name", ""),
                    }
                )
        except Exception as exc:
            self._handle_gcp_error("list_apis", exc)

        # --- list_api_configs (wildcard across all APIs in the project) ---
        self._guard.guard_operation("list_api_configs")
        try:
            configs_parent = (
                f"projects/{self._client.project_id}"
                f"/locations/{self._client.location}/apis/-"
            )
            request = apigateway_v1.ListApiConfigsRequest(parent=configs_parent)
            for cfg in self._client.gateway.list_api_configs(request=request):
                resources.append(
                    {
                        "type": "api_config",
                        "name": cfg.name,
                        "state": str(getattr(cfg, "state", "")),
                    }
                )
        except Exception as exc:
            self._handle_gcp_error("list_api_configs", exc)

        logger.info(
            "GCP discovery complete",
            project=self._client.project_id,
            resource_count=len(resources),
        )
        return resources

    async def audit(self) -> list[GatewayFinding]:
        """Execute all GCP API Gateway security checks and return findings."""
        findings: list[GatewayFinding] = []

        try:
            from google.cloud import apigateway_v1  # type: ignore[import]
        except ImportError:
            logger.warning(
                "google-cloud-api-gateway is not installed — skipping GCP audit. "
                "Install it with: pip install apileaks[gcp]"
            )
            return findings

        # Enumerate API configs and run OpenAPI-level checks
        self._guard.guard_operation("list_api_configs")
        try:
            configs_parent = (
                f"projects/{self._client.project_id}"
                f"/locations/{self._client.location}/apis/-"
            )
            request = apigateway_v1.ListApiConfigsRequest(parent=configs_parent)

            def _list_configs():
                return list(self._client.gateway.list_api_configs(request=request))

            api_configs = await self._call_with_backoff(
                _list_configs, operation="list_api_configs"
            )
            if api_configs is None:
                api_configs = []

            for sdk_config in api_configs:
                api_config = self._normalize_config(sdk_config)

                # 5.1 / 5.2 — securityDefinitions and per-path security
                findings.extend(self._check_security_definitions(api_config))

                # 5.3 — backend over HTTP
                f = self._check_backend_http(api_config)
                if f:
                    findings.append(f)

                # 5.5 — API key / JWT validation for Cloud Endpoints
                f = self._check_api_key_jwt_validation(api_config)
                if f:
                    findings.append(f)

        except InsufficientPermissionsError:
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"projects/{self._client.project_id}",
                    resource_type="gcp_api_config",
                    provider="gcp",
                    account_context=self._account_context,
                    operation="list_api_configs",
                )
            )
        except ProviderThrottledError:
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"projects/{self._client.project_id}",
                    resource_type="gcp_api_config",
                    provider="gcp",
                    account_context=self._account_context,
                    operation="list_api_configs",
                )
            )
        except Exception as exc:
            self._handle_gcp_error("list_api_configs", exc)

        # 5.4 — IAM bindings at project level
        try:
            iam = self._client.iam

            def _get_iam_policy():
                return (
                    iam.projects()
                    .getIamPolicy(resource=self._client.project_id, body={})
                    .execute()
                )

            policy = await self._call_with_backoff(
                _get_iam_policy, operation="getIamPolicy"
            )
            if policy is not None:
                resource_name = f"projects/{self._client.project_id}"
                findings.extend(self._check_iam_bindings(resource_name, policy))
        except InsufficientPermissionsError:
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"projects/{self._client.project_id}",
                    resource_type="gcp_iam_binding",
                    provider="gcp",
                    account_context=self._account_context,
                    operation="getIamPolicy",
                )
            )
        except ProviderThrottledError:
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"projects/{self._client.project_id}",
                    resource_type="gcp_iam_binding",
                    provider="gcp",
                    account_context=self._account_context,
                    operation="getIamPolicy",
                )
            )
        except ImportError:
            logger.warning(
                "google-api-python-client not installed — skipping IAM binding check."
            )
        except Exception as exc:
            self._handle_gcp_error("getIamPolicy", exc)

        logger.info(
            "GCP audit complete",
            project=self._client.project_id,
            finding_count=len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_config(self, sdk_config: Any) -> dict[str, Any]:
        """
        Convert an SDK ApiConfig object to a plain dict for the check methods.

        The returned dict always has:
        - ``name``:        full resource name of the config
        - ``openapi_doc``: parsed OpenAPI YAML/JSON as a dict, or ``None``
        """
        result: dict[str, Any] = {"name": sdk_config.name, "openapi_doc": None}
        for openapi_doc in getattr(sdk_config, "openapi_documents", []):
            try:
                import yaml  # already in project requirements

                raw = openapi_doc.document.contents
                if isinstance(raw, bytes | bytearray):
                    raw = raw.decode("utf-8")
                doc = yaml.safe_load(raw)
                result["openapi_doc"] = doc
                break  # use the first document only
            except Exception:
                continue
        return result

    # ------------------------------------------------------------------
    # Check 5.1 / 5.2 — securityDefinitions and per-path security
    # ------------------------------------------------------------------

    def _check_security_definitions(self, api_config: dict) -> list[GatewayFinding]:
        """
        Return HIGH findings when the OpenAPI spec is missing securityDefinitions
        or when individual path operations have no security requirement (Req 5.1, 5.2).

        One finding is emitted per unsecured path (not per method) to keep noise low.
        If the entire securityDefinitions block is absent, one finding is emitted for
        the whole config instead of per-path findings.
        """
        findings: list[GatewayFinding] = []
        doc = api_config.get("openapi_doc")
        config_name = api_config["name"]

        if not doc:
            return findings

        # OpenAPI 2.0 uses securityDefinitions; 3.0 uses components.securitySchemes
        sec_defs = doc.get("securityDefinitions") or doc.get(
            "components", {}
        ).get("securitySchemes")

        if not sec_defs:
            # Whole spec has no security definitions at all → one high-level finding
            findings.append(
                GatewayFinding(
                    provider="gcp",
                    resource_id=config_name,
                    resource_type="gcp_api_config",
                    check_id="gcp_apigw_no_security_definitions",
                    title="GCP API config has no securityDefinitions / security schemes",
                    severity=GatewaySeverity.HIGH,
                    evidence={
                        "config_name": config_name,
                        "openapi_version": doc.get("swagger") or doc.get("openapi"),
                    },
                    remediation=_REMEDIATION_SECURITY_DEF,
                    account_context=self._account_context,
                )
            )
            return findings

        # securityDefinitions exist — check every path for a security requirement
        global_security = doc.get("security")
        paths = doc.get("paths", {})
        reported_paths: set[str] = set()

        for path, path_item in paths.items():
            if not isinstance(path_item, dict) or path in reported_paths:
                continue

            path_missing_security = False
            for _method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                # Each operation can override global security; absence means
                # it inherits from the top-level `security` key. If neither
                # the operation nor the global security is set, it is unprotected.
                op_security = operation.get("security")
                if op_security is None and not global_security:
                    path_missing_security = True
                    break
                # An empty list [] explicitly disables security for the operation
                if op_security == []:
                    path_missing_security = True
                    break

            if path_missing_security:
                reported_paths.add(path)
                findings.append(
                    GatewayFinding(
                        provider="gcp",
                        resource_id=config_name,
                        resource_type="gcp_api_config",
                        check_id="gcp_apigw_path_no_security_requirement",
                        title=f"GCP API config path '{path}' has no security requirement",
                        severity=GatewaySeverity.HIGH,
                        evidence={
                            "config_name": config_name,
                            "path": path,
                            "has_global_security": bool(global_security),
                        },
                        remediation=_REMEDIATION_SECURITY_DEF,
                        account_context=self._account_context,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Check 5.3 — backend over HTTP
    # ------------------------------------------------------------------

    def _check_backend_http(self, api_config: dict) -> GatewayFinding | None:
        """
        Return a HIGH finding if the x-google-backend address uses plain HTTP
        instead of HTTPS (Req 5.3).
        """
        doc = api_config.get("openapi_doc")
        config_name = api_config["name"]

        if not doc:
            return None

        backend = doc.get("x-google-backend")
        if not isinstance(backend, dict):
            return None

        address = backend.get("address", "")
        if not isinstance(address, str) or not address.startswith("http://"):
            return None

        return GatewayFinding(
            provider="gcp",
            resource_id=config_name,
            resource_type="gcp_api_config",
            check_id="gcp_apigw_http_backend",
            title="GCP API Gateway backend uses HTTP (not HTTPS)",
            severity=GatewaySeverity.HIGH,
            evidence={
                "config_name": config_name,
                "backend_address": address,
            },
            remediation=_REMEDIATION_HTTP_BACKEND,
            account_context=self._account_context,
        )

    # ------------------------------------------------------------------
    # Check 5.4 — IAM bindings to allUsers / allAuthenticatedUsers
    # ------------------------------------------------------------------

    def _check_iam_bindings(
        self, resource_name: str, policy: dict
    ) -> list[GatewayFinding]:
        """
        Return CRITICAL findings for any IAM binding that grants an invoker/
        viewer role to ``allUsers`` or ``allAuthenticatedUsers`` (Req 5.4).

        Parameters
        ----------
        resource_name:  GCP resource path, e.g. ``"projects/my-project"``.
        policy:         Decoded IAM policy dict (from Cloud Resource Manager API).
        """
        findings: list[GatewayFinding] = []

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            members: list[str] = binding.get("members", [])

            public_members = [m for m in members if m in _PUBLIC_MEMBERS]
            if not public_members:
                continue

            if not any(frag in role for frag in _SENSITIVE_ROLE_FRAGMENTS):
                continue

            findings.append(
                GatewayFinding(
                    provider="gcp",
                    resource_id=resource_name,
                    resource_type="gcp_iam_binding",
                    check_id="gcp_apigw_iam_public_invoker",
                    title=(
                        f"GCP IAM grants public access via role '{role}' "
                        f"to {public_members}"
                    ),
                    severity=GatewaySeverity.CRITICAL,
                    evidence={
                        "resource": resource_name,
                        "role": role,
                        "public_members": public_members,
                    },
                    remediation=_REMEDIATION_IAM_BINDING,
                    account_context=self._account_context,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Check 5.5 — API key / JWT validation for Cloud Endpoints
    # ------------------------------------------------------------------

    def _check_api_key_jwt_validation(
        self, api_config: dict
    ) -> GatewayFinding | None:
        """
        Return a HIGH finding when the OpenAPI spec defines no apiKey, OAuth2,
        or OpenID Connect security scheme — meaning Cloud Endpoints (ESPv2)
        will not enforce any token/key validation (Req 5.5).

        If securityDefinitions is absent entirely, ``_check_security_definitions``
        already reports it; this check only fires when schemes exist but none
        of them is a recognised authentication type.
        """
        doc = api_config.get("openapi_doc")
        config_name = api_config["name"]

        if not doc:
            return None

        sec_defs = doc.get("securityDefinitions") or doc.get(
            "components", {}
        ).get("securitySchemes")

        if not sec_defs:
            # Already reported by _check_security_definitions; don't double-report
            return None

        has_valid_scheme = any(
            scheme.get("type") in _VALID_AUTH_SCHEME_TYPES
            or "x-google-jwt-locations" in scheme
            for scheme in sec_defs.values()
            if isinstance(scheme, dict)
        )

        if has_valid_scheme:
            return None

        defined_types = [
            s.get("type", "unknown")
            for s in sec_defs.values()
            if isinstance(s, dict)
        ]
        return GatewayFinding(
            provider="gcp",
            resource_id=config_name,
            resource_type="gcp_api_config",
            check_id="gcp_apigw_no_api_key_or_jwt_validation",
            title=(
                "GCP API config defines no API key, JWT, or OAuth2 security scheme "
                "— Cloud Endpoints will not enforce token/key validation"
            ),
            severity=GatewaySeverity.HIGH,
            evidence={
                "config_name": config_name,
                "defined_scheme_types": defined_types,
            },
            remediation=_REMEDIATION_ESP_VALIDATION,
            account_context=self._account_context,
        )

    # ------------------------------------------------------------------
    # Resilient call helper (backoff + error conversion)
    # ------------------------------------------------------------------

    async def _call_with_backoff(
        self,
        fn: Any,
        *args: Any,
        operation: str,
        **kwargs: Any,
    ) -> Any:
        """
        Call *fn* with exponential backoff on :class:`ProviderThrottledError`.

        Converts Google API exceptions to the appropriate
        :class:`InsufficientPermissionsError` or :class:`ProviderThrottledError`
        before retrying.

        Parameters
        ----------
        fn:        Sync or async callable.
        operation: Human-readable name used in log messages.
        """

        def _call() -> Any:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                self._handle_gcp_error(operation, exc)
                return None  # only reached for non-fatal (logged) errors

        return await with_exponential_backoff(_call, retry_on=ProviderThrottledError)

    # ------------------------------------------------------------------
    # Error handling (Requirement 9)
    # ------------------------------------------------------------------

    def _handle_gcp_error(self, operation: str, exc: Exception) -> None:
        """
        Log and re-raise as the appropriate CloudAuditError subclass.

        Non-fatal: callers catch CloudAuditError when they want to continue
        the audit past a failed operation.
        """
        exc_type = type(exc).__name__
        error_str = str(exc).lower()

        # Check for Google API Core exception types by class name (avoid hard
        # import of google.api_core.exceptions so the module still loads when
        # the GCP SDK is not installed).
        is_permission_denied = (
            exc_type in ("PermissionDenied", "Forbidden")
            or "permission" in error_str
            or "forbidden" in error_str
            or "403" in error_str
            or "permission_denied" in error_str
        )
        is_throttled = (
            exc_type in ("ResourceExhausted", "TooManyRequests")
            or "resource_exhausted" in error_str
            or "quota" in error_str
            or "429" in error_str
            or "rate limit" in error_str
            or "rateLimitExceeded" in error_str.replace("_", "")
        )

        if is_throttled:
            logger.warning(
                "GCP operation throttled — will retry with backoff",
                operation=operation,
                error=str(exc),
                project=self._client.project_id,
            )
            raise ProviderThrottledError(str(exc)) from exc

        if is_permission_denied:
            logger.warning(
                "Insufficient GCP permissions for operation",
                operation=operation,
                error=str(exc),
                project=self._client.project_id,
            )
            raise InsufficientPermissionsError(str(exc)) from exc

        logger.warning(
            "GCP operation failed (non-fatal, continuing audit)",
            operation=operation,
            error=str(exc),
            project=self._client.project_id,
        )
