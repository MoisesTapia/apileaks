"""
tests/cloud/test_gcp_api_gateway.py
Unit tests for GCPGatewayAuditor individual checks.

Coverage (per spec Requirements 5.1 – 5.5, 10.1, 10.2):
  - _check_security_definitions  (Requirements 5.1, 5.2)
  - _check_backend_http          (Requirement 5.3)
  - _check_iam_bindings          (Requirement 5.4)
  - _check_api_key_jwt_validation (Requirement 5.5)
  - discover_resources           (async, Requirement 10.1)
  - audit integration            (async, Requirement 10.1)

All GCP SDK calls are mocked with unittest.mock — no real credentials or
network access is needed.  The entire module is skipped gracefully when the
google-cloud-api-gateway SDK is not installed (Requirement 10.2).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

# GCP SDK is an optional extra; skip this entire module if not installed.
pytest.importorskip("google.cloud.apigateway_v1")

from modules.cloud.base import GatewaySeverity, InsufficientPermissionsError
from modules.cloud.gcp_api_gateway import GCPGatewayAuditor
from utils.cloud.readonly_guard import CloudReadOnlyGuard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor() -> tuple[GCPGatewayAuditor, MagicMock]:
    """Return a GCPGatewayAuditor with a fully mocked GCPGatewayClient."""
    mock_client = MagicMock()
    mock_client.project_id = "test-project"
    mock_client.location = "global"
    mock_client.parent.return_value = "projects/test-project/locations/global"

    guard = CloudReadOnlyGuard(allow_destructive=False)
    auditor = GCPGatewayAuditor(
        client=mock_client,
        guard=guard,
        account_context="test-project/global",
    )
    return auditor, mock_client


def _api_config(
    name: str = "projects/test-project/locations/global/apis/my-api/configs/v1",
    openapi_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a plain api_config dict as produced by _normalize_config."""
    return {"name": name, "openapi_doc": openapi_doc}


def _make_sdk_config(name: str, openapi_yaml: str | None = None) -> MagicMock:
    """
    Build a mock SDK ApiConfig object that _normalize_config can parse.

    If *openapi_yaml* is supplied it is stored in
    ``openapi_documents[0].document.contents`` (bytes) so that
    ``_normalize_config`` can parse it via PyYAML.
    """
    cfg = MagicMock()
    cfg.name = name
    cfg.state = "ACTIVE"
    if openapi_yaml is None:
        cfg.openapi_documents = []
    else:
        mock_inner_doc = MagicMock()
        mock_inner_doc.contents = openapi_yaml.encode("utf-8")
        mock_openapi_doc = MagicMock()
        mock_openapi_doc.document = mock_inner_doc
        cfg.openapi_documents = [mock_openapi_doc]
    return cfg


# ---------------------------------------------------------------------------
# Check 5.1 / 5.2 — _check_security_definitions
# ---------------------------------------------------------------------------


class TestCheckSecurityDefinitions:
    """GCPGatewayAuditor._check_security_definitions (Requirements 5.1, 5.2)."""

    # ------------------------------------------------------------------ clean

    def test_no_openapi_doc_returns_empty_list(self):
        """Config without openapi_doc → no findings (nothing to inspect)."""
        auditor, _ = _make_auditor()
        findings = auditor._check_security_definitions(_api_config(openapi_doc=None))
        assert findings == []

    def test_global_security_with_definitions_clean(self):
        """Global security + securityDefinitions present → no findings."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
            },
            "security": [{"apiKey": []}],
            "paths": {
                "/users": {"get": {"operationId": "listUsers"}},
                "/users/{id}": {"put": {"operationId": "updateUser"}},
            },
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert findings == []

    def test_per_operation_security_clean(self):
        """All path operations carry their own security key → no findings."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {"jwt": {"type": "oauth2"}},
            "paths": {
                "/users": {
                    "get": {"security": [{"jwt": []}]},
                    "post": {"security": [{"jwt": ["write"]}]},
                },
            },
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert findings == []

    # --------------------------------------------------------------- vulnerable

    def test_missing_security_definitions_emits_high_finding(self):
        """OpenAPI 2.0 with no securityDefinitions → single HIGH finding."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {"/users": {"get": {"operationId": "listUsers"}}},
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == GatewaySeverity.HIGH
        assert f.check_id == "gcp_apigw_no_security_definitions"
        assert f.provider == "gcp"

    def test_oas3_missing_security_schemes_emits_high_finding(self):
        """OpenAPI 3.0 with no components.securitySchemes → HIGH finding."""
        auditor, _ = _make_auditor()
        doc = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {"/items": {"get": {}}},
            "components": {},
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert len(findings) == 1
        assert findings[0].check_id == "gcp_apigw_no_security_definitions"

    def test_path_with_empty_security_list_emits_finding(self):
        """securityDefinitions present but an operation has security: [] → HIGH per path."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
            },
            "paths": {
                "/users": {
                    "post": {"operationId": "createUser", "security": []},
                },
                "/items": {
                    "get": {"operationId": "listItems", "security": [{"apiKey": []}]},
                },
            },
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "gcp_apigw_path_no_security_requirement"
        assert "/users" in f.title
        assert f.severity == GatewaySeverity.HIGH

    def test_path_no_security_key_and_no_global_security_emits_finding(self):
        """securityDefinitions present, no global security, path op lacks security key → HIGH."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {"jwt": {"type": "oauth2"}},
            "paths": {
                "/admin": {"delete": {"operationId": "deleteAdmin"}},
            },
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert len(findings) == 1
        assert findings[0].check_id == "gcp_apigw_path_no_security_requirement"

    def test_multiple_unsecured_paths_produce_one_finding_each(self):
        """Two unsecured paths → two findings (one per path, not per method)."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
            },
            "paths": {
                "/path-a": {"post": {}},
                "/path-b": {"delete": {}},
            },
        }
        findings = auditor._check_security_definitions(_api_config(openapi_doc=doc))
        assert len(findings) == 2
        paths_reported = {f.evidence["path"] for f in findings}
        assert "/path-a" in paths_reported
        assert "/path-b" in paths_reported


# ---------------------------------------------------------------------------
# Check 5.3 — _check_backend_http
# ---------------------------------------------------------------------------


class TestCheckBackendHTTP:
    """GCPGatewayAuditor._check_backend_http (Requirement 5.3)."""

    # ------------------------------------------------------------------ clean

    def test_https_backend_clean(self):
        """x-google-backend.address starts with https:// → no finding."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "x-google-backend": {"address": "https://my-backend.internal/api"},
        }
        assert auditor._check_backend_http(_api_config(openapi_doc=doc)) is None

    def test_no_google_backend_key_clean(self):
        """No x-google-backend key → no finding."""
        auditor, _ = _make_auditor()
        doc = {"swagger": "2.0", "paths": {}}
        assert auditor._check_backend_http(_api_config(openapi_doc=doc)) is None

    def test_no_openapi_doc_clean(self):
        """Config without openapi_doc → no finding."""
        auditor, _ = _make_auditor()
        assert auditor._check_backend_http(_api_config(openapi_doc=None)) is None

    def test_google_backend_not_dict_clean(self):
        """x-google-backend is a string (malformed) → no finding."""
        auditor, _ = _make_auditor()
        doc = {"swagger": "2.0", "x-google-backend": "not-a-dict"}
        assert auditor._check_backend_http(_api_config(openapi_doc=doc)) is None

    # --------------------------------------------------------------- vulnerable

    def test_http_backend_emits_high_finding(self):
        """x-google-backend.address starts with http:// → HIGH finding."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "x-google-backend": {"address": "http://my-backend.internal/api"},
        }
        finding = auditor._check_backend_http(_api_config(openapi_doc=doc))
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "gcp_apigw_http_backend"
        assert finding.evidence["backend_address"] == "http://my-backend.internal/api"

    def test_http_backend_finding_has_correct_provider_and_resource(self):
        """HTTP backend finding carries the right provider and resource_id."""
        auditor, _ = _make_auditor()
        config_name = "projects/test-project/locations/global/apis/api1/configs/v1"
        doc = {
            "swagger": "2.0",
            "x-google-backend": {"address": "http://insecure.example.com"},
        }
        finding = auditor._check_backend_http(_api_config(name=config_name, openapi_doc=doc))
        assert finding is not None
        assert finding.provider == "gcp"
        assert finding.resource_id == config_name


# ---------------------------------------------------------------------------
# Check 5.4 — _check_iam_bindings
# ---------------------------------------------------------------------------


class TestCheckIAMBindings:
    """GCPGatewayAuditor._check_iam_bindings (Requirement 5.4)."""

    # ------------------------------------------------------------------ clean

    def test_no_public_members_clean(self):
        """Binding with only service accounts → no finding."""
        auditor, _ = _make_auditor()
        policy = {
            "bindings": [
                {
                    "role": "roles/apigateway.viewer",
                    "members": [
                        "serviceAccount:sa@project.iam.gserviceaccount.com",
                        "user:admin@example.com",
                    ],
                }
            ]
        }
        assert auditor._check_iam_bindings("projects/test-project", policy) == []

    def test_allUsers_on_non_sensitive_role_clean(self):
        """allUsers on roles/storage.objectViewer (not gateway-related) → no finding."""
        auditor, _ = _make_auditor()
        policy = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
            ]
        }
        assert auditor._check_iam_bindings("projects/test-project", policy) == []

    def test_empty_bindings_clean(self):
        """Policy with empty bindings list → no finding."""
        auditor, _ = _make_auditor()
        assert auditor._check_iam_bindings("projects/test-project", {"bindings": []}) == []

    # --------------------------------------------------------------- vulnerable

    def test_allUsers_apigateway_viewer_emits_critical(self):
        """allUsers + roles/apigateway.viewer → CRITICAL finding."""
        auditor, _ = _make_auditor()
        policy = {
            "bindings": [
                {
                    "role": "roles/apigateway.viewer",
                    "members": [
                        "serviceAccount:sa@example.iam.gserviceaccount.com",
                        "allUsers",
                    ],
                }
            ]
        }
        findings = auditor._check_iam_bindings("projects/test-project", policy)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == GatewaySeverity.CRITICAL
        assert f.check_id == "gcp_apigw_iam_public_invoker"
        assert "allUsers" in f.evidence["public_members"]

    def test_allAuthenticatedUsers_invoker_role_emits_critical(self):
        """allAuthenticatedUsers + roles/run.invoker → CRITICAL finding."""
        auditor, _ = _make_auditor()
        policy = {
            "bindings": [
                {"role": "roles/run.invoker", "members": ["allAuthenticatedUsers"]}
            ]
        }
        findings = auditor._check_iam_bindings("projects/test-project", policy)
        assert len(findings) == 1
        assert findings[0].severity == GatewaySeverity.CRITICAL
        assert "allAuthenticatedUsers" in findings[0].evidence["public_members"]

    def test_finding_includes_role_and_resource_in_evidence(self):
        """Finding evidence contains the role name and resource path."""
        auditor, _ = _make_auditor()
        policy = {
            "bindings": [
                {"role": "roles/apigateway.viewer", "members": ["allUsers"]}
            ]
        }
        resource_name = "projects/my-project"
        findings = auditor._check_iam_bindings(resource_name, policy)
        assert len(findings) == 1
        assert findings[0].evidence["role"] == "roles/apigateway.viewer"
        assert findings[0].evidence["resource"] == resource_name

    def test_two_sensitive_bindings_produce_two_findings(self):
        """Two bindings each with a public member on a sensitive role → two findings."""
        auditor, _ = _make_auditor()
        policy = {
            "bindings": [
                {"role": "roles/apigateway.viewer", "members": ["allUsers"]},
                {"role": "roles/run.invoker", "members": ["allAuthenticatedUsers"]},
            ]
        }
        findings = auditor._check_iam_bindings("projects/test-project", policy)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Check 5.5 — _check_api_key_jwt_validation
# ---------------------------------------------------------------------------


class TestCheckAPIKeyJWTValidation:
    """GCPGatewayAuditor._check_api_key_jwt_validation (Requirement 5.5)."""

    # ------------------------------------------------------------------ clean

    def test_api_key_scheme_clean(self):
        """securityDefinitions with type=apiKey → no finding."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            },
        }
        assert auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc)) is None

    def test_oauth2_scheme_clean(self):
        """securityDefinitions with type=oauth2 → no finding."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "oauth2Auth": {"type": "oauth2", "flow": "implicit"},
            },
        }
        assert auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc)) is None

    def test_oidc_scheme_clean(self):
        """OpenAPI 3.0 securitySchemes with type=openIdConnect → no finding."""
        auditor, _ = _make_auditor()
        doc = {
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "oidcAuth": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://accounts.google.com/.well-known/openid-configuration",
                    }
                }
            },
        }
        assert auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc)) is None

    def test_x_google_jwt_locations_extension_clean(self):
        """Scheme with x-google-jwt-locations → no finding (GCP-specific JWT ext)."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "jwtAuth": {
                    "type": "basic",
                    "x-google-jwt-locations": [{"header": "Authorization"}],
                },
            },
        }
        assert auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc)) is None

    def test_no_openapi_doc_clean(self):
        """Config without openapi_doc → no finding."""
        auditor, _ = _make_auditor()
        assert auditor._check_api_key_jwt_validation(_api_config(openapi_doc=None)) is None

    def test_absent_security_definitions_no_double_report(self):
        """No securityDefinitions → None (check 5.1/5.2 already handles this)."""
        auditor, _ = _make_auditor()
        doc = {"swagger": "2.0", "paths": {}}
        assert auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc)) is None

    # --------------------------------------------------------------- vulnerable

    def test_no_valid_auth_scheme_emits_high_finding(self):
        """securityDefinitions present but only 'basic' type → HIGH finding."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "basicAuth": {"type": "basic"},
            },
        }
        finding = auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc))
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "gcp_apigw_no_api_key_or_jwt_validation"
        assert "basic" in finding.evidence["defined_scheme_types"]

    def test_finding_includes_defined_scheme_types(self):
        """The finding lists the actual (invalid) scheme types found."""
        auditor, _ = _make_auditor()
        doc = {
            "swagger": "2.0",
            "securityDefinitions": {
                "custom1": {"type": "http"},
                "custom2": {"type": "mutualTLS"},
            },
        }
        finding = auditor._check_api_key_jwt_validation(_api_config(openapi_doc=doc))
        assert finding is not None
        defined = finding.evidence["defined_scheme_types"]
        assert set(defined) == {"http", "mutualTLS"}


# ---------------------------------------------------------------------------
# discover_resources (async)
# ---------------------------------------------------------------------------


class TestDiscoverResources:
    """GCPGatewayAuditor.discover_resources (async, Requirement 10.1)."""

    @pytest.mark.asyncio
    async def test_returns_all_resource_types(self):
        """discover_resources aggregates gateways, apis, and api_configs."""
        auditor, mock_client = _make_auditor()

        mock_gw = MagicMock()
        mock_gw.name = "projects/test-project/locations/global/gateways/gw1"
        mock_gw.state = "ACTIVE"

        mock_api = MagicMock()
        mock_api.name = "projects/test-project/locations/global/apis/api1"
        mock_api.display_name = "My API"

        mock_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1"
        )

        mock_client.gateway.list_gateways.return_value = [mock_gw]
        mock_client.gateway.list_apis.return_value = [mock_api]
        mock_client.gateway.list_api_configs.return_value = [mock_cfg]

        resources = await auditor.discover_resources()
        types = {r["type"] for r in resources}
        assert "gateway" in types
        assert "api" in types
        assert "api_config" in types

    @pytest.mark.asyncio
    async def test_gateway_resource_has_expected_fields(self):
        """Gateway resource dict contains name, state, type, and api_config fields."""
        auditor, mock_client = _make_auditor()

        mock_gw = MagicMock()
        mock_gw.name = "projects/p/locations/global/gateways/gw1"
        mock_gw.state = "ACTIVE"
        mock_gw.api_config = "projects/p/locations/global/apis/a/configs/v1"

        mock_client.gateway.list_gateways.return_value = [mock_gw]
        mock_client.gateway.list_apis.return_value = []
        mock_client.gateway.list_api_configs.return_value = []

        resources = await auditor.discover_resources()
        gw_resources = [r for r in resources if r["type"] == "gateway"]
        assert len(gw_resources) == 1
        assert gw_resources[0]["name"] == mock_gw.name
        assert gw_resources[0]["api_config"] == mock_gw.api_config

    @pytest.mark.asyncio
    async def test_sdk_error_on_list_api_configs_returns_partial_results(self):
        """A generic SDK error on list_api_configs does not crash; gateways are still returned."""
        auditor, mock_client = _make_auditor()

        mock_gw = MagicMock()
        mock_gw.name = "projects/p/locations/global/gateways/gw1"
        mock_gw.state = "ACTIVE"

        mock_client.gateway.list_gateways.return_value = [mock_gw]
        mock_client.gateway.list_apis.return_value = []
        mock_client.gateway.list_api_configs.side_effect = Exception("transient SDK error")

        # Must not raise
        resources = await auditor.discover_resources()
        assert any(r["type"] == "gateway" for r in resources)


# ---------------------------------------------------------------------------
# audit() — integration tests (async)
# ---------------------------------------------------------------------------


class TestAuditIntegration:
    """End-to-end audit() tests that drive through _normalize_config and all checks."""

    # -----------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _wire_iam(mock_client: MagicMock, bindings: list) -> None:
        """Configure mock_client.iam to return the given IAM policy."""
        (
            mock_client.iam.projects.return_value.getIamPolicy.return_value.execute.return_value
        ) = {"bindings": bindings}

    _CLEAN_OPENAPI = """
swagger: "2.0"
securityDefinitions:
  apiKey:
    type: apiKey
    in: header
    name: X-API-Key
security:
  - apiKey: []
x-google-backend:
  address: https://secure.backend.example.com/api
paths:
  /users:
    get:
      operationId: listUsers
"""

    # -----------------------------------------------------------------
    # Clean-config baseline
    # -----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_clean_config_produces_no_findings(self):
        """Valid security + HTTPS backend + non-public IAM → zero findings."""
        auditor, mock_client = _make_auditor()

        sdk_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1",
            openapi_yaml=self._CLEAN_OPENAPI,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg]
        self._wire_iam(mock_client, bindings=[
            {
                "role": "roles/apigateway.viewer",
                "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"],
            }
        ])

        findings = await auditor.audit()
        assert findings == []

    # -----------------------------------------------------------------
    # Individual checks fire correctly through audit()
    # -----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_http_backend_in_yaml_produces_finding(self):
        """Config with HTTP backend address → gcp_apigw_http_backend finding."""
        auditor, mock_client = _make_auditor()

        yaml_with_http = """
swagger: "2.0"
securityDefinitions:
  apiKey:
    type: apiKey
    in: header
    name: X-API-Key
security:
  - apiKey: []
x-google-backend:
  address: http://insecure.backend.example.com/api
paths: {}
"""
        sdk_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1",
            openapi_yaml=yaml_with_http,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg]
        self._wire_iam(mock_client, bindings=[])

        findings = await auditor.audit()
        assert any(f.check_id == "gcp_apigw_http_backend" for f in findings)

    @pytest.mark.asyncio
    async def test_no_security_definitions_produces_finding(self):
        """Config with no securityDefinitions → gcp_apigw_no_security_definitions finding."""
        auditor, mock_client = _make_auditor()

        yaml_no_sec_defs = """
swagger: "2.0"
paths:
  /data:
    post:
      operationId: postData
"""
        sdk_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1",
            openapi_yaml=yaml_no_sec_defs,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg]
        self._wire_iam(mock_client, bindings=[])

        findings = await auditor.audit()
        assert any(f.check_id == "gcp_apigw_no_security_definitions" for f in findings)

    @pytest.mark.asyncio
    async def test_public_iam_binding_produces_critical_finding(self):
        """allUsers on invoker role → CRITICAL finding from audit()."""
        auditor, mock_client = _make_auditor()

        sdk_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1",
            openapi_yaml=self._CLEAN_OPENAPI,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg]
        self._wire_iam(mock_client, bindings=[
            {"role": "roles/apigateway.viewer", "members": ["allUsers"]}
        ])

        findings = await auditor.audit()
        critical = [f for f in findings if f.severity == GatewaySeverity.CRITICAL]
        assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_findings_combined_from_multiple_configs(self):
        """Two API configs each with issues → findings from both appear in results."""
        auditor, mock_client = _make_auditor()

        cfg1_yaml = """
swagger: "2.0"
securityDefinitions:
  apiKey:
    type: apiKey
    in: header
    name: X-API-Key
security:
  - apiKey: []
x-google-backend:
  address: http://insecure1.example.com
paths: {}
"""
        cfg2_yaml = """
swagger: "2.0"
paths:
  /admin:
    delete: {}
"""
        sdk_cfg1 = _make_sdk_config(
            "projects/p/locations/global/apis/api1/configs/v1",
            openapi_yaml=cfg1_yaml,
        )
        sdk_cfg2 = _make_sdk_config(
            "projects/p/locations/global/apis/api2/configs/v1",
            openapi_yaml=cfg2_yaml,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg1, sdk_cfg2]
        self._wire_iam(mock_client, bindings=[])

        findings = await auditor.audit()
        check_ids = {f.check_id for f in findings}
        assert "gcp_apigw_http_backend" in check_ids
        assert "gcp_apigw_no_security_definitions" in check_ids

    # -----------------------------------------------------------------
    # Error-resilience: InsufficientPermissionsError (Requirement 9.1)
    # -----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_permission_denied_on_list_api_configs_produces_info_finding(self):
        """InsufficientPermissionsError from list_api_configs → INFO finding, no exception."""
        auditor, mock_client = _make_auditor()

        mock_client.gateway.list_api_configs.side_effect = InsufficientPermissionsError(
            "403 Forbidden"
        )
        self._wire_iam(mock_client, bindings=[])

        findings = await auditor.audit()  # must not raise

        info = [f for f in findings if f.severity == GatewaySeverity.INFO]
        assert len(info) >= 1
        assert any("permission" in f.title.lower() for f in info)

    @pytest.mark.asyncio
    async def test_permission_denied_on_iam_produces_info_finding(self):
        """InsufficientPermissionsError from IAM getIamPolicy → INFO finding, no exception."""
        auditor, mock_client = _make_auditor()

        sdk_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1",
            openapi_yaml=self._CLEAN_OPENAPI,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg]
        (
            mock_client.iam.projects.return_value.getIamPolicy.return_value.execute.side_effect
        ) = InsufficientPermissionsError("403 iam.getIamPolicy denied")

        findings = await auditor.audit()  # must not raise

        info = [f for f in findings if f.severity == GatewaySeverity.INFO]
        assert len(info) >= 1

    @pytest.mark.asyncio
    async def test_config_without_openapi_doc_produces_no_spurious_findings(self):
        """API config with no openapi_documents → no findings (graceful skip)."""
        auditor, mock_client = _make_auditor()

        # SDK config with empty openapi_documents
        sdk_cfg = _make_sdk_config(
            "projects/test-project/locations/global/apis/api1/configs/v1",
            openapi_yaml=None,
        )
        mock_client.gateway.list_api_configs.return_value = [sdk_cfg]
        self._wire_iam(mock_client, bindings=[])

        findings = await auditor.audit()
        # Only IAM findings are possible here; there should be none (clean IAM)
        assert findings == []
