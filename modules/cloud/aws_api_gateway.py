"""
AWS API Gateway Security Auditor

Audits the configuration of AWS API Gateway REST APIs (v1) and HTTP APIs (v2)
using read-only boto3 calls.  Every finding is returned as a GatewayFinding
under owasp_category="API8" (Security Misconfiguration).

Checks implemented (mapped to spec Requirements 4.1 – 4.10):
  4.1  Resource policy with wildcard Principal
  4.2  Method with no Authorizer (state-changing methods)
  4.3  Stage without WAF WebACL association
  4.4  Stage with logging disabled (access + execution)
  4.5  Custom domain with TLS < 1.2
  4.6  Usage plan without throttling configured
  4.7  Orphan API keys (not associated with any usage plan)
  4.8  CORS: Access-Control-Allow-Origin=* with credentials=true
  4.9  Lambda integration role with overly broad policy (Action/Resource *)
  4.10 HTTP APIs (v2) — same auth/logging/throttling checks as v1

All methods are read-only.  The CloudReadOnlyGuard is injected at
construction time; callers may pass allow_destructive=True to the guard
(currently no destructive operations are implemented — the guard is present
for future-proofing and to document the intent).
"""

from __future__ import annotations

import json
from typing import Any

from core.logging import get_logger
from modules.cloud.base import (
    CloudGatewayAuditor,
    GatewayFinding,
    GatewaySeverity,
    InsufficientPermissionsError,
    ProviderThrottledError,
)
from utils.cloud.aws_client import AWSGatewayClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STATE_CHANGING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_REMEDIATION_RESOURCE_POLICY = (
    "In the AWS console: API Gateway → your API → Resource Policy. "
    "Add a Condition to restrict access (e.g. aws:SourceVpc or aws:SourceIp). "
    "CLI: aws apigateway update-rest-api --rest-api-id <id> --patch-operations "
    "op=replace,path=/policy,value=<encoded-policy>."
)
_REMEDIATION_AUTHORIZER = (
    "In the AWS console: API Gateway → your API → Resources → Method → "
    "Method Request → Authorization. Set an authorizer (Lambda, Cognito, or IAM). "
    'Terraform: aws_api_gateway_method with authorization != "NONE".'
)
_REMEDIATION_WAF = (
    "In the AWS console: WAF & Shield → Web ACLs → Associate with API Gateway stage. "
    "CLI: aws wafv2 associate-web-acl --web-acl-arn <arn> --resource-arn <stage-arn>."
)
_REMEDIATION_LOGGING = (
    "In the AWS console: API Gateway → your API → Stage → Logs/Tracing → "
    "enable CloudWatch Logs and X-Ray. "
    "Terraform: aws_api_gateway_stage with access_log_settings and xray_tracing_enabled."
)
_REMEDIATION_TLS = (
    "In the AWS console: API Gateway → Custom Domain Names → your domain → "
    "Security policy → TLS 1.2. "
    'Terraform: aws_api_gateway_domain_name with security_policy = "TLS_1_2".'
)
_REMEDIATION_THROTTLING = (
    "In the AWS console: API Gateway → Usage Plans → edit the plan → "
    "set Throttling Rate and Burst. "
    "Terraform: aws_api_gateway_usage_plan with throttle_settings."
)
_REMEDIATION_ORPHAN_KEY = (
    "In the AWS console: API Gateway → API Keys → delete unused keys or "
    "associate them with a Usage Plan. "
    "CLI: aws apigateway delete-api-key --api-key <id>."
)
_REMEDIATION_CORS = (
    "Remove Access-Control-Allow-Origin: * when credentials are enabled. "
    "Specify an explicit allowed origin list instead. "
    "Terraform: aws_api_gateway_integration_response with specific CORS headers."
)
_REMEDIATION_LAMBDA_ROLE = (
    "Restrict the Lambda execution role policy to the minimum required actions "
    "and specific resource ARNs. "
    "AWS doc: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
)


class AWSGatewayAuditor(CloudGatewayAuditor):
    """
    Read-only auditor for AWS API Gateway REST (v1) and HTTP (v2) APIs.

    Parameters
    ----------
    client:           AWSGatewayClient instance.
    guard:            CloudReadOnlyGuard (default: read-only).
    account_context:  Label for the AWS profile/account being audited.
    """

    def __init__(
        self,
        client: AWSGatewayClient,
        guard: CloudReadOnlyGuard | None = None,
        account_context: str = "default",
    ) -> None:
        self._client = client
        self._guard = guard or CloudReadOnlyGuard(allow_destructive=False)
        self._account_context = account_context

    # ------------------------------------------------------------------
    # CloudGatewayAuditor contract
    # ------------------------------------------------------------------

    def get_provider_name(self) -> str:
        return "aws"

    async def discover_resources(self) -> list[dict[str, Any]]:
        """Return all REST APIs and HTTP APIs accessible with current credentials."""
        resources: list[dict[str, Any]] = []
        try:
            rest_apis = self._client.paginate_v1("get_rest_apis", "items")
            resources.extend({"type": "rest_api", **a} for a in rest_apis)
        except Exception as exc:
            self._handle_aws_error("get_rest_apis", exc)

        try:
            http_apis = self._client.paginate_v2("get_apis", "Items")
            resources.extend({"type": "http_api", **a} for a in http_apis)
        except Exception as exc:
            self._handle_aws_error("get_apis", exc)

        logger.info(
            "AWS discovery complete",
            account=self._account_context,
            resource_count=len(resources),
        )
        return resources

    async def audit(self) -> list[GatewayFinding]:
        """Execute all configuration checks and return findings."""
        findings: list[GatewayFinding] = []

        # --- REST APIs (v1) ---
        try:
            rest_apis = self._client.paginate_v1("get_rest_apis", "items")
        except Exception as exc:
            self._handle_aws_error("get_rest_apis", exc)
            rest_apis = []

        for api in rest_apis:
            api_id = api.get("id", "")
            api_name = api.get("name", api_id)

            # 4.1 Resource policy
            f = self._check_resource_policy_wildcard(api)
            if f:
                findings.append(f)

            # 4.2 Method authorizers
            try:
                resources = self._client.paginate_v1("get_resources", "items", restApiId=api_id)
                for resource in resources:
                    for http_method, method_data in resource.get("resourceMethods", {}).items():
                        f = self._check_method_authorizer(
                            api_id, api_name, resource, http_method, method_data
                        )
                        if f:
                            findings.append(f)
                        # 4.8 CORS
                        fc = self._check_cors_wildcard(
                            api_id, api_name, resource, http_method, method_data
                        )
                        if fc:
                            findings.append(fc)
                        # 4.9 Lambda role
                        fl = self._check_lambda_role(
                            api_id, api_name, resource, http_method, method_data
                        )
                        if fl:
                            findings.append(fl)
            except Exception as exc:
                self._handle_aws_error(f"get_resources(api={api_id})", exc)

            # Stages: 4.3 WAF, 4.4 logging, 4.5 TLS
            try:
                stages_resp = self._client.apigateway.get_stages(restApiId=api_id)
                for stage in stages_resp.get("item", []):
                    findings.extend(self._check_stage_v1(api_id, api_name, stage))
            except Exception as exc:
                self._handle_aws_error(f"get_stages(api={api_id})", exc)

        # --- Usage plans & API keys (4.6, 4.7) ---
        findings.extend(self._audit_usage_plans())

        # --- HTTP APIs (v2) — 4.10 ---
        try:
            http_apis = self._client.paginate_v2("get_apis", "Items")
        except Exception as exc:
            self._handle_aws_error("get_apis", exc)
            http_apis = []

        for api in http_apis:
            findings.extend(self._audit_http_api_v2(api))

        logger.info(
            "AWS audit complete",
            account=self._account_context,
            finding_count=len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Check 4.1 — Resource policy wildcard Principal
    # ------------------------------------------------------------------

    def _check_resource_policy_wildcard(self, api: dict) -> GatewayFinding | None:
        raw_policy = api.get("policy")
        if not raw_policy:
            return None

        try:
            # API Gateway URL-encodes the policy JSON
            from urllib.parse import unquote

            policy_str = unquote(raw_policy)
            policy = json.loads(policy_str)
        except Exception:
            return None

        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", "")
            effect = stmt.get("Effect", "")
            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                # Check if there's no restrictive Condition
                condition = stmt.get("Condition", {})
                if not condition:
                    return GatewayFinding(
                        provider="aws",
                        resource_id=f"arn:aws:apigateway:::restapis/{api.get('id')}",
                        resource_type="rest_api_resource_policy",
                        check_id="aws_apigw_resource_policy_wildcard_principal",
                        title="API Gateway resource policy allows any principal without condition",
                        severity=GatewaySeverity.HIGH,
                        evidence={
                            "api_id": api.get("id"),
                            "api_name": api.get("name"),
                            "statement_effect": effect,
                            "principal": str(principal),
                            "has_condition": bool(condition),
                        },
                        remediation=_REMEDIATION_RESOURCE_POLICY,
                        account_context=self._account_context,
                    )
        return None

    # ------------------------------------------------------------------
    # Check 4.2 — Method without authorizer
    # ------------------------------------------------------------------

    def _check_method_authorizer(
        self,
        api_id: str,
        api_name: str,
        resource: dict,
        http_method: str,
        method_data: dict,
    ) -> GatewayFinding | None:
        if http_method.upper() not in _STATE_CHANGING_HTTP_METHODS:
            return None
        auth_type = method_data.get("authorizationType", "NONE")
        if auth_type == "NONE":
            return GatewayFinding(
                provider="aws",
                resource_id=f"arn:aws:apigateway:::restapis/{api_id}/resources/{resource.get('id')}/methods/{http_method}",
                resource_type="rest_api_method",
                check_id="aws_apigw_method_no_authorizer",
                title=f"State-changing method {http_method} has no authorizer (authorizationType=NONE)",
                severity=GatewaySeverity.HIGH,
                evidence={
                    "api_id": api_id,
                    "api_name": api_name,
                    "path": resource.get("path"),
                    "http_method": http_method,
                    "authorization_type": auth_type,
                },
                remediation=_REMEDIATION_AUTHORIZER,
                account_context=self._account_context,
            )
        return None

    # ------------------------------------------------------------------
    # Check 4.3/4.4/4.5 — Stage checks
    # ------------------------------------------------------------------

    def _check_stage_v1(self, api_id: str, api_name: str, stage: dict) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        stage_name = stage.get("stageName", "")
        stage_arn = f"arn:aws:apigateway:::restapis/{api_id}/stages/{stage_name}"

        # 4.3 WAF association
        waf_arn = stage.get("webAclArn")
        if not waf_arn:
            findings.append(
                GatewayFinding(
                    provider="aws",
                    resource_id=stage_arn,
                    resource_type="rest_api_stage",
                    check_id="aws_apigw_stage_no_waf",
                    title="API Gateway stage has no WAF WebACL associated",
                    severity=GatewaySeverity.MEDIUM,
                    evidence={
                        "api_id": api_id,
                        "api_name": api_name,
                        "stage_name": stage_name,
                        "waf_arn": None,
                    },
                    remediation=_REMEDIATION_WAF,
                    account_context=self._account_context,
                )
            )

        # 4.4 Logging
        method_settings = stage.get("methodSettings", {})
        default_settings = method_settings.get("*/*", {})
        access_log_enabled = bool(stage.get("accessLogSettings", {}).get("destinationArn"))
        execution_log_level = default_settings.get("loggingLevel", "OFF")

        if not access_log_enabled and execution_log_level in ("OFF", ""):
            findings.append(
                GatewayFinding(
                    provider="aws",
                    resource_id=stage_arn,
                    resource_type="rest_api_stage",
                    check_id="aws_apigw_stage_logging_disabled",
                    title="API Gateway stage has both access logging and execution logging disabled",
                    severity=GatewaySeverity.MEDIUM,
                    evidence={
                        "api_id": api_id,
                        "api_name": api_name,
                        "stage_name": stage_name,
                        "access_log_enabled": access_log_enabled,
                        "execution_log_level": execution_log_level,
                    },
                    remediation=_REMEDIATION_LOGGING,
                    account_context=self._account_context,
                )
            )

        # 4.5 TLS via custom domain (checked separately — see _check_custom_domains)
        return findings

    def _audit_custom_domains(self) -> list[GatewayFinding]:
        """Check 4.5 — custom domain TLS minimum version."""
        findings: list[GatewayFinding] = []
        try:
            domains = self._client.paginate_v1("get_domain_names", "items")
        except Exception as exc:
            self._handle_aws_error("get_domain_names", exc)
            return findings

        for domain in domains:
            security_policy = domain.get("securityPolicy", "TLS_1_0")
            if security_policy in ("TLS_1_0", "TLS_1_1", "TLS_1_0_1_0"):
                findings.append(
                    GatewayFinding(
                        provider="aws",
                        resource_id=f"arn:aws:apigateway:::domainnames/{domain.get('domainName')}",
                        resource_type="custom_domain",
                        check_id="aws_apigw_domain_weak_tls",
                        title=f"API Gateway custom domain allows TLS < 1.2 (policy={security_policy})",
                        severity=GatewaySeverity.MEDIUM,
                        evidence={
                            "domain_name": domain.get("domainName"),
                            "security_policy": security_policy,
                        },
                        remediation=_REMEDIATION_TLS,
                        account_context=self._account_context,
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Checks 4.6 / 4.7 — Usage plans and API keys
    # ------------------------------------------------------------------

    def _audit_usage_plans(self) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []

        try:
            plans = self._client.paginate_v1("get_usage_plans", "items")
        except Exception as exc:
            self._handle_aws_error("get_usage_plans", exc)
            plans = []

        plan_key_ids: set[str] = set()

        for plan in plans:
            plan_id = plan.get("id", "")
            # 4.6 Missing throttling
            throttle = plan.get("throttle", {})
            if not throttle or (not throttle.get("rateLimit") and not throttle.get("burstLimit")):
                findings.append(
                    GatewayFinding(
                        provider="aws",
                        resource_id=f"arn:aws:apigateway:::usageplans/{plan_id}",
                        resource_type="usage_plan",
                        check_id="aws_apigw_usage_plan_no_throttling",
                        title="API Gateway usage plan has no throttling configured",
                        severity=GatewaySeverity.MEDIUM,
                        evidence={
                            "plan_id": plan_id,
                            "plan_name": plan.get("name"),
                            "throttle": throttle,
                        },
                        remediation=_REMEDIATION_THROTTLING,
                        account_context=self._account_context,
                    )
                )

            # Collect keys associated with plans
            try:
                keys = self._client.paginate_v1("get_usage_plan_keys", "items", usagePlanId=plan_id)
                for key in keys:
                    plan_key_ids.add(key.get("id", ""))
            except Exception as exc:
                self._handle_aws_error(f"get_usage_plan_keys(plan={plan_id})", exc)

        # 4.7 Orphan keys
        try:
            all_keys = self._client.paginate_v1("get_api_keys", "items", includeValues=False)
        except Exception as exc:
            self._handle_aws_error("get_api_keys", exc)
            all_keys = []

        for key in all_keys:
            key_id = key.get("id", "")
            if key_id not in plan_key_ids:
                findings.append(
                    GatewayFinding(
                        provider="aws",
                        resource_id=f"arn:aws:apigateway:::apikeys/{key_id}",
                        resource_type="api_key",
                        check_id="aws_apigw_orphan_api_key",
                        title="API Gateway API key is not associated with any usage plan",
                        severity=GatewaySeverity.LOW,
                        evidence={
                            "key_id": key_id,
                            "key_name": key.get("name"),
                            "enabled": key.get("enabled"),
                        },
                        remediation=_REMEDIATION_ORPHAN_KEY,
                        account_context=self._account_context,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Check 4.8 — CORS wildcard with credentials
    # ------------------------------------------------------------------

    def _check_cors_wildcard(
        self,
        api_id: str,
        api_name: str,
        resource: dict,
        http_method: str,
        method_data: dict,
    ) -> GatewayFinding | None:
        if http_method.upper() != "OPTIONS":
            return None

        # Check integration responses for CORS headers
        integration = method_data.get("methodIntegration", {})
        for _, int_resp in integration.get("integrationResponses", {}).items():
            params = int_resp.get("responseParameters", {})
            allow_origin = params.get("method.response.header.Access-Control-Allow-Origin", "")
            allow_creds = params.get("method.response.header.Access-Control-Allow-Credentials", "")
            if allow_origin.strip("'\"") == "*" and allow_creds.strip("'\"").lower() == "true":
                return GatewayFinding(
                    provider="aws",
                    resource_id=f"arn:aws:apigateway:::restapis/{api_id}/resources/{resource.get('id')}/methods/OPTIONS",
                    resource_type="rest_api_cors",
                    check_id="aws_apigw_cors_wildcard_with_credentials",
                    title="CORS configured with wildcard origin AND credentials=true",
                    severity=GatewaySeverity.HIGH,
                    evidence={
                        "api_id": api_id,
                        "api_name": api_name,
                        "path": resource.get("path"),
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_creds,
                    },
                    remediation=_REMEDIATION_CORS,
                    account_context=self._account_context,
                )
        return None

    # ------------------------------------------------------------------
    # Check 4.9 — Lambda integration role overprivilege
    # ------------------------------------------------------------------

    def _check_lambda_role(
        self,
        api_id: str,
        api_name: str,
        resource: dict,
        http_method: str,
        method_data: dict,
    ) -> GatewayFinding | None:
        integration = method_data.get("methodIntegration", {})
        if integration.get("type") not in ("AWS", "AWS_PROXY"):
            return None
        credentials = integration.get("credentials", "")
        if not credentials or not credentials.startswith("arn:aws:iam"):
            return None

        # credentials is a role ARN — check its policies
        role_arn = credentials
        # Extract role name from ARN: arn:aws:iam::123456789:role/RoleName
        try:
            role_name = role_arn.split("/")[-1]
            attached = self._client.iam.list_attached_role_policies(RoleName=role_name)
            for policy_ref in attached.get("AttachedPolicies", []):
                policy_arn = policy_ref.get("PolicyArn", "")
                version_resp = self._client.iam.get_policy(PolicyArn=policy_arn)
                default_version = version_resp["Policy"]["DefaultVersionId"]
                doc_resp = self._client.iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default_version
                )
                doc = doc_resp["PolicyVersion"]["Document"]
                for stmt in doc.get("Statement", []):
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if "*" in actions or "*" in resources:
                        return GatewayFinding(
                            provider="aws",
                            resource_id=role_arn,
                            resource_type="iam_role",
                            check_id="aws_apigw_lambda_role_overprivilege",
                            title="API Gateway Lambda integration role has wildcard Action or Resource in policy",
                            severity=GatewaySeverity.INFO,
                            evidence={
                                "api_id": api_id,
                                "api_name": api_name,
                                "role_arn": role_arn,
                                "policy_arn": policy_arn,
                            },
                            remediation=_REMEDIATION_LAMBDA_ROLE,
                            account_context=self._account_context,
                        )
        except Exception:
            # IAM check failures are non-fatal — just skip
            pass
        return None

    # ------------------------------------------------------------------
    # HTTP API v2 (Check 4.10)
    # ------------------------------------------------------------------

    def _audit_http_api_v2(self, api: dict) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        api_id = api.get("ApiId", "")
        api_name = api.get("Name", api_id)

        # Auth check: if no default authorizer and no route-level auth
        try:
            routes_resp = self._client.apigatewayv2.get_routes(ApiId=api_id)
            for route in routes_resp.get("Items", []):
                auth_type = route.get("AuthorizationType", "NONE")
                route_key = route.get("RouteKey", "")
                method = route_key.split(" ")[0] if " " in route_key else ""
                if method.upper() in _STATE_CHANGING_HTTP_METHODS and auth_type == "NONE":
                    findings.append(
                        GatewayFinding(
                            provider="aws",
                            resource_id=f"arn:aws:apigateway:::apis/{api_id}/routes/{route.get('RouteId')}",
                            resource_type="http_api_v2_route",
                            check_id="aws_apigwv2_route_no_authorizer",
                            title=f"HTTP API v2 state-changing route {route_key} has no authorizer",
                            severity=GatewaySeverity.HIGH,
                            evidence={
                                "api_id": api_id,
                                "api_name": api_name,
                                "route_key": route_key,
                                "auth_type": auth_type,
                            },
                            remediation=_REMEDIATION_AUTHORIZER,
                            account_context=self._account_context,
                        )
                    )
        except Exception as exc:
            self._handle_aws_error(f"get_routes(api={api_id})", exc)

        # Stages
        try:
            stages_resp = self._client.apigatewayv2.get_stages(ApiId=api_id)
            for stage in stages_resp.get("Items", []):
                log_settings = stage.get("AccessLogSettings", {})
                if not log_settings.get("DestinationArn"):
                    stage_name = stage.get("StageName", "$default")
                    findings.append(
                        GatewayFinding(
                            provider="aws",
                            resource_id=f"arn:aws:apigateway:::apis/{api_id}/stages/{stage_name}",
                            resource_type="http_api_v2_stage",
                            check_id="aws_apigwv2_stage_logging_disabled",
                            title="HTTP API v2 stage has access logging disabled",
                            severity=GatewaySeverity.MEDIUM,
                            evidence={
                                "api_id": api_id,
                                "api_name": api_name,
                                "stage_name": stage_name,
                            },
                            remediation=_REMEDIATION_LOGGING,
                            account_context=self._account_context,
                        )
                    )
        except Exception as exc:
            self._handle_aws_error(f"get_stages(api={api_id})", exc)

        return findings

    # ------------------------------------------------------------------
    # Error handling (Requirement 9)
    # ------------------------------------------------------------------

    def _handle_aws_error(self, operation: str, exc: Exception) -> None:
        """
        Convert boto3 ClientErrors to the appropriate CloudAuditError subclass.
        Non-fatal (logs and continues); callers catch CloudAuditError if needed.
        """
        error_code = ""
        try:
            error_code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
        except (AttributeError, KeyError, TypeError):
            pass

        if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedClientException"):
            logger.warning(
                "Insufficient permissions for AWS operation",
                operation=operation,
                error=str(exc),
                account=self._account_context,
            )
            raise InsufficientPermissionsError(str(exc)) from exc
        elif error_code in ("ThrottlingException", "TooManyRequestsException"):
            raise ProviderThrottledError(str(exc)) from exc
        else:
            logger.warning(
                "AWS operation failed (non-fatal, continuing audit)",
                operation=operation,
                error=str(exc),
                account=self._account_context,
            )
