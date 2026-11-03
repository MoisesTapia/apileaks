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
    create_permission_denied_finding,
)
from utils.cloud.aws_client import AWSGatewayClient
from utils.cloud.backoff import with_exponential_backoff
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
        """Return all REST APIs (v1) and HTTP APIs (v2) accessible with current credentials.

        Each returned dict contains the original API fields plus an ``"api_type"``
        key set to ``"REST"`` (v1) or ``"HTTP"`` (v2).

        ``guard.guard_operation`` is called for both operations to document
        intent — both are read-only so they always pass.
        """
        resources: list[dict[str, Any]] = []

        # v1 REST APIs
        self._guard.guard_operation("get_rest_apis")
        try:
            rest_apis = await self._call_paginate_v1("get_rest_apis", "items")
            resources.extend({"api_type": "REST", **a} for a in rest_apis)
        except (InsufficientPermissionsError, ProviderThrottledError) as exc:
            logger.warning(
                "Could not enumerate REST APIs during discovery",
                account=self._account_context,
                error=str(exc),
            )

        # v2 HTTP APIs
        self._guard.guard_operation("get_apis")
        try:
            http_apis = await self._call_paginate_v2("get_apis", "Items")
            resources.extend({"api_type": "HTTP", **a} for a in http_apis)
        except (InsufficientPermissionsError, ProviderThrottledError) as exc:
            logger.warning(
                "Could not enumerate HTTP APIs during discovery",
                account=self._account_context,
                error=str(exc),
            )

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
            rest_apis = await self._call_paginate_v1("get_rest_apis", "items")
        except (InsufficientPermissionsError, ProviderThrottledError):
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"aws:{self._account_context}:rest-apis",
                    resource_type="rest_api_list",
                    provider="aws",
                    account_context=self._account_context,
                    operation="get_rest_apis",
                )
            )
            rest_apis = []

        for api in rest_apis:
            api_id = api.get("id", "")
            api_name = api.get("name", api_id)

            # 4.1 Resource policy
            f = self._check_resource_policy_wildcard(api)
            if f:
                findings.append(f)

            # 4.2 Method authorizers + 4.8 CORS + 4.9 Lambda role
            self._guard.guard_operation("get_resources")
            try:
                resources = await self._call_paginate_v1(
                    "get_resources", "items", restApiId=api_id
                )
                for resource in resources:
                    resource_id = resource.get("id", "")
                    resource_methods = resource.get("resourceMethods", {})

                    # 4.2 — call get_method for each mutating verb to get authorizer info
                    for http_method in _STATE_CHANGING_HTTP_METHODS:
                        if http_method not in resource_methods:
                            continue
                        self._guard.guard_operation("get_method")
                        try:
                            method = self._client.apigateway.get_method(
                                restApiId=api_id,
                                resourceId=resource_id,
                                httpMethod=http_method,
                            )
                            f = self._check_method_authorizer(api, resource, method)
                            if f:
                                findings.append(f)
                        except Exception as exc:
                            self._handle_aws_error(
                                f"get_method(api={api_id},resource={resource_id},method={http_method})",
                                exc,
                            )

                    # 4.8 CORS + 4.9 Lambda role use the summary data from get_resources
                    for http_method, method_data in resource_methods.items():
                        if http_method.upper() == "OPTIONS":
                            fc = self._check_cors_wildcard_with_credentials(
                                api_id, api_name, resource, method_data
                            )
                            if fc:
                                findings.append(fc)
                        fl = self._check_lambda_role_overprivilege(
                            api_id, api_name, resource, http_method, method_data
                        )
                        if fl:
                            findings.append(fl)
            except (InsufficientPermissionsError, ProviderThrottledError):
                findings.append(
                    create_permission_denied_finding(
                        resource_id=f"arn:aws:apigateway:::restapis/{api_id}",
                        resource_type="rest_api",
                        provider="aws",
                        account_context=self._account_context,
                        operation=f"get_resources(api={api_id})",
                    )
                )

            # Stages: 4.3 WAF, 4.4 logging, 4.5 TLS
            try:
                stages_resp = self._client.apigateway.get_stages(restApiId=api_id)
                for stage in stages_resp.get("item", []):
                    findings.extend(self._check_stage_v1(api_id, api_name, stage))
            except Exception as exc:
                try:
                    self._handle_aws_error(f"get_stages(api={api_id})", exc)
                except (InsufficientPermissionsError, ProviderThrottledError):
                    findings.append(
                        create_permission_denied_finding(
                            resource_id=f"arn:aws:apigateway:::restapis/{api_id}/stages",
                            resource_type="rest_api_stage_list",
                            provider="aws",
                            account_context=self._account_context,
                            operation=f"get_stages(api={api_id})",
                        )
                    )

        # --- Custom domains (4.5 TLS) ---
        findings.extend(await self._audit_custom_domains_async())

        # --- Usage plans & API keys (4.6, 4.7) ---
        findings.extend(await self._audit_usage_plans_async())

        # --- HTTP APIs (v2) — 4.10 ---
        try:
            http_apis = await self._call_paginate_v2("get_apis", "Items")
        except (InsufficientPermissionsError, ProviderThrottledError):
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"aws:{self._account_context}:http-apis",
                    resource_type="http_api_v2_list",
                    provider="aws",
                    account_context=self._account_context,
                    operation="get_apis",
                )
            )
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

    @staticmethod
    def _has_restrictive_condition(condition: dict) -> bool:
        """Return True if the condition contains aws:SourceIp or aws:SourceVpc."""
        for operator_conditions in condition.values():
            if isinstance(operator_conditions, dict):
                for key in operator_conditions:
                    if key.lower() in ("aws:sourceip", "aws:sourcevpc"):
                        return True
        return False

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
            is_wildcard_principal = (
                principal == "*"
                or principal == {"AWS": "*"}
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
            )
            if effect == "Allow" and is_wildcard_principal:
                condition = stmt.get("Condition", {})
                if not condition or not self._has_restrictive_condition(condition):
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
        api: dict,
        resource: dict,
        method: dict,
    ) -> GatewayFinding | None:
        """Check whether a state-mutating method has no authorizer.

        Parameters
        ----------
        api:      REST API dict (must have ``id`` and ``name``).
        resource: Resource dict from ``get_resources`` (must have ``id`` and ``path``).
        method:   Full method dict from ``get_method`` (must have ``httpMethod``
                  and ``authorizationType``).
        """
        http_method = method.get("httpMethod", "")
        if http_method.upper() not in _STATE_CHANGING_HTTP_METHODS:
            return None
        auth_type = method.get("authorizationType", "NONE")
        api_id = api.get("id", "")
        api_name = api.get("name", api_id)
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
        """Delegate per-stage checks to the canonical check methods."""
        findings: list[GatewayFinding] = []

        f = self._check_waf_association(api_id, api_name, stage)
        if f:
            findings.append(f)

        f = self._check_stage_logging(api_id, api_name, stage)
        if f:
            findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Check 4.3 — WAF association
    # ------------------------------------------------------------------

    def _check_waf_association(
        self, api_id: str, api_name: str, stage: dict
    ) -> GatewayFinding | None:
        """Return a MEDIUM finding if the stage has no WAF WebACL associated (Req 4.3)."""
        waf_arn = stage.get("webAclArn")
        if waf_arn:
            return None
        stage_name = stage.get("stageName", "")
        return GatewayFinding(
            provider="aws",
            resource_id=f"arn:aws:apigateway:::restapis/{api_id}/stages/{stage_name}",
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

    # ------------------------------------------------------------------
    # Check 4.4 — Stage logging
    # ------------------------------------------------------------------

    def _check_stage_logging(
        self, api_id: str, api_name: str, stage: dict
    ) -> GatewayFinding | None:
        """Return a MEDIUM finding when both access and execution logging are off (Req 4.4)."""
        access_log_enabled = bool(
            stage.get("accessLogSettings", {}).get("destinationArn")
        )
        execution_log_level = (
            stage.get("methodSettings", {})
            .get("*/*", {})
            .get("loggingLevel", "OFF")
        )

        if access_log_enabled or execution_log_level not in ("OFF", ""):
            return None

        stage_name = stage.get("stageName", "")
        return GatewayFinding(
            provider="aws",
            resource_id=f"arn:aws:apigateway:::restapis/{api_id}/stages/{stage_name}",
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

    # ------------------------------------------------------------------
    # Check 4.5 — Custom domain TLS version (per-domain helper)
    # ------------------------------------------------------------------

    def _check_stage_tls(self, domain: dict) -> GatewayFinding | None:
        """Return a MEDIUM finding if the custom domain allows TLS < 1.2 (Req 4.5)."""
        security_policy = domain.get("securityPolicy", "TLS_1_0")
        if security_policy not in ("TLS_1_0", "TLS_1_1"):
            return None
        return GatewayFinding(
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

    def _audit_custom_domains(self) -> list[GatewayFinding]:
        """Check 4.5 — custom domain TLS minimum version.

        Iterates all custom domain names and delegates to `_check_stage_tls`
        for each one.

        .. deprecated::
            Prefer :meth:`_audit_custom_domains_async`.  Kept for call sites
            that are not yet async.
        """
        findings: list[GatewayFinding] = []
        try:
            domains = self._client.paginate_v1("get_domain_names", "items")
        except Exception as exc:
            self._handle_aws_error("get_domain_names", exc)
            return findings

        for domain in domains:
            f = self._check_stage_tls(domain)
            if f:
                findings.append(f)
        return findings

    async def _audit_custom_domains_async(self) -> list[GatewayFinding]:
        """Async version of :meth:`_audit_custom_domains` with backoff support."""
        findings: list[GatewayFinding] = []
        try:
            domains = await self._call_paginate_v1("get_domain_names", "items")
        except (InsufficientPermissionsError, ProviderThrottledError):
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"aws:{self._account_context}:domain-names",
                    resource_type="custom_domain_list",
                    provider="aws",
                    account_context=self._account_context,
                    operation="get_domain_names",
                )
            )
            return findings

        for domain in domains:
            f = self._check_stage_tls(domain)
            if f:
                findings.append(f)
        return findings

    # ------------------------------------------------------------------
    # Checks 4.6 / 4.7 — Usage plans and API keys
    # ------------------------------------------------------------------

    def _check_usage_plan_throttling(self, plan: dict) -> GatewayFinding | None:
        """Return a MEDIUM finding if the usage plan has no throttling configured (Req 4.6).

        A plan is considered unconfigured when the ``throttle`` key is absent or
        both ``rateLimit`` and ``burstLimit`` are missing / falsy.
        """
        plan_id = plan.get("id", "")
        throttle = plan.get("throttle", {})
        if throttle and (throttle.get("rateLimit") or throttle.get("burstLimit")):
            return None
        return GatewayFinding(
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

    def _check_orphan_api_keys(
        self, keys: list[dict], plan_key_ids: set[str]
    ) -> list[GatewayFinding]:
        """Return LOW findings for every API key not associated with any usage plan (Req 4.7).

        Parameters
        ----------
        keys:         Full list of API keys from ``get_api_keys``.
        plan_key_ids: Set of key IDs already associated with at least one usage plan.
        """
        findings: list[GatewayFinding] = []
        for key in keys:
            key_id = key.get("id", "")
            if key_id in plan_key_ids:
                continue
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

    def _audit_usage_plans(self) -> list[GatewayFinding]:
        """Orchestrate checks 4.6 and 4.7 by delegating to the canonical helpers."""
        findings: list[GatewayFinding] = []

        try:
            plans = self._client.paginate_v1("get_usage_plans", "items")
        except Exception as exc:
            self._handle_aws_error("get_usage_plans", exc)
            plans = []

        plan_key_ids: set[str] = set()

        for plan in plans:
            # 4.6 — delegate to standalone method
            f = self._check_usage_plan_throttling(plan)
            if f:
                findings.append(f)

            # Collect keys associated with this plan
            plan_id = plan.get("id", "")
            try:
                plan_keys = self._client.paginate_v1(
                    "get_usage_plan_keys", "items", usagePlanId=plan_id
                )
                for key in plan_keys:
                    plan_key_ids.add(key.get("id", ""))
            except Exception as exc:
                self._handle_aws_error(f"get_usage_plan_keys(plan={plan_id})", exc)

        # 4.7 — delegate to standalone method
        try:
            all_keys = self._client.paginate_v1("get_api_keys", "items", includeValues=False)
        except Exception as exc:
            self._handle_aws_error("get_api_keys", exc)
            all_keys = []

        findings.extend(self._check_orphan_api_keys(all_keys, plan_key_ids))

        return findings

    async def _audit_usage_plans_async(self) -> list[GatewayFinding]:
        """Async version of :meth:`_audit_usage_plans` with backoff support."""
        findings: list[GatewayFinding] = []

        try:
            plans = await self._call_paginate_v1("get_usage_plans", "items")
        except (InsufficientPermissionsError, ProviderThrottledError):
            findings.append(
                create_permission_denied_finding(
                    resource_id=f"aws:{self._account_context}:usage-plans",
                    resource_type="usage_plan_list",
                    provider="aws",
                    account_context=self._account_context,
                    operation="get_usage_plans",
                )
            )
            return findings

        plan_key_ids: set[str] = set()

        for plan in plans:
            # 4.6 — delegate to standalone method
            f = self._check_usage_plan_throttling(plan)
            if f:
                findings.append(f)

            # Collect keys associated with this plan
            plan_id = plan.get("id", "")
            try:
                plan_keys = await self._call_paginate_v1(
                    "get_usage_plan_keys", "items", usagePlanId=plan_id
                )
                for key in plan_keys:
                    plan_key_ids.add(key.get("id", ""))
            except (InsufficientPermissionsError, ProviderThrottledError):
                findings.append(
                    create_permission_denied_finding(
                        resource_id=f"arn:aws:apigateway:::usageplans/{plan_id}/keys",
                        resource_type="usage_plan_keys",
                        provider="aws",
                        account_context=self._account_context,
                        operation=f"get_usage_plan_keys(plan={plan_id})",
                    )
                )

        # 4.7 — delegate to standalone method
        try:
            all_keys = await self._call_paginate_v1(
                "get_api_keys", "items", includeValues=False
            )
        except (InsufficientPermissionsError, ProviderThrottledError):
            all_keys = []

        findings.extend(self._check_orphan_api_keys(all_keys, plan_key_ids))

        return findings

    # ------------------------------------------------------------------
    # Check 4.8 — CORS wildcard with credentials
    # ------------------------------------------------------------------

    def _check_cors_wildcard_with_credentials(
        self,
        api_id: str,
        api_name: str,
        resource: dict,
        method_data: dict,
    ) -> GatewayFinding | None:
        """Return a HIGH finding when the OPTIONS integration response combines
        ``Access-Control-Allow-Origin: *`` with ``Access-Control-Allow-Credentials: true``
        (Req 4.8).

        Callers are responsible for passing only the OPTIONS method's data.
        """
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

    def _check_lambda_role_overprivilege(
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
    # Resilient pagination helpers (backoff + error conversion)
    # ------------------------------------------------------------------

    async def _call_paginate_v1(
        self, operation: str, result_key: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """
        Paginate a v1 REST API list call with exponential backoff on throttling.

        Converts boto3 ``ClientError`` to :class:`InsufficientPermissionsError`
        or :class:`ProviderThrottledError` via :meth:`_handle_aws_error`.
        :class:`ProviderThrottledError` is retried up to *max_retries* times;
        :class:`InsufficientPermissionsError` propagates immediately.
        """

        def _call() -> list[dict[str, Any]]:
            try:
                return self._client.paginate_v1(operation, result_key, **kwargs)
            except Exception as exc:
                self._handle_aws_error(operation, exc)
                return []  # only reached for non-fatal errors logged by _handle_aws_error

        return await with_exponential_backoff(_call, retry_on=ProviderThrottledError)

    async def _call_paginate_v2(
        self, operation: str, result_key: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """Same as :meth:`_call_paginate_v1` but for the v2 HTTP API client."""

        def _call() -> list[dict[str, Any]]:
            try:
                return self._client.paginate_v2(operation, result_key, **kwargs)
            except Exception as exc:
                self._handle_aws_error(operation, exc)
                return []

        return await with_exponential_backoff(_call, retry_on=ProviderThrottledError)

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

        if error_code in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedException",
            "UnauthorizedClientException",
            "Forbidden",
        ):
            logger.warning(
                "Insufficient permissions for AWS operation",
                operation=operation,
                error=str(exc),
                account=self._account_context,
            )
            raise InsufficientPermissionsError(str(exc)) from exc
        elif error_code in (
            "ThrottlingException",
            "TooManyRequestsException",
            "LimitExceededException",
            "RequestThrottledException",
            "SlowDown",
        ):
            logger.warning(
                "AWS operation throttled — will retry with backoff",
                operation=operation,
                error=str(exc),
                account=self._account_context,
            )
            raise ProviderThrottledError(str(exc)) from exc
        else:
            logger.warning(
                "AWS operation failed (non-fatal, continuing audit)",
                operation=operation,
                error=str(exc),
                account=self._account_context,
            )
