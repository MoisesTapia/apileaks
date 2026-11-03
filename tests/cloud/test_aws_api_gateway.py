"""
Unit tests for AWSGatewayAuditor individual checks.

Each check has at least one "vulnerable" case (finding produced) and one
"clean/correctly configured" case (no finding).  All AWS calls are mocked
with unittest.mock — no real AWS credentials or network access are needed.
"""
import json
import urllib.parse

import pytest
from unittest.mock import MagicMock

from modules.cloud.aws_api_gateway import AWSGatewayAuditor
from modules.cloud.base import GatewaySeverity
from utils.cloud.readonly_guard import CloudReadOnlyGuard


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_auditor() -> tuple[AWSGatewayAuditor, MagicMock]:
    """Build an AWSGatewayAuditor with a fully mocked client."""
    mock_client = MagicMock()
    guard = CloudReadOnlyGuard(allow_destructive=False)
    auditor = AWSGatewayAuditor(
        client=mock_client,
        guard=guard,
        account_context="test-account",
    )
    return auditor, mock_client


def _encode_policy(policy: dict) -> str:
    """URL-encode a policy dict the same way API Gateway stores it."""
    return urllib.parse.quote(json.dumps(policy))


# ---------------------------------------------------------------------------
# Check 4.1 — Resource policy wildcard Principal
# ---------------------------------------------------------------------------


class TestCheckResourcePolicyWildcard:
    def test_vulnerable_principal_star(self):
        """Principal='*' with no condition → HIGH finding."""
        auditor, _ = _make_auditor()
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke"}
            ]
        }
        api = {"id": "api1", "name": "MyAPI", "policy": _encode_policy(policy)}
        finding = auditor._check_resource_policy_wildcard(api)
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "aws_apigw_resource_policy_wildcard_principal"
        assert finding.evidence["api_id"] == "api1"

    def test_vulnerable_principal_aws_star_dict(self):
        """Principal={'AWS': '*'} without condition → HIGH finding."""
        auditor, _ = _make_auditor()
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "execute-api:Invoke",
                }
            ]
        }
        api = {"id": "api2", "name": "AnotherAPI", "policy": _encode_policy(policy)}
        finding = auditor._check_resource_policy_wildcard(api)
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH

    def test_clean_principal_star_with_source_vpc_condition(self):
        """Principal='*' BUT aws:SourceVpc condition present → no finding."""
        auditor, _ = _make_auditor()
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "execute-api:Invoke",
                    "Condition": {
                        "StringEquals": {"aws:SourceVpc": "vpc-abc123"}
                    },
                }
            ]
        }
        api = {"id": "api3", "name": "RestrictedAPI", "policy": _encode_policy(policy)}
        finding = auditor._check_resource_policy_wildcard(api)
        assert finding is None

    def test_clean_no_policy_field(self):
        """API with no 'policy' key → no finding."""
        auditor, _ = _make_auditor()
        api = {"id": "api4", "name": "NoPolicyAPI"}
        finding = auditor._check_resource_policy_wildcard(api)
        assert finding is None

    def test_clean_deny_effect(self):
        """Effect=Deny with wildcard principal → not flagged (only Allow is checked)."""
        auditor, _ = _make_auditor()
        policy = {
            "Statement": [
                {"Effect": "Deny", "Principal": "*", "Action": "execute-api:Invoke"}
            ]
        }
        api = {"id": "api5", "name": "DenyAPI", "policy": _encode_policy(policy)}
        finding = auditor._check_resource_policy_wildcard(api)
        assert finding is None


# ---------------------------------------------------------------------------
# Check 4.2 — Method without authorizer
# ---------------------------------------------------------------------------


class TestCheckMethodAuthorizer:
    def test_vulnerable_post_no_auth(self):
        """POST with authorizationType=NONE → HIGH finding."""
        auditor, _ = _make_auditor()
        api = {"id": "api1", "name": "API"}
        resource = {"id": "res1", "path": "/users"}
        method = {"httpMethod": "POST", "authorizationType": "NONE"}
        finding = auditor._check_method_authorizer(api, resource, method)
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert "POST" in finding.title
        assert finding.check_id == "aws_apigw_method_no_authorizer"

    def test_clean_post_with_iam_auth(self):
        """POST with authorizationType=AWS_IAM → no finding."""
        auditor, _ = _make_auditor()
        api = {"id": "api1", "name": "API"}
        resource = {"id": "res1", "path": "/users"}
        method = {"httpMethod": "POST", "authorizationType": "AWS_IAM"}
        finding = auditor._check_method_authorizer(api, resource, method)
        assert finding is None

    def test_clean_get_no_auth(self):
        """GET with authorizationType=NONE → no finding (GET is not state-changing)."""
        auditor, _ = _make_auditor()
        api = {"id": "api1", "name": "API"}
        resource = {"id": "res1", "path": "/users"}
        method = {"httpMethod": "GET", "authorizationType": "NONE"}
        finding = auditor._check_method_authorizer(api, resource, method)
        assert finding is None

    def test_vulnerable_delete_no_auth(self):
        """DELETE with authorizationType=NONE → HIGH finding."""
        auditor, _ = _make_auditor()
        api = {"id": "api1", "name": "API"}
        resource = {"id": "res1", "path": "/items/1"}
        method = {"httpMethod": "DELETE", "authorizationType": "NONE"}
        finding = auditor._check_method_authorizer(api, resource, method)
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH

    def test_clean_put_with_cognito_auth(self):
        """PUT with authorizationType=COGNITO_USER_POOLS → no finding."""
        auditor, _ = _make_auditor()
        api = {"id": "api1", "name": "API"}
        resource = {"id": "res1", "path": "/items/1"}
        method = {"httpMethod": "PUT", "authorizationType": "COGNITO_USER_POOLS"}
        finding = auditor._check_method_authorizer(api, resource, method)
        assert finding is None


# ---------------------------------------------------------------------------
# Check 4.3 — WAF association
# ---------------------------------------------------------------------------


class TestCheckWafAssociation:
    def test_vulnerable_no_waf_arn(self):
        """Stage with no webAclArn → MEDIUM finding."""
        auditor, _ = _make_auditor()
        stage = {"stageName": "prod"}
        finding = auditor._check_waf_association("api1", "MyAPI", stage)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM
        assert finding.check_id == "aws_apigw_stage_no_waf"
        assert finding.evidence["stage_name"] == "prod"

    def test_clean_with_waf_arn(self):
        """Stage with a webAclArn → no finding."""
        auditor, _ = _make_auditor()
        stage = {
            "stageName": "prod",
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789:webacl/MyWebACL/abc",
        }
        finding = auditor._check_waf_association("api1", "MyAPI", stage)
        assert finding is None


# ---------------------------------------------------------------------------
# Check 4.4 — Stage logging
# ---------------------------------------------------------------------------


class TestCheckStageLogging:
    def test_vulnerable_both_logging_off(self):
        """accessLogSettings={} and methodSettings={} → MEDIUM finding."""
        auditor, _ = _make_auditor()
        stage = {
            "stageName": "prod",
            "accessLogSettings": {},
            "methodSettings": {},
        }
        finding = auditor._check_stage_logging("api1", "MyAPI", stage)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM
        assert finding.check_id == "aws_apigw_stage_logging_disabled"

    def test_clean_access_log_enabled(self):
        """Stage with accessLogSettings.destinationArn set → no finding."""
        auditor, _ = _make_auditor()
        stage = {
            "stageName": "prod",
            "accessLogSettings": {
                "destinationArn": "arn:aws:logs:us-east-1:123:log-group:/aws/apigw/prod"
            },
            "methodSettings": {},
        }
        finding = auditor._check_stage_logging("api1", "MyAPI", stage)
        assert finding is None

    def test_clean_execution_log_enabled(self):
        """Stage with methodSettings['*/*'].loggingLevel=INFO → no finding."""
        auditor, _ = _make_auditor()
        stage = {
            "stageName": "prod",
            "accessLogSettings": {},
            "methodSettings": {"*/*": {"loggingLevel": "INFO"}},
        }
        finding = auditor._check_stage_logging("api1", "MyAPI", stage)
        assert finding is None

    def test_vulnerable_missing_log_keys(self):
        """Stage with no accessLogSettings or methodSettings keys → MEDIUM finding."""
        auditor, _ = _make_auditor()
        stage = {"stageName": "dev"}
        finding = auditor._check_stage_logging("api1", "MyAPI", stage)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM


# ---------------------------------------------------------------------------
# Check 4.5 — Custom domain TLS version
# ---------------------------------------------------------------------------


class TestCheckStageTls:
    def test_vulnerable_tls_1_0(self):
        """securityPolicy=TLS_1_0 → MEDIUM finding."""
        auditor, _ = _make_auditor()
        domain = {"domainName": "api.example.com", "securityPolicy": "TLS_1_0"}
        finding = auditor._check_stage_tls(domain)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM
        assert finding.check_id == "aws_apigw_domain_weak_tls"
        assert "TLS_1_0" in finding.title

    def test_vulnerable_tls_1_1(self):
        """securityPolicy=TLS_1_1 → MEDIUM finding."""
        auditor, _ = _make_auditor()
        domain = {"domainName": "api.example.com", "securityPolicy": "TLS_1_1"}
        finding = auditor._check_stage_tls(domain)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM
        assert "TLS_1_1" in finding.title

    def test_clean_tls_1_2(self):
        """securityPolicy=TLS_1_2 → no finding."""
        auditor, _ = _make_auditor()
        domain = {"domainName": "api.example.com", "securityPolicy": "TLS_1_2"}
        finding = auditor._check_stage_tls(domain)
        assert finding is None


# ---------------------------------------------------------------------------
# Check 4.6 — Usage plan throttling
# ---------------------------------------------------------------------------


class TestCheckUsagePlanThrottling:
    def test_vulnerable_empty_throttle(self):
        """Usage plan with throttle={} → MEDIUM finding."""
        auditor, _ = _make_auditor()
        plan = {"id": "plan1", "name": "BasicPlan", "throttle": {}}
        finding = auditor._check_usage_plan_throttling(plan)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM
        assert finding.check_id == "aws_apigw_usage_plan_no_throttling"

    def test_vulnerable_no_throttle_key(self):
        """Usage plan with no 'throttle' key → MEDIUM finding."""
        auditor, _ = _make_auditor()
        plan = {"id": "plan2", "name": "NoPlan"}
        finding = auditor._check_usage_plan_throttling(plan)
        assert finding is not None
        assert finding.severity == GatewaySeverity.MEDIUM

    def test_clean_throttle_configured(self):
        """Usage plan with rateLimit and burstLimit → no finding."""
        auditor, _ = _make_auditor()
        plan = {
            "id": "plan3",
            "name": "GoodPlan",
            "throttle": {"rateLimit": 1000, "burstLimit": 500},
        }
        finding = auditor._check_usage_plan_throttling(plan)
        assert finding is None


# ---------------------------------------------------------------------------
# Check 4.7 — Orphan API keys
# ---------------------------------------------------------------------------


class TestCheckOrphanApiKeys:
    def test_vulnerable_key_not_in_plan(self):
        """Key not in plan_key_ids → LOW finding."""
        auditor, _ = _make_auditor()
        keys = [{"id": "key1", "name": "MyKey", "enabled": True}]
        plan_key_ids: set = set()  # key1 is NOT in any plan
        findings = auditor._check_orphan_api_keys(keys, plan_key_ids)
        assert len(findings) == 1
        assert findings[0].severity == GatewaySeverity.LOW
        assert findings[0].check_id == "aws_apigw_orphan_api_key"
        assert findings[0].evidence["key_id"] == "key1"

    def test_clean_key_in_plan(self):
        """Key id present in plan_key_ids → no finding."""
        auditor, _ = _make_auditor()
        keys = [{"id": "key2", "name": "UsedKey", "enabled": True}]
        plan_key_ids = {"key2"}
        findings = auditor._check_orphan_api_keys(keys, plan_key_ids)
        assert findings == []

    def test_multiple_keys_mixed(self):
        """One orphan key and one associated key → exactly one LOW finding."""
        auditor, _ = _make_auditor()
        keys = [
            {"id": "orphan", "name": "Orphan", "enabled": True},
            {"id": "used", "name": "Used", "enabled": True},
        ]
        plan_key_ids = {"used"}
        findings = auditor._check_orphan_api_keys(keys, plan_key_ids)
        assert len(findings) == 1
        assert findings[0].evidence["key_id"] == "orphan"


# ---------------------------------------------------------------------------
# Check 4.8 — CORS wildcard with credentials
# ---------------------------------------------------------------------------


class TestCheckCorsWildcardWithCredentials:
    def _make_method_data(
        self,
        allow_origin: str = "'*'",
        allow_credentials: str = "'true'",
    ) -> dict:
        return {
            "methodIntegration": {
                "integrationResponses": {
                    "200": {
                        "responseParameters": {
                            "method.response.header.Access-Control-Allow-Origin": allow_origin,
                            "method.response.header.Access-Control-Allow-Credentials": allow_credentials,
                        }
                    }
                }
            }
        }

    def test_vulnerable_wildcard_origin_with_credentials(self):
        """Origin='*' and credentials='true' → HIGH finding."""
        auditor, _ = _make_auditor()
        resource = {"id": "res1", "path": "/items"}
        method_data = self._make_method_data("'*'", "'true'")
        finding = auditor._check_cors_wildcard_with_credentials(
            "api1", "MyAPI", resource, method_data
        )
        assert finding is not None
        assert finding.severity == GatewaySeverity.HIGH
        assert finding.check_id == "aws_apigw_cors_wildcard_with_credentials"

    def test_clean_specific_origin(self):
        """Specific origin (not *) with credentials → no finding."""
        auditor, _ = _make_auditor()
        resource = {"id": "res1", "path": "/items"}
        method_data = self._make_method_data("'https://app.example.com'", "'true'")
        finding = auditor._check_cors_wildcard_with_credentials(
            "api1", "MyAPI", resource, method_data
        )
        assert finding is None

    def test_clean_wildcard_origin_no_credentials(self):
        """Wildcard origin but credentials=false → no finding."""
        auditor, _ = _make_auditor()
        resource = {"id": "res1", "path": "/items"}
        method_data = self._make_method_data("'*'", "'false'")
        finding = auditor._check_cors_wildcard_with_credentials(
            "api1", "MyAPI", resource, method_data
        )
        assert finding is None

    def test_clean_no_integration_responses(self):
        """No integrationResponses at all → no finding."""
        auditor, _ = _make_auditor()
        resource = {"id": "res1", "path": "/items"}
        method_data = {"methodIntegration": {}}
        finding = auditor._check_cors_wildcard_with_credentials(
            "api1", "MyAPI", resource, method_data
        )
        assert finding is None


# ---------------------------------------------------------------------------
# Check 4.9 — Lambda integration role overprivilege
# ---------------------------------------------------------------------------


class TestCheckLambdaRoleOverprivilege:
    def _make_method_data_aws(
        self, integration_type: str = "AWS_PROXY"
    ) -> dict:
        """Build a method_data dict with an AWS integration and a role ARN."""
        return {
            "methodIntegration": {
                "type": integration_type,
                "credentials": "arn:aws:iam::123456789012:role/MyLambdaRole",
                "uri": "arn:aws:apigateway:us-east-1:lambda:path/functions/arn:aws:lambda:::function:MyFn/invocations",
            }
        }

    def _setup_iam_mocks(
        self,
        mock_client: MagicMock,
        actions: list,
        resources: list | None = None,
    ) -> None:
        """Wire IAM mock returns for list_attached_role_policies → get_policy → get_policy_version."""
        if resources is None:
            resources = ["*"]
        mock_client.iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/MyPolicy"}]
        }
        mock_client.iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_client.iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": actions,
                            "Resource": resources,
                        }
                    ]
                }
            }
        }

    def test_vulnerable_wildcard_action(self):
        """IAM policy with Action='*' → INFO finding."""
        auditor, mock_client = _make_auditor()
        self._setup_iam_mocks(mock_client, actions=["*"], resources=["*"])
        resource = {"id": "res1", "path": "/fn"}
        method_data = self._make_method_data_aws("AWS_PROXY")
        finding = auditor._check_lambda_role_overprivilege(
            "api1", "MyAPI", resource, "POST", method_data
        )
        assert finding is not None
        assert finding.severity == GatewaySeverity.INFO
        assert finding.check_id == "aws_apigw_lambda_role_overprivilege"

    def test_vulnerable_wildcard_resource(self):
        """IAM policy with Resource='*' even with specific actions → INFO finding."""
        auditor, mock_client = _make_auditor()
        self._setup_iam_mocks(
            mock_client,
            actions=["lambda:InvokeFunction"],
            resources=["*"],
        )
        resource = {"id": "res1", "path": "/fn"}
        method_data = self._make_method_data_aws("AWS")
        finding = auditor._check_lambda_role_overprivilege(
            "api1", "MyAPI", resource, "POST", method_data
        )
        assert finding is not None
        assert finding.severity == GatewaySeverity.INFO

    def test_clean_specific_actions_and_resources(self):
        """IAM policy with specific actions and resources → no finding."""
        auditor, mock_client = _make_auditor()
        self._setup_iam_mocks(
            mock_client,
            actions=["lambda:InvokeFunction"],
            resources=["arn:aws:lambda:us-east-1:123:function:MyFn"],
        )
        resource = {"id": "res1", "path": "/fn"}
        method_data = self._make_method_data_aws("AWS_PROXY")
        finding = auditor._check_lambda_role_overprivilege(
            "api1", "MyAPI", resource, "POST", method_data
        )
        assert finding is None

    def test_clean_non_aws_integration_type(self):
        """Integration type=HTTP → no finding (not an AWS/Lambda integration)."""
        auditor, mock_client = _make_auditor()
        resource = {"id": "res1", "path": "/fn"}
        method_data = {
            "methodIntegration": {
                "type": "HTTP",
                "uri": "https://backend.example.com/proxy",
            }
        }
        finding = auditor._check_lambda_role_overprivilege(
            "api1", "MyAPI", resource, "GET", method_data
        )
        assert finding is None
        # IAM should NOT have been called
        mock_client.iam.list_attached_role_policies.assert_not_called()

    def test_clean_no_credentials_field(self):
        """AWS integration but no credentials (role) → no finding."""
        auditor, mock_client = _make_auditor()
        resource = {"id": "res1", "path": "/fn"}
        method_data = {
            "methodIntegration": {
                "type": "AWS_PROXY",
                # credentials key absent
            }
        }
        finding = auditor._check_lambda_role_overprivilege(
            "api1", "MyAPI", resource, "POST", method_data
        )
        assert finding is None
        mock_client.iam.list_attached_role_policies.assert_not_called()
