"""
Cloud API Gateway Security Audit modules.

Provides credentialed, read-only auditing of cloud API gateway configurations
(AWS API Gateway, GCP API Gateway/Cloud Endpoints, Azure API Management),
normalizing findings to the standard APILeak Finding model under OWASP API8
(Security Misconfiguration).
"""

from modules.cloud.aws_api_gateway import AWSGatewayAuditor
from modules.cloud.azure_apim import AzureAPIMAuditor
from modules.cloud.base import CloudGatewayAuditor, GatewayFinding, GatewaySeverity
from modules.cloud.gcp_api_gateway import GCPGatewayAuditor
from modules.cloud.normalizer import GatewayFindingNormalizer
from modules.cloud.orchestrator import CloudAuditOrchestrator

__all__ = [
    "CloudGatewayAuditor",
    "GatewayFinding",
    "GatewaySeverity",
    "GatewayFindingNormalizer",
    "AWSGatewayAuditor",
    "GCPGatewayAuditor",
    "AzureAPIMAuditor",
    "CloudAuditOrchestrator",
]
