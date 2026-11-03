"""
Cloud Gateway Auditor — base contract and data models.

Defines the common GatewaySeverity / GatewayFinding types and the
CloudGatewayAuditor ABC that every provider-specific auditor implements.
The abstract contract is deliberately minimal: discover what resources are
auditable, then audit them and return a list of GatewayFinding objects that
the GatewayFindingNormalizer converts to standard Finding objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GatewaySeverity(str, Enum):
    """Severity levels for gateway configuration findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CloudAuditError(Exception):
    """Base exception for cloud gateway audit errors."""


class CredentialResolutionError(CloudAuditError):
    """Credentials are absent or invalid for a provider."""


class InsufficientPermissionsError(CloudAuditError):
    """A read operation was denied due to insufficient permissions."""


class ProviderThrottledError(CloudAuditError):
    """The provider's management API returned a rate-limit error."""


# ---------------------------------------------------------------------------
# GatewayFinding
# ---------------------------------------------------------------------------


@dataclass
class GatewayFinding:
    """
    Normalised finding from a cloud API gateway configuration audit.

    All fields except the optional ones must be populated by the
    provider-specific auditor.  The ``account_context`` should identify
    which profile/account/project/subscription produced the finding so
    Multi_Account_Scan results can be traced back to their origin.
    """

    provider: str
    """One of "aws", "gcp", "azure"."""

    resource_id: str
    """ARN / resource name / resource URI of the audited resource."""

    resource_type: str
    """e.g. "rest_api", "stage", "usage_plan", "product", "gateway_config" …"""

    check_id: str
    """Stable snake_case identifier, e.g. "aws_apigw_resource_policy_wildcard"."""

    title: str
    """Short human-readable description of the misconfiguration."""

    severity: GatewaySeverity

    evidence: dict[str, Any]
    """
    Provider-specific key/value evidence.  Any secret or credential values
    must be redacted by the auditor before populating this field.
    """

    remediation: str
    """Provider-specific remediation guidance (console / CLI / Terraform path)."""

    account_context: str
    """Profile / account / project / subscription that was audited."""

    region_or_location: str | None = None

    additional_info: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper: permission-denied / not-auditable finding factory
# ---------------------------------------------------------------------------


def create_permission_denied_finding(
    resource_id: str,
    resource_type: str,
    provider: str,
    account_context: str,
    operation: str,
) -> GatewayFinding:
    """
    Return an INFO-level GatewayFinding for a resource that could not be audited
    due to insufficient permissions or exhausted retries after throttling.

    Parameters
    ----------
    resource_id:      ARN / resource URI of the resource that could not be read.
    resource_type:    Type label (e.g. ``"rest_api"``, ``"gcp_api_config"``).
    provider:         Short provider identifier: ``"aws"``, ``"gcp"``, or ``"azure"``.
    account_context:  Profile / project / subscription label.
    operation:        The SDK operation that was denied (e.g. ``"get_rest_apis"``).
    """
    return GatewayFinding(
        provider=provider,
        resource_id=resource_id,
        resource_type=resource_type,
        check_id="cloud_resource_not_auditable",
        title=f"Resource not auditable: insufficient permissions or throttled for '{operation}'",
        severity=GatewaySeverity.INFO,
        evidence={
            "operation": operation,
            "reason": "InsufficientPermissionsError or ProviderThrottledError",
        },
        remediation=(
            "Grant the auditing identity the minimum read-only permissions required. "
            "If the issue is throttling, increase the retry limit or reduce audit scope. "
            "See your cloud provider's IAM documentation for required roles."
        ),
        account_context=account_context,
    )


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class CloudGatewayAuditor(ABC):
    """
    Common contract for cloud API gateway auditors.

    Each provider implements exactly two methods:
    - ``discover_resources``: enumerate auditable resources.
    - ``audit``: run all checks and return GatewayFinding objects.

    Both methods are async to allow concurrent sub-calls within a single
    auditor without blocking the event loop.
    """

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the short provider identifier, e.g. "aws"."""
        ...

    @abstractmethod
    async def discover_resources(self) -> list[dict[str, Any]]:
        """
        Enumerate the resources that will be audited.

        Returns a list of raw resource dicts as returned by the provider SDK.
        Used primarily for logging/reporting how many resources were found.
        """
        ...

    @abstractmethod
    async def audit(self) -> list[GatewayFinding]:
        """
        Execute all configuration checks and return findings.

        Must only invoke read operations (Get*/List*/Describe*) unless the
        CloudReadOnlyGuard that was injected into the auditor allows
        destructive operations.
        """
        ...
