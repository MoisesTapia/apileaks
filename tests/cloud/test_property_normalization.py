"""
Property-based tests for GatewayFindingNormalizer — Normalización Consistente a Finding.

Feature: cloud-gateway-security-audit

**Property 3: Normalización Consistente a Finding**

For *any* ``GatewayFinding`` produced by any of the three auditors (aws, gcp,
azure), after normalization via ``GatewayFindingNormalizer.to_finding()``, the
resulting ``Finding`` SHALL:

1. Have ``owasp_category = "API8"`` (Security Misconfiguration).
2. Include the originating ``provider`` in its evidence string.
3. Include the originating ``account_context`` in its evidence string.
4. Have ``endpoint`` populated with ``resource_id`` (not an HTTP URL).
5. Have a non-empty ``remediation`` field.

**Validates: Requirements 7.1, 7.2, 7.3**
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from modules.cloud.base import GatewayFinding, GatewaySeverity
from modules.cloud.normalizer import GatewayFindingNormalizer

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_PROVIDERS = ["aws", "gcp", "azure"]
_SEVERITIES = list(GatewaySeverity)

_RESOURCE_TYPES = [
    "rest_api",
    "stage",
    "usage_plan",
    "product",
    "api_config",
    "gateway",
    "apim_instance",
    "api_management",
    "gateway_config",
]


@st.composite
def gateway_findings(draw) -> GatewayFinding:
    """
    Generate an arbitrary but structurally valid GatewayFinding for any of
    the three supported providers with varied resource_id and account_context.
    """
    provider = draw(st.sampled_from(_PROVIDERS))

    # resource_id: realistic cloud resource identifiers (ARN / GCP resource
    # name / Azure resource URI) — deliberately NOT plain HTTP URLs.
    resource_id = draw(
        st.one_of(
            # AWS ARN format
            st.from_regex(
                r"arn:aws:[a-z]+:[a-z0-9-]*:\d{12}:[a-z_]+/[a-zA-Z0-9_-]+",
                fullmatch=True,
            ),
            # GCP resource name format
            st.from_regex(
                r"projects/[a-z0-9-]+/locations/[a-z0-9-]+/gateways/[a-z0-9-]+",
                fullmatch=True,
            ),
            # Azure resource URI format
            st.from_regex(
                r"/subscriptions/[a-f0-9-]+/resourceGroups/[a-zA-Z0-9_-]+"
                r"/providers/Microsoft\.ApiManagement/service/[a-zA-Z0-9]+",
                fullmatch=True,
            ),
        )
    )

    account_context = draw(
        st.from_regex(r"[a-zA-Z0-9_-]{3,30}", fullmatch=True)
    )

    severity = draw(st.sampled_from(_SEVERITIES))
    resource_type = draw(st.sampled_from(_RESOURCE_TYPES))
    check_id = draw(
        st.from_regex(r"[a-z]{3}_apigw_[a-z_]{3,20}", fullmatch=True)
    )
    title = draw(st.text(min_size=5, max_size=80))
    evidence = draw(
        st.fixed_dictionaries({"description": st.text(min_size=1, max_size=100)})
    )
    # Ensure remediation is a non-empty string (auditors must provide it)
    remediation = draw(st.text(min_size=5, max_size=200))
    region_or_location = draw(
        st.one_of(
            st.none(),
            st.from_regex(r"[a-z]{2,3}-[a-z]+-\d", fullmatch=True),
        )
    )

    return GatewayFinding(
        provider=provider,
        resource_id=resource_id,
        resource_type=resource_type,
        check_id=check_id,
        title=title,
        severity=severity,
        evidence=evidence,
        remediation=remediation,
        account_context=account_context,
        region_or_location=region_or_location,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    provider: str = "aws",
    resource_id: str = "arn:aws:apigateway:us-east-1:123456789012:restapi/abc123",
    account_context: str = "default-profile",
    severity: GatewaySeverity = GatewaySeverity.HIGH,
    remediation: str = "Restrict the resource policy principal.",
    region_or_location: str | None = "us-east-1",
) -> GatewayFinding:
    """Return a concrete GatewayFinding suitable for example-based tests."""
    return GatewayFinding(
        provider=provider,
        resource_id=resource_id,
        resource_type="rest_api",
        check_id="aws_apigw_resource_policy_wildcard",
        title="Resource policy allows wildcard principal",
        severity=severity,
        evidence={"policy": '{"Principal": "*"}'},
        remediation=remediation,
        account_context=account_context,
        region_or_location=region_or_location,
    )


# ---------------------------------------------------------------------------
# Example-based tests (fast, deterministic)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", _PROVIDERS)
def test_owasp_category_is_api8_for_all_providers(provider: str) -> None:
    """Req 7.1: owasp_category must be 'API8' regardless of provider."""
    gf = _make_finding(provider=provider)
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert finding.owasp_category == "API8", (
        f"Expected owasp_category='API8', got {finding.owasp_category!r} "
        f"for provider={provider}"
    )


@pytest.mark.parametrize("provider", _PROVIDERS)
def test_provider_appears_in_evidence(provider: str) -> None:
    """Req 7.2: provider name must appear in the Finding evidence."""
    gf = _make_finding(provider=provider)
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert provider in finding.evidence, (
        f"Provider '{provider}' not found in evidence: {finding.evidence!r}"
    )


@pytest.mark.parametrize(
    "account_context",
    ["default-profile", "prod-account-123", "my-gcp-project", "sub-east-us"],
)
def test_account_context_appears_in_evidence(account_context: str) -> None:
    """Req 7.2: account_context must appear in the Finding evidence."""
    gf = _make_finding(account_context=account_context)
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert account_context in finding.evidence, (
        f"account_context '{account_context}' not found in evidence: "
        f"{finding.evidence!r}"
    )


@pytest.mark.parametrize(
    "resource_id",
    [
        "arn:aws:apigateway:us-east-1:123456789012:restapi/myapi",
        "projects/my-proj/locations/us-central1/gateways/my-gw",
        "/subscriptions/abc123/resourceGroups/rg1/providers/Microsoft.ApiManagement/service/svc1",
    ],
)
def test_endpoint_equals_resource_id(resource_id: str) -> None:
    """Req 7.2: Finding.endpoint must equal GatewayFinding.resource_id."""
    gf = _make_finding(resource_id=resource_id)
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert finding.endpoint == resource_id, (
        f"Expected endpoint={resource_id!r}, got {finding.endpoint!r}"
    )


def test_endpoint_is_not_http_url() -> None:
    """Req 7.2: endpoint must be a resource identifier, not a plain HTTP URL."""
    arn = "arn:aws:apigateway:us-east-1:123456789012:restapi/abc"
    gf = _make_finding(resource_id=arn)
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert not finding.endpoint.startswith("http://") and not finding.endpoint.startswith(
        "https://"
    ), f"endpoint looks like an HTTP URL: {finding.endpoint!r}"


@pytest.mark.parametrize("severity", _SEVERITIES)
def test_all_severities_map_without_error(severity: GatewaySeverity) -> None:
    """Every GatewaySeverity must produce a valid Finding without raising."""
    gf = _make_finding(severity=severity)
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert finding.severity is not None, (
        f"severity mapping returned None for GatewaySeverity.{severity.name}"
    )


def test_remediation_non_empty() -> None:
    """Req 7.3: recommendation must be non-empty."""
    gf = _make_finding(remediation="Restrict the resource policy principal.")
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert finding.recommendation, "recommendation field must not be empty"


def test_batch_to_findings_preserves_api8() -> None:
    """to_findings must propagate owasp_category='API8' to every finding."""
    normalizer = GatewayFindingNormalizer()
    gfs = [_make_finding(provider=p) for p in _PROVIDERS]
    findings = normalizer.to_findings(gfs)

    assert len(findings) == len(gfs)
    for f in findings:
        assert f.owasp_category == "API8", (
            f"Expected owasp_category='API8', got {f.owasp_category!r}"
        )


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis) — Property 3
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_owasp_category_always_api8(gf: GatewayFinding) -> None:
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding (any provider, any severity, any resource_id),
    the resulting Finding.owasp_category MUST equal "API8".

    **Validates: Requirements 7.1, 7.2**
    """
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert finding.owasp_category == "API8", (
        f"owasp_category must always be 'API8' for cloud gateway findings; "
        f"got {finding.owasp_category!r} (provider={gf.provider})"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_provider_in_evidence(gf: GatewayFinding) -> None:
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.evidence MUST contain the
    originating provider name so findings can be traced back to their origin.

    **Validates: Requirement 7.2**
    """
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert gf.provider in finding.evidence, (
        f"provider '{gf.provider}' not found in evidence. "
        f"Evidence: {finding.evidence!r}"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_account_context_in_evidence(gf: GatewayFinding) -> None:
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.evidence MUST contain the
    account_context so multi-account scan results can be traced to their origin.

    **Validates: Requirement 7.2**
    """
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert gf.account_context in finding.evidence, (
        f"account_context '{gf.account_context}' not found in evidence. "
        f"Evidence: {finding.evidence!r}"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_endpoint_equals_resource_id(gf: GatewayFinding) -> None:
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.endpoint MUST equal the
    GatewayFinding.resource_id (the cloud resource ARN / URI), and MUST NOT
    be a plain HTTP URL.

    **Validates: Requirement 7.2**
    """
    finding = GatewayFindingNormalizer().to_finding(gf)

    assert finding.endpoint == gf.resource_id, (
        f"Finding.endpoint must equal GatewayFinding.resource_id. "
        f"Expected {gf.resource_id!r}, got {finding.endpoint!r}"
    )
    assert not finding.endpoint.startswith("http://") and not finding.endpoint.startswith(
        "https://"
    ), (
        f"Finding.endpoint must not be an HTTP URL; got {finding.endpoint!r}"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_remediation_non_empty(gf: GatewayFinding) -> None:
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding with a non-empty remediation, the resulting
    Finding.recommendation MUST be non-empty (provider-specific guidance is
    preserved verbatim).

    **Validates: Requirement 7.3**
    """
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert finding.recommendation, (
        f"Finding.recommendation must not be empty; "
        f"GatewayFinding.remediation was {gf.remediation!r}"
    )
    assert finding.recommendation == gf.remediation, (
        f"Finding.recommendation must equal GatewayFinding.remediation. "
        f"Expected {gf.remediation!r}, got {finding.recommendation!r}"
    )
