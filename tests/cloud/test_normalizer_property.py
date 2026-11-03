"""
Property-based tests for GatewayFindingNormalizer — Normalización Consistente.

Feature: cloud-gateway-security-audit

**Property 3: Normalización Consistente a Finding**

For *any* ``GatewayFinding`` produced by any of the three auditors, the
resulting ``Finding`` MUST:

1. Have ``owasp_category = "API8"``.
2. Include the originating ``provider`` in its evidence string.
3. Include the originating ``account_context`` in its evidence string.
4. Have ``endpoint`` populated with ``resource_id`` of the GatewayFinding.

**Validates: Requirements 7.1, 7.2, 7.3**
"""

from __future__ import annotations

import string

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from modules.cloud.base import GatewayFinding, GatewaySeverity
from modules.cloud.normalizer import GatewayFindingNormalizer
from modules.owasp.bola_testing import BOLATestingModule

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_PROVIDERS = ["aws", "gcp", "azure"]

_RESOURCE_TYPES = [
    "rest_api",
    "stage",
    "usage_plan",
    "product",
    "api_config",
    "gateway",
    "apim_instance",
]

_SEVERITIES = list(GatewaySeverity)


@st.composite
def gateway_findings(draw) -> GatewayFinding:
    """Generate an arbitrary but structurally valid GatewayFinding."""
    provider = draw(st.sampled_from(_PROVIDERS))
    # resource_id: look like an ARN / GCP resource name / Azure resource URI
    resource_id = draw(
        st.one_of(
            st.from_regex(r"arn:aws:[a-z]+:[a-z0-9-]*:\d{12}:[a-z_]+/[a-zA-Z0-9_-]+", fullmatch=True),
            st.from_regex(r"projects/[a-z0-9-]+/locations/[a-z0-9-]+/gateways/[a-z0-9-]+", fullmatch=True),
            st.from_regex(r"/subscriptions/[a-f0-9-]+/resourceGroups/[a-zA-Z0-9_-]+/providers/Microsoft\.ApiManagement/service/[a-zA-Z0-9]+", fullmatch=True),
        )
    )
    resource_type = draw(st.sampled_from(_RESOURCE_TYPES))
    check_id = draw(st.from_regex(r"[a-z]{3}_apigw_[a-z_]+", fullmatch=True))
    title = draw(st.text(min_size=5, max_size=80))
    severity = draw(st.sampled_from(_SEVERITIES))
    evidence = draw(
        st.fixed_dictionaries(
            {
                "description": st.text(min_size=1, max_size=100),
            }
        )
    )
    remediation = draw(st.text(min_size=5, max_size=200))
    account_context = draw(st.from_regex(r"[a-zA-Z0-9_-]{3,30}", fullmatch=True))
    region_or_location = draw(st.one_of(st.none(), st.from_regex(r"[a-z]{2,3}-[a-z]+-\d", fullmatch=True)))

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
# Baseline / example-based tests (fast, deterministic)
# ---------------------------------------------------------------------------


def _make_finding(
    provider: str = "aws",
    resource_id: str = "arn:aws:apigateway:us-east-1:123456789012:restapi/abc123",
    account_context: str = "default-profile",
    severity: GatewaySeverity = GatewaySeverity.HIGH,
    region_or_location: str | None = "us-east-1",
) -> GatewayFinding:
    return GatewayFinding(
        provider=provider,
        resource_id=resource_id,
        resource_type="rest_api",
        check_id="aws_apigw_resource_policy_wildcard",
        title="Resource policy allows wildcard principal",
        severity=severity,
        evidence={"policy": '{"Principal": "*"}'},
        remediation="Restrict the resource policy principal.",
        account_context=account_context,
        region_or_location=region_or_location,
    )


@pytest.mark.parametrize("provider", _PROVIDERS)
def test_owasp_category_is_api8_for_all_providers(provider: str):
    """owasp_category must be 'API8' regardless of which provider produced the finding."""
    gf = _make_finding(provider=provider)
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert finding.owasp_category == "API8", (
        f"Expected owasp_category='API8', got {finding.owasp_category!r} for provider={provider}"
    )


@pytest.mark.parametrize("provider", _PROVIDERS)
def test_provider_present_in_evidence(provider: str):
    """The provider name must appear in the Finding evidence."""
    gf = _make_finding(provider=provider)
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert provider in finding.evidence, (
        f"Provider '{provider}' not found in finding evidence: {finding.evidence!r}"
    )


@pytest.mark.parametrize("account_context", ["default-profile", "prod-account", "dev-project"])
def test_account_context_present_in_evidence(account_context: str):
    """The account_context must appear in the Finding evidence."""
    gf = _make_finding(account_context=account_context)
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert account_context in finding.evidence, (
        f"account_context '{account_context}' not found in finding evidence: {finding.evidence!r}"
    )


def test_endpoint_populated_with_resource_id():
    """The Finding.endpoint must equal GatewayFinding.resource_id."""
    resource_id = "arn:aws:apigateway:us-east-1:123456789012:restapi/myapi"
    gf = _make_finding(resource_id=resource_id)
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert finding.endpoint == resource_id, (
        f"Expected endpoint={resource_id!r}, got {finding.endpoint!r}"
    )


@pytest.mark.parametrize("severity", _SEVERITIES)
def test_severity_mapping_covers_all_gateway_severities(severity: GatewaySeverity):
    """Every GatewaySeverity must produce a valid Finding without raising KeyError."""
    gf = _make_finding(severity=severity)
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert finding.severity is not None, (
        f"Severity mapping returned None for GatewaySeverity.{severity.name}"
    )


def test_batch_conversion_preserves_owasp_category():
    """to_findings must propagate the API8 category to every finding in a batch."""
    normalizer = GatewayFindingNormalizer()
    gateway_findings = [
        _make_finding(provider=p)
        for p in _PROVIDERS
    ]
    findings = normalizer.to_findings(gateway_findings)
    assert len(findings) == len(gateway_findings)
    for f in findings:
        assert f.owasp_category == "API8", (
            f"Expected owasp_category='API8', got {f.owasp_category!r}"
        )


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_owasp_category_always_api8(gf: GatewayFinding):
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.owasp_category MUST be
    "API8" (Security Misconfiguration).

    **Validates: Requirements 7.1, 7.2**
    """
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert finding.owasp_category == "API8", (
        f"owasp_category must be 'API8' for any cloud gateway finding; "
        f"got {finding.owasp_category!r} for provider={gf.provider}"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_provider_always_in_evidence(gf: GatewayFinding):
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.evidence MUST contain the
    originating provider name.

    **Validates: Requirement 7.2**
    """
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert gf.provider in finding.evidence, (
        f"Provider '{gf.provider}' not found in finding evidence. "
        f"Evidence: {finding.evidence!r}"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_account_context_always_in_evidence(gf: GatewayFinding):
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.evidence MUST contain the
    account_context value.

    **Validates: Requirement 7.2**
    """
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert gf.account_context in finding.evidence, (
        f"account_context '{gf.account_context}' not found in finding evidence. "
        f"Evidence: {finding.evidence!r}"
    )


@settings(max_examples=200, deadline=None)
@given(gf=gateway_findings())
def test_property_endpoint_equals_resource_id(gf: GatewayFinding):
    """
    **Property 3: Normalización Consistente a Finding**

    For *any* GatewayFinding, the resulting Finding.endpoint MUST equal the
    GatewayFinding.resource_id.

    **Validates: Requirement 7.2**
    """
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)
    assert finding.endpoint == gf.resource_id, (
        f"Finding.endpoint must equal GatewayFinding.resource_id. "
        f"Expected {gf.resource_id!r}, got {finding.endpoint!r}"
    )


# ===========================================================================
# Property 2: Redacción de Secretos en Hallazgos
# ===========================================================================
#
# For *any* GatewayFinding generated, no credential/secret/key value SHALL
# appear in plain text in its ``evidence`` field after normalization.
#
# **Validates: Requirements 2.9**
#
# Strategy: three complementary snippet generators, each targeting one of the
# three rules in ``BOLATestingModule.redact_secrets``:
#
#   Rule 1 – JSON-style credential-named field inside a string value
#   Rule 2 – key: value / key=value form where key is a credential keyword
#   Rule 3 – bare token with a known credential prefix (AKIA, sk_, …)
#
# Every strategy returns (GatewayFinding, plaintext_secret) so the property
# can assert the secret is absent after normalization.
# ===========================================================================

# Alphabet for generated secret values: alphanumerics only, so a generated
# value is never split by a delimiter that the redactor treats specially
# (whitespace, quotes, commas, braces …).  Min size >= 12 ensures the value
# can never be a substring of the 10-char "<redacted>" marker.
_SECRET_ALPHABET: str = string.ascii_letters + string.digits

# ---------------------------------------------------------------------------
# Minimal base GatewayFinding builder (evidence filled in by each strategy)
# ---------------------------------------------------------------------------


def _base_finding(
    provider: str,
    resource_id: str,
    account_context: str,
    evidence: dict,
) -> GatewayFinding:
    """Return the smallest valid GatewayFinding with the supplied evidence dict."""
    return GatewayFinding(
        provider=provider,
        resource_id=resource_id,
        resource_type="rest_api",
        check_id="cloud_test_secret_redaction",
        title="Property-2 secret-redaction test finding",
        severity=GatewaySeverity.HIGH,
        evidence=evidence,
        remediation="Rotate the exposed credential immediately.",
        account_context=account_context,
    )


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------


@st.composite
def _findings_with_credential_kv(draw) -> tuple[GatewayFinding, str]:
    """Rule 2: evidence dict key is a SECRET_FIELD_KEYWORD, value is plaintext.

    ``_format_evidence`` serialises each entry as ``"key: value"``, matching
    the ``keyword: value`` pattern that rule 2 of ``redact_secrets`` targets.
    """
    cred_key = draw(st.sampled_from(BOLATestingModule.SECRET_FIELD_KEYWORDS))
    secret = draw(st.text(alphabet=_SECRET_ALPHABET, min_size=12, max_size=48))
    provider = draw(st.sampled_from(_PROVIDERS))
    resource_id = draw(
        st.from_regex(
            r"arn:aws:[a-z]+:[a-z0-9-]{2,20}:\d{12}:[a-z_]+/[a-zA-Z0-9_-]{1,20}",
            fullmatch=True,
        )
    )
    account_context = draw(st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{2,19}", fullmatch=True))
    # Filter out cases where the secret coincidentally appears in non-evidence
    # parts of the formatted string (resource_id, account_context), which
    # would cause a false failure unrelated to redaction correctness.
    assume(secret not in resource_id)
    assume(secret not in account_context)
    gf = _base_finding(provider, resource_id, account_context, {cred_key: secret})
    return gf, secret


@st.composite
def _findings_with_json_credential_in_value(draw) -> tuple[GatewayFinding, str]:
    """Rule 1: evidence dict value is a JSON-like string containing a credential field.

    Simulates real-world policy / response blobs embedded in evidence, e.g.:
    ``{"Principal": "*", "password": "SECRETVALUE"}``.
    """
    cred_key = draw(st.sampled_from(BOLATestingModule.SECRET_FIELD_KEYWORDS))
    secret = draw(st.text(alphabet=_SECRET_ALPHABET, min_size=12, max_size=48))
    template = draw(
        st.sampled_from(
            [
                '{{"note": "audit", "{key}": "{val}"}}',
                '{{"{key}": "{val}", "id": 1}}',
                '{{"config": {{"nested": true}}, "{key}": "{val}"}}',
            ]
        )
    )
    json_blob = template.format(key=cred_key, val=secret)
    provider = draw(st.sampled_from(_PROVIDERS))
    resource_id = draw(
        st.from_regex(
            r"arn:aws:[a-z]+:[a-z0-9-]{2,20}:\d{12}:[a-z_]+/[a-zA-Z0-9_-]{1,20}",
            fullmatch=True,
        )
    )
    account_context = draw(st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{2,19}", fullmatch=True))
    # Filter out cases where the secret coincidentally appears in non-evidence
    # parts of the formatted string (resource_id, account_context).
    assume(secret not in resource_id)
    assume(secret not in account_context)
    gf = _base_finding(
        provider, resource_id, account_context, {"policy_document": json_blob}
    )
    return gf, secret


@st.composite
def _findings_with_prefix_token(draw) -> tuple[GatewayFinding, str]:
    """Rule 3 (prefix): evidence dict value carries a known credential prefix.

    Covers AWS access keys (AKIA…), Stripe secret keys (sk_…), GitHub tokens
    (ghp_…), and Slack bot tokens (xoxb-…).
    """
    prefix = draw(st.sampled_from(BOLATestingModule.CREDENTIAL_PREFIXES))
    core = draw(st.text(alphabet=_SECRET_ALPHABET, min_size=16, max_size=40))
    token = prefix + core
    # Use a neutral key so we verify rule 3 fires on the *value*, not the key.
    evidence_key = draw(st.sampled_from(["value", "id", "result", "data"]))
    provider = draw(st.sampled_from(_PROVIDERS))
    resource_id = draw(
        st.from_regex(
            r"arn:aws:[a-z]+:[a-z0-9-]{2,20}:\d{12}:[a-z_]+/[a-zA-Z0-9_-]{1,20}",
            fullmatch=True,
        )
    )
    account_context = draw(st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{2,19}", fullmatch=True))
    gf = _base_finding(provider, resource_id, account_context, {evidence_key: token})
    return gf, token


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------


@settings(max_examples=150, deadline=None)
@given(payload=_findings_with_credential_kv())
def test_property_credential_kv_field_redacted(payload: tuple[GatewayFinding, str]) -> None:
    """
    **Property 2: Redacción de Secretos en Hallazgos**

    When a ``GatewayFinding`` has a credential-named key (from
    ``SECRET_FIELD_KEYWORDS``) in its ``evidence`` dict, the normalizer MUST
    ensure the plaintext secret value does NOT appear in the resulting
    ``Finding.evidence`` string.

    Also verifies minimum Property 3 coverage:
    - ``owasp_category == "API8"``
    - ``endpoint == resource_id``

    **Validates: Requirements 2.9**
    """
    gf, secret = payload
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)

    # --- Property 2: secret must be redacted ---
    assert secret not in finding.evidence, (
        f"Plaintext secret found in Finding.evidence after normalization.\n"
        f"  Secret: {secret!r}\n"
        f"  Evidence: {finding.evidence!r}"
    )

    # --- Property 3 minimum coverage ---
    assert finding.owasp_category == "API8", (
        f"Expected owasp_category='API8', got {finding.owasp_category!r}"
    )
    assert finding.endpoint == gf.resource_id, (
        f"Expected endpoint={gf.resource_id!r}, got {finding.endpoint!r}"
    )


@settings(max_examples=150, deadline=None)
@given(payload=_findings_with_json_credential_in_value())
def test_property_json_credential_in_evidence_value_redacted(
    payload: tuple[GatewayFinding, str],
) -> None:
    """
    **Property 2: Redacción de Secretos en Hallazgos**

    When a ``GatewayFinding`` embeds a JSON-style policy/response blob in its
    ``evidence`` dict that contains a credential-named field (e.g.
    ``{"password": "SECRETVALUE"}``), the normalizer MUST ensure the plaintext
    secret value does NOT appear in the resulting ``Finding.evidence`` string.

    **Validates: Requirements 2.9**
    """
    gf, secret = payload
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)

    assert secret not in finding.evidence, (
        f"Plaintext secret found in Finding.evidence after normalization "
        f"(JSON credential-in-value rule).\n"
        f"  Secret: {secret!r}\n"
        f"  Evidence: {finding.evidence!r}"
    )
    assert finding.owasp_category == "API8"
    assert finding.endpoint == gf.resource_id


@settings(max_examples=150, deadline=None)
@given(payload=_findings_with_prefix_token())
def test_property_known_prefix_token_redacted(
    payload: tuple[GatewayFinding, str],
) -> None:
    """
    **Property 2: Redacción de Secretos en Hallazgos**

    When a ``GatewayFinding`` embeds a token that carries a known credential
    prefix (AKIA…, sk_…, ghp_…, xoxb-…) anywhere in its ``evidence`` dict,
    the normalizer MUST ensure the full token does NOT appear in the resulting
    ``Finding.evidence`` string.

    **Validates: Requirements 2.9**
    """
    gf, token = payload
    normalizer = GatewayFindingNormalizer()
    finding = normalizer.to_finding(gf)

    assert token not in finding.evidence, (
        f"Plaintext prefix-token found in Finding.evidence after normalization "
        f"(known credential-prefix rule).\n"
        f"  Token: {token!r}\n"
        f"  Evidence: {finding.evidence!r}"
    )
    assert finding.owasp_category == "API8"
    assert finding.endpoint == gf.resource_id


# ---------------------------------------------------------------------------
# Deterministic baseline examples for quick regression coverage
# ---------------------------------------------------------------------------


def test_aws_access_key_redacted_in_evidence() -> None:
    """An AWS AKIA access key embedded in evidence must be redacted."""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    gf = _base_finding(
        provider="aws",
        resource_id="arn:aws:apigateway:us-east-1:123456789012:restapi/abc1",
        account_context="prod-profile",
        evidence={"access_key_id": aws_key},
    )
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert aws_key not in finding.evidence, (
        f"AWS access key found unredacted in evidence: {finding.evidence!r}"
    )
    assert finding.owasp_category == "API8"
    assert finding.endpoint == gf.resource_id


def test_plaintext_password_redacted_in_evidence() -> None:
    """A password value embedded in a credential-named field must be redacted."""
    password = "SuperSecretPassword99"
    gf = _base_finding(
        provider="gcp",
        resource_id="projects/my-proj/locations/us-central1/gateways/gw1",
        account_context="my-gcp-project",
        evidence={"password": password},
    )
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert password not in finding.evidence, (
        f"Plaintext password found in evidence: {finding.evidence!r}"
    )
    assert finding.owasp_category == "API8"


def test_api_key_in_json_policy_redacted() -> None:
    """An API key embedded in a JSON policy blob within evidence must be redacted."""
    api_key_value = "MyApiKey1234567890AB"
    policy_blob = f'{{"action": "allow", "api_key": "{api_key_value}"}}'
    gf = _base_finding(
        provider="azure",
        resource_id=(
            "/subscriptions/00000000-0000-0000-0000-000000000000"
            "/resourceGroups/rg1/providers/Microsoft.ApiManagement/service/svc1"
        ),
        account_context="sub-00000000",
        evidence={"security_policy": policy_blob},
    )
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert api_key_value not in finding.evidence, (
        f"API key found unredacted in evidence: {finding.evidence!r}"
    )
    assert finding.owasp_category == "API8"


def test_stripe_secret_key_redacted_in_evidence() -> None:
    """A Stripe sk_live secret key token must be redacted (known-prefix rule)."""
    stripe_key = "sk_EXAMPLE_AbCdEfGhIjKlMnOpQrSt1234"
    gf = _base_finding(
        provider="aws",
        resource_id="arn:aws:apigateway:eu-west-1:123456789012:restapi/xyz99",
        account_context="staging-profile",
        evidence={"integration_credential": stripe_key},
    )
    finding = GatewayFindingNormalizer().to_finding(gf)
    assert stripe_key not in finding.evidence, (
        f"Stripe secret key found unredacted in evidence: {finding.evidence!r}"
    )
    assert finding.owasp_category == "API8"
