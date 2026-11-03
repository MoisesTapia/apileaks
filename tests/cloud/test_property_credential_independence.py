"""
Property-based tests for CloudAuditConfig — Independencia de Credenciales en Texto Plano.

Feature: cloud-gateway-security-audit

**Property 5: Independencia de Credenciales en Texto Plano**

For ANY valid ``CloudAuditConfig`` without explicit credentials in
``Cloud_Audit_Config``, the system SHALL resolve credentials exclusively through
the native SDK chain of the corresponding provider (never requiring a secret
pasted in the APILeak YAML).

Specifically validated:

1. A ``CloudAuditConfig`` with all credential fields empty/None reports
   ``uses_sdk_chain(provider) == True`` for every listed provider.
2. A ``CloudAuditConfig`` that sets ``azure_client_secret`` to a non-empty,
   non-env-var string reports ``has_plaintext_secret() == True``, indicating a
   policy violation.
3. When a sensitive field contains an environment-variable reference
   (``${VAR}``, ``$VAR``, or ``env:VAR``), ``has_plaintext_secret()`` returns
   ``False`` (env-var references are *not* raw secrets).
4. ``uses_sdk_chain(provider)`` returns ``False`` only when at least one
   provider-specific credential field is set to a non-empty value.

**Validates: Requirements 2.1, 2.4, 2.6**
"""

from __future__ import annotations

import string

import pytest
from hypothesis import assume, given, settings, strategies as st

from core.config import CloudAuditConfig, _looks_like_env_var_ref

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PROVIDERS = ["aws", "gcp", "azure"]

# Characters that may appear in an env-var name (POSIX: [A-Za-z_][A-Za-z0-9_]*)
_VAR_CHARS = string.ascii_letters + string.digits + "_"

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------


@st.composite
def env_var_references(draw) -> str:
    """Generate a valid environment-variable reference in any supported format."""
    # var name: starts with a letter or '_', followed by 0-14 alphanumeric/_
    first = draw(st.sampled_from(string.ascii_letters + "_"))
    rest = draw(st.text(alphabet=_VAR_CHARS, min_size=0, max_size=14))
    var_name = first + rest
    fmt = draw(st.sampled_from(["${%s}", "$%s", "env:%s"]))
    return fmt % var_name


@st.composite
def raw_secret_values(draw) -> str:
    """Generate a non-empty string that is NOT an env-var reference.

    Simulates the kind of value a user might accidentally paste directly into a
    YAML file (UUIDs, bearer tokens, passwords, API keys, etc.).
    """
    # Use a printable ASCII alphabet excluding the leading '$' and 'e' (to
    # avoid accidentally producing a valid env-var reference); we achieve the
    # exclusion via `assume` below for simplicity.
    value = draw(st.text(alphabet=string.printable, min_size=4, max_size=64).filter(
        lambda v: v.strip() != "" and not _looks_like_env_var_ref(v)
    ))
    return value


@st.composite
def sdk_chain_configs(draw) -> CloudAuditConfig:
    """Generate a ``CloudAuditConfig`` that defers entirely to the SDK credential chain.

    All credential fields (profiles, role ARNs, service account file, tenant/
    client/secret) are deliberately empty so the system MUST use the native SDK
    chain for each provider.
    """
    providers = draw(
        st.lists(
            st.sampled_from(_PROVIDERS),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    return CloudAuditConfig(
        providers=providers,
        # AWS — empty means boto3 default chain
        aws_profiles=[],
        aws_role_arns=[],
        aws_regions=draw(
            st.lists(st.sampled_from(["us-east-1", "eu-west-1", "ap-southeast-1"]),
                     min_size=1, max_size=2)
        ),
        # GCP — no SA file means ADC
        gcp_project_ids=draw(
            st.lists(st.from_regex(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", fullmatch=True),
                     min_size=0, max_size=2)
        ),
        gcp_service_account_file=None,
        # Azure — no tenant/client/secret means DefaultAzureCredential
        azure_subscription_ids=draw(
            st.lists(st.from_regex(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                   fullmatch=True),
                     min_size=0, max_size=2)
        ),
        azure_resource_groups=[],
        azure_tenant_id=None,
        azure_client_id=None,
        azure_client_secret=None,
        allow_destructive=False,
    )


@st.composite
def explicit_azure_sp_configs(draw) -> CloudAuditConfig:
    """Generate a ``CloudAuditConfig`` with an Azure service principal set.

    The ``azure_client_secret`` is a raw string (not an env-var reference), so
    ``has_plaintext_secret()`` MUST return ``True``.
    """
    secret = draw(raw_secret_values())
    tenant_id = draw(
        st.from_regex(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                      fullmatch=True)
    )
    client_id = draw(
        st.from_regex(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                      fullmatch=True)
    )
    return CloudAuditConfig(
        providers=["azure"],
        azure_tenant_id=tenant_id,
        azure_client_id=client_id,
        azure_client_secret=secret,
    )


# ---------------------------------------------------------------------------
# Baseline / example-based tests
# ---------------------------------------------------------------------------


class TestCloudAuditConfigDefaults:
    """Concrete examples that pin the baseline SDK-chain behaviour."""

    def test_default_config_uses_aws_sdk_chain(self):
        cfg = CloudAuditConfig(providers=["aws"])
        assert cfg.uses_sdk_chain("aws") is True

    def test_explicit_aws_profile_disables_sdk_chain(self):
        cfg = CloudAuditConfig(providers=["aws"], aws_profiles=["my-profile"])
        assert cfg.uses_sdk_chain("aws") is False

    def test_explicit_aws_role_arn_disables_sdk_chain(self):
        cfg = CloudAuditConfig(providers=["aws"], aws_role_arns=["arn:aws:iam::123:role/Audit"])
        assert cfg.uses_sdk_chain("aws") is False

    def test_default_config_uses_gcp_sdk_chain(self):
        cfg = CloudAuditConfig(providers=["gcp"])
        assert cfg.uses_sdk_chain("gcp") is True

    def test_explicit_sa_file_disables_gcp_sdk_chain(self):
        cfg = CloudAuditConfig(providers=["gcp"], gcp_service_account_file="/path/sa.json")
        assert cfg.uses_sdk_chain("gcp") is False

    def test_default_config_uses_azure_sdk_chain(self):
        cfg = CloudAuditConfig(providers=["azure"])
        assert cfg.uses_sdk_chain("azure") is True

    def test_explicit_azure_sp_disables_azure_sdk_chain(self):
        cfg = CloudAuditConfig(
            providers=["azure"],
            azure_tenant_id="tid",
            azure_client_id="cid",
            azure_client_secret="raw-secret",
        )
        assert cfg.uses_sdk_chain("azure") is False

    def test_no_plaintext_secret_on_default_config(self):
        cfg = CloudAuditConfig(providers=["aws", "gcp", "azure"])
        assert cfg.has_plaintext_secret() is False

    def test_plaintext_secret_detected(self):
        cfg = CloudAuditConfig(
            providers=["azure"],
            azure_client_secret="super-secret-abc123",
        )
        assert cfg.has_plaintext_secret() is True

    def test_env_var_ref_not_flagged_as_plaintext(self):
        cfg = CloudAuditConfig(
            providers=["azure"],
            azure_client_secret="${AZURE_CLIENT_SECRET}",
        )
        assert cfg.has_plaintext_secret() is False

    def test_env_var_bare_ref_not_flagged_as_plaintext(self):
        cfg = CloudAuditConfig(
            providers=["azure"],
            azure_client_secret="$AZURE_CLIENT_SECRET",
        )
        assert cfg.has_plaintext_secret() is False

    def test_env_var_prefix_ref_not_flagged_as_plaintext(self):
        cfg = CloudAuditConfig(
            providers=["azure"],
            azure_client_secret="env:AZURE_CLIENT_SECRET",
        )
        assert cfg.has_plaintext_secret() is False

    def test_invalid_provider_raises(self):
        with pytest.raises(ValueError, match="unknown provider"):
            CloudAuditConfig(providers=["unknown_cloud"])

    def test_uses_sdk_chain_raises_for_unknown_provider(self):
        cfg = CloudAuditConfig(providers=["aws"])
        with pytest.raises(ValueError, match="Unknown provider"):
            cfg.uses_sdk_chain("oracle_cloud")


class TestLooksLikeEnvVarRef:
    """Unit tests for the ``_looks_like_env_var_ref`` helper."""

    @pytest.mark.parametrize("ref", [
        "${AZURE_CLIENT_SECRET}",
        "${MY_VAR}",
        "${_LEADING_UNDERSCORE}",
        "$MY_VAR",
        "$AZURE_CLIENT_SECRET",
        "env:MY_VAR",
        "env:AZURE_TENANT_ID",
    ])
    def test_recognises_valid_env_var_refs(self, ref: str):
        assert _looks_like_env_var_ref(ref) is True

    @pytest.mark.parametrize("value", [
        "",
        "raw-secret",
        "abc123-def456",
        "super$ecret",          # '$' in middle is not a bare ref
        "${incomplete",         # no closing brace
        "env:",                 # empty var name
        "env:123invalid",       # starts with digit
        "hello world",
        "mypassword",
    ])
    def test_rejects_non_env_var_refs(self, value: str):
        assert _looks_like_env_var_ref(value) is False


# ---------------------------------------------------------------------------
# Property 5.A: SDK-chain config always reports uses_sdk_chain=True per provider
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(cfg=sdk_chain_configs())
def test_property_no_explicit_credentials_uses_sdk_chain(cfg: CloudAuditConfig):
    """
    **Property 5: Independencia de Credenciales en Texto Plano — SDK chain**

    For any ``CloudAuditConfig`` with all credential fields empty/None, every
    listed provider SHALL be resolved via its native SDK credential chain
    (``uses_sdk_chain(provider) == True``).

    **Validates: Requirements 2.1, 2.4, 2.6**
    """
    for provider in cfg.providers:
        assert cfg.uses_sdk_chain(provider) is True, (
            f"Expected uses_sdk_chain({provider!r}) == True for a config with no "
            f"explicit credentials, but got False. Config: {cfg!r}"
        )


# ---------------------------------------------------------------------------
# Property 5.B: SDK-chain config never has a plaintext secret
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(cfg=sdk_chain_configs())
def test_property_sdk_chain_config_has_no_plaintext_secret(cfg: CloudAuditConfig):
    """
    **Property 5: Independencia de Credenciales en Texto Plano — no plaintext secret**

    A ``CloudAuditConfig`` that defers to the SDK chain (no explicit credentials)
    SHALL report ``has_plaintext_secret() == False`` — there is nothing to leak.

    **Validates: Requirements 2.1, 2.4, 2.6**
    """
    assert cfg.has_plaintext_secret() is False, (
        f"Expected has_plaintext_secret() == False for a no-credential config, "
        f"but got True. Config: {cfg!r}"
    )


# ---------------------------------------------------------------------------
# Property 5.C: Raw secret in azure_client_secret detected as policy violation
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(cfg=explicit_azure_sp_configs())
def test_property_raw_credential_triggers_plaintext_detection(cfg: CloudAuditConfig):
    """
    **Property 5: Independencia de Credenciales en Texto Plano — raw secret detected**

    For any ``CloudAuditConfig`` where ``azure_client_secret`` is set to a
    non-empty, non-env-var string, ``has_plaintext_secret()`` SHALL return
    ``True``, signalling a no-secret-in-YAML policy violation.

    **Validates: Requirements 2.1, 2.4, 2.6**
    """
    assert cfg.has_plaintext_secret() is True, (
        f"Expected has_plaintext_secret() == True for config with raw "
        f"azure_client_secret, but got False. Config: {cfg!r}"
    )


# ---------------------------------------------------------------------------
# Property 5.D: Env-var references are NEVER flagged as plaintext secrets
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(ref=env_var_references())
def test_property_env_var_reference_never_flagged_as_plaintext(ref: str):
    """
    **Property 5: Independencia de Credenciales en Texto Plano — env-var ref exemption**

    When a sensitive field contains an environment-variable reference
    (``${VAR}``, ``$VAR``, or ``env:VAR``), the system SHALL NOT report it as a
    plaintext secret — the actual value lives outside the YAML.

    **Validates: Requirements 2.1, 2.4, 2.6**
    """
    cfg = CloudAuditConfig(
        providers=["azure"],
        azure_client_secret=ref,
    )
    assert cfg.has_plaintext_secret() is False, (
        f"env-var reference {ref!r} was incorrectly flagged as a plaintext secret"
    )


# ---------------------------------------------------------------------------
# Property 5.E: uses_sdk_chain returns False when any provider credential is set
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    aws_profiles=st.lists(
        st.from_regex(r"[a-z][a-z0-9_-]{2,19}", fullmatch=True), min_size=1, max_size=3
    )
)
def test_property_explicit_aws_profile_disables_sdk_chain(aws_profiles: list[str]):
    """
    **Property 5: Independencia de Credenciales en Texto Plano — explicit credential disables chain**

    When ``aws_profiles`` is non-empty, ``uses_sdk_chain("aws")`` SHALL return
    ``False`` because the config explicitly designates a named credential source
    rather than deferring to the boto3 default chain.

    **Validates: Requirements 2.1, 2.4, 2.6**
    """
    cfg = CloudAuditConfig(providers=["aws"], aws_profiles=aws_profiles)
    assert cfg.uses_sdk_chain("aws") is False, (
        f"Expected uses_sdk_chain('aws') == False when aws_profiles={aws_profiles!r}, "
        f"but got True"
    )
