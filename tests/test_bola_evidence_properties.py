# Feature: owasp-auth-modules-hardening, Property 19: Least-destructive method selection
"""
Property-based test for BOLA least-destructive write-method selection.

Feature: owasp-auth-modules-hardening

Property 19: Least-destructive method selection.
For all configured ``destructive_methods`` sets, ``_select_write_method``
returns ``PATCH`` when present, otherwise ``PUT`` when present, otherwise
``POST`` when present, and returns ``DELETE`` only when ``DELETE`` is explicitly
included in the configured set; it never returns a method absent from the
configured set.

**Validates: Requirements 28.4, 36.4**
"""

import re
import string
from unittest.mock import Mock, AsyncMock

from hypothesis import assume, given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule
from utils.http_client import HTTPRequestEngine
from core.config import BOLAConfig


# Pool of method tokens the selection may be configured with. Includes
# Safe_Methods and mixed casing so the test also exercises that selection is
# case-insensitive and never returns a Safe_Method as a "write" method.
_METHOD_POOL = [
    "PATCH", "PUT", "POST", "DELETE",
    "patch", "put", "post", "delete",
    "GET", "HEAD", "OPTIONS",
]

_WRITE_METHODS = {"PATCH", "PUT", "POST", "DELETE"}


def _make_module(destructive_methods):
    """Build a BOLATestingModule with a stubbed HTTP client.

    ``_select_write_method`` reads only ``config.destructive_methods`` and does
    not touch instance HTTP state, so a stub client and empty auth contexts
    suffice.
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    config = BOLAConfig(enabled=True, destructive_methods=set(destructive_methods))
    return BOLATestingModule(config, client, [])


def _expected_method(configured_upper):
    """Reference implementation of the least-destructive selection rule."""
    for method in ("PATCH", "PUT", "POST"):
        if method in configured_upper:
            return method
    if "DELETE" in configured_upper:
        return "DELETE"
    return None


@settings(max_examples=200)
@given(st.sets(st.sampled_from(_METHOD_POOL), max_size=len(_METHOD_POOL)))
def test_select_write_method_is_least_destructive(configured):
    # Feature: owasp-auth-modules-hardening, Property 19: Least-destructive method selection
    module = _make_module(configured)
    configured_upper = {m.upper() for m in configured}

    result = module._select_write_method()

    # Matches the priority order PATCH > PUT > POST, with DELETE only when
    # explicitly configured (Requirement 28.4).
    assert result == _expected_method(configured_upper)

    if result is None:
        # No write method was configured, so no state-changing method is chosen.
        assert not (_WRITE_METHODS & configured_upper)
        return

    # Never returns a method absent from the configured set.
    assert result in configured_upper

    # DELETE is only ever returned when explicitly included in the set.
    if result == "DELETE":
        assert "DELETE" in configured_upper

    # PATCH/PUT/POST always take priority over DELETE when any of them is present.
    if _WRITE_METHODS & configured_upper - {"DELETE"}:
        assert result != "DELETE"


@settings(max_examples=200)
@given(st.sets(st.sampled_from(_METHOD_POOL), min_size=1, max_size=len(_METHOD_POOL)))
def test_select_write_method_priority_ordering(configured):
    # Feature: owasp-auth-modules-hardening, Property 19: Least-destructive method selection
    module = _make_module(configured)
    configured_upper = {m.upper() for m in configured}

    result = module._select_write_method()

    # PATCH strictly wins whenever present.
    if "PATCH" in configured_upper:
        assert result == "PATCH"
    # PUT wins when PATCH is absent.
    elif "PUT" in configured_upper:
        assert result == "PUT"
    # POST wins when neither PATCH nor PUT is present.
    elif "POST" in configured_upper:
        assert result == "POST"
    # DELETE only when it is the sole configured write method.
    elif "DELETE" in configured_upper:
        assert result == "DELETE"
    else:
        assert result is None


# Feature: owasp-auth-modules-hardening, Property 20: Evidence-chain snippets never echo full secrets
# ---------------------------------------------------------------------------
# Property 20: Evidence-chain snippets never echo full secrets.
#
# For every snippet that embeds a credential value in a form
# ``redact_secrets`` is designed to recognise (credential-named JSON fields,
# ``key=value`` / ``Authorization: Bearer`` forms, known-prefix API keys, and
# high-entropy credential-shaped blobs), the redacted output must never contain
# the full secret value verbatim.
#
# **Validates: Requirements 33.3**
# ---------------------------------------------------------------------------

# Alphabet for generated secret values: alphanumerics only, so a value is never
# split by a character the recognised forms treat as a delimiter (whitespace,
# quote, comma, ``}``/``]`` etc). Values are >= 12 chars, which guarantees the
# value can never be a substring of the 10-char REDACTION_MARKER and rules out
# spurious "secret still present" matches against the marker itself.
_SECRET_ALPHABET = string.ascii_letters + string.digits

_secret_value = st.text(alphabet=_SECRET_ALPHABET, min_size=12, max_size=48)


@st.composite
def _json_credential_snippets(draw):
    """A credential-named JSON field with a quoted value (rule 1)."""
    field = draw(st.sampled_from(BOLATestingModule.SECRET_FIELD_KEYWORDS))
    secret = draw(_secret_value)
    template = draw(st.sampled_from([
        '{{"user": "alice", "{field}": "{secret}"}}',
        '{{"{field}":"{secret}","id":42}}',
        'response body -> {{"{field}": "{secret}"}}',
    ]))
    return template.format(field=field, secret=secret), secret


@st.composite
def _kv_credential_snippets(draw):
    """A credential-named ``key=value`` / ``key: value`` field (rule 2)."""
    field = draw(st.sampled_from(BOLATestingModule.SECRET_FIELD_KEYWORDS))
    secret = draw(_secret_value)
    sep = draw(st.sampled_from(['=', ': ', ':', ' = ']))
    template = draw(st.sampled_from([
        '{field}{sep}{secret}',
        'log line: {field}{sep}{secret} end',
        '?{field}{sep}{secret}&next=1',
    ]))
    return template.format(field=field, sep=sep, secret=secret), secret


@st.composite
def _bearer_snippets(draw):
    """An ``Authorization: Bearer <token>`` header form (rule 2)."""
    token = draw(st.text(alphabet=_SECRET_ALPHABET, min_size=16, max_size=48))
    field = draw(st.sampled_from(['Authorization', 'authorization', 'AUTHORIZATION']))
    return f"{field}: Bearer {token}", token


@st.composite
def _prefix_token_snippets(draw):
    """A bare token carrying a known credential prefix (rule 3, self-sufficient)."""
    prefix = draw(st.sampled_from(BOLATestingModule.CREDENTIAL_PREFIXES))
    core = draw(st.text(alphabet=_SECRET_ALPHABET, min_size=16, max_size=40))
    token = prefix + core
    template = draw(st.sampled_from([
        'leaked key {token} in logs',
        'value -> {token}',
        '{token}',
    ]))
    return template.format(token=token), token


@st.composite
def _high_entropy_snippets(draw):
    """A bare high-entropy credential-shaped blob (rule 3, entropy-corroborated)."""
    token = draw(st.text(alphabet=_SECRET_ALPHABET, min_size=40, max_size=64))
    # Ensure the token is genuinely a secret by the module's own discipline:
    # credential-shaped AND high Shannon entropy. Random 40+ char alnum blobs
    # almost always clear the threshold, so this rarely filters.
    assume(re.fullmatch(r'[A-Za-z0-9]{32,}', token) is not None)
    assume(
        BOLATestingModule._shannon_entropy(token)
        >= BOLATestingModule.CREDENTIAL_ENTROPY_THRESHOLD
    )
    return f"data blob {token} end", token


_redaction_snippets = st.one_of(
    _json_credential_snippets(),
    _kv_credential_snippets(),
    _bearer_snippets(),
    _prefix_token_snippets(),
    _high_entropy_snippets(),
)


@settings(max_examples=200)
@given(_redaction_snippets)
def test_evidence_snippets_never_echo_full_secrets(payload):
    # Feature: owasp-auth-modules-hardening, Property 20: Evidence-chain snippets never echo full secrets
    snippet, secret = payload
    module = _make_module(set())

    redacted = module.redact_secrets(snippet)

    # The full secret value is never echoed back into the evidence snippet
    # (Requirement 33.3).
    assert secret not in redacted

    # Redaction actually fired for these recognised forms, so the property is
    # meaningful and not vacuously satisfied by an unchanged snippet.
    assert module.REDACTION_MARKER in redacted


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
