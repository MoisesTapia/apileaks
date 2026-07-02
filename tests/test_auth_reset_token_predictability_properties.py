"""
Property-based tests for reset-token predictability classification.

Feature: owasp-auth-modules-hardening

Property 22: Reset-token predictability classification is correct.
The extended ``analyze_identifier_predictability`` analyzer (the shared BOLA
identifier-predictability analyzer reused by the Authentication Testing Module's
``_predictability_analyzer``) classifies timestamp-based, sequential, and
hash-of-known-input tokens (e.g. ``MD5(email)``) as predictable, and classifies
random high-entropy tokens (including UUIDv4) as NOT predictable. For the random
case it reports ``predictable=False``, which - consistent with
``_test_reset_token_predictability`` - produces no ``AUTH_PREDICTABLE_RESET_TOKEN``
finding.

**Validates: Requirements 40.1, 40.2, 48.2**
"""

import hashlib
import string

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


def _make_analyzer():
    """Build the shared identifier-predictability analyzer exactly the way the
    Authentication Testing Module wires it up in
    ``_get_predictability_analyzer`` (Requirement 40.2): a bare
    ``BOLATestingModule`` instance created via ``__new__`` (no config / HTTP
    client), because ``analyze_identifier_predictability`` is a pure function of
    its arguments and ``self``'s static tables.
    """
    return BOLATestingModule.__new__(BOLATestingModule)


# The analyzer instance under test is the same shared analyzer object used by
# ``AuthenticationTestingModule._test_reset_token_predictability``.
_ANALYZER = _make_analyzer()


# ---------------------------------------------------------------------------
# Strategies for the four generated reset-token input classes
# ---------------------------------------------------------------------------

# Plausible Unix epoch seconds window used by the module (~2001 .. 2100).
_epoch_seconds = st.integers(min_value=1_000_000_000, max_value=4_102_444_800)

_hash_algorithms = st.sampled_from(("md5", "sha1", "sha256"))


@st.composite
def _sequential_tokens(draw):
    """A monotonic all-digit sequence stepping by a small constant.

    The analyzer recognizes a constant step ``0 < step <= 1000`` across two or
    more all-digit samples as a ``sequential-integer`` scheme.
    """
    start = draw(st.integers(min_value=0, max_value=10_000_000))
    step = draw(st.integers(min_value=1, max_value=1000))
    count = draw(st.integers(min_value=2, max_value=8))
    return [str(start + i * step) for i in range(count)]


@st.composite
def _random_hex_token(draw):
    """A random high-entropy token (>= 24 chars) drawn from a URL-safe-style
    alphabet and guaranteed to contain a non-hex letter.

    Reset tokens are typically random URL-safe strings, not bare hex. Forcing a
    non-hex letter (``g``-``z``) means the token can be neither parsed as a UUID
    (a bare 32-char hex string IS a valid UUID) nor read as an all-digit
    integer, so it exposes no predictable structure.
    """
    body = draw(
        st.text(
            alphabet=string.ascii_letters + string.digits + "-_",
            min_size=23,
            max_size=63,
        )
    )
    non_hex = draw(st.sampled_from("ghijklmnopqrstuvwxyz"))
    insert_at = draw(st.integers(min_value=0, max_value=len(body)))
    return body[:insert_at] + non_hex + body[insert_at:]


# ===========================================================================
# Property 22: Reset-token predictability classification is correct.
# ===========================================================================


@settings(max_examples=200)
@given(_epoch_seconds.map(str))
def test_timestamp_based_reset_tokens_are_predictable(sample):
    # Feature: owasp-auth-modules-hardening, Property 22: Reset-token predictability classification is correct
    assessment = _ANALYZER.analyze_identifier_predictability(sample)

    # A single token in a plausible epoch window is timestamp-based and
    # predictable (Requirements 40.1, 40.2).
    assert assessment.scheme == "timestamp-based"
    assert assessment.predictable is True


@settings(max_examples=200)
@given(_sequential_tokens())
def test_sequential_reset_tokens_are_predictable(samples):
    # Feature: owasp-auth-modules-hardening, Property 22: Reset-token predictability classification is correct
    assessment = _ANALYZER.analyze_identifier_predictability(samples)

    # A constant-step all-digit sequence is a sequential-integer scheme and is
    # trivially enumerable (Requirements 40.1, 40.2).
    assert assessment.scheme == "sequential-integer"
    assert assessment.predictable is True


@settings(max_examples=200)
@given(st.emails(), _hash_algorithms)
def test_hash_of_known_input_reset_tokens_are_predictable(email, algo):
    # Feature: owasp-auth-modules-hardening, Property 22: Reset-token predictability classification is correct
    token = hashlib.new(algo, email.encode("utf-8")).hexdigest()

    assessment = _ANALYZER.analyze_identifier_predictability(
        token, known_inputs=[email]
    )

    # A token equal to MD5/SHA1/SHA256 of a known input (e.g. the account email)
    # is reproducible by anyone who knows that value (Requirement 40.1).
    assert assessment.scheme == "hash-of-known-input"
    assert assessment.predictable is True


@settings(max_examples=200)
@given(st.uuids(version=4).map(str))
def test_uuid_v4_reset_tokens_are_not_predictable(sample):
    # Feature: owasp-auth-modules-hardening, Property 22: Reset-token predictability classification is correct
    assessment = _ANALYZER.analyze_identifier_predictability(sample)

    # Random UUIDs (version nibble 4) expose no exploitable structure
    # (Requirements 40.1, 48.2).
    assert assessment.scheme == "uuid-v4"
    assert assessment.predictable is False

    # predictable=False => consistent with _test_reset_token_predictability,
    # NO AUTH_PREDICTABLE_RESET_TOKEN finding is produced for the random case.
    assert _would_emit_finding(assessment) is False


@settings(max_examples=200)
@given(_random_hex_token())
def test_random_high_entropy_reset_tokens_are_not_predictable(sample):
    # Feature: owasp-auth-modules-hardening, Property 22: Reset-token predictability classification is correct
    assessment = _ANALYZER.analyze_identifier_predictability(sample)

    # A random high-entropy token is neither integer nor UUID and is classified
    # as not predictable (Requirements 40.1, 48.2).
    assert assessment.predictable is False

    # No AUTH_PREDICTABLE_RESET_TOKEN finding is produced for the random case.
    assert _would_emit_finding(assessment) is False


def _would_emit_finding(assessment) -> bool:
    """Mirror the module rule: ``_test_reset_token_predictability`` emits an
    ``AUTH_PREDICTABLE_RESET_TOKEN`` finding exactly when the assessment is
    predictable, and skips (no finding) otherwise.
    """
    return bool(assessment.predictable)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
