# Feature: owasp-auth-modules-hardening, Property 8: Auth-context option parsing is correct and total
"""
Property-Based Tests for ``--auth-context`` option parsing.

**Feature: owasp-auth-modules-hardening, Property 8: Auth-context option
parsing is correct and total**

Property 8 (from design.md / Requirement 20):
    For ALL well-formed ``user:token[:privilege]`` values, parsing yields an
    ``AuthContext`` whose name/token/privilege match the supplied value; for
    ALL values lacking a ``:`` separator, parsing raises a descriptive
    ``click.BadParameter`` BEFORE any request is issued. The function is
    *total*: every possible input either parses deterministically or raises a
    descriptive error, and never returns an inconsistent result.

These tests drive the real ``parse_auth_context_option`` in ``apileaks``.
No network or mocking is involved -- the function is a pure parser, so the
"before any request is issued" guarantee (Requirement 20.5) holds structurally:
raising happens inside the parser, ahead of any discovery/scan call site.

Implementation note (the ACTUAL behavior this test pins down):
    Each value is split with ``str.split(':', 2)`` (``maxsplit=2``). Therefore
    ``name = parts[0]``, ``token = parts[1]`` (the segment *between* the first
    and second colon), and everything AFTER the second colon becomes the
    ``parts[2]`` privilege candidate. A privilege candidate that is present and
    non-empty must parse as an ``int`` or the value is rejected. This means a
    value whose tail (after the second colon) contains a colon or any other
    non-integer text is rejected -- these tests validate that observed behavior
    rather than assuming tokens with embedded colons round-trip.

Requirements covered: 20.1, 20.3, 20.5.
"""

import click
import pytest
from hypothesis import given, settings, strategies as st

from apileaks import parse_auth_context_option
from core.config import AuthContext, AuthType


# ---------------------------------------------------------------------------
# Reference model of the documented parsing contract
# ---------------------------------------------------------------------------
#
# The reference mirrors the documented ``user:token[:privilege]`` format using
# the same ``maxsplit=2`` split semantics the implementation is specified to
# use. The totality property below asserts the implementation agrees with this
# model for EVERY input: it either parses to the modeled (name, token,
# privilege) triple or raises ``click.BadParameter`` -- there is no third
# outcome.


def _reference_parse(value):
    """Return ``('ok', name, token, privilege)`` or ``('error',)``."""
    if ':' not in value:
        return ('error',)
    parts = value.split(':', 2)
    name, token = parts[0], parts[1]
    privilege = 1
    if len(parts) == 3 and parts[2] != '':
        try:
            privilege = int(parts[2])
        except ValueError:
            return ('error',)
    return ('ok', name, token, privilege)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Text with NO colon: the only segments that survive a ``:`` split intact.
_no_colon_text = st.text(
    alphabet=st.characters(blacklist_characters=':'),
    min_size=0,
    max_size=20,
)

# Non-empty colon-free tokens are the realistic "well-formed" token space.
_no_colon_token = st.text(
    alphabet=st.characters(blacklist_characters=':'),
    min_size=1,
    max_size=40,
)

# Arbitrary text that never contains a colon -- the "lacking ':'" input space.
_lacks_colon = st.text(
    alphabet=st.characters(blacklist_characters=':'),
    min_size=0,
    max_size=40,
)


@st.composite
def _arbitrary_colonish_value(draw):
    """Build an arbitrary value from 1-4 colon-joined segments.

    Joining 1..4 segments guarantees a healthy mix of: values with no colon
    (single segment -> the error branch), simple two-part values, and
    multi-colon values whose tail lands in the privilege slot. Segments may be
    empty, digits, or arbitrary non-colon text so the privilege branch is
    exercised across both integer and non-integer tails.
    """
    n = draw(st.integers(min_value=1, max_value=4))
    segment = st.one_of(
        _no_colon_text,
        st.integers(min_value=-999, max_value=999).map(str),
    )
    segments = draw(st.lists(segment, min_size=n, max_size=n))
    return ':'.join(segments)


# ---------------------------------------------------------------------------
# Property 8a: well-formed values yield matching name / token / privilege
# ---------------------------------------------------------------------------


@given(
    name=_no_colon_text,
    token=_no_colon_token,
    privilege=st.one_of(st.none(), st.integers(min_value=-100, max_value=100000)),
)
@settings(max_examples=200, deadline=None)
def test_wellformed_value_parses_to_matching_context(name, token, privilege):
    """A well-formed ``user:token[:privilege]`` yields matching fields.

    Validates: Requirements 20.1, 20.3
    """
    if privilege is None:
        value = f"{name}:{token}"
        expected_privilege = 1
    else:
        value = f"{name}:{token}:{privilege}"
        expected_privilege = privilege

    contexts = parse_auth_context_option([value])

    assert len(contexts) == 1
    ctx = contexts[0]
    assert isinstance(ctx, AuthContext)
    assert ctx.name == name
    assert ctx.token == token
    assert ctx.privilege_level == expected_privilege
    # Every parsed context is a bearer identity (Requirement 20.1/20.2).
    assert ctx.type == AuthType.BEARER


# ---------------------------------------------------------------------------
# Property 8b: values lacking ':' raise a descriptive error
# ---------------------------------------------------------------------------


@given(value=_lacks_colon)
@settings(max_examples=200, deadline=None)
def test_value_without_colon_is_rejected(value):
    """A value with no ``:`` separator raises a descriptive ``BadParameter``.

    Validates: Requirement 20.5
    """
    assert ':' not in value  # generator invariant

    with pytest.raises(click.BadParameter) as exc_info:
        parse_auth_context_option([value])

    message = str(exc_info.value)
    # "descriptive": the error names the required format and the offending value.
    assert "user:token" in message
    assert "':'" in message or ":" in message


# ---------------------------------------------------------------------------
# Property 8 (total): parsing agrees with the documented model on ALL inputs
# ---------------------------------------------------------------------------


@given(value=_arbitrary_colonish_value())
@settings(max_examples=300, deadline=None)
def test_parsing_is_total_and_matches_reference(value):
    """For any input, parsing either raises ``BadParameter`` or matches the model.

    This covers values whose tokens/tails contain colons: with ``maxsplit=2``
    everything after the second colon is the privilege candidate, so such
    values are rejected unless that tail is empty or a valid integer.

    Validates: Requirements 20.1, 20.3, 20.5
    """
    expected = _reference_parse(value)

    if expected[0] == 'error':
        with pytest.raises(click.BadParameter):
            parse_auth_context_option([value])
    else:
        _, name, token, privilege = expected
        contexts = parse_auth_context_option([value])
        assert len(contexts) == 1
        ctx = contexts[0]
        assert ctx.name == name
        assert ctx.token == token
        assert ctx.privilege_level == privilege
        assert ctx.type == AuthType.BEARER


@given(
    values=st.lists(
        st.builds(
            lambda n, t, p: f"{n}:{t}:{p}" if p is not None else f"{n}:{t}",
            _no_colon_text,
            _no_colon_token,
            st.one_of(st.none(), st.integers(min_value=0, max_value=50)),
        ),
        min_size=0,
        max_size=5,
    )
)
@settings(max_examples=150, deadline=None)
def test_one_context_per_wellformed_value(values):
    """Parsing N well-formed values yields exactly N contexts, in order.

    Validates: Requirement 20.2 (one Auth_Context per supplied option value)
    """
    contexts = parse_auth_context_option(values)
    assert len(contexts) == len(values)
    for value, ctx in zip(values, contexts):
        assert value.startswith(ctx.name + ":")


# ---------------------------------------------------------------------------
# Example-based edge cases (complement the properties)
# ---------------------------------------------------------------------------


def test_empty_input_yields_empty_list():
    """No values -> empty list, preserving single ``--jwt`` behavior."""
    assert parse_auth_context_option([]) == []
    assert parse_auth_context_option(None) == []


def test_empty_privilege_suffix_defaults_to_one():
    """A trailing ``:`` with no privilege digits keeps the default privilege."""
    contexts = parse_auth_context_option(["alice:tok:"])
    assert len(contexts) == 1
    assert contexts[0].name == "alice"
    assert contexts[0].token == "tok"
    assert contexts[0].privilege_level == 1


def test_privilege_suffix_sets_level():
    """A numeric privilege suffix sets ``privilege_level`` (Requirement 20.3)."""
    contexts = parse_auth_context_option(["admin:secret-token:5"])
    assert contexts[0].privilege_level == 5


def test_non_integer_privilege_is_rejected():
    """A non-integer tail (e.g. a token with an embedded colon) is rejected."""
    with pytest.raises(click.BadParameter):
        parse_auth_context_option(["user:tok:notanint"])
