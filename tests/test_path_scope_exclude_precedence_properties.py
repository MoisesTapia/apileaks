"""
Property-Based Tests for Path-Scope Exclude Precedence

**Feature: owasp-complete-purple-teaming-cicd, Property 17: Path-scope exclude
precedence**

Property 17 (from design.md):
    FOR ALL candidate (path, url) pairs and ALL include/exclude regex sets, if
    ANY exclude pattern matches against the path OR the url, then
    PathScope.admits(path, url) returns False -- unconditionally, and
    independently of the include set. Conversely, when no exclude pattern
    matches, the candidate is admitted exactly when there is no include
    restriction or at least one include pattern matches the path or url.

These tests use Hypothesis to generate candidate path/url strings together with
include/exclude regex sets. To make exclude-precedence meaningfully exercised
(rather than relying on a randomly-matching regex), the exclude set is seeded
with a literal substring that is guaranteed present in the generated path or
url (escaped via re.escape so it is a valid, matching regex). Include patterns
are drawn from safe, escaped literals so Hypothesis never trips on
invalid-regex inputs unrelated to the property under test.

**Validates: Requirements 33.10, 33.2, 33.3, 33.4**
"""

import re

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from utils.discovery_scope import PathScope, parse_path_scope


# A safe alphabet for path/url text so generated literals re.escape cleanly and
# substring slicing always yields a valid, matching regex.
_SAFE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-."

_safe_text = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=40)
_safe_text_or_empty = st.text(alphabet=_SAFE_ALPHABET, min_size=0, max_size=40)


@composite
def _substring_of(draw, source: str) -> str:
    """Draw a non-empty contiguous substring of ``source``.

    Used to build an exclude literal that is guaranteed to match ``source`` once
    escaped, so the exclude-precedence branch is genuinely exercised.
    """
    n = len(source)
    start = draw(st.integers(min_value=0, max_value=n - 1))
    end = draw(st.integers(min_value=start + 1, max_value=n))
    return source[start:end]


@composite
def _safe_regex_literals(draw, min_size=0, max_size=4):
    """Draw a list of escaped-literal regexes (always valid, never raise)."""
    literals = draw(
        st.lists(
            st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=12),
            min_size=min_size,
            max_size=max_size,
        )
    )
    return [re.escape(lit) for lit in literals]


@composite
def _matching_exclude_scenario(draw):
    """Build (path, url, include_exprs, exclude_exprs) where >=1 exclude matches.

    The exclude set always contains at least one regex guaranteed to match the
    path or the url (a re.escape'd substring of whichever string is non-empty),
    plus optional arbitrary escaped-literal excludes. Includes are arbitrary
    escaped literals so the property tests that exclude wins regardless.
    """
    path = draw(_safe_text_or_empty)
    url = draw(_safe_text_or_empty)

    # Guarantee at least one of path/url is non-empty so we can slice a substring
    # to use as a definitely-matching exclude literal.
    if not path and not url:
        path = draw(_safe_text)

    # Pick the source string (non-empty) to derive the guaranteed-matching
    # exclude literal from.
    source_choices = [s for s in (path, url) if s]
    source = draw(st.sampled_from(source_choices))
    sub = draw(_substring_of(source))
    guaranteed_exclude = re.escape(sub)

    extra_excludes = draw(_safe_regex_literals(min_size=0, max_size=3))
    exclude_exprs = draw(
        st.permutations([guaranteed_exclude] + extra_excludes)
    )

    include_exprs = draw(_safe_regex_literals(min_size=0, max_size=4))

    return path, url, list(include_exprs), list(exclude_exprs)


@given(scenario=_matching_exclude_scenario())
@settings(max_examples=300, deadline=None)
def test_matching_exclude_rejects_regardless_of_include(scenario):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 17: Path-scope
    exclude precedence**
    **Validates: Requirements 33.10, 33.3, 33.4**

    When ANY exclude pattern matches against the path OR the url,
    PathScope.admits(path, url) is False -- unconditionally, and independently
    of the include set.
    """
    path, url, include_exprs, exclude_exprs = scenario

    scope = parse_path_scope(include_exprs, exclude_exprs)

    # Sanity: the scenario really does produce a matching exclude (against path
    # or url), so this case meaningfully exercises exclude precedence.
    assert any(
        p.search(path) or p.search(url) for p in scope.exclude
    ), "scenario failed to produce a matching exclude pattern"

    # Core property: a matching exclude rejects regardless of includes (33.3,
    # 33.4, 33.10).
    assert scope.admits(path, url) is False

    # Independence from the include set: adding/removing arbitrary includes can
    # never resurrect an excluded candidate.
    no_include_scope = parse_path_scope((), exclude_exprs)
    assert no_include_scope.admits(path, url) is False


@composite
def _non_matching_exclude_scenario(draw):
    """Build (path, url, include_exprs, exclude_exprs) where NO exclude matches.

    Excludes are drawn from a disjoint alphabet from the path/url so they cannot
    match, letting us assert the converse: when nothing is excluded, admission
    follows the include rule (empty include => admit; otherwise need a match).
    """
    path = draw(st.text(alphabet="abcdef0123456789/", min_size=0, max_size=40))
    url = draw(st.text(alphabet="abcdef0123456789/", min_size=0, max_size=40))

    # Exclude literals use characters that never appear in path/url above, so no
    # exclude can match.
    disjoint = st.text(alphabet="GHJKLMNPQRSTUVWXYZ", min_size=1, max_size=10)
    exclude_exprs = [
        re.escape(lit)
        for lit in draw(st.lists(disjoint, min_size=0, max_size=3))
    ]

    include_exprs = draw(_safe_regex_literals(min_size=0, max_size=4))

    return path, url, include_exprs, exclude_exprs


@given(scenario=_non_matching_exclude_scenario())
@settings(max_examples=300, deadline=None)
def test_no_matching_exclude_follows_include_rule(scenario):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 17: Path-scope
    exclude precedence**
    **Validates: Requirements 33.2, 33.4**

    When NO exclude pattern matches, admission follows the include rule: with no
    include patterns everything is admitted; otherwise the candidate is admitted
    exactly when at least one include pattern matches the path or the url.
    """
    path, url, include_exprs, exclude_exprs = scenario

    scope = parse_path_scope(include_exprs, exclude_exprs)

    # Precondition for this scenario: no exclude matches.
    assert not any(p.search(path) or p.search(url) for p in scope.exclude)

    if not scope.include:
        # No include restriction => admitted (33.4 default-admit).
        assert scope.admits(path, url) is True
    else:
        expected = any(p.search(path) or p.search(url) for p in scope.include)
        assert scope.admits(path, url) is expected
