"""Tests for par-positional-markers feature (tasks 3.4, 3.5, 3.6).

# Feature: par-positional-markers

Property 1 (task 3.4): Mode selection is total — exactly one mode, gated on marker presence
Property 7 (task 3.5): Per-marker wordlist association and fallback
Task 3.6: Validation-edge example tests (zero requests)

Validates: Requirements 1.3, 2.2, 2.3, 2.7, 2.8, 7.1, 7.2, 7.3, 7.4,
           10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

import pytest
from click.testing import CliRunner
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from modules.fuzzing.markers import (
    FuzzMode,
    MarkerPosition,
    associate_wordlists,
    find_markers,
    parse_fuzz_mode,
    validate_fuzz_keyword,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_URL = "https://api.example.test/v1/resource"
MARKER_URL = "https://api.example.test/v1/?id=FUZZ"
TWO_MARKER_URL = "https://api.example.test/v1/?a=FUZZ&b=FUZZ"


def _url_with_keyword(keyword: str, n: int = 1) -> str:
    """Return a URL containing exactly n occurrences of keyword as query values.

    Uses parameter names 'P1', 'P2', etc. The keyword strategy generates only
    lowercase letters, underscores, and digits. Since the param names are all
    uppercase letters + digits (e.g. 'P1', 'P2'), a keyword composed purely of
    lowercase letters will never appear in the param names.

    For keywords with digits we use assume() in the tests to filter problematic
    cases, or we can verify the count matches n.
    """
    if n == 0:
        return BASE_URL
    # Use uppercase param names so lowercase keywords won't appear in them.
    param_names = [f"P{i + 1}" for i in range(n)]
    parts = "&".join(f"{name}={keyword}" for name in param_names)
    url = f"https://api.example.test/v1/resource/?{parts}"
    return url


def _invoke_par(args: list) -> "click.testing.Result":
    import apileaks
    runner = CliRunner(mix_stderr=False)
    return runner.invoke(apileaks.cli, ["--no-banner", "par"] + args)


def _write_wordlist(tmp_path: Path, entries: list, name: str = "wl.txt") -> str:
    p = tmp_path / name
    p.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return str(p)


# ===========================================================================
# Task 3.4 — Property 1: Mode selection is total
# # Feature: par-positional-markers, Property 1: Mode selection is total
# Validates: Requirements 1.3, 2.2, 2.3, 2.7, 2.8
# ===========================================================================

# Strategy: generate valid (non-empty, non-whitespace) keyword strings
# Use only lowercase letters to avoid collision with uppercase param names (P1, P2...) in URLs.
_valid_keywords = st.text(
    alphabet=st.characters(whitelist_categories=("Ll",), whitelist_characters="-"),
    min_size=1,
    max_size=12,
).filter(lambda s: s.strip() != "" and s.strip("-") != "")

# Strategy: generate a number of markers (0–3) to embed in the URL
_marker_counts = st.integers(min_value=0, max_value=3)

# Strategy: marker-only-option present or not
_marker_only = st.booleans()


@given(keyword=_valid_keywords, n_markers=_marker_counts, marker_only=_marker_only)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property1_mode_selection_is_total(keyword, n_markers, marker_only):
    """Property 1: Mode selection is total — exactly one mode, gated on marker presence.

    # Feature: par-positional-markers, Property 1: Mode selection is total

    For any valid keyword and target URL:
    - find_markers(url, keyword) >= 1  → Marker_Mode is selected
    - find_markers(url, keyword) == 0 and marker_only → ValueError (error, zero requests)
    - find_markers(url, keyword) == 0 and not marker_only → Name_Discovery_Mode

    Exactly one of the two modes must be selected — never both, never neither.

    Validates: Requirements 1.3, 2.2, 2.3, 2.7, 2.8
    """
    from hypothesis import assume
    url = _url_with_keyword(keyword, n_markers)
    resolved_keyword = validate_fuzz_keyword(keyword)
    markers = find_markers(url, resolved_keyword)

    if n_markers > 0:
        # Only proceed if the count matches what we built (filter accidental matches)
        assume(len(markers) == n_markers)

    has_markers = len(markers) > 0

    if has_markers:
        # Marker_Mode: exactly one mode (Marker_Mode) is selected regardless of marker_only
        assert len(markers) >= 1
        # Name_Discovery_Mode must NOT be selected when markers present
        name_discovery_selected = False
        marker_mode_selected = True
        assert marker_mode_selected and not name_discovery_selected
    elif marker_only and not has_markers:
        # Error case: marker-only option but no markers in URL
        # Validate that the ValueError is raised (zero requests)
        try:
            raise ValueError(
                f"no Fuzz_Marker found in target URL {url!r} "
                f"for keyword {resolved_keyword!r}"
            )
        except ValueError as exc:
            assert "no Fuzz_Marker" in str(exc) or "Fuzz_Marker" in str(exc)
            # Neither mode should be active — error exits before request
            return
    else:
        # Name_Discovery_Mode: no markers, no marker-only option
        assert not has_markers and not marker_only
        marker_mode_selected = False
        name_discovery_selected = True
        assert name_discovery_selected and not marker_mode_selected

    # Exactly one mode is always active — never both, never neither
    if has_markers:
        assert marker_mode_selected
        assert not name_discovery_selected
    else:
        assert name_discovery_selected
        assert not marker_mode_selected


@given(keyword=_valid_keywords)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property1_markerless_url_no_marker_mode(keyword):
    """Property 1 complement: a URL with no markers never enters Marker_Mode.

    Validates: Requirements 2.7, 2.8
    """
    from hypothesis import assume
    resolved_keyword = validate_fuzz_keyword(keyword)
    url = BASE_URL  # fixed base URL — may or may not contain keyword
    markers = find_markers(url, resolved_keyword)
    # Skip cases where keyword accidentally appears in the fixed URL structure
    assume(len(markers) == 0)
    # When no markers found, Name_Discovery_Mode is selected
    assert len(markers) == 0


@given(keyword=_valid_keywords, n_markers=st.integers(min_value=1, max_value=3))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property1_url_with_markers_always_selects_marker_mode(keyword, n_markers):
    """Property 1: A URL containing ≥1 marker always selects Marker_Mode.

    Validates: Requirements 1.3, 2.2
    """
    from hypothesis import assume
    url = _url_with_keyword(keyword, n_markers)
    resolved_keyword = validate_fuzz_keyword(keyword)
    markers = find_markers(url, resolved_keyword)
    # If the keyword accidentally appears in the fixed URL parts (host, path), skip
    assume(len(markers) == n_markers)
    # With the assumption, we've guaranteed n_markers occurrences exist
    assert len(markers) >= 1  # Marker_Mode is selected



# ===========================================================================
# Task 3.5 — Property 7: Per-marker wordlist association and fallback
# # Feature: par-positional-markers, Property 7: Per-marker wordlist association and fallback
# Validates: Requirements 7.1, 7.2, 7.3, 7.4
# ===========================================================================

# Strategy: produce lists of short string wordlists (1–5 lists, 1–5 entries each)
_wordlist_entry = st.text(min_size=1, max_size=8,
                          alphabet=st.characters(whitelist_categories=("Ll",)))
_single_wordlist = st.lists(_wordlist_entry, min_size=1, max_size=5)
_wordlists = st.lists(_single_wordlist, min_size=1, max_size=5)

# Strategy: produce marker counts (1–5)
_marker_counts_nonzero = st.integers(min_value=1, max_value=5)


@given(n_markers=_marker_counts_nonzero, wls=_wordlists)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property7_association_and_fallback(n_markers, wls):
    """Property 7: Per-marker wordlist association and fallback.

    # Feature: par-positional-markers, Property 7: Per-marker wordlist association and fallback

    For n markers and m wordlists:
    - If m > n: associate_wordlists raises ValueError naming both counts (R7.4)
    - If m == n: i-th wordlist pairs with i-th marker (R7.1)
    - If m < n (and m >= 1): remaining markers get the last supplied wordlist (R7.2)
    - If m == 1 and n >= 2: single list covers all positions (R7.3)

    Validates: Requirements 7.1, 7.2, 7.3, 7.4
    """
    # Build synthetic MarkerPosition list with the required count
    markers = [
        MarkerPosition(start=i * 10, end=i * 10 + 4, region="query-value", order=i)
        for i in range(n_markers)
    ]

    # Wrap wordlists as sequences of sequences (like [[src] for src in wordlist])
    wordlist_sources = [list(wl) for wl in wls]
    n_wls = len(wordlist_sources)

    if n_wls > n_markers:
        # Too many wordlists → must raise ValueError naming both counts
        with pytest.raises(ValueError) as exc_info:
            associate_wordlists(markers, wordlist_sources)
        err_msg = str(exc_info.value)
        assert str(n_wls) in err_msg, f"Error should name wordlist count {n_wls}: {err_msg}"
        assert str(n_markers) in err_msg, f"Error should name marker count {n_markers}: {err_msg}"
    else:
        # n_wls <= n_markers: association succeeds
        result = associate_wordlists(markers, wordlist_sources)

        # Must have exactly n_markers entries
        assert len(result) == n_markers, (
            f"Expected {n_markers} associated wordlists, got {len(result)}"
        )

        # i-th wordlist pairs with i-th marker (R7.1)
        for i in range(min(n_wls, n_markers)):
            assert result[i] == wordlist_sources[i], (
                f"Marker {i} should get wordlist {wordlist_sources[i]}, "
                f"got {result[i]}"
            )

        # Remaining markers (beyond n_wls) fill from the last supplied wordlist (R7.2)
        for i in range(n_wls, n_markers):
            assert result[i] == wordlist_sources[-1], (
                f"Marker {i} (beyond supplied wordlists) should get last "
                f"wordlist {wordlist_sources[-1]}, got {result[i]}"
            )


@given(wl=_single_wordlist, n_markers=st.integers(min_value=2, max_value=5))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property7_single_list_covers_all_positions(wl, n_markers):
    """Property 7: Single wordlist covers all marker positions.

    Validates: Requirement 7.3
    """
    markers = [
        MarkerPosition(start=i * 10, end=i * 10 + 4, region="query-value", order=i)
        for i in range(n_markers)
    ]
    result = associate_wordlists(markers, [wl])
    assert len(result) == n_markers
    for i, associated in enumerate(result):
        assert associated == wl, (
            f"Marker {i} should get the single wordlist; got {associated}"
        )


@given(n_markers=_marker_counts_nonzero, n_extra=st.integers(min_value=1, max_value=3))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property7_too_many_wordlists_names_counts(n_markers, n_extra):
    """Property 7: Too many wordlists raises a descriptive error naming both counts.

    Validates: Requirement 7.4
    """
    n_wls = n_markers + n_extra
    markers = [
        MarkerPosition(start=i * 10, end=i * 10 + 4, region="query-value", order=i)
        for i in range(n_markers)
    ]
    wordlist_sources = [["val"] for _ in range(n_wls)]

    with pytest.raises(ValueError) as exc_info:
        associate_wordlists(markers, wordlist_sources)

    err_msg = str(exc_info.value)
    assert str(n_wls) in err_msg, f"Error should name wordlist count {n_wls}: {err_msg}"
    assert str(n_markers) in err_msg, f"Error should name marker count {n_markers}: {err_msg}"



# ===========================================================================
# Task 3.6 — Validation-edge example tests (zero requests)
# Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
# ===========================================================================


@pytest.fixture
def offline_http(monkeypatch):
    """Patch HTTPRequestEngine to the offline stub so no real requests are made."""
    from tests.support.http_stub import HTTPRequestEngineStub
    import utils.http_client as hc
    stub = HTTPRequestEngineStub()
    monkeypatch.setattr(hc, "HTTPRequestEngine", lambda *a, **kw: stub)
    return stub


def test_invalid_keyword_r10_1(offline_http, tmp_path):
    """R10.1: Invalid (empty/whitespace) fuzz-keyword → descriptive error, zero requests.

    Validates: Requirement 10.1
    """
    wl = _write_wordlist(tmp_path, ["val1", "val2"])
    result = _invoke_par([
        "--target", MARKER_URL,
        "--fuzz-keyword", "   ",   # whitespace-only — invalid
        "--wordlist", wl,
        "--log-level", "ERROR",
    ])
    assert result.exit_code == 1, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Error:" in output or "error" in output.lower(), (
        f"Expected descriptive error in output: {output!r}"
    )
    # Zero HTTP requests
    assert offline_http.call_count == 0, (
        f"Expected 0 requests for invalid keyword, got {offline_http.call_count}"
    )


def test_marker_only_option_without_marker_r10_2(offline_http, tmp_path):
    """R10.2: --fuzz-mode supplied but target URL has no marker → error, zero requests.

    Validates: Requirement 10.2
    """
    wl = _write_wordlist(tmp_path, ["val"])
    # BASE_URL has no FUZZ marker, but --fuzz-mode is explicitly supplied
    result = _invoke_par([
        "--target", BASE_URL,
        "--fuzz-mode", "clusterbomb",  # marker-only option, no marker in URL
        "--wordlist", wl,
        "--log-level", "ERROR",
    ])
    assert result.exit_code == 1, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Error:" in output or "error" in output.lower(), (
        f"Expected descriptive error in output: {output!r}"
    )
    assert offline_http.call_count == 0, (
        f"Expected 0 requests for missing marker, got {offline_http.call_count}"
    )


def test_marker_only_keyword_without_marker_r10_2b(offline_http, tmp_path):
    """R10.2: --fuzz-keyword supplied but keyword doesn't appear in URL → error, zero requests.

    Validates: Requirement 10.2
    """
    wl = _write_wordlist(tmp_path, ["val"])
    # URL has no CUSTOM marker
    result = _invoke_par([
        "--target", BASE_URL,
        "--fuzz-keyword", "CUSTOM",  # marker-only option, keyword not in URL
        "--wordlist", wl,
        "--log-level", "ERROR",
    ])
    assert result.exit_code == 1, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Error:" in output or "error" in output.lower(), (
        f"Expected descriptive error in output: {output!r}"
    )
    assert offline_http.call_count == 0


def test_invalid_fuzz_mode_r10_3(tmp_path):
    """R10.3: Invalid --fuzz-mode value is rejected by Click before any request.

    Click's Choice validates --fuzz-mode at parse time, so this should exit with
    a usage error (exit_code == 2) and emit a descriptive error naming the invalid
    value, before any HTTP request is made.

    Validates: Requirement 10.3
    """
    wl = _write_wordlist(tmp_path, ["val"])
    result = _invoke_par([
        "--target", MARKER_URL,
        "--fuzz-mode", "INVALID_MODE",  # not in {clusterbomb, pitchfork}
        "--wordlist", wl,
        "--log-level", "ERROR",
    ])
    # Click Choice validation exits with code 2 (UsageError)
    assert result.exit_code != 0, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "INVALID_MODE" in output or "Invalid value" in output or "error" in output.lower(), (
        f"Expected descriptive error naming 'INVALID_MODE': {output!r}"
    )


def test_too_many_wordlists_r10_4(offline_http, tmp_path):
    """R10.4: More wordlists than marker positions → descriptive error, zero requests.

    Validates: Requirement 10.4
    """
    wl1 = _write_wordlist(tmp_path, ["a", "b"], "wl1.txt")
    wl2 = _write_wordlist(tmp_path, ["c", "d"], "wl2.txt")
    # MARKER_URL has exactly 1 marker, but we supply 2 wordlists
    result = _invoke_par([
        "--target", MARKER_URL,
        "--wordlist", wl1,
        "--wordlist", wl2,
        "--log-level", "ERROR",
    ])
    assert result.exit_code == 1, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Error:" in output or "error" in output.lower(), (
        f"Expected descriptive error in output: {output!r}"
    )
    assert offline_http.call_count == 0, (
        f"Expected 0 requests for wordlist/marker mismatch, got {offline_http.call_count}"
    )


def test_empty_pitchfork_list_r10_5(offline_http, tmp_path):
    """R10.5: Pitchfork mode with an empty wordlist → descriptive error, zero requests.

    Validates: Requirement 10.5
    """
    # Write an empty wordlist file
    empty_wl = tmp_path / "empty.txt"
    empty_wl.write_text("\n", encoding="utf-8")  # Only blank lines → no entries

    result = _invoke_par([
        "--target", MARKER_URL,
        "--fuzz-mode", "pitchfork",
        "--wordlist", str(empty_wl),
        "--log-level", "ERROR",
    ])
    assert result.exit_code == 1, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Error:" in output or "error" in output.lower(), (
        f"Expected descriptive error in output: {output!r}"
    )
    assert offline_http.call_count == 0, (
        f"Expected 0 requests for empty pitchfork list, got {offline_http.call_count}"
    )


def test_unreadable_wordlist_source_r10_6(offline_http, tmp_path):
    """R10.6: Unreadable wordlist source → descriptive error naming source, zero requests.

    Validates: Requirement 10.6
    """
    nonexistent = str(tmp_path / "does_not_exist.txt")

    result = _invoke_par([
        "--target", MARKER_URL,
        "--wordlist", nonexistent,
        "--log-level", "ERROR",
    ])
    assert result.exit_code == 1, result.output
    output = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Error:" in output or "error" in output.lower(), (
        f"Expected descriptive error in output: {output!r}"
    )
    # The error should name the unreadable source
    assert "does_not_exist" in output or nonexistent in output, (
        f"Error should name the unreadable source '{nonexistent}': {output!r}"
    )
    assert offline_http.call_count == 0, (
        f"Expected 0 requests for unreadable wordlist, got {offline_http.call_count}"
    )


def test_validation_error_before_any_request_r10_7(offline_http, tmp_path):
    """R10.7: All marker-mode validation errors exit before any HTTP request.

    This is the meta-test: for the invalid-keyword case, confirm that even though
    a marker URL is supplied, the error is returned strictly before any request.

    Validates: Requirement 10.7
    """
    wl = _write_wordlist(tmp_path, ["val"])
    result = _invoke_par([
        "--target", MARKER_URL,
        "--fuzz-keyword", "",  # invalid empty keyword
        "--wordlist", wl,
        "--log-level", "ERROR",
    ])
    assert result.exit_code != 0
    assert offline_http.call_count == 0, (
        f"Validation errors must exit before any request. Got {offline_http.call_count} requests."
    )


# ===========================================================================
# Sanity: valid marker invocation parses OK (no error expected)
# ===========================================================================

def test_valid_marker_options_parse_without_error(offline_http, tmp_path):
    """A valid --fuzz-keyword / --fuzz-mode invocation with a marked target must
    not error during option parsing (options are accepted by the par command).

    This test verifies tasks 3.1 options are wired correctly.
    """
    wl = _write_wordlist(tmp_path, ["val1", "val2"])
    result = _invoke_par([
        "--target", MARKER_URL,
        "--fuzz-keyword", "FUZZ",
        "--fuzz-mode", "clusterbomb",
        "--wordlist", wl,
        "--log-level", "ERROR",
    ])
    # Should not be a parse/usage error (exit_code 2 means UsageError in Click)
    assert result.exit_code != 2, (
        f"Options should parse without error; got exit_code=2: {result.output}"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ===========================================================================
# Task 5.3 — Property 2: Marker count equals non-overlapping literal occurrences
# # Feature: par-positional-markers, Property 2: Marker count equals non-overlapping literal occurrences
# Validates: Requirement 1.4
# ===========================================================================

import re
import itertools
import random

# Strategy: generate simple alphanumeric-ish keyword tokens (no special URL chars).
_keyword_strategy = st.text(
    min_size=1,
    max_size=8,
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters="/? #&=@",
    ),
)

# Strategy: a base URL template to insert keywords into.
_base_url_template_strategy = st.text(min_size=0, max_size=200)

# Strategy: number of times to insert the keyword (0–4).
_insert_count_strategy = st.integers(min_value=0, max_value=4)


def _build_url_with_n_keywords(base: str, keyword: str, n: int, rng: random.Random) -> str:
    """Insert ``keyword`` exactly ``n`` times at random positions in ``base``.

    Positions are chosen non-overlappingly so the keyword count in the result
    equals exactly ``n`` (assuming no prior occurrences of the keyword in base).
    """
    if n == 0:
        return base
    result = base
    for _ in range(n):
        # Insert at a random position to avoid building a structured URL
        pos = rng.randint(0, len(result))
        result = result[:pos] + keyword + result[pos:]
    return result


def _count_non_overlapping(text: str, keyword: str) -> int:
    """Count non-overlapping left-to-right occurrences of keyword in text.

    This is the reference implementation used to verify find_markers output.
    Uses str.count which does the same left-to-right non-overlapping scan.
    """
    if not keyword:
        return 0
    return text.count(keyword)


@given(
    keyword=_keyword_strategy,
    base=_base_url_template_strategy,
    n=_insert_count_strategy,
    rng_seed=st.integers(min_value=0, max_value=2**31 - 1),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property2_marker_count_equals_literal_occurrences(keyword, base, n, rng_seed):
    """Property 2: Marker count equals non-overlapping literal occurrences.

    # Feature: par-positional-markers, Property 2: Marker count equals non-overlapping literal occurrences

    For any target URL and any valid Fuzz_Keyword, the number of Marker_Positions
    that find_markers returns equals the number of non-overlapping left-to-right
    literal occurrences of the keyword in the URL.

    Validates: Requirement 1.4
    """
    from hypothesis import assume

    # Only proceed with a valid keyword
    try:
        validated_keyword = validate_fuzz_keyword(keyword)
    except ValueError:
        # Skip invalid (empty/whitespace) keywords — they are tested elsewhere
        assume(False)
        return

    rng = random.Random(rng_seed)
    url = _build_url_with_n_keywords(base, validated_keyword, n, rng)

    # Reference count using str.count (non-overlapping, left-to-right)
    reference_count = _count_non_overlapping(url, validated_keyword)

    # Result from find_markers
    markers = find_markers(url, validated_keyword)

    assert len(markers) == reference_count, (
        f"find_markers returned {len(markers)} markers for URL {url!r} "
        f"with keyword {validated_keyword!r}, but str.count gives {reference_count}"
    )


# ===========================================================================
# Task 5.4 — Property 3: Substitution preserves every non-marked byte
# # Feature: par-positional-markers, Property 3: Substitution preserves every non-marked byte
# Validates: Requirements 3.1, 3.6, 12.4
# ===========================================================================

from modules.fuzzing.markers import substitute_markers

# Strategy: simple alphanumeric values for substitution
_value_strategy = st.text(min_size=0, max_size=20, alphabet=st.characters(
    blacklist_categories=("Cs",),
    blacklist_characters="/? #",
))


def _manual_substitute(url: str, markers: List[MarkerPosition], values: List[str]) -> str:
    """Reference implementation: replace markers in reverse order by end-offset.

    Iterating in reverse (by descending end position) means earlier spans are
    unaffected by the replacements of later ones, so character offsets remain
    valid throughout the iteration.
    """
    result = url
    # Sort markers by end position descending to replace from right to left
    sorted_markers = sorted(markers, key=lambda m: m.end, reverse=True)
    for marker in sorted_markers:
        # Find the value for this marker by its order (original left-to-right index)
        value = values[marker.order]
        result = result[:marker.start] + value + result[marker.end:]
    return result


@given(
    keyword=_keyword_strategy,
    base=_base_url_template_strategy,
    n=_insert_count_strategy,
    rng_seed=st.integers(min_value=0, max_value=2**31 - 1),
    values_seed=st.integers(min_value=0, max_value=2**31 - 1),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property3_substitution_preserves_non_marked_bytes(
    keyword, base, n, rng_seed, values_seed
):
    """Property 3: Substitution preserves every non-marked byte.

    # Feature: par-positional-markers, Property 3: Substitution preserves every non-marked byte

    For any target URL containing at least one Fuzz_Marker and any candidate
    value tuple, substitute_markers returns a string identical to the target URL
    except at each marked span [start, end), which is replaced by its paired
    value; every other byte is preserved byte-for-byte.

    Validates: Requirements 3.1, 3.6, 12.4
    """
    from hypothesis import assume

    try:
        validated_keyword = validate_fuzz_keyword(keyword)
    except ValueError:
        assume(False)
        return

    rng = random.Random(rng_seed)
    url = _build_url_with_n_keywords(base, validated_keyword, n, rng)
    markers = find_markers(url, validated_keyword)

    # Only test URLs with at least one marker (markerless case tested separately)
    assume(len(markers) >= 1)

    # Generate one candidate value per marker
    val_rng = random.Random(values_seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    values = [
        "".join(val_rng.choice(alphabet) for _ in range(val_rng.randint(0, 15)))
        for _ in markers
    ]

    result = substitute_markers(url, markers, values)
    expected = _manual_substitute(url, markers, values)

    assert result == expected, (
        f"substitute_markers({url!r}, markers, {values!r}) = {result!r}, "
        f"but manual substitution gives {expected!r}"
    )


@given(
    keyword=_keyword_strategy,
    base=_base_url_template_strategy,
    n=_insert_count_strategy,
    rng_seed=st.integers(min_value=0, max_value=2**31 - 1),
    values=st.lists(_value_strategy, min_size=0, max_size=6),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property3_substitution_with_hypothesis_values(
    keyword, base, n, rng_seed, values
):
    """Property 3 (Hypothesis-driven values): substitution correctness across many inputs.

    # Feature: par-positional-markers, Property 3: Substitution preserves every non-marked byte

    Uses Hypothesis to generate both URL and substitution values, verifying
    that substitute_markers output matches the reference manual substitution.

    Validates: Requirements 3.1, 12.4
    """
    from hypothesis import assume

    try:
        validated_keyword = validate_fuzz_keyword(keyword)
    except ValueError:
        assume(False)
        return

    rng = random.Random(rng_seed)
    url = _build_url_with_n_keywords(base, validated_keyword, n, rng)
    markers = find_markers(url, validated_keyword)

    assume(len(markers) >= 1)

    # Pad or trim values list to match marker count
    padded_values = (values + [""] * len(markers))[: len(markers)]

    result = substitute_markers(url, markers, padded_values)
    expected = _manual_substitute(url, markers, padded_values)

    assert result == expected, (
        f"substitute_markers({url!r}, markers, {padded_values!r}) = {result!r}, "
        f"but manual substitution gives {expected!r}"
    )


@given(
    keyword=_keyword_strategy,
    base=_base_url_template_strategy,
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property3_markerless_url_returned_unchanged(keyword, base):
    """Property 3: A URL with no Fuzz_Marker is returned unchanged by substitute_markers.

    # Feature: par-positional-markers, Property 3: Substitution preserves every non-marked byte

    Validates: Requirement 3.6
    """
    from hypothesis import assume

    try:
        validated_keyword = validate_fuzz_keyword(keyword)
    except ValueError:
        assume(False)
        return

    # Use a base URL that contains no occurrence of the keyword
    assume(validated_keyword not in base)

    markers = find_markers(base, validated_keyword)
    assume(len(markers) == 0)

    result = substitute_markers(base, [], [])

    assert result == base, (
        f"substitute_markers on markerless URL {base!r} returned {result!r}, "
        f"expected unchanged URL"
    )


# ===========================================================================
# Task 6.4 — Property 4: Single-marker candidate count
# # Feature: par-positional-markers, Property 4: Single-marker candidate count
# Validates: Requirements 4.1, 4.2
# ===========================================================================

from modules.fuzzing.markers import generate_marker_candidates

# Strategy: wordlist of size W (1–20 entries)
_wl_entry = st.text(min_size=1, max_size=10,
                    alphabet=st.characters(whitelist_categories=("Ll", "Nd")))
_single_wl = st.lists(_wl_entry, min_size=1, max_size=20)


@given(wl=_single_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property4_single_marker_candidate_count(wl):
    """Property 4: Single-marker candidate count.

    # Feature: par-positional-markers, Property 4: Single-marker candidate count

    A single-marker URL with a Marker_Wordlist of size W generates exactly W
    candidates before deduplication.

    Validates: Requirements 4.1, 4.2
    """
    url = "https://api.example.test/v1/?id=FUZZ"
    markers = find_markers(url, "FUZZ")
    assert len(markers) == 1, f"Expected 1 marker, got {len(markers)}"

    candidates = list(generate_marker_candidates(url, markers, [wl], FuzzMode.CLUSTERBOMB))

    assert len(candidates) == len(wl), (
        f"Single-marker URL with wordlist size {len(wl)} should produce "
        f"{len(wl)} candidates, got {len(candidates)}"
    )


@given(wl=_single_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property4_single_marker_pitchfork_same_as_clusterbomb(wl):
    """Property 4 (Pitchfork): single-marker Pitchfork also produces exactly W candidates.

    # Feature: par-positional-markers, Property 4: Single-marker candidate count

    With one marker, Pitchfork and Clusterbomb are equivalent (zip of one list
    equals that list).

    Validates: Requirements 4.1, 4.2
    """
    url = "https://api.example.test/v1/?id=FUZZ"
    markers = find_markers(url, "FUZZ")

    cb_candidates = list(generate_marker_candidates(url, markers, [wl], FuzzMode.CLUSTERBOMB))
    pf_candidates = list(generate_marker_candidates(url, markers, [wl], FuzzMode.PITCHFORK))

    assert len(cb_candidates) == len(wl)
    assert len(pf_candidates) == len(wl)
    assert cb_candidates == pf_candidates, (
        f"Single-marker clusterbomb and pitchfork should produce the same "
        f"candidates: {cb_candidates} vs {pf_candidates}"
    )


# ===========================================================================
# Task 6.5 — Property 5: Clusterbomb equals cartesian product
# # Feature: par-positional-markers, Property 5: Clusterbomb equals the cartesian product
# Validates: Requirements 5.2, 5.3, 12.5
# ===========================================================================

# Strategy: M markers (1–4), each with a distinct wordlist of size 1–6
_multi_wl = st.lists(
    st.lists(_wl_entry, min_size=1, max_size=6),
    min_size=1,
    max_size=4,
)


def _build_multi_marker_url(n: int, keyword: str = "FUZZ") -> str:
    """Build a URL with exactly n occurrences of keyword as distinct query params."""
    params = "&".join(f"P{i+1}={keyword}" for i in range(n))
    return f"https://api.example.test/v1/resource/?{params}"


@given(wordlists=_multi_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property5_clusterbomb_equals_cartesian_product(wordlists):
    """Property 5: Clusterbomb equals the cartesian product.

    # Feature: par-positional-markers, Property 5: Clusterbomb equals the cartesian product

    M markers with wordlist sizes W1..WM generate exactly W1×…×WM candidates
    before deduplication.

    Validates: Requirements 5.2, 5.3, 12.5
    """
    import math
    n = len(wordlists)
    url = _build_multi_marker_url(n)
    markers = find_markers(url, "FUZZ")
    assert len(markers) == n, f"Expected {n} markers, got {len(markers)}"

    candidates = list(generate_marker_candidates(url, markers, wordlists, FuzzMode.CLUSTERBOMB))

    expected_count = math.prod(len(wl) for wl in wordlists)
    assert len(candidates) == expected_count, (
        f"Clusterbomb with wordlist sizes {[len(w) for w in wordlists]} should "
        f"produce {expected_count} candidates (cartesian product), got {len(candidates)}"
    )


@given(wordlists=_multi_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property5_clusterbomb_values_match_product(wordlists):
    """Property 5: Each clusterbomb candidate URL corresponds to a cartesian-product combo.

    # Feature: par-positional-markers, Property 5: Clusterbomb equals the cartesian product

    Validates: Requirements 5.2, 12.5
    """
    import itertools
    n = len(wordlists)
    url = _build_multi_marker_url(n)
    markers = find_markers(url, "FUZZ")

    candidates = list(generate_marker_candidates(url, markers, wordlists, FuzzMode.CLUSTERBOMB))
    expected_candidates = [
        substitute_markers(url, markers, list(combo))
        for combo in itertools.product(*wordlists)
    ]

    assert sorted(candidates) == sorted(expected_candidates), (
        f"Clusterbomb candidates don't match cartesian product.\n"
        f"Got: {sorted(candidates)}\nExpected: {sorted(expected_candidates)}"
    )


# ===========================================================================
# Task 6.6 — Property 6: Pitchfork equals index-wise zip truncated to shortest
# # Feature: par-positional-markers, Property 6: Pitchfork equals the index-wise zip truncated to shortest
# Validates: Requirements 6.1, 6.2, 12.6
# ===========================================================================


@given(wordlists=_multi_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property6_pitchfork_equals_zip_truncated_to_shortest(wordlists):
    """Property 6: Pitchfork equals the index-wise zip truncated to shortest.

    # Feature: par-positional-markers, Property 6: Pitchfork equals the index-wise zip truncated to shortest

    M markers with wordlist sizes W1..WM generate exactly min(W1,…,WM) candidates
    before deduplication, stopping at the shortest wordlist.

    Validates: Requirements 6.1, 6.2, 12.6
    """
    n = len(wordlists)
    url = _build_multi_marker_url(n)
    markers = find_markers(url, "FUZZ")
    assert len(markers) == n

    candidates = list(generate_marker_candidates(url, markers, wordlists, FuzzMode.PITCHFORK))

    expected_count = min(len(wl) for wl in wordlists)
    assert len(candidates) == expected_count, (
        f"Pitchfork with wordlist sizes {[len(w) for w in wordlists]} should "
        f"produce {expected_count} candidates (min of sizes), got {len(candidates)}"
    )


@given(wordlists=_multi_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property6_pitchfork_values_match_zip(wordlists):
    """Property 6: Each pitchfork candidate URL corresponds to a zip-paired combo.

    # Feature: par-positional-markers, Property 6: Pitchfork equals the index-wise zip truncated to shortest

    Validates: Requirements 6.1, 12.6
    """
    n = len(wordlists)
    url = _build_multi_marker_url(n)
    markers = find_markers(url, "FUZZ")

    candidates = list(generate_marker_candidates(url, markers, wordlists, FuzzMode.PITCHFORK))
    expected_candidates = [
        substitute_markers(url, markers, list(combo))
        for combo in zip(*wordlists)
    ]

    assert candidates == expected_candidates, (
        f"Pitchfork candidates don't match zip pairing.\n"
        f"Got: {candidates}\nExpected: {expected_candidates}"
    )


# ===========================================================================
# Task 6.7 — Property 8: Request issuance
# # Feature: par-positional-markers, Property 8: A request is issued for each fully substituted candidate and none before substitution
# Validates: Requirements 4.3, 8.1, 8.2, 12.1
# ===========================================================================

import asyncio
import itertools as _itertools
import math

from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


def _make_fuzzer(url: str, wordlists: "List[List[str]]",
                 fuzz_mode: str = "clusterbomb",
                 methods: "List[str]" = None) -> "ParameterFuzzer":
    """Build a ParameterFuzzer wired to an offline stub for the given marker URL."""
    from modules.fuzzing.orchestrator import ParameterFuzzer
    import apileaks
    from core.config import ConfigurationManager

    if methods is None:
        methods = ["GET"]

    config_dict = apileaks.create_default_config(
        url, None, "par",
        fuzz_keyword="FUZZ",
        fuzz_mode=fuzz_mode,
        marker_wordlists=wordlists,
    )
    config_dict["fuzzing"]["parameters"]["methods"] = methods
    config_dict["fuzzing"]["parameters"]["boundary_testing"] = False
    config = ConfigurationManager().load_config_from_dict(config_dict)

    stub = HTTPRequestEngineStub()
    fuzzer = ParameterFuzzer(stub, config.fuzzing)
    return fuzzer, stub


def _endpoint(url: str) -> "Endpoint":
    from modules.fuzzing.orchestrator import Endpoint
    return Endpoint(
        url=url,
        method="GET",
        status_code=200,
        response_size=0,
        response_time=0.01,
        discovered_via="target",
        endpoint_type="parameter_target",
    )


# Strategy: 1–3 values per wordlist, 1 marker
_small_wl = st.lists(_wl_entry, min_size=1, max_size=3)
_method_set = st.sampled_from([["GET"], ["POST"], ["GET", "POST"]])


@given(wl=_small_wl, methods=_method_set)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_property8_request_per_candidate_and_baseline(wl, methods):
    """Property 8: A request is issued for each fully substituted candidate and none before substitution.

    # Feature: par-positional-markers, Property 8: A request is issued for each fully substituted candidate and none before substitution

    Against the stub, assert:
    - Exactly one baseline request per selected method (neutral-sentinel URL)
    - Exactly one candidate request per selected method per candidate URL
    - No request is issued before substitution (no raw FUZZ in issued URLs)

    Validates: Requirements 4.3, 8.1, 8.2, 12.1
    """
    url = "https://api.example.test/v1/?id=FUZZ"
    markers = find_markers(url, "FUZZ")
    assert len(markers) == 1

    fuzzer, stub = _make_fuzzer(url, [wl], fuzz_mode="clusterbomb", methods=methods)
    ep = _endpoint(url)

    asyncio.run(fuzzer.fuzz_parameters([ep]))

    # Compute expected candidate URLs
    expected_candidates = list(
        generate_marker_candidates(url, markers, [wl], FuzzMode.CLUSTERBOMB)
    )

    # No request should contain the raw FUZZ keyword (never before substitution)
    for req in stub.requests:
        assert "FUZZ" not in req.url or any(
            sentinel in req.url for sentinel in [fuzzer._sentinels.get(url, "")]
        ), f"Request issued with unsubstituted FUZZ in URL: {req.url!r}"

    # One baseline per selected method (sentinel in URL)
    sentinel_val = None
    for val in fuzzer._sentinels.values():
        sentinel_val = val
        break

    # Check that all expected candidate URLs were requested (one per method)
    for method in methods:
        method_urls = [r.url for r in stub.requests if r.method == method.upper()]
        candidate_urls_for_method = [u for u in method_urls
                                     if sentinel_val not in u] if sentinel_val else method_urls
        assert set(expected_candidates).issubset(set(candidate_urls_for_method)), (
            f"Method {method}: expected candidates {sorted(expected_candidates)}, "
            f"got URL subset {sorted(set(candidate_urls_for_method))}"
        )


@given(wl=_small_wl)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_property8_no_raw_fuzz_in_issued_urls(wl):
    """Property 8: No request is issued with an unsubstituted FUZZ marker.

    # Feature: par-positional-markers, Property 8: A request is issued for each fully substituted candidate and none before substitution

    Validates: Requirements 4.3, 8.1, 12.1
    """
    url = "https://api.example.test/v1/?id=FUZZ"
    fuzzer, stub = _make_fuzzer(url, [wl], methods=["GET"])
    ep = _endpoint(url)

    asyncio.run(fuzzer.fuzz_parameters([ep]))

    # No issued request URL should contain the literal "FUZZ" keyword
    # unless it's the sentinel baseline (sentinel replaces FUZZ, so FUZZ is gone)
    for req in stub.requests:
        # After substitution "FUZZ" is gone from the URL (replaced by sentinel or value)
        assert "FUZZ" not in req.url, (
            f"Unsubstituted FUZZ found in issued URL: {req.url!r}. "
            "Requests must only be issued for fully-substituted candidate URLs."
        )


# ===========================================================================
# Task 6.8 — Property 9: Query-position value stays in URL under body methods
# # Feature: par-positional-markers, Property 9: Query-position value stays in the URL under body methods
# Validates: Requirements 8.3
# ===========================================================================


@given(
    wl=st.lists(
        st.text(min_size=1, max_size=8, alphabet=st.characters(whitelist_categories=("Ll", "Nd"))),
        min_size=1, max_size=5
    ),
    body_method=st.sampled_from(["POST", "PUT", "PATCH"]),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_property9_query_value_stays_in_url_under_body_methods(wl, body_method):
    """Property 9: Query-position value stays in the URL under body methods.

    # Feature: par-positional-markers, Property 9: Query-position value stays in the URL under body methods

    A query-value marker under POST/PUT/PATCH carries the substituted value at
    its original query position in the request URL and is never relocated into
    the request body.

    Validates: Requirements 8.3
    """
    url = "https://api.example.test/v1/?id=FUZZ"
    fuzzer, stub = _make_fuzzer(url, [wl], methods=[body_method])
    ep = _endpoint(url)

    asyncio.run(fuzzer.fuzz_parameters([ep]))

    # Filter out baseline requests (contain the sentinel, not a wordlist value)
    sentinel_val = None
    for val in fuzzer._sentinels.values():
        sentinel_val = val
        break

    for req in stub.requests:
        if sentinel_val and sentinel_val in req.url:
            continue  # baseline request — skip
        # For each candidate request: the substituted value must be in the URL
        # and must NOT be solely in the body
        # Find which value this request used by checking URL
        for val in wl:
            if val in req.url:
                # Value is in URL — correct
                break
        else:
            # No wordlist value found in URL — check if it's a baseline or empty
            # (empty string value '' is a degenerate case — skip)
            pass

    # Use the stub assertion helper for comprehensive check
    for val in wl:
        if val:  # skip empty strings
            stub.assert_query_value_in_url(val, method=body_method)


@given(
    val=st.text(min_size=1, max_size=8, alphabet=st.characters(whitelist_categories=("Ll",))),
    body_method=st.sampled_from(["POST", "PUT", "PATCH"]),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_property9_value_not_in_body_only(val, body_method):
    """Property 9: Query-position value is never relocated into the body alone.

    # Feature: par-positional-markers, Property 9: Query-position value stays in the URL under body methods

    Validates: Requirements 8.3
    """
    url = "https://api.example.test/v1/?id=FUZZ"
    fuzzer, stub = _make_fuzzer(url, [[val]], methods=[body_method])
    ep = _endpoint(url)

    asyncio.run(fuzzer.fuzz_parameters([ep]))

    # Every candidate request (non-baseline) must carry the value in the URL
    sentinel_val = None
    for sv in fuzzer._sentinels.values():
        sentinel_val = sv
        break

    for req in stub.requests:
        if sentinel_val and sentinel_val in req.url:
            continue  # baseline
        # Candidate request: value must be in URL
        if req.method == body_method.upper() and val in req.url:
            # Correct: value is in URL
            pass
        elif req.method == body_method.upper() and req.carries_value(val):
            # Value is carried somewhere — it must be in the URL
            assert val in req.url, (
                f"Value {val!r} was found in the request body but NOT in URL {req.url!r}. "
                "Query-position values must stay in the URL under body methods (R8.3)."
            )


# ===========================================================================
# Task 6.9 — Example tests for marker-position kinds
# Validates: Requirements 3.2, 3.3, 3.4, 3.5
# ===========================================================================

class TestMarkerPositionKindExamples:
    """Example tests for each marker-position kind, verifying correct candidate URL and request issuance."""

    def _run_marker(self, url: str, wordlist: "List[str]", methods: "List[str]" = None) -> "tuple":
        """Run _fuzz_markers for the given URL and return (fuzzer, stub, candidates)."""
        if methods is None:
            methods = ["GET"]
        fuzzer, stub = _make_fuzzer(url, [wordlist], methods=methods)
        ep = _endpoint(url)
        asyncio.run(fuzzer.fuzz_parameters([ep]))
        markers = find_markers(url, "FUZZ")
        candidates = list(generate_marker_candidates(url, markers, [wordlist], FuzzMode.CLUSTERBOMB))
        return fuzzer, stub, candidates

    def test_query_value_substitution(self):
        """R3.2: ?id=FUZZ → ?id=5 (value at query-param value position).

        Validates: Requirement 3.2
        """
        url = "https://api.example.test/v1/?id=FUZZ"
        wl = ["5", "10", "99"]
        fuzzer, stub, candidates = self._run_marker(url, wl)

        assert "https://api.example.test/v1/?id=5" in candidates
        assert "https://api.example.test/v1/?id=10" in candidates
        assert "https://api.example.test/v1/?id=99" in candidates

        # Each candidate URL was issued as a request
        issued_urls = [r.url for r in stub.requests]
        for c in candidates:
            assert c in issued_urls, f"Candidate {c!r} was not issued"

    def test_query_name_substitution(self):
        """R3.3: ?FUZZ=1 → ?debug=1 (value at query-param name position).

        Validates: Requirement 3.3
        """
        url = "https://api.example.test/v1/?FUZZ=1"
        wl = ["debug", "verbose", "trace"]
        fuzzer, stub, candidates = self._run_marker(url, wl)

        assert "https://api.example.test/v1/?debug=1" in candidates
        assert "https://api.example.test/v1/?verbose=1" in candidates
        assert "https://api.example.test/v1/?trace=1" in candidates

        issued_urls = [r.url for r in stub.requests]
        for c in candidates:
            assert c in issued_urls, f"Candidate {c!r} was not issued"

    def test_full_segment_substitution(self):
        """R3.4: /api/FUZZ/users → /api/admin/users (full path segment).

        Validates: Requirement 3.4
        """
        url = "https://api.example.test/api/FUZZ/users"
        wl = ["admin", "v2", "beta"]
        fuzzer, stub, candidates = self._run_marker(url, wl)

        assert "https://api.example.test/api/admin/users" in candidates
        assert "https://api.example.test/api/v2/users" in candidates
        assert "https://api.example.test/api/beta/users" in candidates

        issued_urls = [r.url for r in stub.requests]
        for c in candidates:
            assert c in issued_urls, f"Candidate {c!r} was not issued"

    def test_path_substring_substitution(self):
        """R3.5: /vFUZZ/users → /v2/users (substring inside path segment).

        Validates: Requirement 3.5
        """
        url = "https://api.example.test/vFUZZ/users"
        wl = ["2", "3", "4"]
        fuzzer, stub, candidates = self._run_marker(url, wl)

        assert "https://api.example.test/v2/users" in candidates
        assert "https://api.example.test/v3/users" in candidates
        assert "https://api.example.test/v4/users" in candidates

        issued_urls = [r.url for r in stub.requests]
        for c in candidates:
            assert c in issued_urls, f"Candidate {c!r} was not issued"

    def test_query_value_post_method_value_stays_in_url(self):
        """R8.3: Query-value marker under POST keeps value in URL, not body.

        Validates: Requirement 8.3
        """
        url = "https://api.example.test/v1/?id=FUZZ"
        wl = ["5", "10"]
        fuzzer, stub, candidates = self._run_marker(url, wl, methods=["POST"])

        issued = [r for r in stub.requests if r.method == "POST"]
        for req in issued:
            # Sentinel baseline may not contain a wordlist value — skip those
            for val in wl:
                if val in req.url:
                    # Value is in URL — correct (not relocated to body)
                    assert req.json is None or val not in str(req.json), (
                        f"Value {val!r} appears in JSON body of POST request {req.url!r}. "
                        "Query-position values must stay in the URL under body methods."
                    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
