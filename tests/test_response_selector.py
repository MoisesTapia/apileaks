"""
Unit tests for response matcher/filter selector parsing, soft-404 calibration,
and conjunctive composition (Requirement 22).

These are example-based unit tests complementing the property-based suite in
``test_response_selector_properties.py``. They cover:

  * Valid ``--match-*``/``--filter-*`` expressions parse into the right
    selectors across every numeric bound form (==, range, >, >=, <, <=), a
    response-body regex, and a status filter (Requirement 22.1).
  * Invalid expressions raise :class:`SelectorError` whose message *names* the
    offending value (Requirements 22.1, 22.9).
  * Soft-404 calibration builds a :class:`Soft404Baseline` from a fuzzer's
    captured ``soft_404_signature`` and suppresses records matching the baseline
    on status + size + words while keeping non-matching ones (Requirements 22.5,
    22.6).
  * Status filter + matcher + filter combine conjunctively (Requirement 22.7),
    while soft-404 and catch-all suppression operate independently of each other
    and of the selectors (Requirement 22.8).
"""

import re
from types import SimpleNamespace

import pytest

from utils.discovery_session import DiscoveryResult, StatusFilter
from utils.response_selector import (
    Bound,
    DiscoveryResultEx,
    ResponseSelector,
    SelectorError,
    Soft404Baseline,
    apply_selectors,
    calibrate_soft_404,
    parse_selectors,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ex(status_code=200, size=0, words=0, lines=0, elapsed=0.0, text="", url="https://t/x"):
    """Build a DiscoveryResultEx with sensible defaults for selection tests."""
    return DiscoveryResultEx(
        result=DiscoveryResult(
            url=url,
            method="GET",
            status_code=status_code,
            endpoint_status="valid",
        ),
        size=size,
        words=words,
        lines=lines,
        elapsed=elapsed,
        text=text,
    )


# ---------------------------------------------------------------------------
# Valid expression parsing (Requirement 22.1)
# ---------------------------------------------------------------------------

class TestValidSelectorParsing:
    """Valid match/filter expressions parse into the correct selectors."""

    def test_numeric_bound_forms_parse_across_all_operators(self):
        """**Validates: Requirements 22.1**

        Each numeric bound form (bare equality, range, >, >=, <, <=) parses into
        the matching :class:`Bound` op/value on the right attribute.
        """
        matchers, filters = parse_selectors(
            [
                "size:100",     # bare value -> equality
                "words:10-20",  # inclusive range
                "lines:>5",     # strictly greater
                "time:>=1.5",   # greater or equal
            ],
            [
                "size:<50",     # strictly less
                "words:<=3",    # less or equal
            ],
        )

        assert matchers[0].size == Bound(op="==", lo=100.0)
        assert matchers[1].words == Bound(op="range", lo=10.0, hi=20.0)
        assert matchers[2].lines == Bound(op=">", lo=5.0)
        assert matchers[3].time == Bound(op=">=", lo=1.5)

        assert filters[0].size == Bound(op="<", lo=50.0)
        assert filters[1].words == Bound(op="<=", lo=3.0)

    def test_regex_and_status_expressions_parse(self):
        """**Validates: Requirements 22.1**

        A ``regex:`` expression compiles a response-body pattern and a
        ``status:`` expression reuses the status-filter grammar (class token and
        explicit codes).
        """
        matchers, filters = parse_selectors(
            ["regex:admin", "status:2xx"],
            ["status:404"],
        )

        # regex predicate compiled and usable.
        assert matchers[0].regex is not None
        assert matchers[0].regex.search("/admin/panel") is not None
        assert matchers[0].regex.search("/public") is None

        # status class token.
        assert matchers[1].status == StatusFilter(status_class="2xx")

        # explicit status code.
        assert filters[0].status == StatusFilter(codes=frozenset({404}))

    def test_parsed_bound_evaluates_records_correctly(self):
        """**Validates: Requirements 22.1**

        A parsed range matcher accepts in-range records and rejects out-of-range
        ones, confirming the bound is wired to the right attribute.
        """
        (matcher,), _ = parse_selectors(["size:100-200"], [])
        assert matcher.satisfies(_ex(size=150)) is True
        assert matcher.satisfies(_ex(size=100)) is True   # inclusive lower
        assert matcher.satisfies(_ex(size=200)) is True   # inclusive upper
        assert matcher.satisfies(_ex(size=99)) is False
        assert matcher.satisfies(_ex(size=201)) is False


# ---------------------------------------------------------------------------
# Invalid expression parsing -> SelectorError naming the value (22.1, 22.9)
# ---------------------------------------------------------------------------

class TestInvalidSelectorParsing:
    """Invalid expressions raise SelectorError naming the offending value."""

    def test_non_numeric_bound_raises_naming_value(self):
        """**Validates: Requirements 22.1, 22.9**"""
        with pytest.raises(SelectorError) as exc:
            parse_selectors(["size:abc"], [])
        assert "size:abc" in str(exc.value) or "abc" in str(exc.value)

    def test_unparseable_regex_raises_naming_value(self):
        """**Validates: Requirements 22.1, 22.9**"""
        with pytest.raises(SelectorError) as exc:
            parse_selectors(["regex:["], [])
        assert "[" in str(exc.value)

    def test_unknown_attribute_raises_naming_value(self):
        """**Validates: Requirements 22.1, 22.9**"""
        with pytest.raises(SelectorError) as exc:
            parse_selectors(["bogus:5"], [])
        message = str(exc.value)
        assert "bogus" in message

    def test_missing_colon_raises_naming_expression(self):
        """**Validates: Requirements 22.1, 22.9**"""
        with pytest.raises(SelectorError) as exc:
            parse_selectors(["size100"], [])
        assert "size100" in str(exc.value)

    def test_empty_bound_raises(self):
        """**Validates: Requirements 22.1, 22.9**"""
        with pytest.raises(SelectorError) as exc:
            parse_selectors(["size:"], [])
        assert "size" in str(exc.value)

    def test_inverted_range_raises_naming_value(self):
        """**Validates: Requirements 22.1, 22.9**"""
        with pytest.raises(SelectorError) as exc:
            parse_selectors([], ["words:20-10"])
        assert "20-10" in str(exc.value)

    def test_invalid_filter_expression_also_raises(self):
        """**Validates: Requirements 22.1, 22.9**

        Filter expressions are validated with the same grammar as matchers.
        """
        with pytest.raises(SelectorError) as exc:
            parse_selectors([], ["time:fast"])
        assert "time:fast" in str(exc.value) or "fast" in str(exc.value)


# ---------------------------------------------------------------------------
# Soft-404 calibration and suppression (Requirements 22.5, 22.6)
# ---------------------------------------------------------------------------

class TestSoft404Calibration:
    """calibrate_soft_404 builds a baseline that suppresses matching records."""

    def test_calibrate_from_captured_signature(self):
        """**Validates: Requirements 22.5**

        The baseline reflects the fuzzer's captured ``(status, size, words)``
        probe signature.
        """
        fuzzer = SimpleNamespace(soft_404_signature=(404, 512, 42))
        baseline = calibrate_soft_404(fuzzer)
        assert baseline == Soft404Baseline(status_code=404, size=512, words=42)

    def test_calibrate_without_signature_returns_none(self):
        """**Validates: Requirements 22.5**

        When the probes did not agree on a signature, no baseline is derived and
        nothing is suppressed by this mechanism.
        """
        fuzzer = SimpleNamespace(soft_404_signature=None)
        assert calibrate_soft_404(fuzzer) is None

    def test_baseline_suppresses_only_full_status_size_words_match(self):
        """**Validates: Requirements 22.5, 22.6**

        A record is suppressed only when status, size, AND words all equal the
        baseline; differing on any single attribute keeps the record.
        """
        fuzzer = SimpleNamespace(soft_404_signature=(404, 512, 42))
        baseline = calibrate_soft_404(fuzzer)

        soft_404 = _ex(status_code=404, size=512, words=42)
        diff_status = _ex(status_code=200, size=512, words=42)
        diff_size = _ex(status_code=404, size=513, words=42)
        diff_words = _ex(status_code=404, size=512, words=43)

        assert baseline.matches(soft_404) is True
        assert baseline.matches(diff_status) is False
        assert baseline.matches(diff_size) is False
        assert baseline.matches(diff_words) is False

    def test_suppression_drops_matching_records_keeps_others(self):
        """**Validates: Requirements 22.5, 22.6**

        Applying the baseline as an independent suppression pass (mirroring the
        ``dir`` command) drops every soft-404 record and retains genuine hits.
        """
        baseline = Soft404Baseline(status_code=404, size=512, words=42)
        records = [
            _ex(status_code=404, size=512, words=42, url="https://t/a"),  # soft-404
            _ex(status_code=200, size=128, words=10, url="https://t/b"),  # real
            _ex(status_code=404, size=512, words=42, url="https://t/c"),  # soft-404
            _ex(status_code=200, size=512, words=42, url="https://t/d"),  # real (status differs)
        ]

        # apply_selectors with no selectors retains all; soft-404 suppression is
        # then layered independently, exactly as _run_dir_triage does.
        selected = apply_selectors(records, [], [])
        kept = [r for r in selected if not baseline.matches(r)]

        kept_urls = [r.result.url for r in kept]
        assert kept_urls == ["https://t/b", "https://t/d"]


# ---------------------------------------------------------------------------
# Conjunctive composition (22.7) and independent suppression (22.8)
# ---------------------------------------------------------------------------

class TestConjunctiveComposition:
    """Status filter + matcher + filter compose conjunctively (22.7)."""

    def _dataset(self):
        return [
            _ex(status_code=200, size=150, words=10, url="https://t/keep"),
            _ex(status_code=200, size=10, words=10, url="https://t/small"),     # fails size matcher
            _ex(status_code=404, size=150, words=10, url="https://t/notfound"), # fails status filter
            _ex(status_code=200, size=150, words=10, url="https://t/login"),    # caught by filter
        ]

    def test_status_matcher_filter_combine_conjunctively(self):
        """**Validates: Requirements 22.7**

        Only records satisfying the status filter AND the matcher AND not the
        filter survive.
        """
        records = self._dataset()
        status_filter = StatusFilter(status_class="2xx")
        matchers, filters = parse_selectors(
            ["size:>100"],          # require large body
            ["regex:login"],         # drop login pages
        )
        records[3] = _ex(
            status_code=200, size=150, words=10,
            url="https://t/login", text="please login here",
        )

        selected = apply_selectors(records, matchers, filters, status_filter)
        urls = [r.result.url for r in selected]
        assert urls == ["https://t/keep"]

    def test_each_constraint_independently_removes_records(self):
        """**Validates: Requirements 22.7**

        Removing any single constraint admits exactly the record it had excluded,
        confirming the constraints are conjunctive rather than overlapping.
        """
        records = self._dataset()
        records[3] = _ex(
            status_code=200, size=150, words=10,
            url="https://t/login", text="please login here",
        )
        matchers, filters = parse_selectors(["size:>100"], ["regex:login"])
        status_filter = StatusFilter(status_class="2xx")

        # Drop the status filter -> the 404 record is admitted.
        no_status = apply_selectors(records, matchers, filters, None)
        assert "https://t/notfound" in [r.result.url for r in no_status]

        # Drop the matcher -> the small-body record is admitted.
        no_matcher = apply_selectors(records, [], filters, status_filter)
        assert "https://t/small" in [r.result.url for r in no_matcher]

        # Drop the filter -> the login record is admitted.
        no_filter = apply_selectors(records, matchers, [], status_filter)
        assert "https://t/login" in [r.result.url for r in no_filter]

    def test_soft404_and_catch_all_suppress_independently(self):
        """**Validates: Requirements 22.8**

        Soft-404 suppression and catch-all suppression each exclude records on
        their own criteria, independently of each other and of the selectors. A
        record removed by either mechanism is excluded.
        """
        # Soft-404 baseline matches on (status, size, words).
        soft_404 = Soft404Baseline(status_code=404, size=512, words=42)
        # Catch-all suppression matches on (status_code, size) only -- modeled
        # here exactly as EndpointFuzzer._is_catch_all does.
        catch_all_signature = (200, 999)

        def is_catch_all(ex):
            return (ex.result.status_code, ex.size) == catch_all_signature

        records = [
            _ex(status_code=404, size=512, words=42, url="https://t/soft"),   # soft-404 only
            _ex(status_code=200, size=999, words=5, url="https://t/wild"),    # catch-all only
            _ex(status_code=200, size=999, words=42, url="https://t/both"),   # neither baseline (status differs)
            _ex(status_code=200, size=128, words=7, url="https://t/real"),    # real hit
        ]

        # No selectors: both suppressions operate purely on signatures.
        selected = apply_selectors(records, [], [])
        kept = [
            r for r in selected
            if not soft_404.matches(r) and not is_catch_all(r)
        ]
        kept_urls = [r.result.url for r in kept]

        # soft-only removed by soft-404, wild removed by catch-all, real kept.
        assert "https://t/soft" not in kept_urls
        assert "https://t/wild" not in kept_urls
        assert "https://t/real" in kept_urls
        # The "both" URL has status 200/size 999 -> caught by catch-all, not soft-404.
        assert "https://t/both" not in kept_urls

    def test_suppression_independent_of_selectors(self):
        """**Validates: Requirements 22.8**

        A catch-all/soft-404 suppressed record is excluded even when it would
        otherwise satisfy the matchers and pass the filters.
        """
        soft_404 = Soft404Baseline(status_code=404, size=512, words=42)
        # This record satisfies a permissive matcher and no filter, yet must
        # still be suppressed by the soft-404 baseline.
        record = _ex(status_code=404, size=512, words=42, url="https://t/soft")
        matchers, filters = parse_selectors(["size:>0"], [])

        selected = apply_selectors([record], matchers, filters)
        assert selected == [record]  # selectors alone retain it

        kept = [r for r in selected if not soft_404.matches(r)]
        assert kept == []  # independent suppression removes it
