"""
Response matchers and filters for discovery results (Requirement 22).

This module models *selection* over response attributes beyond the HTTP status
code -- response body size, word count, line count, response-body regular
expression, and response time -- so that triage can suppress noise such as
soft-404 pages and keep only the responses that matter.

The model is intentionally **pure**: it issues no requests and operates only on
already-discovered records, so it does not affect the ``Request_Budget``,
``Concurrency_Limit`` or ``Rate_Limit``. Matchers and filters share one
expression grammar but differ in semantics -- a matcher *includes* (every
matcher must hold) while a filter *excludes* (any matching filter drops the
record). :func:`apply_selectors` combines the existing ``Status_Code_Filter``,
the matchers, and the filters conjunctively (Requirement 22.7) as an
order-independent, idempotent set-narrowing operation (Requirement 22.10).

Because selecting on ``size``/``words``/``lines``/``regex``/``time`` needs the
response body and timing -- which the persisted :class:`DiscoveryResult`
(``url``, ``method``, ``status_code``, ``endpoint_status``) does not carry --
selection operates on an **in-memory-only** extended view,
:class:`DiscoveryResultEx`. That view is *never serialized*, so the Requirement
14 session round-trip is unaffected.
"""

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from utils.discovery_session import (
    DiscoveryResult,
    StatusFilter,
    apply_status_filter,
    parse_status_filter,
)

if TYPE_CHECKING:  # pragma: no cover - import only for type hints
    from modules.fuzzing.orchestrator import EndpointFuzzer

# Numeric response attributes selectable via a :class:`Bound` expression. The
# response-body ``regex`` and the ``status`` filter are handled separately
# because they are not numeric comparisons.
NUMERIC_ATTRIBUTES = ("size", "words", "lines", "time")

# Comparison operators a :class:`Bound` may carry, longest-first so the parser
# matches ``>=``/``<=`` before the single-character ``>``/``<``.
_COMPARISON_OPERATORS = (">=", "<=", ">", "<")

# An inclusive numeric range like ``10-20`` (integers or decimals).
_RANGE_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s*$")


class SelectorError(Exception):
    """Raised when a matcher/filter expression is syntactically invalid.

    The message names the offending expression value so the ``dir`` command can
    surface a descriptive CLI error and perform no ``Endpoint_Discovery``
    (Requirement 22.9).
    """


@dataclass(frozen=True)
class DiscoveryResultEx:
    """In-memory-only extended view of a discovered record for selection.

    Wraps the persisted :class:`DiscoveryResult` projection with the response
    attributes needed to evaluate matchers/filters. This view is **never
    serialized** -- only the wrapped :attr:`result` is persisted by the
    discovery session -- so the Requirement 14 round-trip stays intact.

    ``text`` carries the response body used for the response-body ``regex``
    predicate (Requirement 22.1); it defaults to empty and, like every other
    field here, is held only in memory.
    """

    result: DiscoveryResult        # the persisted projection
    size: int = 0                  # response body size in bytes
    words: int = 0                 # whitespace-delimited word count
    lines: int = 0                 # newline-delimited line count
    elapsed: float = 0.0           # response time, seconds
    text: str = ""                 # response body, for regex matching only


@dataclass(frozen=True)
class Soft404Baseline:
    """A reference soft-404 response signature for automatic suppression.

    Models the ``Soft_404_Baseline`` (Requirement 22.5): the response signature a
    base URL returns for paths that are *not expected to exist* -- its HTTP
    ``status_code``, response body ``size`` in bytes, and whitespace-delimited
    ``words`` count. A discovered record whose status, size, and words **all**
    equal this baseline is treated as a soft-404 page and suppressed
    (Requirement 22.6).

    This mechanism is deliberately kept **distinct from and complementary to**
    ``Catch_All_Response`` detection (Requirement 22.8): catch-all suppression
    matches on ``(status_code, size)`` only after every probe returns 2xx,
    whereas the soft-404 baseline additionally constrains the ``words`` count and
    is derived whenever the probe responses agree on a single signature
    regardless of status class. A record may be suppressed by either mechanism
    independently.

    The baseline is built by :func:`calibrate_soft_404` from the catch-all probe
    responses, so deriving it issues **no requests** beyond the probes that
    already ran and counted toward the ``Request_Budget``.
    """

    status_code: int               # HTTP status code of the soft-404 response
    size: int                      # response body size in bytes
    words: int                     # whitespace-delimited word count

    def matches(self, ex: DiscoveryResultEx) -> bool:
        """Return whether ``ex`` matches this baseline on all three attributes.

        A record is a soft-404 match only when its status code, response body
        size, and word count **all** equal the baseline (Requirement 22.6).
        """
        return (
            ex.result.status_code == self.status_code
            and ex.size == self.size
            and ex.words == self.words
        )


def calibrate_soft_404(fuzzer: "EndpointFuzzer") -> Soft404Baseline | None:
    """Build a :class:`Soft404Baseline` from the fuzzer's catch-all probes.

    Reuses the ``(status_code, size, words)`` signature that
    ``EndpointFuzzer._detect_catch_all`` already captured from its probes to
    paths that are not expected to exist (Requirement 22.5). Because the probes
    have already been issued and counted toward the ``Request_Budget``,
    calibration adds **no extra requests** (Requirement 22.8).

    Args:
        fuzzer: The :class:`~modules.fuzzing.orchestrator.EndpointFuzzer` that
            ran discovery; its ``soft_404_signature`` carries the captured probe
            signature (``None`` when the probes did not agree on a single
            signature or none were issued).

    Returns:
        A :class:`Soft404Baseline` when a probe signature was captured, else
        ``None`` (no baseline -- nothing is suppressed by this mechanism).
    """
    signature = getattr(fuzzer, "soft_404_signature", None)
    if signature is None:
        return None
    status_code, size, words = signature
    return Soft404Baseline(status_code=status_code, size=size, words=words)


@dataclass(frozen=True)
class Bound:
    """A numeric comparison parsed from an expression like ``>100``/``10-20``.

    Exactly one comparison is represented. For every operator except
    ``"range"`` only :attr:`lo` is used; ``"range"`` is the inclusive interval
    ``[lo, hi]``.
    """

    op: str                        # one of '==','>','>=','<','<=','range'
    lo: float
    hi: float | None = None

    def test(self, value: float) -> bool:
        """Return whether ``value`` satisfies this bound."""
        if self.op == "==":
            return value == self.lo
        if self.op == ">":
            return value > self.lo
        if self.op == ">=":
            return value >= self.lo
        if self.op == "<":
            return value < self.lo
        if self.op == "<=":
            return value <= self.lo
        if self.op == "range":
            hi = self.hi if self.hi is not None else self.lo
            return self.lo <= value <= hi
        # Unreachable for bounds built via parse_selectors, which only emits the
        # operators above; guard defensively rather than silently pass.
        raise SelectorError(f"unknown bound operator: '{self.op}'")


@dataclass(frozen=True)
class ResponseSelector:
    """A conjunction of response-attribute predicates over a record.

    Every *present* predicate must hold for the selector to
    :meth:`satisfies` a record; absent predicates impose no constraint. The
    ``status`` predicate reuses the existing :class:`StatusFilter` semantics
    from :mod:`utils.discovery_session`.
    """

    status: StatusFilter | None = None      # reuse existing status semantics
    size: Bound | None = None               # response body size in bytes
    words: Bound | None = None              # whitespace-delimited word count
    lines: Bound | None = None              # newline-delimited line count
    regex: re.Pattern | None = None         # response-body regular expression
    time: Bound | None = None               # response time, seconds

    def satisfies(self, r: DiscoveryResultEx) -> bool:
        """Return whether record ``r`` satisfies every present predicate."""
        if self.status is not None and not _status_matches(self.status, r.result):
            return False
        if self.size is not None and not self.size.test(r.size):
            return False
        if self.words is not None and not self.words.test(r.words):
            return False
        if self.lines is not None and not self.lines.test(r.lines):
            return False
        if self.time is not None and not self.time.test(r.elapsed):
            return False
        if self.regex is not None and self.regex.search(r.text) is None:
            return False
        return True


def _status_matches(status_filter: StatusFilter, result: DiscoveryResult) -> bool:
    """Return whether ``result`` matches ``status_filter``.

    Reuses :func:`apply_status_filter` so class-token and explicit-code
    semantics stay identical to the existing status filtering.
    """
    return bool(apply_status_filter([result], status_filter))


def _parse_bound(raw: str, attribute: str) -> Bound:
    """Parse a single numeric bound expression for ``attribute``.

    Accepts ``>100``, ``>=100``, ``<50``, ``<=50``, a bare value ``200`` (an
    equality bound) and an inclusive range ``10-20``.

    Raises:
        SelectorError: If the value is not a parseable numeric bound. The
            message names the offending expression (Requirement 22.9).
    """
    value = raw.strip()
    if not value:
        raise SelectorError(
            f"invalid {attribute} bound: expression must not be empty"
        )

    range_match = _RANGE_PATTERN.match(value)
    if range_match is not None:
        lo = float(range_match.group(1))
        hi = float(range_match.group(2))
        if hi < lo:
            raise SelectorError(
                f"invalid {attribute} range '{raw}': "
                f"upper bound is below lower bound"
            )
        return Bound(op="range", lo=lo, hi=hi)

    operator = ""
    for candidate in _COMPARISON_OPERATORS:
        if value.startswith(candidate):
            operator = candidate
            value = value[len(candidate):].strip()
            break

    try:
        number = float(value)
    except ValueError as exc:
        raise SelectorError(
            f"invalid {attribute} bound '{raw}': not a numeric value"
        ) from exc

    return Bound(op=operator or "==", lo=number)


def _parse_one_selector(expr: str) -> ResponseSelector:
    """Parse a single ``attribute:expression`` selector string.

    The attribute prefix selects the predicate type: ``size``/``words``/
    ``lines``/``time`` carry a :class:`Bound`, ``regex`` carries a compiled
    response-body pattern, and ``status`` reuses :func:`parse_status_filter`.

    Raises:
        SelectorError: If the prefix is missing/unknown, the regular expression
            is unparseable, or a numeric bound is non-numeric (Requirement
            22.9). The message names the offending value.
    """
    attribute, separator, raw = expr.partition(":")
    if not separator:
        raise SelectorError(
            f"invalid selector '{expr}': expected '<attribute>:<expression>'"
        )

    attribute = attribute.strip().lower()

    if attribute == "regex":
        try:
            pattern = re.compile(raw)
        except re.error as exc:
            raise SelectorError(
                f"invalid regex '{raw}': {exc}"
            ) from exc
        return ResponseSelector(regex=pattern)

    if attribute == "status":
        try:
            status_filter = parse_status_filter(raw)
        except ValueError as exc:
            raise SelectorError(
                f"invalid status selector '{raw}': {exc}"
            ) from exc
        return ResponseSelector(status=status_filter)

    if attribute in NUMERIC_ATTRIBUTES:
        bound = _parse_bound(raw, attribute)
        return ResponseSelector(**{attribute: bound})

    raise SelectorError(
        f"invalid selector '{expr}': unknown attribute '{attribute}' "
        f"(expected one of: status, {', '.join(NUMERIC_ATTRIBUTES)}, regex)"
    )


def parse_selectors(
    match_exprs: list[str],
    filter_exprs: list[str],
) -> tuple[list[ResponseSelector], list[ResponseSelector]]:
    """Parse ``--match-*``/``--filter-*`` expressions into selectors.

    Each expression is an ``<attribute>:<expression>`` string where the bound
    grammar is ``>100``, ``>=100``, ``<50``, ``<=50``, a bare ``200`` (equality)
    or an inclusive range ``10-20``; ``regex:`` carries a response-body pattern
    and ``status:`` reuses the existing status-filter grammar.

    Args:
        match_exprs: Matcher expressions (records must satisfy every matcher).
        filter_exprs: Filter expressions (records satisfying any are excluded).

    Returns:
        A ``(matchers, filters)`` tuple of :class:`ResponseSelector` lists.

    Raises:
        SelectorError: On an unparseable regex or a non-numeric size/word/line/
            time bound; the message names the offending value (Requirement
            22.9).
    """
    matchers = [_parse_one_selector(expr) for expr in match_exprs]
    filters = [_parse_one_selector(expr) for expr in filter_exprs]
    return matchers, filters


def apply_selectors(
    records: list[DiscoveryResultEx],
    matchers: list[ResponseSelector],
    filters: list[ResponseSelector],
    status_filter: StatusFilter | None = None,
) -> list[DiscoveryResultEx]:
    """Narrow ``records`` by status filter, matchers, then filters.

    Applies the three selections conjunctively (Requirement 22.7): a record is
    retained when it matches the ``status_filter`` (if any) **and** satisfies
    every matcher **and** satisfies no filter. With no matchers and no filters
    and no status filter every record is retained.

    The operation is a pure set-narrowing function: it preserves the relative
    order of ``records`` and is order-independent and idempotent in its result
    set -- applying it twice retains the same set as applying it once
    (Requirement 22.10).

    Args:
        records: The extended discovery views to select over.
        matchers: Matcher selectors; a record must satisfy all of them.
        filters: Filter selectors; a record satisfying any of them is excluded.
        status_filter: Optional existing ``Status_Code_Filter`` applied first.

    Returns:
        The retained records, in their original relative order.
    """
    retained: list[DiscoveryResultEx] = []
    for record in records:
        if status_filter is not None and not _status_matches(
            status_filter, record.result
        ):
            continue
        if not all(matcher.satisfies(record) for matcher in matchers):
            continue
        if any(response_filter.satisfies(record) for response_filter in filters):
            continue
        retained.append(record)
    return retained
