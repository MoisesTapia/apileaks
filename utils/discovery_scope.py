"""
Discovery scope selection: path scope and storage-level status selection.

This module defines the *storage-time* selection rules applied during endpoint
discovery (Requirement 33). Unlike the display-only ``Status_Code_Filter`` of
Requirement 13 (see :func:`utils.discovery_session.apply_status_filter`), these
selections decide which records are ever *persisted*: a record dropped here
never enters ``discovered_endpoints`` and therefore never reaches the discovery
session file, the CSV/JSONL output, or the triage table, regardless of any later
display-only filter (Requirements 33.6, 33.7).

Two pure, frozen selection rules are modeled:

* :class:`PathScope` — include/exclude regular expressions evaluated against the
  candidate path *and* the discovered URL, with exclude taking precedence over
  include (Requirements 33.1-33.4, 33.10).
* :class:`StorageStatusSelection` — include/exclude HTTP status selection
  expressed as a status class (``"2xx".."5xx"``) or explicit codes, reusing the
  :class:`~utils.discovery_session.StatusFilter` semantics, with exclude taking
  precedence (Requirement 33.5).

Both parsers (:func:`parse_path_scope`, :func:`parse_storage_status_selection`)
raise a descriptive error naming the offending value on invalid input so the
``dir`` command can surface it and perform no discovery (Requirements 33.8,
33.9).
"""

import re
from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

from utils.discovery_session import (
    MAX_STATUS_CODE,
    MIN_STATUS_CODE,
    STATUS_CLASSES,
    StatusFilter,
    parse_status_filter,
    status_code_class,
)


class PathScopeError(Exception):
    """Raised when an ``--include-path``/``--exclude-path`` value is not a valid
    regular expression (Requirement 33.8)."""


class StorageStatusError(Exception):
    """Raised when an ``--include-status``/``--exclude-status`` value is an
    out-of-range code or an unrecognized token (Requirement 33.9)."""


def _status_matches(status_filter: StatusFilter, code: int) -> bool:
    """Return whether a single status ``code`` matches ``status_filter``.

    This is the single-code form of the leading-digit / exact-code test
    implemented by :func:`utils.discovery_session.apply_status_filter`: a class
    filter matches when the code shares the class's leading digit (via
    :func:`~utils.discovery_session.status_code_class`), while an explicit-code
    filter matches when the code is exactly in the filter's set.

    Args:
        status_filter: The parsed filter to test against.
        code: The HTTP status code to test.

    Returns:
        ``True`` iff ``code`` satisfies ``status_filter``.
    """
    if status_filter.status_class is not None:
        return status_code_class(code) == status_filter.status_class
    codes = status_filter.codes or frozenset()
    return code in codes


@dataclass(frozen=True)
class PathScope:
    """Include/exclude path selection (``Path_Scope``).

    Each pattern is a compiled regular expression evaluated against BOTH the
    candidate path and the discovered URL. Exclude takes precedence over include
    (Requirements 33.4, 33.10).
    """

    include: Tuple[re.Pattern, ...] = ()
    exclude: Tuple[re.Pattern, ...] = ()

    def admits(self, path: str, url: str) -> bool:
        """Return whether the candidate is permitted by this scope.

        A match of ANY ``exclude`` pattern (against ``path`` OR ``url``) rejects
        unconditionally (Requirements 33.3, 33.4, 33.10). Otherwise, when one or
        more ``include`` patterns exist, at least one must match against ``path``
        or ``url`` (Requirement 33.2). With no ``include`` patterns, everything
        not excluded is admitted.

        Args:
            path: The candidate path (e.g. the wordlist word).
            url: The full discovered URL.

        Returns:
            ``True`` iff the candidate is admitted.
        """
        if any(pattern.search(path) or pattern.search(url) for pattern in self.exclude):
            return False
        if self.include:
            return any(
                pattern.search(path) or pattern.search(url) for pattern in self.include
            )
        return True


def parse_path_scope(include_exprs, exclude_exprs) -> PathScope:
    """Compile ``--include-path`` / ``--exclude-path`` regexes into a :class:`PathScope`.

    Args:
        include_exprs: An iterable of include regex strings (may be ``None`` or
            empty for no include restriction).
        exclude_exprs: An iterable of exclude regex strings (may be ``None`` or
            empty for no exclude restriction).

    Returns:
        The compiled :class:`PathScope`.

    Raises:
        PathScopeError: If any value is not a valid regular expression; the
            message names the offending pattern (Requirement 33.8).
    """

    def _compile_all(exprs) -> Tuple[re.Pattern, ...]:
        compiled = []
        for expr in exprs or ():
            try:
                compiled.append(re.compile(expr))
            except re.error as exc:
                raise PathScopeError(
                    f"invalid path pattern '{expr}': {exc}"
                ) from exc
        return tuple(compiled)

    return PathScope(
        include=_compile_all(include_exprs),
        exclude=_compile_all(exclude_exprs),
    )


@dataclass(frozen=True)
class StorageStatusSelection:
    """Storage-level status selection (``Storage_Status_Selection``).

    Decides which status codes are PERSISTED at discovery time. Reuses
    :class:`~utils.discovery_session.StatusFilter` semantics (a class token or
    explicit codes). ``include`` and ``exclude`` are each an optional
    :class:`StatusFilter`; exclude takes precedence over include.
    """

    include: Optional[StatusFilter] = None
    exclude: Optional[StatusFilter] = None

    def admits(self, status_code: int) -> bool:
        """Return whether a record with ``status_code`` is stored.

        The record is dropped if it matches ``exclude``; otherwise it is kept
        when ``include`` is ``None`` or it matches ``include`` (Requirement
        33.5).

        Args:
            status_code: The discovered HTTP status code.

        Returns:
            ``True`` iff the record should be persisted.
        """
        if self.exclude is not None and _status_matches(self.exclude, status_code):
            return False
        if self.include is not None:
            return _status_matches(self.include, status_code)
        return True


def parse_storage_status_selection(
    include: Optional[str],
    exclude: Optional[str],
) -> StorageStatusSelection:
    """Parse ``--include-status`` / ``--exclude-status`` into a :class:`StorageStatusSelection`.

    Each value is a ``Status_Code_Class`` (e.g. ``"2xx"``) or explicit
    codes/ranges (e.g. ``"200,404"``), parsed via the existing
    :func:`~utils.discovery_session.parse_status_filter`, which validates
    explicit codes to the inclusive ``MIN_STATUS_CODE``-``MAX_STATUS_CODE``
    (100-599) range.

    Args:
        include: The raw include selection, or ``None``/empty for no include
            restriction.
        exclude: The raw exclude selection, or ``None``/empty for no exclude
            restriction.

    Returns:
        The parsed :class:`StorageStatusSelection`.

    Raises:
        StorageStatusError: If a value is an explicit code outside 100-599 or a
            token that is neither a class nor a code; the message names the
            offending value (Requirement 33.9).
    """

    def _parse_one(raw: Optional[str]) -> Optional[StatusFilter]:
        if raw is None:
            return None
        try:
            status_filter = parse_status_filter(raw)
        except ValueError as exc:
            # Out-of-range explicit code (e.g. "600", "99"): parse_status_filter
            # raises ValueError naming the offending code (Requirement 33.9).
            raise StorageStatusError(
                f"invalid status value '{raw}': {exc} "
                f"(expected a status class like '2xx' or codes in "
                f"{MIN_STATUS_CODE}-{MAX_STATUS_CODE})"
            ) from exc

        # A token that is neither a Status_Code_Class nor any recognizable
        # explicit code parses to an explicit-code filter with an empty set
        # (parse_status_codes ignores unparseable tokens). Reject it explicitly
        # so an unrecognized token never silently admits/excludes nothing
        # (Requirement 33.9).
        if (
            status_filter is not None
            and status_filter.status_class is None
            and not status_filter.codes
        ):
            raise StorageStatusError(
                f"invalid status value '{raw}': not a status class "
                f"(e.g. '2xx') or an explicit status code in "
                f"{MIN_STATUS_CODE}-{MAX_STATUS_CODE}"
            )
        return status_filter

    return StorageStatusSelection(
        include=_parse_one(include),
        exclude=_parse_one(exclude),
    )


# The endpoint types a Recursion_Scope may select (Requirement 34.2). These mirror
# the user-selectable ``Endpoint.endpoint_type`` values; internal classifications
# such as ``method_not_allowed`` are intentionally not selectable here.
VALID_ENDPOINT_TYPES = frozenset(
    {"admin", "api_version", "authentication", "development", "standard"}
)


class RecursionScopeError(Exception):
    """Raised when a ``--recursion-status``/``--recursion-type`` value names an
    unrecognized status class or endpoint type (Requirement 34.8)."""


@dataclass(frozen=True)
class RecursionScope:
    """Optional restrictions on which records recursion descends into (``Recursion_Scope``).

    Two independent dimensions narrow the recursable set: the discovered status
    class (computed via :func:`~utils.discovery_session.status_code_class`) and
    the ``Endpoint.endpoint_type``. An EMPTY frozenset on a dimension means "no
    restriction on that dimension" (Requirements 34.1, 34.2). This rule only ever
    *narrows* the default recursion eligibility; it never relaxes it
    (Requirements 34.3, 34.9).
    """

    status_classes: FrozenSet[str] = frozenset()
    endpoint_types: FrozenSet[str] = frozenset()

    def admits(self, endpoint) -> bool:
        """Return whether ``endpoint`` satisfies EVERY supplied selection.

        A dimension with a non-empty set requires the endpoint to match it: the
        status class of ``endpoint.status_code`` must be in ``status_classes``
        (when that set is non-empty) AND ``endpoint.endpoint_type`` must be in
        ``endpoint_types`` (when that set is non-empty). A dimension with an empty
        set imposes no restriction. An endpoint whose status code has no class
        (leading digit not in 2-5) is rejected whenever ``status_classes`` is
        non-empty.

        Args:
            endpoint: A discovered endpoint exposing ``status_code`` and
                ``endpoint_type``.

        Returns:
            ``True`` iff the endpoint satisfies every supplied selection.
        """
        if self.status_classes:
            status_class = status_code_class(endpoint.status_code)
            if status_class is None or status_class not in self.status_classes:
                return False
        if self.endpoint_types:
            if endpoint.endpoint_type not in self.endpoint_types:
                return False
        return True


def parse_recursion_scope(
    status_csv: Optional[str],
    type_csv: Optional[str],
) -> RecursionScope:
    """Parse ``--recursion-status`` / ``--recursion-type`` into a :class:`RecursionScope`.

    ``status_csv`` is a comma-separated list of :data:`~utils.discovery_session.STATUS_CLASSES`
    tokens (``"2xx".."5xx"``, case-insensitive) and ``type_csv`` is a
    comma-separated list of :data:`VALID_ENDPOINT_TYPES` values. Empty/whitespace
    tokens are ignored, and a ``None``/empty value leaves that dimension
    unrestricted.

    Args:
        status_csv: The raw status-class selection, or ``None``/empty for no
            status restriction.
        type_csv: The raw endpoint-type selection, or ``None``/empty for no type
            restriction.

    Returns:
        The parsed :class:`RecursionScope`.

    Raises:
        RecursionScopeError: If a status token is not a recognized
            ``Status_Code_Class`` or an endpoint type is not in
            :data:`VALID_ENDPOINT_TYPES`; the message names the offending value
            (Requirement 34.8).
    """

    def _tokens(raw: Optional[str]):
        if raw is None:
            return []
        return [token.strip() for token in raw.split(",") if token.strip()]

    status_classes = set()
    for token in _tokens(status_csv):
        normalized = token.lower()
        if normalized not in STATUS_CLASSES:
            raise RecursionScopeError(
                f"invalid recursion status class '{token}': "
                f"expected one of {', '.join(STATUS_CLASSES)}"
            )
        status_classes.add(normalized)

    endpoint_types = set()
    for token in _tokens(type_csv):
        if token not in VALID_ENDPOINT_TYPES:
            raise RecursionScopeError(
                f"invalid recursion endpoint type '{token}': "
                f"expected one of {', '.join(sorted(VALID_ENDPOINT_TYPES))}"
            )
        endpoint_types.add(token)

    return RecursionScope(
        status_classes=frozenset(status_classes),
        endpoint_types=frozenset(endpoint_types),
    )
