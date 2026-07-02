"""
Positional Fuzz Markers

Pure functions and data models for ffuf/wfuzz-style positional fuzzing in the
``dir`` command. A Fuzz_Keyword (default ``FUZZ``) is placed literally inside a
target URL; each literal occurrence defines one Marker_Position that the
discovery engine sweeps with candidate values.

This module is intentionally free of I/O and network concerns: it only detects
markers, validates the keyword, and classifies the URL region a marker falls in
(informational only). Substitution, wordlist association, and candidate
generation are added by sibling tasks in this same module.

Requirements: 39.2, 39.3, 39.4, 39.5 (marker detection, keyword validation, and
region classification).
"""

import itertools
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
from typing import Iterator, List, Optional, Sequence

# One of the informational region labels below. Classification never affects
# substitution, which is purely span-based (Requirement 40.1).
MarkerRegion = str  # "path-substring" | "full-segment" | "query-name"
#                   | "query-value" | "filename" | "extension"

REGION_PATH_SUBSTRING: MarkerRegion = "path-substring"
REGION_FULL_SEGMENT: MarkerRegion = "full-segment"
REGION_QUERY_NAME: MarkerRegion = "query-name"
REGION_QUERY_VALUE: MarkerRegion = "query-value"
REGION_FILENAME: MarkerRegion = "filename"
REGION_EXTENSION: MarkerRegion = "extension"


@dataclass(frozen=True)
class MarkerPosition:
    """One literal Fuzz_Keyword occurrence in the raw target URL.

    ``start``/``end`` are character offsets into the raw URL string such that
    ``url[start:end] == keyword``. ``region`` is the classified URL area the
    marker falls in (informational; substitution is span-based and
    region-independent). ``order`` is the left-to-right index (0-based) of this
    marker, used to pair it with its Marker_Wordlist (Requirement 44.1).

    The dataclass is frozen and therefore hashable, so generated candidate sets
    and marker lists are easy to compare in property tests.
    """

    start: int
    end: int
    region: MarkerRegion
    order: int


def validate_fuzz_keyword(keyword: str) -> str:
    """Return the keyword unchanged if valid.

    Raise ``ValueError`` naming the invalid keyword when it is empty or
    whitespace-only (Requirement 39.5). The keyword is always treated as a
    plain literal; it is never interpreted as a regular expression.
    """
    if keyword is None or keyword.strip() == "":
        raise ValueError(
            f"Invalid Fuzz_Keyword {keyword!r}: the fuzz keyword must not be "
            "empty or whitespace-only"
        )
    return keyword


def find_markers(url: str, keyword: str = "FUZZ") -> List[MarkerPosition]:
    """Return one :class:`MarkerPosition` per NON-OVERLAPPING literal occurrence
    of ``keyword`` in ``url``, scanned left-to-right (Requirements 39.2, 39.4).

    Matching uses :meth:`str.find` (a plain literal search, never a regex).
    Each match advances the scan cursor by ``len(keyword)`` so occurrences never
    overlap. Returns ``[]`` when the keyword does not occur (Requirement 39.3).

    ``region`` on each marker is filled by :func:`classify_marker_region`.
    """
    markers: List[MarkerPosition] = []

    # Guard against a zero-length keyword, which would otherwise loop forever.
    # The CLI validates the keyword via validate_fuzz_keyword before discovery,
    # so this is a defensive no-op for valid callers.
    if not keyword:
        return markers

    cursor = 0
    order = 0
    while True:
        idx = url.find(keyword, cursor)
        if idx == -1:
            break
        start = idx
        end = idx + len(keyword)
        region = classify_marker_region(url, start, end)
        markers.append(
            MarkerPosition(start=start, end=end, region=region, order=order)
        )
        order += 1
        cursor = end  # advance past the whole match => non-overlapping
    return markers


def substitute_markers(
    url: str, markers: List[MarkerPosition], values: List[str]
) -> str:
    """Return ``url`` with each marked span replaced by its paired candidate
    value, preserving every other byte of the target URL (Requirement 40.1).

    ``markers[i]`` is paired with ``values[i]``: the span ``url[start:end]`` of
    each marker is spliced out and the corresponding value inserted in its
    place. Substitution is purely span-based on the raw URL string and never
    consults the marker's ``region`` classification, so every other character,
    path segment, query-parameter name, and query-parameter value is preserved
    byte-for-byte (Requirements 40.2-40.7).

    To keep every marker's ``start``/``end`` offsets valid while splicing, the
    replacements are applied right-to-left (markers sorted by ``start``
    descending); editing a later span never shifts the offsets of an earlier
    one.

    When ``markers`` is empty the target URL is returned unchanged
    (Requirement 40.8). ``len(values)`` must equal ``len(markers)``; a mismatch
    raises ``ValueError`` naming both counts.
    """
    if not markers:
        # No Fuzz_Marker present => return the target URL untouched (40.8).
        return url

    if len(values) != len(markers):
        raise ValueError(
            f"Marker/value count mismatch: {len(markers)} marker(s) but "
            f"{len(values)} value(s); each marker must be paired with exactly "
            "one value"
        )

    # Pair markers with their values, then splice right-to-left so earlier
    # spans keep their original offsets as later spans are replaced.
    paired = sorted(zip(markers, values), key=lambda mv: mv[0].start, reverse=True)

    result = url
    for marker, value in paired:
        result = result[: marker.start] + value + result[marker.end :]
    return result


def _path_bounds(url: str) -> "tuple[int, int]":
    """Return the ``[start, end)`` char offsets of the path component of ``url``.

    The path begins after any ``scheme://netloc`` prefix and ends at the first
    ``?`` (query) or ``#`` (fragment). Works for absolute URLs
    (``https://host/p``) and relative ones (``/p``).
    """
    scheme_sep = url.find("://")
    if scheme_sep != -1:
        cursor = scheme_sep + 3
        # The netloc runs until the first '/', '?', or '#' after '://'.
        netloc_end = len(url)
        for ch in ("/", "?", "#"):
            i = url.find(ch, cursor)
            if i != -1:
                netloc_end = min(netloc_end, i)
        path_start = netloc_end
    else:
        path_start = 0

    path_end = len(url)
    for ch in ("?", "#"):
        i = url.find(ch, path_start)
        if i != -1:
            path_end = min(path_end, i)
    return path_start, path_end


def _classify_query_region(url: str, start: int, end: int, q_index: int) -> MarkerRegion:
    """Classify a span that falls inside the query component as a parameter name
    or value by locating the enclosing ``name=value`` pair.
    """
    query_start = q_index + 1
    frag = url.find("#", query_start)
    query_end = frag if frag != -1 else len(url)

    pos = query_start
    while pos < query_end:
        amp = url.find("&", pos)
        pend = amp if (amp != -1 and amp < query_end) else query_end
        if start >= pos and end <= pend:
            eq = url.find("=", pos)
            if eq == -1 or eq >= pend:
                # No value delimiter => the whole token is a parameter name.
                return REGION_QUERY_NAME
            if end <= eq:
                return REGION_QUERY_NAME
            if start >= eq + 1:
                return REGION_QUERY_VALUE
            # Span straddles the '=' delimiter; treat it as a value edit.
            return REGION_QUERY_VALUE
        pos = pend + 1

    # Fallback: span is after '?' but not matched to a pair (unusual input).
    return REGION_QUERY_VALUE


def classify_marker_region(url: str, start: int, end: int) -> MarkerRegion:
    """Classify the URL area a marked span ``[start:end)`` falls in.

    Uses :func:`urllib.parse.urlparse` to locate the path vs. query, splits the
    path on ``'/'``, and splits the final path segment on the last ``'.'`` to
    distinguish a filename from an extension:

    - ``query-name``    : span is within a key of the query component
    - ``query-value``   : span is within a value of the query component
    - ``extension``     : span is within the substring after the last ``'.'`` of
                          the final path segment
    - ``filename``      : span is within the final path segment, before any
                          ``'.'``
    - ``full-segment``  : span exactly equals a whole path segment
    - ``path-substring``: span is a proper substring inside a path segment

    Classification is informational only; substitution never depends on it.
    """
    # urlparse is used to confirm the component split; the char offsets are
    # computed directly so they stay aligned with the raw URL string.
    urlparse(url)

    q_index = url.find("?")
    if q_index != -1 and start > q_index:
        return _classify_query_region(url, start, end, q_index)

    path_start, path_end = _path_bounds(url)

    # Split the path into segments, tracking each segment's [start, end) offsets.
    segments: List["tuple[int, int]"] = []
    pos = path_start
    while pos <= path_end:
        slash = url.find("/", pos)
        seg_end = slash if (slash != -1 and slash < path_end) else path_end
        segments.append((pos, seg_end))
        if seg_end >= path_end:
            break
        pos = seg_end + 1

    # The "final path segment" is the last non-empty segment (ignoring a
    # trailing slash's empty tail).
    final_index = -1
    for i, (s_start, s_end) in enumerate(segments):
        if s_end > s_start:
            final_index = i

    for i, (s_start, s_end) in enumerate(segments):
        if start >= s_start and end <= s_end:
            if start == s_start and end == s_end:
                return REGION_FULL_SEGMENT
            if i == final_index:
                last_dot = url.rfind(".", s_start, s_end)
                if last_dot != -1:
                    if start >= last_dot + 1 and end <= s_end:
                        return REGION_EXTENSION
                    if end <= last_dot:
                        return REGION_FILENAME
                    # Span straddles the '.'; not cleanly filename or extension.
                    return REGION_PATH_SUBSTRING
                # No extension delimiter: the whole segment is the filename.
                return REGION_FILENAME
            return REGION_PATH_SUBSTRING

    # Span not contained in a single path segment (e.g. it straddles a '/', or
    # lies in the netloc). Report it as a generic path substring.
    return REGION_PATH_SUBSTRING


def associate_wordlists(
    markers: Sequence[MarkerPosition],
    wordlists: Sequence[Sequence[str]],
) -> List[List[str]]:
    """Pair Marker_Wordlists with Marker_Positions in left-to-right marker order.

    ``markers`` already carry their 0-based ``order``; the i-th supplied wordlist
    is the Marker_Wordlist of the i-th marker (Requirement 44.1). The returned
    list has exactly ``len(markers)`` entries, one per Marker_Position, each entry
    being the resolved Marker_Wordlist for that position (materialized as a
    ``list``).

    Fallbacks (fewer wordlists than markers):

    - ``len(wordlists) == 1`` and ``len(markers) >= 2`` => that single wordlist is
      used as the Marker_Wordlist of every Marker_Position (Requirement 44.3).
    - ``1 < len(wordlists) < len(markers)`` => the LAST supplied wordlist fills
      every remaining Marker_Position that has no explicitly associated wordlist
      (Requirement 44.2).

    Error (surfaced later as exit-before-discovery):

    - ``len(wordlists) > len(markers)`` => raise ``ValueError`` naming both the
      wordlist count and the Marker_Position count (Requirement 44.4).

    When ``markers`` is empty the result is ``[]`` (there are no positions to
    associate). When at least one marker is present, at least one wordlist must be
    supplied so a Marker_Wordlist can be resolved for every position; supplying
    none raises ``ValueError`` naming both counts.
    """
    n_markers = len(markers)
    n_wordlists = len(wordlists)

    if n_wordlists > n_markers:
        raise ValueError(
            f"Wordlist/marker count mismatch: {n_wordlists} wordlist(s) supplied "
            f"but the target URL contains {n_markers} marker position(s); supply "
            "at most one wordlist per marker position"
        )

    if n_markers == 0:
        # No Marker_Positions => nothing to associate.
        return []

    if n_wordlists == 0:
        # At least one marker but no wordlist => no list can be resolved for any
        # position; report the mismatch by naming both counts.
        raise ValueError(
            f"Wordlist/marker count mismatch: 0 wordlist(s) supplied but the "
            f"target URL contains {n_markers} marker position(s); supply at least "
            "one wordlist"
        )

    # Fewer-or-equal wordlists than markers: pair by index and fill any remaining
    # positions with the last supplied wordlist (covers the single-list case,
    # Requirements 44.2 and 44.3).
    associated: List[List[str]] = []
    for i in range(n_markers):
        source = wordlists[i] if i < n_wordlists else wordlists[-1]
        associated.append(list(source))
    return associated


class FuzzMode(str, Enum):
    """The strategy used to combine the Marker_Wordlists of two or more
    Marker_Positions into the set of generated candidate URLs.

    ``CLUSTERBOMB`` (the default Fuzz_Mode) takes the cartesian product of the
    Marker_Wordlists across all Marker_Positions, so that every combination of
    one value per Marker_Position becomes a distinct candidate URL
    (Requirement 42). ``PITCHFORK`` iterates the Marker_Wordlists in parallel,
    pairing the i-th value of each list together and stopping at the length of
    the shortest list (Requirement 43).

    Subclassing ``str`` keeps ``.value`` JSON/config-native, matching the
    ``EndpointStatus`` convention already used in this codebase.
    """

    CLUSTERBOMB = "clusterbomb"  # default Fuzz_Mode
    PITCHFORK = "pitchfork"


def parse_fuzz_mode(raw: Optional[str]) -> FuzzMode:
    """Map a CLI token to a :class:`FuzzMode` (case-insensitive).

    ``None`` or an absent value resolves to :attr:`FuzzMode.CLUSTERBOMB`, the
    default Fuzz_Mode (Requirement 43.1). Any value other than a recognized
    ``clusterbomb``/``pitchfork`` selector raises ``ValueError`` naming the
    invalid mode so the Dir_Command can fail before discovery
    (Requirement 46.5).
    """
    if raw is None:
        return FuzzMode.CLUSTERBOMB

    token = raw.strip().lower()
    for mode in FuzzMode:
        if mode.value == token:
            return mode

    valid = ", ".join(m.value for m in FuzzMode)
    raise ValueError(
        f"Invalid Fuzz_Mode {raw!r}: expected one of {valid}"
    )


def generate_marker_candidates(
    url: str,
    markers: Sequence[MarkerPosition],
    wordlists: Sequence[Sequence[str]],
    mode: FuzzMode,
) -> Iterator[str]:
    """Yield candidate URLs by substituting values at every Marker_Position.

    ``wordlists[i]`` is the Marker_Wordlist for ``markers[i]`` (as resolved by
    :func:`associate_wordlists`). Generation is lazy: candidates are produced one
    at a time so a downstream Request_Budget cut-off can stop pulling from this
    iterator and terminate discovery gracefully (Requirements 42.3, 42.4, 43.4).

    - :attr:`FuzzMode.CLUSTERBOMB` iterates ``itertools.product(*wordlists)``:
      each tuple is one value per Marker_Position, yielding the cartesian product
      across all markers. The number of candidates equals the product of the
      wordlist sizes ``W1 x ... x WM`` (Requirements 42.1, 42.2, 42.5). A single
      marker reduces to exactly ``W`` candidates (Requirements 41.1, 41.2).
    - :attr:`FuzzMode.PITCHFORK` iterates ``zip(*wordlists)``: the i-th entry of
      each list is paired together, stopping at the shortest list. The number of
      candidates equals ``min(W1, ..., WM)`` (Requirements 43.2, 43.3, 43.5).

    Each combination tuple is applied via :func:`substitute_markers`, so every
    non-marked byte of the target URL is preserved (Requirement 40.1).
    """
    if mode == FuzzMode.PITCHFORK:
        combinations = zip(*wordlists)
    else:
        combinations = itertools.product(*wordlists)

    for combo in combinations:
        yield substitute_markers(url, list(markers), list(combo))
