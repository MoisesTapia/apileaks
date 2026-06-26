"""
Discovery Session model and persistence.

This module defines the in-memory data model for interactive discovery triage
(:class:`DiscoveryResult`) and the persistent session artifact
(:class:`DiscoverySession`).

The session file is the *source of truth* for reload: ``save`` serializes every
discovered record to JSON and ``load`` reconstructs the records exclusively from
that JSON file. Writes are atomic (temp-file-then-``os.replace``) so a failure
never leaves a partially written session file behind (Requirement 14.2), and
reload errors are explicit and distinct: a missing path raises a descriptive
"file not found" error (Requirement 14.9) while unparseable or wrong-structure
JSON raises a descriptive "invalid session file" error and loads zero records
(Requirement 14.10).
"""

import json
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional

from core.logging import get_logger

logger = get_logger(__name__)

# Version of the on-disk session file schema. Bumped if the JSON shape changes.
SCHEMA_VERSION = 1

# The four HTTP status-code classes, in fixed ascending order by leading digit
# (Requirements 13.1, 13.4). Grouping always exposes exactly these four keys.
STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx")

# Inclusive bounds for explicit status codes accepted by a status filter
# (Requirement 13.6). Values outside this range are rejected by name.
MIN_STATUS_CODE = 100
MAX_STATUS_CODE = 599


class DiscoverySessionError(Exception):
    """Base class for discovery-session persistence errors."""


class DiscoverySessionWriteError(DiscoverySessionError):
    """Raised when a session file cannot be written (Requirement 14.2)."""


class DiscoverySessionNotFoundError(DiscoverySessionError):
    """Raised when a session file path does not exist (Requirement 14.9)."""


class InvalidSessionFileError(DiscoverySessionError):
    """Raised when a session file is unparseable or malformed (Requirement 14.10)."""


@dataclass(frozen=True)
class DiscoveryResult:
    """A single discovered endpoint projected for triage.

    This is a lossless, JSON-native projection of a discovered
    :class:`~modules.fuzzing.orchestrator.Endpoint`. ``endpoint_status`` stores
    the :class:`EndpointStatus` enum's string value (the enum subclasses
    ``str``), so the projection preserves the classification and is directly
    serializable.
    """

    url: str            # endpoint URL
    method: str         # HTTP method
    status_code: int    # raw HTTP status code
    endpoint_status: str  # EndpointStatus value, e.g. "valid", "auth_required", "redirect"

    @classmethod
    def from_endpoint(cls, endpoint) -> "DiscoveryResult":
        """Project an :class:`Endpoint` into a :class:`DiscoveryResult`.

        The projection is lossless for the four triage fields: ``url``,
        ``method``, and ``status_code`` are copied directly and
        ``endpoint_status`` stores ``endpoint.status.value`` (the JSON-native
        string value of the :class:`EndpointStatus` enum).

        Args:
            endpoint: A discovered endpoint exposing ``url``, ``method``,
                ``status_code`` and a ``status`` :class:`EndpointStatus`.

        Returns:
            The corresponding :class:`DiscoveryResult`.
        """
        return cls(
            url=endpoint.url,
            method=endpoint.method,
            status_code=endpoint.status_code,
            endpoint_status=endpoint.status.value,
        )

    def to_dict(self) -> dict:
        """Serialize this record to a JSON-native dict."""
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "endpoint_status": self.endpoint_status,
        }

    @classmethod
    def from_dict(cls, data) -> "DiscoveryResult":
        """Reconstruct a :class:`DiscoveryResult` from a parsed JSON object.

        Args:
            data: A mapping that must contain the four ``DiscoveryResult`` keys
                with correct types (``url``/``method``/``endpoint_status`` as
                strings and ``status_code`` as an integer).

        Returns:
            The reconstructed :class:`DiscoveryResult`.

        Raises:
            InvalidSessionFileError: If ``data`` is not a mapping or any field is
                missing or of the wrong type.
        """
        if not isinstance(data, dict):
            raise InvalidSessionFileError(
                "invalid session file: each result must be a JSON object"
            )

        # bool is a subclass of int; reject it explicitly so a JSON ``true`` is
        # not silently accepted as a status code.
        status_code = data.get("status_code")
        if not isinstance(status_code, int) or isinstance(status_code, bool):
            raise InvalidSessionFileError(
                "invalid session file: 'status_code' must be an integer"
            )

        for key in ("url", "method", "endpoint_status"):
            if not isinstance(data.get(key), str):
                raise InvalidSessionFileError(
                    f"invalid session file: '{key}' must be a string"
                )

        return cls(
            url=data["url"],
            method=data["method"],
            status_code=status_code,
            endpoint_status=data["endpoint_status"],
        )


@dataclass
class DiscoverySession:
    """A persisted discovery session: metadata plus the ordered records.

    The session file produced by :meth:`save` is the source-of-truth artifact
    used for reload by :meth:`load`; the human-readable export is never read
    back.
    """

    target: str
    timestamp: str
    tool_version: str
    results: List[DiscoveryResult] = field(default_factory=list)

    def save(self, path: str) -> None:
        """Atomically write the session to ``path`` as JSON.

        Every record is serialized (Requirement 14.1). The write is atomic: the
        document is written to a temporary file in the same directory and then
        moved into place with :func:`os.replace`, so a failure mid-write never
        leaves a partial session file (Requirement 14.2).

        Args:
            path: Destination path for the session JSON file.

        Raises:
            DiscoverySessionWriteError: If the file cannot be written. The
                underlying :class:`OSError` is wrapped with a descriptive
                message and any temporary file is removed.
        """
        document = {
            "schema_version": SCHEMA_VERSION,
            "target": self.target,
            "timestamp": self.timestamp,
            "tool_version": self.tool_version,
            "results": [result.to_dict() for result in self.results],
        }

        directory = os.path.dirname(os.path.abspath(path))
        tmp_path = f"{path}.tmp"
        try:
            os.makedirs(directory, exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
            os.replace(tmp_path, path)
        except OSError as exc:
            # Clean up the partial temp file so no partially written session
            # artifact remains (Requirement 14.2).
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            raise DiscoverySessionWriteError(
                f"failed to write discovery session file '{path}': {exc}"
            ) from exc

        logger.info(
            "Discovery session saved",
            path=path,
            records=len(self.results),
        )

    @classmethod
    def load(cls, path: str) -> "DiscoverySession":
        """Load a discovery session from its JSON session file.

        The JSON session file is the sole source of truth: records are read only
        from this file's ``results`` array. The top-level object must contain a
        ``results`` array whose every element carries the four
        :class:`DiscoveryResult` keys with correct types. An empty
        ``results: []`` is valid and yields an empty session (Requirement 14.8).

        Args:
            path: Path to the session JSON file.

        Returns:
            The reconstructed :class:`DiscoverySession`.

        Raises:
            DiscoverySessionNotFoundError: If ``path`` does not exist
                (Requirement 14.9).
            InvalidSessionFileError: If the file is not valid JSON or does not
                match the expected ``DiscoveryResult`` structure; zero records
                are loaded in this case (Requirement 14.10).
        """
        if not path or not os.path.exists(path):
            raise DiscoverySessionNotFoundError(
                f"discovery session file not found: '{path}'"
            )

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise InvalidSessionFileError(
                f"invalid session file '{path}': not valid JSON ({exc})"
            ) from exc

        if not isinstance(data, dict):
            raise InvalidSessionFileError(
                f"invalid session file '{path}': top-level value must be an object"
            )

        raw_results = data.get("results")
        if not isinstance(raw_results, list):
            raise InvalidSessionFileError(
                f"invalid session file '{path}': missing 'results' array"
            )

        results = [DiscoveryResult.from_dict(entry) for entry in raw_results]

        session = cls(
            target=data.get("target", "") if isinstance(data.get("target"), str) else "",
            timestamp=data.get("timestamp", "") if isinstance(data.get("timestamp"), str) else "",
            tool_version=data.get("tool_version", "")
            if isinstance(data.get("tool_version"), str)
            else "",
            results=results,
        )

        logger.info(
            "Discovery session loaded",
            path=path,
            records=len(results),
        )
        return session


def status_code_class(code: int) -> Optional[str]:
    """Return the :data:`STATUS_CLASSES` token for an HTTP status code.

    Assignment uses the leading digit of ``code`` (Requirement 13.2): a leading
    digit of 2, 3, 4 or 5 maps to ``"2xx".."5xx"`` respectively. Any other
    leading digit (for example a 1xx code) yields ``None``, which excludes the
    record from every group (Requirement 13.3).

    Args:
        code: An HTTP status code.

    Returns:
        The ``"2xx".."5xx"`` class token, or ``None`` when the leading digit is
        not in 2-5.
    """
    lead = code // 100
    return f"{lead}xx" if lead in (2, 3, 4, 5) else None


def group_by_status_class(
    records: List[DiscoveryResult],
) -> "OrderedDict[str, List[DiscoveryResult]]":
    """Group discovery records into the four status classes in ascending order.

    The returned mapping always contains exactly the four keys in
    :data:`STATUS_CLASSES` (``2xx, 3xx, 4xx, 5xx``) in that fixed ascending
    order, each mapping to a (possibly empty) list (Requirements 13.1, 13.4). A
    non-matching set of records therefore still yields four empty groups
    (Requirement 13.9). Records whose leading digit is not 2-5 are excluded from
    every group (Requirement 13.3).

    Args:
        records: The discovery records to group.

    Returns:
        An :class:`~collections.OrderedDict` keyed by status class, preserving
        the relative order of ``records`` within each group.
    """
    grouped: "OrderedDict[str, List[DiscoveryResult]]" = OrderedDict(
        (status_class, []) for status_class in STATUS_CLASSES
    )
    for record in records:
        status_class = status_code_class(record.status_code)
        if status_class is not None:
            grouped[status_class].append(record)
    return grouped


@dataclass(frozen=True)
class StatusFilter:
    """A parsed status filter: either a class token or explicit codes.

    Exactly one of the two fields is populated. ``status_class`` carries a single
    :data:`STATUS_CLASSES` token (class filter, Requirement 13.7); ``codes``
    carries the set of explicit status codes to match exactly (explicit filter,
    Requirement 13.8).
    """

    status_class: Optional[str] = None
    codes: Optional[FrozenSet[int]] = None


def parse_status_filter(raw: str) -> Optional[StatusFilter]:
    """Parse a raw status-filter string into a :class:`StatusFilter`.

    A value equal to one of the :data:`STATUS_CLASSES` tokens (case-insensitive,
    e.g. ``"2xx"``) is interpreted as a class filter (Requirement 13.7).
    Otherwise the value is parsed as explicit codes/ranges via the existing
    ``parse_status_codes`` (e.g. ``"200,404"`` or ``"200-300"``); every resulting
    code is validated to the inclusive range 100-599 and an out-of-range value
    raises :class:`ValueError` naming the offending value (Requirements 13.5,
    13.6).

    Args:
        raw: The raw filter string (typically from the ``--status-code`` flag).

    Returns:
        A :class:`StatusFilter`, or ``None`` when ``raw`` is empty/``None``
        (meaning no filtering).

    Raises:
        ValueError: If an explicit code is outside the inclusive range 100-599.
    """
    if not raw or not raw.strip():
        return None

    token = raw.strip()
    if token.lower() in STATUS_CLASSES:
        return StatusFilter(status_class=token.lower())

    # Reuse the existing CLI parser for explicit codes/ranges. Imported lazily to
    # avoid a circular import (apileaks.py imports the utils package).
    from apileaks import parse_status_codes

    codes = parse_status_codes(token)
    for code in codes:
        if code < MIN_STATUS_CODE or code > MAX_STATUS_CODE:
            raise ValueError(
                f"status code {code} is out of range "
                f"({MIN_STATUS_CODE}-{MAX_STATUS_CODE})"
            )
    return StatusFilter(codes=frozenset(codes))


def apply_status_filter(
    records: List[DiscoveryResult],
    status_filter: Optional[StatusFilter],
) -> List[DiscoveryResult]:
    """Retain only the records matching ``status_filter``.

    A class filter retains records whose status code shares the leading digit of
    the class (Requirement 13.7); an explicit-code filter retains records whose
    status code is exactly in the filter's set (Requirement 13.8). A ``None``
    filter retains every record. Relative order is preserved.

    Args:
        records: The discovery records to filter.
        status_filter: The parsed filter, or ``None`` for no filtering.

    Returns:
        The retained records, in their original relative order.
    """
    if status_filter is None:
        return list(records)

    if status_filter.status_class is not None:
        return [
            record
            for record in records
            if status_code_class(record.status_code) == status_filter.status_class
        ]

    codes = status_filter.codes or frozenset()
    return [record for record in records if record.status_code in codes]
