"""
Machine-readable discovery output.

This module serializes a set of
:class:`~utils.discovery_session.DiscoveryResult` records into a
machine-readable ``Discovery_Output_File`` in either CSV (``.csv``) or JSON
Lines (``.jsonl``) format (Requirement 31.1). The selected format is determined
by the file extension of the destination path.

Records are emitted ordered consistently with the interactive triage table
grouping: the records belonging to a ``Status_Code_Class`` are written first in
ascending class order (``2xx, 3xx, 4xx, 5xx``), reusing
:func:`~utils.discovery_session.group_by_status_class` so the output and the
triage table never diverge (Requirement 31.2). Records whose status code does
not fall into any ``2xx``-``5xx`` class (for example a ``1xx`` code) are not
dropped: they are appended after the grouped records in their original, stable
relative order so that every input record is written exactly once.

Any requested output format other than ``.csv`` or ``.jsonl`` raises a
descriptive :class:`UnsupportedOutputFormatError` and writes nothing: no
``Discovery_Output_File`` is created on disk (Requirement 31.4). An
:class:`OSError` encountered while writing is wrapped in a descriptive
:class:`DiscoveryOutputError` naming the destination path (Requirement 31.5).
"""

import csv
import json
import os
from typing import List

from core.logging import get_logger

from utils.discovery_session import (
    DiscoveryResult,
    group_by_status_class,
    status_code_class,
)

logger = get_logger(__name__)

# File extensions for the two supported machine-readable output formats
# (Requirement 31.1). Any other extension is rejected (Requirement 31.4).
CSV_EXTENSION = ".csv"
JSONL_EXTENSION = ".jsonl"
SUPPORTED_OUTPUT_FORMATS = (CSV_EXTENSION, JSONL_EXTENSION)

# Column order for the CSV output. Mirrors the ``DiscoveryResult`` fields.
CSV_FIELDNAMES = ("url", "method", "status_code", "endpoint_status")


class DiscoveryOutputError(Exception):
    """Base class for discovery-output errors."""


class UnsupportedOutputFormatError(DiscoveryOutputError):
    """Raised when an unsupported output format is requested (Requirement 31.4)."""


def _format_extension(path: str) -> str:
    """Return the lower-cased file extension of ``path`` (including the dot)."""
    return os.path.splitext(path)[1].lower()


def _order_records(records: List[DiscoveryResult]) -> List[DiscoveryResult]:
    """Order records for output: grouped ``2xx``-``5xx`` first, others appended.

    The records assigned to a status class are emitted in ascending class order
    (``2xx, 3xx, 4xx, 5xx``) using
    :func:`~utils.discovery_session.group_by_status_class`, keeping the output
    consistent with the triage table (Requirement 31.2). Records whose status
    code maps to no class (``status_code_class`` returns ``None``, e.g. ``1xx``)
    are then appended in their original, stable relative order so no input
    record is lost. Every input record appears exactly once.

    Args:
        records: The discovery records to order.

    Returns:
        A new list containing every input record exactly once, grouped records
        first and unclassified records last.
    """
    grouped = group_by_status_class(records)
    ordered: List[DiscoveryResult] = []
    for status_records in grouped.values():
        ordered.extend(status_records)
    # Append records excluded from every status class (Requirement 31.2 note):
    # they must still survive the round-trip even though they are unclassified.
    ordered.extend(
        record
        for record in records
        if status_code_class(record.status_code) is None
    )
    return ordered


def write_discovery_output(records: List[DiscoveryResult], path: str) -> None:
    """Write a machine-readable discovery output to ``path``.

    The output format is selected from the file extension of ``path``: ``.csv``
    produces a CSV document (a header row followed by one row per record) and
    ``.jsonl`` produces a JSON Lines document (one JSON object per line)
    (Requirement 31.1). In both formats records are ordered consistently with
    the triage-table grouping (ascending ``2xx, 3xx, 4xx, 5xx``) with any
    unclassified records appended afterwards in stable order, so every input
    record is written exactly once (Requirement 31.2).

    Both formats preserve unicode URLs and special characters: the CSV writer
    uses :data:`csv.QUOTE_MINIMAL` quoting so embedded delimiters and newlines
    round-trip, and the JSON Lines writer uses ``ensure_ascii=False`` so unicode
    characters are written verbatim.

    Args:
        records: The discovery records to serialize.
        path: Destination path whose extension (``.csv`` or ``.jsonl``) selects
            the format.

    Raises:
        UnsupportedOutputFormatError: If ``path`` does not end in ``.csv`` or
            ``.jsonl``. No file is written in this case (Requirement 31.4).
        DiscoveryOutputError: If the file cannot be written. The underlying
            :class:`OSError` is wrapped with a descriptive message naming the
            path (Requirement 31.5).
    """
    extension = _format_extension(path)
    if extension not in SUPPORTED_OUTPUT_FORMATS:
        # Reject before touching the filesystem so nothing is written
        # (Requirement 31.4).
        raise UnsupportedOutputFormatError(
            f"unsupported output format '{extension or path}': supported formats "
            f"are {CSV_EXTENSION} and {JSONL_EXTENSION}"
        )

    ordered = _order_records(records)

    try:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        if extension == CSV_EXTENSION:
            # newline="" is required so the csv module controls line endings and
            # quoted fields containing newlines round-trip correctly.
            with open(path, "w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle, quoting=csv.QUOTE_MINIMAL)
                writer.writerow(CSV_FIELDNAMES)
                for record in ordered:
                    writer.writerow(
                        [
                            record.url,
                            record.method,
                            record.status_code,
                            record.endpoint_status,
                        ]
                    )
        else:
            with open(path, "w", encoding="utf-8") as handle:
                for record in ordered:
                    handle.write(
                        json.dumps(record.to_dict(), ensure_ascii=False)
                    )
                    handle.write("\n")
    except OSError as exc:
        raise DiscoveryOutputError(
            f"failed to write discovery output file '{path}': {exc}"
        ) from exc

    logger.info(
        "Discovery output written",
        path=path,
        format=extension,
        records=len(ordered),
    )
