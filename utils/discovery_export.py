"""
Human-readable discovery export.

This module renders a set of :class:`~utils.discovery_session.DiscoveryResult`
records into a human-readable ``Discovery_Export_File`` in either Markdown
(``.md``) or plain text (``.txt``) format (Requirement 14.3). The selected format
is determined by the file extension of the destination path.

Records are presented grouped by ``Status_Code_Class`` in ascending numeric
order of the class (``2xx, 3xx, 4xx, 5xx``) (Requirement 14.5). Grouping is
delegated to :func:`~utils.discovery_session.group_by_status_class` so the export
and the interactive triage table stay consistent and never diverge.

Any requested export format other than ``.md`` or ``.txt`` raises a descriptive
:class:`UnsupportedExportFormatError` and writes nothing: no
``Discovery_Export_File`` is created on disk (Requirement 14.4).
"""

import os
from typing import List

from core.logging import get_logger

from utils.discovery_session import (
    STATUS_CLASSES,
    DiscoveryResult,
    group_by_status_class,
)

logger = get_logger(__name__)

# File extensions for the two supported human-readable export formats
# (Requirement 14.3). Any other extension is rejected (Requirement 14.4).
MARKDOWN_EXTENSION = ".md"
TEXT_EXTENSION = ".txt"
SUPPORTED_EXTENSIONS = (MARKDOWN_EXTENSION, TEXT_EXTENSION)


class DiscoveryExportError(Exception):
    """Base class for discovery-export errors."""


class UnsupportedExportFormatError(DiscoveryExportError):
    """Raised when an unsupported export format is requested (Requirement 14.4)."""


def _format_extension(path: str) -> str:
    """Return the lower-cased file extension of ``path`` (including the dot)."""
    return os.path.splitext(path)[1].lower()


def _render_markdown(
    grouped: "OrderedDict[str, List[DiscoveryResult]]",  # noqa: F821
) -> str:
    """Render grouped records as a Markdown document.

    Each status class becomes a ``##`` section, in the ascending order supplied
    by :func:`group_by_status_class`, followed by a Markdown table of the records
    in that class. An empty class still produces its heading so all four classes
    are represented.

    Args:
        grouped: Status-class-keyed records in ascending class order.

    Returns:
        The Markdown document as a single string.
    """
    lines: List[str] = ["# Discovery Results", ""]
    for status_class in STATUS_CLASSES:
        records = grouped[status_class]
        lines.append(f"## {status_class} ({len(records)})")
        lines.append("")
        if records:
            lines.append("| URL | Method | Status | Endpoint Status |")
            lines.append("| --- | --- | --- | --- |")
            for record in records:
                lines.append(
                    f"| {record.url} | {record.method} | "
                    f"{record.status_code} | {record.endpoint_status} |"
                )
        else:
            lines.append("_No results._")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _render_text(
    grouped: "OrderedDict[str, List[DiscoveryResult]]",  # noqa: F821
) -> str:
    """Render grouped records as a plain-text document.

    Each status class becomes a labelled section, in the ascending order supplied
    by :func:`group_by_status_class`, followed by one line per record. An empty
    class still produces its heading so all four classes are represented.

    Args:
        grouped: Status-class-keyed records in ascending class order.

    Returns:
        The plain-text document as a single string.
    """
    lines: List[str] = ["Discovery Results", "================="]
    for status_class in STATUS_CLASSES:
        records = grouped[status_class]
        lines.append("")
        lines.append(f"[{status_class}] ({len(records)})")
        if records:
            for record in records:
                lines.append(
                    f"  {record.status_code} {record.method} {record.url} "
                    f"({record.endpoint_status})"
                )
        else:
            lines.append("  (no results)")
    return "\n".join(lines).rstrip("\n") + "\n"


def write_discovery_export(records: List[DiscoveryResult], path: str) -> None:
    """Write a human-readable discovery export to ``path``.

    The export format is selected from the file extension of ``path``: ``.md``
    produces a Markdown document and ``.txt`` produces a plain-text document
    (Requirement 14.3). In both formats the records are presented grouped by
    ``Status_Code_Class`` in ascending class order (``2xx, 3xx, 4xx, 5xx``),
    reusing :func:`~utils.discovery_session.group_by_status_class` so the export
    matches the triage table (Requirement 14.5).

    Args:
        records: The discovery records to export.
        path: Destination path whose extension (``.md`` or ``.txt``) selects the
            format.

    Raises:
        UnsupportedExportFormatError: If ``path`` does not end in ``.md`` or
            ``.txt``. No file is written in this case (Requirement 14.4).
    """
    extension = _format_extension(path)
    if extension not in SUPPORTED_EXTENSIONS:
        # Reject before touching the filesystem so nothing is written
        # (Requirement 14.4).
        raise UnsupportedExportFormatError(
            f"unsupported export format '{extension or path}': supported formats "
            f"are {MARKDOWN_EXTENSION} and {TEXT_EXTENSION}"
        )

    grouped = group_by_status_class(records)
    if extension == MARKDOWN_EXTENSION:
        content = _render_markdown(grouped)
    else:
        content = _render_text(grouped)

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)

    logger.info(
        "Discovery export written",
        path=path,
        format=extension,
        records=len(records),
    )
