"""
Triage table rendering.

This module renders a set of in-memory
:class:`~utils.discovery_session.DiscoveryResult` records into a ``rich`` table
for at-a-glance CLI triage (Requirement 15.1). The renderer is driven *only* by
in-memory ``DiscoveryResult`` records — either freshly discovered records or
records reconstructed by :meth:`~utils.discovery_session.DiscoverySession.load` —
and never reads a ``Discovery_Export_File`` (Requirements 15.2, 15.6).

The table always exposes exactly four columns, left-to-right: the endpoint URL,
the HTTP method, the HTTP status code, and the ``EndpointStatus`` classification
(Requirement 15.3). Rows are grouped by ``Status_Code_Class`` and the groups are
emitted in ascending order of the leading status-code digit — ``2xx``, ``3xx``,
``4xx``, then ``5xx`` (Requirement 15.4) — by reusing
:func:`~utils.discovery_session.group_by_status_class`. When a status filter is
supplied, only matching records are shown via
:func:`~utils.discovery_session.apply_status_filter` (Requirement 15.5). An empty
record set yields a table with the header row and zero data rows
(Requirement 15.7).
"""

from typing import List, Optional

from rich.table import Table

from core.logging import get_logger

from utils.discovery_session import (
    DiscoveryResult,
    StatusFilter,
    apply_status_filter,
    group_by_status_class,
)

logger = get_logger(__name__)

# The four column headers, in fixed left-to-right order (Requirement 15.3).
COLUMN_HEADERS = ("URL", "Method", "Status", "EndpointStatus")


def render_triage_table(
    records: List[DiscoveryResult],
    status_filter: Optional[StatusFilter] = None,
    console=None,
) -> Table:
    """Build a ``rich`` table from in-memory ``DiscoveryResult`` records.

    The table is constructed exclusively from the supplied in-memory
    ``DiscoveryResult`` records (from a fresh discovery or from
    :meth:`~utils.discovery_session.DiscoverySession.load`) and never from a
    ``Discovery_Export_File`` (Requirements 15.1, 15.2, 15.6).

    Exactly four columns are emitted, left-to-right: ``URL``, ``Method``,
    ``Status`` and ``EndpointStatus`` (Requirement 15.3). When ``status_filter``
    is provided, only the records matching it are displayed (Requirement 15.5).
    The displayed records are grouped by ``Status_Code_Class`` and the groups are
    rendered in ascending order ``2xx, 3xx, 4xx, 5xx`` (Requirement 15.4). An
    empty record set produces a table with the header row and zero data rows
    (Requirement 15.7).

    Args:
        records: The in-memory discovery records to display.
        status_filter: An optional parsed
            :class:`~utils.discovery_session.StatusFilter`; ``None`` shows every
            record.
        console: An optional ``rich`` console. Accepted for call-site symmetry
            with other renderers; the function returns the table object and does
            not print it.

    Returns:
        A :class:`rich.table.Table` with the four triage columns and one data row
        per displayed record, ordered by ascending status class.
    """
    table = Table(title="Discovery Triage")
    for header in COLUMN_HEADERS:
        table.add_column(header)

    # Filter first (Requirement 15.5), then group ascending by class
    # (Requirement 15.4). Both helpers operate on in-memory records only.
    filtered = apply_status_filter(records, status_filter)
    grouped = group_by_status_class(filtered)

    row_count = 0
    for status_class, class_records in grouped.items():
        for record in class_records:
            table.add_row(
                record.url,
                record.method,
                str(record.status_code),
                record.endpoint_status,
            )
            row_count += 1

    logger.info(
        "Triage table rendered",
        displayed=row_count,
        total=len(records),
        filtered=status_filter is not None,
    )
    return table
