"""
Cloud Read-Only Guard

Analogous to SafeModeGuard in utils/safe_mode.py, but applied to cloud
provider management API operations instead of HTTP requests to the target API.

By default (allow_destructive=False) the guard permits only read-only
operations (those whose name starts with one of READ_ONLY_PREFIXES).  Any
attempt to invoke a write/mutate operation is blocked and logged.

The guard is intentionally conservative — if an operation name does not match
any read-only prefix it is treated as destructive and blocked unless the caller
has explicitly enabled destructive mode.
"""

from __future__ import annotations

from core.logging import get_logger

logger = get_logger(__name__)

# Prefixes that identify read-only (non-mutating) operations in each provider's SDK.
# boto3 methods:            get_*, list_*, describe_*
# GCP Python SDK methods:   get_*, list_*
# Azure Python SDK methods: get, list, list_by_*, get_*
_READ_ONLY_PREFIXES: tuple[str, ...] = (
    "get",
    "list",
    "describe",
)


class CloudReadOnlyGuard:
    """
    Gate that prevents destructive management-plane operations unless
    explicitly permitted.

    Usage::

        guard = CloudReadOnlyGuard(allow_destructive=False)
        if guard.allow("get_rest_apis"):
            client.get_rest_apis()
    """

    def __init__(self, allow_destructive: bool = False) -> None:
        self.allow_destructive = allow_destructive

    def is_read_only(self, operation_name: str) -> bool:
        """Return True if the operation name is clearly a read-only call."""
        normalized = operation_name.lower().lstrip("_").replace("-", "_")
        return any(normalized.startswith(prefix) for prefix in _READ_ONLY_PREFIXES)

    def allow(self, operation_name: str) -> bool:
        """
        Return True if the operation may be executed.

        Always True for read-only operations.  For write operations, True only
        when ``allow_destructive`` is set.  Logs a warning when a write
        operation is blocked.
        """
        if self.is_read_only(operation_name):
            return True
        if self.allow_destructive:
            logger.warning(
                "Executing destructive cloud management operation",
                operation=operation_name,
            )
            return True
        logger.info(
            "Blocked destructive cloud management operation (Read_Only_Mode)",
            operation=operation_name,
        )
        return False
