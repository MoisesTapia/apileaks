"""
Cloud Read-Only Guard

Analogous to SafeModeGuard in utils/safe_mode.py, but applied to cloud
provider management API operations instead of HTTP requests to the target API.

By default (allow_destructive=False) the guard permits only read-only
operations — those whose name starts with one of READ_ONLY_PREFIXES.  Any
attempt to invoke a write/mutate operation is blocked and logged.

The guard is intentionally conservative: if an operation name does not match
any read-only prefix it is treated as destructive and blocked unless the caller
has explicitly enabled destructive mode.
"""

from __future__ import annotations

from core.logging import get_logger

logger = get_logger(__name__)


class CloudReadOnlyGuard:
    """
    Gate that prevents destructive management-plane operations unless
    explicitly permitted.

    The prefixes cover the three most common naming conventions used
    across cloud provider SDKs:

    * PascalCase AWS-style: ``GetRestApi``, ``ListRestApis``, ``DescribeApi``
    * snake_case Python-SDK style: ``get_rest_api``, ``list_apis``
    * lowercase snake_case GCP/Azure style: ``list_gateways``, ``describe_*``

    Usage::

        guard = CloudReadOnlyGuard(allow_destructive=False)
        if guard.guard_operation("get_rest_apis"):
            client.get_rest_apis()
    """

    READ_ONLY_PREFIXES: tuple[str, ...] = (
        "Get",
        "List",
        "Describe",
        "get_",
        "list_",
        "describe_",
    )

    def __init__(self, allow_destructive: bool = False) -> None:
        self.allow_destructive = allow_destructive

    def guard_operation(self, operation_name: str) -> bool:
        """
        Return True if the operation may be executed, False if it must be skipped.

        Always True for read-only operations.  For write operations, True only
        when ``allow_destructive`` is set.  Logs a warning or info message to
        inform the operator of the decision.
        """
        if self._is_read_only(operation_name):
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

    def _is_read_only(self, operation_name: str) -> bool:
        """Return True if the operation name starts with a known read-only prefix."""
        return any(operation_name.startswith(prefix) for prefix in self.READ_ONLY_PREFIXES)

    # ------------------------------------------------------------------
    # Backward-compatible aliases (used internally before the interface
    # was standardised to guard_operation / _is_read_only).
    # ------------------------------------------------------------------

    def allow(self, operation_name: str) -> bool:
        """Alias for guard_operation (backward compatibility)."""
        return self.guard_operation(operation_name)

    def is_read_only(self, operation_name: str) -> bool:
        """Public alias for _is_read_only (backward compatibility)."""
        return self._is_read_only(operation_name)
