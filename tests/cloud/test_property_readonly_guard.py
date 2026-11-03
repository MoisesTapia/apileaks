"""
Property-based tests for CloudReadOnlyGuard — Modo Solo-Lectura por Defecto.

Feature: cloud-gateway-security-audit

**Property 1: Modo Solo-Lectura por Defecto**

For ANY invocation of a ``CloudGatewayAuditor`` without
``--allow-destructive-cloud-audit``, NO operation that is not prefixed with a
read-only token (``Get``/``List``/``Describe``/``get_``/``list_``/``describe_``)
SHALL be allowed to execute.

Specifically validated:

1. For any write operation name, ``CloudReadOnlyGuard(allow_destructive=False)``
   MUST return ``False`` from ``guard_operation``.
2. For any write operation name, ``CloudReadOnlyGuard(allow_destructive=True)``
   MUST return ``True`` from ``guard_operation``.
3. A concrete ``CloudGatewayAuditor`` subclass that consults the guard before
   calling any operation MUST never execute a write call when
   ``allow_destructive=False``, regardless of how many write operations it
   attempts.
4. Read-only operation names MUST be permitted (``True``) regardless of the
   ``allow_destructive`` flag value.

**Validates: Requirements 3.1, 3.2, 3.3**

Import note
-----------
``modules.cloud.base`` is imported before ``utils.cloud.readonly_guard`` to
ensure that the ``core`` and ``utils`` packages are fully initialised through
the safe path (``modules`` → ``core`` → ``utils``) before the ``utils``
package's own ``__init__.py`` might be reached via the guard import.  Without
this ordering a circular-import error arises because ``utils/__init__.py``
→ ``utils.findings`` → ``core.config`` → ``core.__init__`` → ``core.engine``
→ ``utils.findings`` (cycle).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# Import via the modules path first to safely prime the import chain and
# avoid the utils/__init__.py → utils.findings → core → utils circular import.
from modules.cloud.base import (  # noqa: F401 — side-effect import intentional
    CloudGatewayAuditor,
    GatewayFinding,
    GatewaySeverity,
)

# Safe to import now that core + utils are fully in sys.modules.
from utils.cloud.readonly_guard import CloudReadOnlyGuard

from hypothesis import given, settings, strategies as st

# ---------------------------------------------------------------------------
# Canonical operation-name sets
# ---------------------------------------------------------------------------

_WRITE_OPERATIONS: list[str] = [
    # AWS PascalCase write ops
    "CreateApi",
    "UpdateApi",
    "DeleteApi",
    "PutMethod",
    "CreateRestApi",
    "DeleteRestApi",
    "UpdateRestApi",
    "PutIntegration",
    "CreateDeployment",
    "DeleteDeployment",
    "PutGatewayResponse",
    # Python snake_case write ops
    "create_api",
    "update_api",
    "delete_api",
    "put_method",
    "create_gateway",
    "update_gateway",
    "delete_gateway",
    "patch_service",
    "post_resource",
    "put_rest_api",
    "create_deployment",
    # Azure / GCP style
    "CreateOrUpdate",
    "PatchService",
    "DeleteService",
]

_READ_OPERATIONS: list[str] = [
    # AWS PascalCase
    "GetApi",
    "ListApis",
    "DescribeApi",
    "GetRestApi",
    "ListRestApis",
    "DescribeStages",
    "GetStage",
    "ListStages",
    "GetMethod",
    "DescribeGateway",
    # Python snake_case
    "get_api",
    "list_apis",
    "describe_api",
    "get_gateway",
    "list_gateways",
    "describe_stages",
    "get_rest_api",
    "list_rest_apis",
    "get_stage",
    "list_resources",
    # GCP / Azure style
    "list_gateways",
    "describe_service",
    "get_service_config",
]

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_OP_SUFFIXES = st.sampled_from(["", "V2", "_v2", "Config", "Policy", "Access"])

_WRITE_PREFIXES = ["Create", "Delete", "Update", "Put", "Post", "Patch",
                   "create_", "delete_", "update_", "put_", "post_", "patch_"]

_READ_PREFIXES = ["Get", "List", "Describe", "get_", "list_", "describe_"]


@st.composite
def write_operation_names(draw) -> str:
    """Generate an operation name that starts with a write prefix."""
    prefix = draw(st.sampled_from(_WRITE_PREFIXES))
    suffix = draw(st.from_regex(r"[A-Za-z][A-Za-z0-9]{2,15}", fullmatch=True))
    return prefix + suffix


@st.composite
def read_operation_names(draw) -> str:
    """Generate an operation name that starts with a read-only prefix."""
    prefix = draw(st.sampled_from(_READ_PREFIXES))
    suffix = draw(st.from_regex(r"[A-Za-z][A-Za-z0-9]{2,15}", fullmatch=True))
    return prefix + suffix


# ---------------------------------------------------------------------------
# Concrete CloudGatewayAuditor test double
# ---------------------------------------------------------------------------


class _RecordingAuditor(CloudGatewayAuditor):
    """
    Minimal concrete auditor that records whether any write operation was
    actually executed.  It calls ``guard.guard_operation(name)`` before
    executing any operation — exactly as production auditors should.
    """

    def __init__(self, guard: CloudReadOnlyGuard, operations_to_attempt: list[str]):
        self._guard = guard
        self._operations_to_attempt = operations_to_attempt
        self.executed_operations: list[str] = []
        self.blocked_operations: list[str] = []

    def get_provider_name(self) -> str:
        return "test"

    async def discover_resources(self) -> list[dict[str, Any]]:
        return []

    async def audit(self) -> list[GatewayFinding]:
        for op in self._operations_to_attempt:
            if self._guard.guard_operation(op):
                self.executed_operations.append(op)
            else:
                self.blocked_operations.append(op)
        return []


def _is_write_op(name: str) -> bool:
    """Return True if the name starts with a write prefix (mirrors guard logic inversely)."""
    read_prefixes = CloudReadOnlyGuard.READ_ONLY_PREFIXES
    return not any(name.startswith(p) for p in read_prefixes)


# ---------------------------------------------------------------------------
# Parametrised baseline tests (fast, deterministic)
# ---------------------------------------------------------------------------


class TestCloudReadOnlyGuardDefaultMode:
    """Guard instantiated with default allow_destructive=False."""

    def setup_method(self):
        self.guard = CloudReadOnlyGuard()

    @pytest.mark.parametrize("op", _WRITE_OPERATIONS)
    def test_write_operations_blocked(self, op: str):
        """Write ops must be blocked in default read-only mode."""
        assert self.guard.guard_operation(op) is False

    @pytest.mark.parametrize("op", _READ_OPERATIONS)
    def test_read_operations_permitted(self, op: str):
        """Read ops must be permitted in default read-only mode."""
        assert self.guard.guard_operation(op) is True

    def test_allow_destructive_defaults_to_false(self):
        assert self.guard.allow_destructive is False


class TestCloudReadOnlyGuardDestructiveMode:
    """Guard instantiated with allow_destructive=True."""

    def setup_method(self):
        self.guard = CloudReadOnlyGuard(allow_destructive=True)

    @pytest.mark.parametrize("op", _WRITE_OPERATIONS)
    def test_write_operations_permitted_in_destructive_mode(self, op: str):
        assert self.guard.guard_operation(op) is True

    @pytest.mark.parametrize("op", _READ_OPERATIONS)
    def test_read_operations_always_permitted(self, op: str):
        assert self.guard.guard_operation(op) is True


class TestConcreteAuditorWithGuard:
    """End-to-end: a concrete CloudGatewayAuditor subclass respects the guard."""

    def test_auditor_never_executes_write_ops_in_readonly_mode(self):
        """A concrete auditor that checks guard_operation must never execute write ops."""
        guard = CloudReadOnlyGuard(allow_destructive=False)
        auditor = _RecordingAuditor(
            guard=guard,
            operations_to_attempt=_WRITE_OPERATIONS + _READ_OPERATIONS,
        )
        asyncio.run(auditor.audit())

        # No write operation should have been executed
        executed_writes = [
            op for op in auditor.executed_operations if _is_write_op(op)
        ]
        assert executed_writes == [], (
            f"Write operations were executed despite read-only mode: {executed_writes}"
        )

    def test_auditor_executes_all_read_ops_in_readonly_mode(self):
        """All read ops must be executed even when allow_destructive=False."""
        guard = CloudReadOnlyGuard(allow_destructive=False)
        auditor = _RecordingAuditor(
            guard=guard,
            operations_to_attempt=_READ_OPERATIONS,
        )
        asyncio.run(auditor.audit())

        assert set(auditor.executed_operations) == set(_READ_OPERATIONS), (
            "Some read operations were unexpectedly blocked in read-only mode"
        )

    def test_auditor_executes_all_ops_in_destructive_mode(self):
        """In destructive mode, all operations must be executed."""
        guard = CloudReadOnlyGuard(allow_destructive=True)
        auditor = _RecordingAuditor(
            guard=guard,
            operations_to_attempt=_WRITE_OPERATIONS + _READ_OPERATIONS,
        )
        asyncio.run(auditor.audit())

        assert set(auditor.executed_operations) == set(_WRITE_OPERATIONS + _READ_OPERATIONS), (
            "Some operations were unexpectedly blocked in destructive mode"
        )

    def test_blocked_write_ops_are_recorded(self):
        """Blocked write ops must appear in blocked_operations (not silently dropped)."""
        guard = CloudReadOnlyGuard(allow_destructive=False)
        auditor = _RecordingAuditor(
            guard=guard,
            operations_to_attempt=_WRITE_OPERATIONS,
        )
        asyncio.run(auditor.audit())

        assert set(auditor.blocked_operations) == set(_WRITE_OPERATIONS), (
            f"Expected all write ops to be in blocked_operations; "
            f"got {auditor.blocked_operations!r}"
        )


# ---------------------------------------------------------------------------
# Property 1: Write ops always blocked in read-only mode (Req 3.1, 3.2)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(op=write_operation_names())
def test_property_write_ops_always_blocked_in_readonly_mode(op: str):
    """
    **Property 1: Modo Solo-Lectura por Defecto**

    For *any* write operation name, ``CloudReadOnlyGuard(allow_destructive=False)``
    MUST return ``False`` from ``guard_operation``.

    **Validates: Requirements 3.1, 3.2**
    """
    guard = CloudReadOnlyGuard(allow_destructive=False)
    result = guard.guard_operation(op)
    assert result is False, (
        f"guard_operation({op!r}) returned {result!r} in read-only mode; "
        f"expected False for a write operation"
    )


# ---------------------------------------------------------------------------
# Property 1 (opt-in variant): Write ops permitted in destructive mode (Req 3.3)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(op=write_operation_names())
def test_property_write_ops_permitted_in_destructive_mode(op: str):
    """
    **Property 1: Modo destructivo explícito**

    For *any* write operation name, ``CloudReadOnlyGuard(allow_destructive=True)``
    MUST return ``True`` from ``guard_operation``.

    **Validates: Requirement 3.3**
    """
    guard = CloudReadOnlyGuard(allow_destructive=True)
    result = guard.guard_operation(op)
    assert result is True, (
        f"guard_operation({op!r}) returned {result!r} in destructive mode; "
        f"expected True"
    )


# ---------------------------------------------------------------------------
# Property invariant: Read ops always allowed (Req 3.1, 3.2, 3.3)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(op=read_operation_names())
def test_property_read_ops_always_allowed_regardless_of_mode(op: str):
    """
    **Property 1: invariante**

    Read-only operation names MUST be permitted regardless of the
    ``allow_destructive`` flag.

    **Validates: Requirements 3.1, 3.2, 3.3**
    """
    for allow_destructive in (False, True):
        guard = CloudReadOnlyGuard(allow_destructive=allow_destructive)
        result = guard.guard_operation(op)
        assert result is True, (
            f"guard_operation({op!r}) returned {result!r} with "
            f"allow_destructive={allow_destructive}; read-only ops must always be True"
        )


# ---------------------------------------------------------------------------
# Property 3 (from task spec): Concrete auditor never executes write ops
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(ops=st.lists(write_operation_names(), min_size=1, max_size=10))
def test_property_concrete_auditor_never_executes_writes_in_readonly_mode(ops: list[str]):
    """
    **Property 1: Modo Solo-Lectura por Defecto — via concrete auditor**

    A concrete ``CloudGatewayAuditor`` subclass that consults ``guard_operation``
    before executing each operation MUST never execute a write call when
    ``allow_destructive=False``, regardless of how many write operations it
    attempts.

    **Validates: Requirements 3.1, 3.2**
    """
    guard = CloudReadOnlyGuard(allow_destructive=False)
    auditor = _RecordingAuditor(guard=guard, operations_to_attempt=ops)
    asyncio.run(auditor.audit())

    executed_writes = [op for op in auditor.executed_operations if _is_write_op(op)]
    assert executed_writes == [], (
        f"Concrete auditor executed write operations in read-only mode: {executed_writes}"
    )


@settings(max_examples=100, deadline=None)
@given(ops=st.lists(write_operation_names(), min_size=1, max_size=10))
def test_property_concrete_auditor_executes_all_writes_in_destructive_mode(ops: list[str]):
    """
    **Property 1: Modo destructivo — via concrete auditor**

    When ``allow_destructive=True``, a concrete auditor MUST execute every
    operation it attempts (including write ops).

    **Validates: Requirement 3.3**
    """
    guard = CloudReadOnlyGuard(allow_destructive=True)
    auditor = _RecordingAuditor(guard=guard, operations_to_attempt=ops)
    asyncio.run(auditor.audit())

    assert set(auditor.executed_operations) == set(ops), (
        f"Concrete auditor did not execute all operations in destructive mode. "
        f"Missing: {set(ops) - set(auditor.executed_operations)!r}"
    )
