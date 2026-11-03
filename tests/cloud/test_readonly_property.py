"""
Property-based tests for CloudReadOnlyGuard — Read-Only Mode by default.

Feature: cloud-gateway-security-audit

**Property 1: Modo Solo-Lectura por Defecto**

For any instantiation of ``CloudReadOnlyGuard`` without
``allow_destructive=True``:

* Every write/mutate operation name MUST return ``False`` from
  ``guard_operation`` (the operation is blocked).
* Every read-only operation name MUST return ``True`` from
  ``guard_operation`` (the operation is permitted).

When ``allow_destructive=True`` all operations — including write ones —
MUST return ``True``.

**Validates: Requirements 3.1, 3.2, 3.3**
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from utils.cloud.readonly_guard import CloudReadOnlyGuard

# ---------------------------------------------------------------------------
# Constant operation-name sets used in both parametrised and PBT tests
# ---------------------------------------------------------------------------

# Operations that are unambiguously writes and must always be blocked in
# default (read-only) mode.
_WRITE_OPERATIONS: list[str] = [
    # AWS PascalCase write operations
    "CreateApi",
    "UpdateApi",
    "DeleteApi",
    "PutMethod",
    "CreateRestApi",
    "DeleteRestApi",
    "UpdateRestApi",
    "PutIntegration",
    # Python-SDK snake_case write operations
    "create_api",
    "update_api",
    "delete_api",
    "put_method",
    "create_gateway",
    "update_gateway",
    "delete_gateway",
    "patch_service",
]

# Operations that are unambiguously reads and must always be permitted.
_READ_OPERATIONS: list[str] = [
    # AWS PascalCase read operations
    "GetApi",
    "ListApis",
    "DescribeApi",
    "GetRestApi",
    "ListRestApis",
    "DescribeStages",
    "GetStage",
    "ListStages",
    # Python-SDK snake_case read operations
    "get_api",
    "list_apis",
    "describe_api",
    "get_gateway",
    "list_gateways",
    "describe_stages",
    "get_rest_api",
    "list_rest_apis",
]


# ---------------------------------------------------------------------------
# Hypothesis strategies for operation names
# ---------------------------------------------------------------------------

# Strategy: generate a write operation name by picking from the write-ops list
# then optionally appending a realistic suffix to exercise the prefix logic
# across many variants.
_write_suffixes = st.sampled_from(["", "V2", "_v2", "Config", "Policy"])


@st.composite
def write_operation_names(draw) -> str:
    """Generate an operation name that is clearly a write (non-read)."""
    base = draw(st.sampled_from(_WRITE_OPERATIONS))
    suffix = draw(_write_suffixes)
    return base + suffix


# Strategy: generate a read operation name by picking from the read-ops list.
@st.composite
def read_operation_names(draw) -> str:
    """Generate an operation name that starts with a read-only prefix."""
    base = draw(st.sampled_from(_READ_OPERATIONS))
    suffix = draw(_write_suffixes)
    return base + suffix


# ---------------------------------------------------------------------------
# Parametrised baseline tests (fast, deterministic)
# ---------------------------------------------------------------------------


class TestCloudReadOnlyGuardDefaultMode:
    """Guard instantiated with default allow_destructive=False."""

    def setup_method(self):
        self.guard = CloudReadOnlyGuard()  # default: allow_destructive=False

    @pytest.mark.parametrize("op", _WRITE_OPERATIONS)
    def test_write_operations_are_blocked(self, op: str):
        """Write operations must be blocked in read-only mode."""
        assert self.guard.guard_operation(op) is False, (
            f"Expected guard_operation({op!r}) to return False in read-only mode"
        )

    @pytest.mark.parametrize("op", _READ_OPERATIONS)
    def test_read_operations_are_permitted(self, op: str):
        """Read operations must be permitted in read-only mode."""
        assert self.guard.guard_operation(op) is True, (
            f"Expected guard_operation({op!r}) to return True in read-only mode"
        )

    def test_allow_destructive_is_false_by_default(self):
        """allow_destructive defaults to False."""
        assert self.guard.allow_destructive is False

    @pytest.mark.parametrize("op", _WRITE_OPERATIONS)
    def test_is_read_only_returns_false_for_write_ops(self, op: str):
        """_is_read_only must return False for write operation names."""
        assert self.guard._is_read_only(op) is False

    @pytest.mark.parametrize("op", _READ_OPERATIONS)
    def test_is_read_only_returns_true_for_read_ops(self, op: str):
        """_is_read_only must return True for read operation names."""
        assert self.guard._is_read_only(op) is True


class TestCloudReadOnlyGuardDestructiveMode:
    """Guard instantiated with allow_destructive=True."""

    def setup_method(self):
        self.guard = CloudReadOnlyGuard(allow_destructive=True)

    @pytest.mark.parametrize("op", _WRITE_OPERATIONS)
    def test_write_operations_are_permitted_in_destructive_mode(self, op: str):
        """Write operations must be permitted when allow_destructive=True."""
        assert self.guard.guard_operation(op) is True, (
            f"Expected guard_operation({op!r}) to return True in destructive mode"
        )

    @pytest.mark.parametrize("op", _READ_OPERATIONS)
    def test_read_operations_are_always_permitted(self, op: str):
        """Read operations are always permitted regardless of allow_destructive."""
        assert self.guard.guard_operation(op) is True


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(op=write_operation_names())
def test_property_write_operations_always_blocked_in_readonly_mode(op: str):
    """
    **Property 1: Modo Solo-Lectura por Defecto**

    For *any* write operation name, CloudReadOnlyGuard() (allow_destructive=False)
    MUST return False from guard_operation.

    **Validates: Requirements 3.1, 3.2**
    """
    guard = CloudReadOnlyGuard(allow_destructive=False)
    result = guard.guard_operation(op)
    assert result is False, (
        f"guard_operation({op!r}) returned {result!r} in read-only mode; "
        f"expected False for a write operation"
    )


@settings(max_examples=200, deadline=None)
@given(op=read_operation_names())
def test_property_read_operations_always_permitted_in_readonly_mode(op: str):
    """
    **Property 1: Modo Solo-Lectura por Defecto**

    For *any* read-only operation name, CloudReadOnlyGuard() MUST return
    True from guard_operation.

    **Validates: Requirements 3.1, 3.2**
    """
    guard = CloudReadOnlyGuard(allow_destructive=False)
    result = guard.guard_operation(op)
    assert result is True, (
        f"guard_operation({op!r}) returned {result!r} in read-only mode; "
        f"expected True for a read-only operation"
    )


@settings(max_examples=200, deadline=None)
@given(op=write_operation_names())
def test_property_write_operations_permitted_in_destructive_mode(op: str):
    """
    **Property 1 (opt-in): Modo destructivo explícito**

    For *any* write operation name, CloudReadOnlyGuard(allow_destructive=True)
    MUST return True from guard_operation.

    **Validates: Requirement 3.3**
    """
    guard = CloudReadOnlyGuard(allow_destructive=True)
    result = guard.guard_operation(op)
    assert result is True, (
        f"guard_operation({op!r}) returned {result!r} in destructive mode; "
        f"expected True"
    )


@settings(max_examples=200, deadline=None)
@given(op=read_operation_names())
def test_property_read_operations_never_blocked_regardless_of_mode(op: str):
    """
    **Property 1: invariante**

    Read-only operations MUST be permitted regardless of allow_destructive value.

    **Validates: Requirements 3.1, 3.2, 3.3**
    """
    for allow_destructive in (False, True):
        guard = CloudReadOnlyGuard(allow_destructive=allow_destructive)
        result = guard.guard_operation(op)
        assert result is True, (
            f"guard_operation({op!r}) returned {result!r} with "
            f"allow_destructive={allow_destructive}; read-only ops must always be True"
        )
