"""OWASP module descriptor registry — the single source of truth for the CLI.

One immutable :class:`OwaspModuleDescriptor` is declared per engine registration
key, in OWASP API Security Top 10 category order (API1..API10). This registry
drives dynamic generation of the ``owasp`` subcommands, the ``owasp`` module
listing, the module -> ``OWASPConfig`` field mapping, and per-module option
wiring.

The ``specific_options`` / ``apply_options`` callables are left ``None`` here;
they are attached to the ``bola`` and ``auth`` descriptors in a later task. This
module is CLI-surface only and does not import or touch OWASP detection logic.

An import-time consistency guard asserts that the descriptor key set is exactly
the engine's default ``enabled_modules`` set, so drift between the engine and the
CLI fails fast at import rather than silently omitting a subcommand.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Optional

from cli.module_options import (
    apply_auth_options,
    apply_bola_options,
    apply_ssrf_options,
    auth_options,
    bola_options,
    ssrf_options,
)

# Match the package-relative import style used across ``apileaks/`` (e.g.
# ``from core.config import ...`` in modules/owasp/*), so this module imports
# cleanly when the ``apileaks`` directory is the import root.
from core.config import OWASPConfig


@dataclass(frozen=True)
class OwaspModuleDescriptor:
    """Immutable description of a single OWASP detection module for the CLI.

    Attributes:
        key: Engine registration key (e.g. ``"bola"``). Character-for-character
            identical to the module's registration key in the engine.
        owasp_category: OWASP API Security Top 10 category id, ``"API1".."API10"``.
        summary: Single-line, <= 80 character description of the category the
            module covers.
        config_field: Name of the ``OWASPConfig`` field this module configures
            (e.g. ``"bola_testing"``).
        specific_options: Optional Click decorator attaching this module's
            module-specific options. Wired in a later task; ``None`` for now.
        apply_options: Optional callable applying collected specific-option
            values onto the module's config object. Signature:
            ``(module_cfg, option_values: dict) -> None``. Wired in a later task.
    """

    key: str
    owasp_category: str
    summary: str
    config_field: str
    specific_options: Optional[Callable] = None
    apply_options: Optional[Callable] = None


# Descriptors in OWASP category order (API1..API10). NOTE: this order differs
# from the engine's default ``enabled_modules`` list order (ssrf/business_flow
# are swapped there); the consistency guard below compares sets, not order.
OWASP_MODULE_DESCRIPTORS: list[OwaspModuleDescriptor] = [
    OwaspModuleDescriptor(
        key="bola",
        owasp_category="API1",
        summary="Broken Object Level Authorization (BOLA) detection",
        config_field="bola_testing",
        specific_options=bola_options,
        apply_options=apply_bola_options,
    ),
    OwaspModuleDescriptor(
        key="auth",
        owasp_category="API2",
        summary="Broken Authentication detection",
        config_field="auth_testing",
        specific_options=auth_options,
        apply_options=apply_auth_options,
    ),
    OwaspModuleDescriptor(
        key="property",
        owasp_category="API3",
        summary="Broken Object Property Level Authorization detection",
        config_field="property_testing",
    ),
    OwaspModuleDescriptor(
        key="resource",
        owasp_category="API4",
        summary="Unrestricted Resource Consumption detection",
        config_field="resource_testing",
    ),
    OwaspModuleDescriptor(
        key="function_auth",
        owasp_category="API5",
        summary="Broken Function Level Authorization detection",
        config_field="function_auth_testing",
    ),
    OwaspModuleDescriptor(
        key="business_flow",
        owasp_category="API6",
        summary="Unrestricted Access to Sensitive Business Flows detection",
        config_field="business_flow_testing",
    ),
    OwaspModuleDescriptor(
        key="ssrf",
        owasp_category="API7",
        summary="Server-Side Request Forgery (SSRF) detection",
        config_field="ssrf_testing",
        specific_options=ssrf_options,
        apply_options=apply_ssrf_options,
    ),
    OwaspModuleDescriptor(
        key="security_misconfig",
        owasp_category="API8",
        summary="Security Misconfiguration detection",
        config_field="security_misconfig_testing",
    ),
    OwaspModuleDescriptor(
        key="inventory",
        owasp_category="API9",
        summary="Improper Inventory Management detection",
        config_field="inventory_testing",
    ),
    OwaspModuleDescriptor(
        key="unsafe_consumption",
        owasp_category="API10",
        summary="Unsafe Consumption of APIs detection",
        config_field="unsafe_consumption_testing",
    ),
]


def get_descriptor(key: str) -> OwaspModuleDescriptor:
    """Return the descriptor registered under ``key``.

    Args:
        key: The engine registration key to look up.

    Returns:
        The matching :class:`OwaspModuleDescriptor`.

    Raises:
        KeyError: If ``key`` is not a registered descriptor key. The message
            names the unregistered key and lists the registered keys.
    """
    for descriptor in OWASP_MODULE_DESCRIPTORS:
        if descriptor.key == key:
            return descriptor
    raise KeyError(
        f"Unknown OWASP module key: {key!r}. "
        f"Registered keys are: {', '.join(all_keys())}."
    )


def all_keys() -> list[str]:
    """Return the descriptor keys in OWASP category order (API1..API10)."""
    return [descriptor.key for descriptor in OWASP_MODULE_DESCRIPTORS]


def iter_descriptors() -> Iterator[OwaspModuleDescriptor]:
    """Iterate the descriptors in OWASP category order (API1..API10)."""
    return iter(OWASP_MODULE_DESCRIPTORS)


def _assert_descriptor_engine_consistency() -> None:
    """Fail fast at import if descriptors drift from the engine default set.

    Compares the descriptor key set against the engine's default
    ``enabled_modules`` set (a fresh default ``OWASPConfig`` instance). Order is
    intentionally ignored; only set membership must match. On mismatch, a
    :class:`RuntimeError` naming the specific offending keys is raised.
    """
    descriptor_keys = {descriptor.key for descriptor in OWASP_MODULE_DESCRIPTORS}
    engine_default_keys = set(OWASPConfig().enabled_modules)

    if descriptor_keys != engine_default_keys:
        missing_from_descriptors = engine_default_keys - descriptor_keys
        missing_from_engine = descriptor_keys - engine_default_keys
        raise RuntimeError(
            "OWASP descriptor registry is out of sync with the engine default "
            "enabled_modules set. "
            f"Keys registered in the engine but missing a descriptor: "
            f"{sorted(missing_from_descriptors) or 'none'}. "
            f"Keys with a descriptor but not registered in the engine default: "
            f"{sorted(missing_from_engine) or 'none'}."
        )


# Import-time consistency guard: a module added to the engine without a
# descriptor (or vice versa) fails fast here rather than silently drifting.
_assert_descriptor_engine_consistency()
