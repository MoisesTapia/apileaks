"""Descriptor-registry tests for the CLI restructure (Property 1 & 2 anchors).

These tests pin the structural invariants of the OWASP module descriptor
registry created in task 1 (``apileaks/cli/owasp_descriptors.py``), the single
source of truth that drives ``owasp`` subcommand generation. They are plain
assertion tests: Property 1 (descriptor <-> engine bijection) and Property 2
(subcommand name equals engine key / category ordering) are structural
invariants best expressed directly.

Cross-checks performed here:

* The descriptor key set is exactly the ten engine registration keys AND equals
  the engine's default ``enabled_modules`` set derived from ``OWASPConfig``
  (Property 1 / Requirements 1.2, 9.1, 11.1, 11.5).
* Each descriptor's ``owasp_category`` matches the OWASP category string the
  owning module emits in ``modules/owasp/*`` (Requirement 9.3), and each
  ``config_field`` is a real field on ``OWASPConfig``.
* Every ``summary`` is a single line of at most 80 characters (Requirement 1.4).
* ``get_descriptor`` raises on an unregistered key (Requirements 1.6, 9.4) and
  ``all_keys()`` preserves API1..API10 category order matching the descriptor
  list order (Property 2).

**Validates: Requirements 1.2, 9.1, 9.3, 11.1, 11.5**
"""

import re
from pathlib import Path

import pytest

from cli.owasp_descriptors import (
    OWASP_MODULE_DESCRIPTORS,
    OwaspModuleDescriptor,
    all_keys,
    get_descriptor,
    iter_descriptors,
)
from core.config import OWASPConfig


# The ten engine registration keys, in OWASP API Security Top 10 category order
# (API1..API10). This is the authoritative literal the task specifies.
EXPECTED_KEYS = [
    "bola",
    "auth",
    "property",
    "resource",
    "function_auth",
    "business_flow",
    "ssrf",
    "security_misconfig",
    "inventory",
    "unsafe_consumption",
]

EXPECTED_CATEGORY_ORDER = [
    "API1",
    "API2",
    "API3",
    "API4",
    "API5",
    "API6",
    "API7",
    "API8",
    "API9",
    "API10",
]

# Maps each engine key to the source file under ``modules/owasp/`` that owns it,
# so the test can cross-check each descriptor's ``owasp_category`` against the
# category string the owning module actually emits in its findings.
KEY_TO_MODULE_FILE = {
    "bola": "bola_testing.py",
    "auth": "auth_testing.py",
    "property": "property_level_auth.py",
    "resource": "resource_consumption.py",
    "function_auth": "function_level_auth.py",
    "business_flow": "business_flows.py",
    "ssrf": "ssrf_testing.py",
    "security_misconfig": "security_misconfiguration.py",
    "inventory": "inventory_management.py",
    "unsafe_consumption": "unsafe_consumption.py",
}

_OWASP_MODULES_DIR = Path(__file__).resolve().parent.parent / "modules" / "owasp"

# Matches ``owasp_category="API7"`` / ``owasp_category='API7'`` in module source.
_OWASP_CATEGORY_RE = re.compile(r"""owasp_category\s*=\s*['"](API\d+)['"]""")


def _module_owasp_categories(module_filename: str) -> set:
    """Return the distinct ``owasp_category`` strings emitted by a module file."""
    source = (_OWASP_MODULES_DIR / module_filename).read_text(encoding="utf-8")
    return set(_OWASP_CATEGORY_RE.findall(source))


# --------------------------------------------------------------------------- #
# Property 1: descriptor <-> engine bijection
# --------------------------------------------------------------------------- #

def test_descriptor_keys_are_exactly_the_ten_engine_keys():
    """Descriptor keys equal the ten literal engine registration keys."""
    assert all_keys() == EXPECTED_KEYS


def test_descriptor_keys_match_engine_default_enabled_modules():
    """Descriptor key set equals the engine default ``enabled_modules`` set.

    Derived from the config source of truth (a fresh default ``OWASPConfig``),
    not only the literal list, so the two cannot silently drift.
    """
    descriptor_keys = {d.key for d in OWASP_MODULE_DESCRIPTORS}
    engine_default_keys = set(OWASPConfig().enabled_modules)

    assert descriptor_keys == engine_default_keys
    # And both agree with the specified literal set.
    assert descriptor_keys == set(EXPECTED_KEYS)


def test_no_duplicate_descriptor_keys():
    """Each engine key appears exactly once (bijection, not multimap)."""
    keys = all_keys()
    assert len(keys) == len(set(keys)) == 10


# --------------------------------------------------------------------------- #
# owasp_category cross-check and config_field existence
# --------------------------------------------------------------------------- #

def test_descriptor_categories_in_expected_order():
    """Descriptor categories are API1..API10 in descriptor list order."""
    assert [d.owasp_category for d in OWASP_MODULE_DESCRIPTORS] == EXPECTED_CATEGORY_ORDER


@pytest.mark.parametrize("descriptor", OWASP_MODULE_DESCRIPTORS, ids=lambda d: d.key)
def test_descriptor_category_matches_owning_module(descriptor: OwaspModuleDescriptor):
    """Each descriptor's ``owasp_category`` matches the owning module's strings."""
    module_filename = KEY_TO_MODULE_FILE[descriptor.key]
    module_categories = _module_owasp_categories(module_filename)

    # The owning module must actually emit findings under this category, and it
    # should be the only OWASP category that module uses.
    assert descriptor.owasp_category in module_categories, (
        f"{descriptor.key}: descriptor category {descriptor.owasp_category!r} "
        f"not found among {sorted(module_categories)} in {module_filename}"
    )
    assert module_categories == {descriptor.owasp_category}, (
        f"{descriptor.key}: module {module_filename} emits multiple categories "
        f"{sorted(module_categories)}; expected only {descriptor.owasp_category!r}"
    )


@pytest.mark.parametrize("descriptor", OWASP_MODULE_DESCRIPTORS, ids=lambda d: d.key)
def test_descriptor_config_field_exists_on_owasp_config(descriptor: OwaspModuleDescriptor):
    """Each descriptor's ``config_field`` is a real field on ``OWASPConfig``."""
    config = OWASPConfig()
    assert hasattr(config, descriptor.config_field), (
        f"{descriptor.key}: OWASPConfig has no field {descriptor.config_field!r}"
    )


# --------------------------------------------------------------------------- #
# summary shape: single line, <= 80 chars
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("descriptor", OWASP_MODULE_DESCRIPTORS, ids=lambda d: d.key)
def test_summary_is_single_line_at_most_80_chars(descriptor: OwaspModuleDescriptor):
    """Every ``summary`` is non-empty, single-line, and at most 80 characters."""
    summary = descriptor.summary
    assert summary, f"{descriptor.key}: summary is empty"
    assert len(summary) <= 80, (
        f"{descriptor.key}: summary is {len(summary)} chars (> 80): {summary!r}"
    )
    assert "\n" not in summary and "\r" not in summary, (
        f"{descriptor.key}: summary is not single-line: {summary!r}"
    )


# --------------------------------------------------------------------------- #
# get_descriptor / all_keys / iter_descriptors behavior
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_get_descriptor_returns_matching_descriptor(key: str):
    """``get_descriptor`` returns the descriptor whose key matches (Property 2)."""
    descriptor = get_descriptor(key)
    assert descriptor.key == key


def test_get_descriptor_raises_keyerror_on_unregistered_key():
    """``get_descriptor`` raises ``KeyError`` naming an unregistered key."""
    with pytest.raises(KeyError) as excinfo:
        get_descriptor("does_not_exist")
    # The raised message should reference the offending key (Requirement 9.4).
    assert "does_not_exist" in str(excinfo.value)


def test_all_keys_preserves_category_order():
    """``all_keys()`` order matches the descriptor list / API1..API10 order."""
    keys = all_keys()
    assert keys == [d.key for d in OWASP_MODULE_DESCRIPTORS]
    # Category order and key order advance together (Property 2).
    categories = [get_descriptor(k).owasp_category for k in keys]
    assert categories == EXPECTED_CATEGORY_ORDER


def test_iter_descriptors_matches_registry_order():
    """``iter_descriptors()`` yields the descriptors in registry order."""
    assert list(iter_descriptors()) == OWASP_MODULE_DESCRIPTORS
