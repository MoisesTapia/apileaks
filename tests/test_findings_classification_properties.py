# Feature: owasp-auth-modules-hardening, Property 7: Every emitted finding category resolves to a severity and an in-scope OWASP category
"""
Property-Based Tests for findings-classification completeness.

**Feature: owasp-auth-modules-hardening, Property 7: Every emitted finding
category resolves to a severity and an in-scope OWASP category**

Property 7 (from design.md):
    Every Finding_Category emitted by the four hardened capabilities (BOLA /
    Broken Authentication / Property-Level / JWT subsystem) MUST resolve to:
      * a defined ``Severity`` (one of the concrete enum members, never
        ``None`` / ``UNKNOWN``), and
      * an in-scope ``OWASP_Category`` in ``{API1, API2, API3}``.

The canonical set of emitted categories is the single source of truth
``FindingsCollector.EMITTED_CATEGORIES`` defined in ``utils.findings`` (reused
here rather than re-declared, so the test cannot drift from production). The
test drives that set with Hypothesis ``sampled_from`` and exercises the real
strict-resolution helpers ``_classify_severity`` / ``_get_owasp_category``. No
network or mocking is involved.

Requirements covered: 18.3, 22.1, 22.2, 22.3, 22.4, 24.6, 26.1.
"""

import pytest
from hypothesis import given, settings, strategies as st

from core.config import Severity
from utils.findings import FindingsCollector


# Canonical emitted-category list (single source of truth in production code).
EMITTED_CATEGORIES = sorted(FindingsCollector.EMITTED_CATEGORIES)

# The complete set of concrete Severity enum members. A "defined" severity is
# any one of these (there is no UNKNOWN member; the strict resolver must never
# return None for an emitted category).
DEFINED_SEVERITIES = frozenset(Severity)

# OWASP categories the four hardened capabilities are restricted to.
IN_SCOPE_OWASP = frozenset({"API1", "API2", "API3"})


def _collector():
    """Build a FindingsCollector to exercise its resolution helpers."""
    return FindingsCollector(scan_id="prop7-classification")


# ---------------------------------------------------------------------------
# Property 7: every emitted category resolves to a defined severity AND an
# in-scope OWASP category.
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(category=st.sampled_from(EMITTED_CATEGORIES))
def test_emitted_category_resolves_to_severity_and_in_scope_owasp(category):
    """For every emitted Finding_Category, severity resolution returns a defined
    Severity and OWASP resolution returns a category in {API1, API2, API3}.

    **Validates: Requirements 18.3, 22.1, 22.2, 22.3, 22.4, 24.6, 26.1**
    """
    collector = _collector()

    # Severity resolution: must be a concrete Severity enum member, never None.
    severity = collector._classify_severity(category)
    assert severity is not None
    assert isinstance(severity, Severity)
    assert severity in DEFINED_SEVERITIES

    # OWASP resolution: must be present and in-scope ({API1, API2, API3}).
    owasp_category = collector._get_owasp_category(category)
    assert owasp_category is not None
    assert owasp_category in IN_SCOPE_OWASP


@settings(max_examples=100)
@given(category=st.sampled_from(EMITTED_CATEGORIES))
def test_emitted_category_owasp_is_a_known_owasp_definition(category):
    """The resolved OWASP category for every emitted category is a key in the
    OWASP_CATEGORIES definition table (i.e. a real, described category).

    **Validates: Requirements 22.2, 22.4, 26.1**
    """
    collector = _collector()
    owasp_category = collector._get_owasp_category(category)
    assert owasp_category in FindingsCollector.OWASP_CATEGORIES


def test_emitted_categories_set_is_non_empty():
    """Guard: the canonical emitted-category list is non-empty so the
    property-driven tests actually exercise inputs.

    **Validates: Requirements 24.6**
    """
    assert EMITTED_CATEGORIES, "EMITTED_CATEGORIES must not be empty"


# Feature: owasp-auth-modules-hardening, Property 21: Every advanced finding category resolves to a severity and an in-scope OWASP category
# ---------------------------------------------------------------------------
# Property 21: every one of the seven new advanced BOLA finding categories
# resolves to a defined Severity and an in-scope OWASP_Category in {API1, API3}.
# ---------------------------------------------------------------------------

# The seven advanced BOLA categories added by the hardening work (Reqs 27-32,
# 35). Extends the EMITTED_CATEGORIES drive set for this property.
ADVANCED_BOLA_CATEGORIES = [
    "BOLA_WRITE_ESCALATION",
    "BOLA_ACCOUNT_TAKEOVER",
    "BOLA_BROKEN_OBJECT_RELATIONSHIP",
    "BOLA_CROSS_TENANT",
    "BOLA_ID_LEAKAGE",
    "BOLA_PREDICTABLE_IDENTIFIER",
    "BOLA_STATE_MANIPULATION",
]

# OWASP categories the advanced BOLA capability is restricted to.
ADVANCED_IN_SCOPE_OWASP = frozenset({"API1", "API3"})


@settings(max_examples=100)
@given(category=st.sampled_from(ADVANCED_BOLA_CATEGORIES))
def test_advanced_category_resolves_to_severity_and_in_scope_owasp(category):
    """For every advanced BOLA Finding_Category, severity resolution returns a
    defined Severity and OWASP resolution returns a category in {API1, API3}.
    The category must also be part of the canonical EMITTED_CATEGORIES set.

    **Validates: Requirements 35.1, 35.2, 35.3, 36.1**
    """
    collector = _collector()

    # Category must be part of the canonical emitted-category source of truth.
    assert category in FindingsCollector.EMITTED_CATEGORIES

    # Severity resolution: must be a concrete Severity enum member, never None.
    severity = collector._classify_severity(category)
    assert severity is not None
    assert isinstance(severity, Severity)
    assert severity in DEFINED_SEVERITIES

    # OWASP resolution: must be present and in-scope ({API1, API3}).
    owasp_category = collector._get_owasp_category(category)
    assert owasp_category is not None
    assert owasp_category in ADVANCED_IN_SCOPE_OWASP


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
