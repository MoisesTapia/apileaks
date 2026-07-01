"""
Property-based tests for identifier predictability classification and
identifier-harvest completeness (ID leakage support).

Feature: owasp-auth-modules-hardening

Property 17: Identifier predictability classification is correct.
``analyze_identifier_predictability`` classifies an observed identifier scheme
as: all-digit values -> ``sequential-integer`` (or ``timestamp-based`` for
epoch-like values), both predictable; UUIDs by their RFC 4122 version nibble ->
version 1 (time-based) is predictable (``uuid-v1``) while version 4 (random) is
NOT predictable (``uuid-v4``). A random UUIDv4 scheme yields ``predictable=False``
and raises no ``BOLA_PREDICTABLE_IDENTIFIER`` finding.

**Validates: Requirements 30.4, 30.5, 30.6**

Property 18: Harvesting collects every exposed identifier.
Extraction (via ``_extract_ids_from_json`` / ``_extract_ids_from_response``,
which the harvester reuses) collects every value placed under a recognized
Identifying_Field name (including UUIDs) and nothing placed outside a recognized
field.

**Validates: Requirements 30.1**
"""

import json
import string
from unittest.mock import Mock, AsyncMock

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import BOLAConfig


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_module():
    """Build a BOLATestingModule with stubbed dependencies.

    ``analyze_identifier_predictability``, ``_test_identifier_predictability``
    and ``_extract_ids_from_json`` are pure functions of their arguments (or of
    ``self``'s static tables), so a stub HTTP client and empty auth contexts are
    sufficient.
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return BOLATestingModule(BOLAConfig(enabled=True), client, [])


_MODULE = _make_module()

# The recognized Identifying_Field names the extractor keys on.
_ID_PARAMETER_NAMES = list(BOLATestingModule.ID_PARAMETER_NAMES)

# Every recognized Identifying_Field name contains the letter 'd' (they all
# embed the substring "id"). Building non-recognized field names from an
# alphabet with no 'd'/'D' therefore GUARANTEES they contain no recognized
# substring, with no Hypothesis filtering required.
_NON_ID_ALPHABET = "".join(
    c for c in (string.ascii_letters + string.digits + "_") if c.lower() != "d"
)
_non_recognized_key = st.text(alphabet=_NON_ID_ALPHABET, min_size=1, max_size=10)

# Identifier-pattern values recognized by ``_determine_id_type``: all-digit
# sequential ids and UUIDs (the "including UUIDs" case of Requirement 30.1).
_digit_value = st.integers(min_value=0, max_value=10_000_000).map(str)
_uuid_value = st.uuids().map(str)
_id_pattern_value = st.one_of(_digit_value, _uuid_value)


# ===========================================================================
# Property 17: Identifier predictability classification is correct.
# ===========================================================================


@settings(max_examples=150)
@given(st.lists(st.integers(min_value=0, max_value=10**15).map(str),
                min_size=1, max_size=8))
def test_all_digit_identifiers_are_predictable(samples):
    # Feature: owasp-auth-modules-hardening, Property 17: Identifier predictability classification is correct
    assessment = _MODULE.analyze_identifier_predictability(samples)

    # Every all-digit scheme is enumerable: it resolves to a sequential-integer
    # or (for epoch-like values) a timestamp-based scheme, and is predictable
    # (Requirements 30.4, 30.5).
    assert assessment.scheme in ("sequential-integer", "timestamp-based")
    assert assessment.predictable is True


# Plausible Unix epoch seconds window used by the module (~2001 .. 2100).
_epoch_seconds = st.integers(min_value=1_000_000_000, max_value=4_102_444_800)


@settings(max_examples=150)
@given(_epoch_seconds.map(str))
def test_epoch_like_identifiers_are_timestamp_based(sample):
    # Feature: owasp-auth-modules-hardening, Property 17: Identifier predictability classification is correct
    assessment = _MODULE.analyze_identifier_predictability(sample)

    # A single value in a plausible epoch window is classified as timestamp-based
    # and predictable (Requirement 30.4).
    assert assessment.scheme == "timestamp-based"
    assert assessment.predictable is True


@settings(max_examples=150)
@given(st.lists(st.uuids(version=1).map(str), min_size=1, max_size=6))
def test_uuid_v1_identifiers_are_predictable(samples):
    # Feature: owasp-auth-modules-hardening, Property 17: Identifier predictability classification is correct
    assessment = _MODULE.analyze_identifier_predictability(samples)

    # Time-based UUIDs (version nibble 1) are partially predictable
    # (Requirement 30.4).
    assert assessment.scheme == "uuid-v1"
    assert assessment.predictable is True

    # A predictable scheme emits exactly the BOLA_PREDICTABLE_IDENTIFIER finding.
    findings = _MODULE._test_identifier_predictability(set(samples))
    assert findings
    assert all(f.category == "BOLA_PREDICTABLE_IDENTIFIER" for f in findings)
    assert all(f.owasp_category == "API1" for f in findings)


@settings(max_examples=150)
@given(st.lists(st.uuids(version=4).map(str), min_size=1, max_size=6))
def test_uuid_v4_identifiers_are_not_predictable(samples):
    # Feature: owasp-auth-modules-hardening, Property 17: Identifier predictability classification is correct
    assessment = _MODULE.analyze_identifier_predictability(samples)

    # Random UUIDs (version nibble 4) expose no exploitable structure
    # (Requirements 30.5, 30.6).
    assert assessment.scheme == "uuid-v4"
    assert assessment.predictable is False

    # predictable=False => NO predictability finding is emitted for uuid-v4.
    findings = _MODULE._test_identifier_predictability(set(samples))
    assert findings == []


# ===========================================================================
# Property 18: Harvesting collects every exposed identifier.
# ===========================================================================


@st.composite
def _harvest_case(draw):
    """Build a JSON object mixing recognized and non-recognized id fields.

    Recognized Identifying_Field names map to identifier-pattern values (digits
    or UUIDs) that MUST be collected. Non-recognized field names map to
    identifier-pattern values that MUST be ignored. All values are globally
    unique so the collected set can be compared exactly.
    """
    n_rec = draw(st.integers(min_value=1, max_value=5))
    n_non = draw(st.integers(min_value=0, max_value=5))

    rec_keys = draw(st.lists(st.sampled_from(_ID_PARAMETER_NAMES),
                             min_size=n_rec, max_size=n_rec, unique=True))
    non_keys = draw(st.lists(_non_recognized_key,
                             min_size=n_non, max_size=n_non, unique=True))

    total = len(rec_keys) + len(non_keys)
    values = draw(st.lists(_id_pattern_value, min_size=total, max_size=total,
                           unique=True))

    rec_values = values[:len(rec_keys)]
    non_values = values[len(rec_keys):]

    obj = {}
    for key, value in zip(rec_keys, rec_values):
        obj[key] = value
    for key, value in zip(non_keys, non_values):
        obj[key] = value

    # Recognized keys and non-recognized keys are disjoint by construction
    # (recognized names all contain 'id'; non-recognized names contain no 'd'),
    # so no recognized value is clobbered.
    return obj, set(rec_values)


@settings(max_examples=200)
@given(_harvest_case())
def test_extraction_collects_exactly_recognized_field_values(case):
    # Feature: owasp-auth-modules-hardening, Property 18: Harvesting collects every exposed identifier
    obj, expected = case

    endpoint = "https://api.example.com/list"
    extracted = {
        oi.value for oi in _MODULE._extract_ids_from_json(obj, endpoint)
    }

    # Every value placed under a recognized Identifying_Field is collected
    # (including UUIDs), and nothing placed under a non-recognized field is
    # collected (Requirement 30.1).
    assert extracted == expected


def _make_json_response(body_text):
    content = body_text.encode("utf-8")
    return Response(
        status_code=200,
        headers={"content-type": "application/json"},
        content=content,
        text=body_text,
        url="https://api.example.com/list",
        elapsed=0.001,
        request_method="GET",
    )


@settings(max_examples=200)
@given(_harvest_case())
def test_response_extraction_collects_exactly_recognized_field_values(case):
    # Feature: owasp-auth-modules-hardening, Property 18: Harvesting collects every exposed identifier
    obj, expected = case

    endpoint = "https://api.example.com/list"
    response = _make_json_response(json.dumps(obj))
    extracted = {
        oi.value for oi in _MODULE._extract_ids_from_response(response, endpoint)
    }

    # The response-level harvest path (used by ``_harvest_identifiers``) collects
    # exactly the values under recognized Identifying_Fields (Requirement 30.1).
    assert extracted == expected


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
