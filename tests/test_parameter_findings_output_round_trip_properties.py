"""
Property-Based Tests for Parameter Machine-Readable Output Round-Trip

# Feature: parameter-fuzzing, Property 12: Machine-readable output round-trips findings

Property 12 (from design.md):
    *For any* set of parameter findings written in the selected ``csv`` or
    ``jsonl`` format, re-parsing the written output SHALL reproduce the same set
    of findings (their identifying and detection fields) that were written.

These tests use Hypothesis to generate sets of parameter
:class:`~utils.findings.Finding` objects with varied identifying fields
(``category``/``endpoint``/``method``/``status_code``) and varied
detection-signal fields (``detection_signal``, ``detection_signals``,
``reflection_location``, ``new_json_fields``, ``confirmation_status``),
deliberately covering the empty-list-vs-``None`` distinction and unicode
strings. For each generated set we write it with
:func:`~utils.discovery_output.write_parameter_findings_output` to a temp file in
BOTH supported formats (``.csv`` and ``.jsonl``), re-parse the written file with
a parser that mirrors the writer's encoding, and assert the reproduced set of
findings equals the written set (over their identifying and detection fields).

The re-parser mirrors ``utils/discovery_output.py``:

* CSV: the header is :data:`FINDING_CSV_FIELDNAMES`. List-valued fields
  (``detection_signals``/``new_json_fields``) are JSON-encoded cells, so we
  ``json.loads`` them back (this preserves the empty-list-``[]`` vs ``null``
  distinction). ``status_code`` is written via ``str(int)`` so we parse it with
  ``int``. Optional scalar string fields are written as an empty cell when
  ``None``; to keep the CSV round-trip well-defined we generate those fields as
  either ``None`` or a *non-empty* string, and map the empty cell back to
  ``None`` on parse.
* JSONL: each finding is a ``json.dumps`` object per line, so ``json.loads``
  reproduces every field (including ``null`` vs ``[]``) directly.

All generation and IO is local (a per-example ``tempfile.TemporaryDirectory``,
mirroring the discovery-output round-trip suite so no function-scoped fixture is
reused across generated inputs); the test issues no network requests and runs
fully offline.
"""

import csv
import json
import tempfile
from collections import Counter
from pathlib import Path

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from core.config import Severity
from utils.discovery_output import (
    FINDING_CSV_FIELDNAMES,
    _finding_to_output_dict,
    write_parameter_findings_output,
)
from utils.findings import Finding


# HTTP methods and finding categories drawn for the identifying fields. The
# exact values do not matter for the round-trip; variety exercises the encoders.
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Detection-signal vocabulary reflecting R3.5/R4.2/R5 (values are opaque to the
# writer, which serializes whatever strings the finding carries).
DETECTION_SIGNAL_VALUES = [
    "reflection",
    "new_json_field",
    "status_code",
    "response_size",
    "response_time",
]
REFLECTION_LOCATIONS = ["body", "header"]
CONFIRMATION_STATUSES = ["confirmed", "excluded_failed_retest"]

# Unicode-capable text. min_size defaults per-field: identifying string fields
# are non-empty (an empty CSV cell is indistinguishable from ``None``); optional
# fields are either ``None`` or non-empty text so the CSV round-trip stays
# well-defined for both formats under a single comparison.
_nonempty_text = st.text(min_size=1, max_size=24)
_optional_text = st.one_of(st.none(), _nonempty_text)
# A short list of unicode strings (possibly empty) for the list-valued fields.
_string_list = st.lists(_nonempty_text, min_size=0, max_size=4)


@composite
def parameter_finding_strategy(draw):
    """Generate a single parameter :class:`Finding` with broad field coverage.

    Only the identifying and detection-signal fields that
    :func:`write_parameter_findings_output` serializes are varied; the remaining
    mandatory :class:`Finding` fields are filled with fixed placeholders because
    they are neither written nor asserted by Property 12.

    * ``detection_signals`` is a (possibly empty) list -- exercises the
      empty-list case.
    * ``new_json_fields`` is ``None`` OR a (possibly empty) list -- exercises the
      ``null`` vs ``[]`` distinction that the JSON-encoded cells preserve.
    * ``detection_signal``/``reflection_location``/``confirmation_status`` are
      ``None`` or non-empty unicode text.
    """
    category = draw(st.sampled_from(DETECTION_SIGNAL_VALUES + ["PARAM_FINDING"]))
    endpoint = draw(_nonempty_text)
    method = draw(st.sampled_from(HTTP_METHODS))
    status_code = draw(st.integers(min_value=0, max_value=599))

    detection_signal = draw(
        st.one_of(st.none(), st.sampled_from(DETECTION_SIGNAL_VALUES))
    )
    detection_signals = draw(_string_list)
    reflection_location = draw(
        st.one_of(st.none(), st.sampled_from(REFLECTION_LOCATIONS))
    )
    new_json_fields = draw(st.one_of(st.none(), _string_list))
    confirmation_status = draw(
        st.one_of(st.none(), st.sampled_from(CONFIRMATION_STATUSES))
    )

    return Finding(
        id="fixed-id",
        scan_id="fixed-scan",
        category=category,
        owasp_category=None,
        severity=Severity.INFO,
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        response_size=0,
        response_time=0.0,
        evidence="",
        recommendation="",
        detection_signal=detection_signal,
        detection_signals=detection_signals,
        reflection_location=reflection_location,
        new_json_fields=new_json_fields,
        confirmation_status=confirmation_status,
    )


def _canonical(record: dict) -> tuple:
    """Return a hashable canonical projection of a finding's output fields.

    Both the *expected* projection (from :func:`_finding_to_output_dict`) and the
    *parsed* projection are funnelled through this so lists become tuples and the
    ``None`` vs ``[]`` distinction for ``new_json_fields`` is preserved.
    """
    new_json_fields = record["new_json_fields"]
    return (
        record["category"],
        record["endpoint"],
        record["method"],
        record["status_code"],
        record["detection_signal"],
        tuple(record["detection_signals"]),
        record["reflection_location"],
        None if new_json_fields is None else tuple(new_json_fields),
        record["confirmation_status"],
    )


def _expected_multiset(findings):
    """Canonical multiset (``Counter`` of tuples) of the written findings.

    A ``Counter`` compares as an order-independent multiset -- so it captures
    "the same set of findings" (Property 12) while still catching a dropped or
    duplicated finding. Tuples are used (not sorted lists) because canonical
    tuples mix ``str`` and ``None`` values, which are unorderable in Python 3.
    """
    return Counter(
        _canonical(_finding_to_output_dict(finding)) for finding in findings
    )


def _parse_csv(path: str):
    """Re-parse a finding CSV, mirroring the writer's encoding."""
    parsed = []
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert tuple(reader.fieldnames) == FINDING_CSV_FIELDNAMES
        for row in reader:
            parsed.append(
                {
                    "category": row["category"],
                    "endpoint": row["endpoint"],
                    "method": row["method"],
                    "status_code": int(row["status_code"]),
                    # Empty scalar cell means the source value was ``None``
                    # (generation never produces empty non-None strings).
                    "detection_signal": row["detection_signal"] or None,
                    "detection_signals": json.loads(row["detection_signals"]),
                    "reflection_location": row["reflection_location"] or None,
                    "new_json_fields": json.loads(row["new_json_fields"]),
                    "confirmation_status": row["confirmation_status"] or None,
                }
            )
    return parsed


def _parse_jsonl(path: str):
    """Re-parse a finding JSON Lines file."""
    parsed = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            parsed.append(json.loads(line))
    return parsed


def _parsed_multiset(records):
    """Canonical multiset (``Counter`` of tuples) of the re-parsed records."""
    return Counter(_canonical(record) for record in records)


@given(findings=st.lists(parameter_finding_strategy(), min_size=0, max_size=25))
@settings(max_examples=150, deadline=None)
def test_csv_findings_round_trip(findings):
    """
    # Feature: parameter-fuzzing, Property 12: Machine-readable output round-trips findings
    **Validates: Requirements 12.5**

    *For any* set of parameter findings written in ``csv`` format, re-parsing the
    written output reproduces the same set of findings over their identifying and
    detection fields.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = str(Path(tmp_dir) / "findings.csv")
        write_parameter_findings_output(findings, path)
        parsed = _parse_csv(path)

    assert _parsed_multiset(parsed) == _expected_multiset(findings)


@given(findings=st.lists(parameter_finding_strategy(), min_size=0, max_size=25))
@settings(max_examples=150, deadline=None)
def test_jsonl_findings_round_trip(findings):
    """
    # Feature: parameter-fuzzing, Property 12: Machine-readable output round-trips findings
    **Validates: Requirements 12.5**

    *For any* set of parameter findings written in ``jsonl`` format, re-parsing
    the written output reproduces the same set of findings over their identifying
    and detection fields.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = str(Path(tmp_dir) / "findings.jsonl")
        write_parameter_findings_output(findings, path)
        parsed = _parse_jsonl(path)

    assert _parsed_multiset(parsed) == _expected_multiset(findings)
