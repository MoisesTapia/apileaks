"""
Unit tests for the additive parameter-fuzzing data-model/config fields
(tasks 4.1 and 4.2).

These tests lock in that the NEW, defaulted fields added to
``ParameterFuzzingConfig`` (core/config.py) and ``Finding`` (utils/findings.py)
resolve to their intended defaults, that pre-existing defaults are unchanged,
and that existing ``Finding`` construction paths used by other commands remain
unaffected (behavior preservation, R2.4).

Requirements: 2.4, 5.1, 6.1, 11.5
"""

import uuid

from core.config import ParameterFuzzingConfig, Severity
from utils.findings import Finding


class TestParameterFuzzingConfigDefaults:
    """ParameterFuzzingConfig NEW fields (task 4.1) resolve correctly and the
    pre-existing defaults are preserved (R5.1, R6.1, R11.5)."""

    def test_new_fields_default_correctly(self):
        config = ParameterFuzzingConfig()

        # R6.1: injection-point-driving methods default to GET + POST.
        assert config.methods == ["GET", "POST"]
        # R5.1: hit confirmation disabled unless explicitly configured.
        assert config.confirm_hits is None
        # R11.5: request budget unbounded unless explicitly configured.
        assert config.max_requests is None
        # R10.1/R10.2: in-memory candidate overrides are absent by default.
        assert config.query_candidates is None
        assert config.body_candidates is None

    def test_existing_defaults_are_preserved(self):
        """The additive fields must not have changed the prior defaults."""
        config = ParameterFuzzingConfig()

        assert config.enabled is True
        assert config.query_wordlist == "wordlists/parameters.txt"
        assert config.body_wordlist == "wordlists/parameters.txt"
        assert config.boundary_testing is True

    def test_methods_default_is_per_instance_independent(self):
        """The mutable list default must not be shared across instances."""
        first = ParameterFuzzingConfig()
        second = ParameterFuzzingConfig()

        assert first.methods == second.methods
        assert first.methods is not second.methods

        first.methods.append("PUT")
        assert second.methods == ["GET", "POST"]


class TestFindingDetectionSignalDefaults:
    """Finding NEW detection-signal fields (task 4.2) default correctly when a
    Finding is constructed without specifying them (R3.5/R4.2/R5)."""

    def _make_minimal_finding(self) -> Finding:
        """Construct a Finding supplying only the historically-required fields,
        omitting every NEW detection-signal field."""
        return Finding(
            id=str(uuid.uuid4()),
            scan_id="test-scan",
            category="PARAMETER_DISCOVERED",
            owasp_category=None,
            severity=Severity.INFO,
            endpoint="/api/resource",
            method="GET",
            status_code=200,
            response_size=123,
            response_time=0.01,
            evidence="parameter accepted",
            recommendation="review parameter handling",
        )

    def test_new_fields_default_correctly(self):
        finding = self._make_minimal_finding()

        assert finding.detection_signal is None
        assert finding.detection_signals == []
        assert finding.reflection_location is None
        assert finding.new_json_fields is None
        assert finding.confirmation_status is None

    def test_detection_signals_list_is_per_instance_independent(self):
        """The default empty list must be a fresh per-instance object so
        mutating one Finding's signals never leaks into another."""
        first = self._make_minimal_finding()
        second = self._make_minimal_finding()

        assert first.detection_signals == []
        assert second.detection_signals == []
        assert first.detection_signals is not second.detection_signals

        first.detection_signals.append("reflection")
        assert second.detection_signals == []


class TestFindingConstructionBehaviorPreservation:
    """R2.4: existing Finding construction paths for other commands remain
    unaffected by the additive fields."""

    def test_existing_construction_pattern_still_succeeds(self):
        """Mirror a representative existing construction site (BOLA module):
        keyword args only, no NEW detection-signal fields."""
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id="",  # set later by the findings collector
            category="BOLA_ANONYMOUS_ACCESS",
            owasp_category="API1",
            severity=Severity.CRITICAL,
            endpoint="/api/users/123",
            method="GET",
            status_code=200,
            response_size=456,
            response_time=0.02,
            evidence="Object 123 accessible without authentication.",
            recommendation="Implement proper authentication checks.",
            payload="123",
            response_snippet="{\"id\": 123}",
        )

        # Construction succeeds and legacy fields carry the supplied values.
        assert finding.category == "BOLA_ANONYMOUS_ACCESS"
        assert finding.owasp_category == "API1"
        assert finding.severity == Severity.CRITICAL
        assert finding.payload == "123"
        assert finding.response_snippet == "{\"id\": 123}"

        # __post_init__ defaults still apply for the legacy optional fields.
        assert finding.headers == {}
        assert finding.timestamp is not None

        # And the NEW detection-signal fields default without being specified.
        assert finding.detection_signal is None
        assert finding.detection_signals == []
        assert finding.reflection_location is None
        assert finding.new_json_fields is None
        assert finding.confirmation_status is None
