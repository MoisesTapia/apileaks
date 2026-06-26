"""
Test suite for SARIFFormatter

Verifies SARIF 2.1.0 document generation: severity-to-level mapping, one result
per finding, valid empty documents, and that each result carries the affected
endpoint, HTTP method, OWASP category, and remediation recommendation.
"""

import json
from uuid import uuid4

import pytest

from core.config import Severity
from utils.findings import Finding
from utils.sarif_formatter import SARIFFormatter


def make_finding(
    category="SSRF_INTERNAL_ACCESS",
    owasp_category="API7",
    severity=Severity.HIGH,
    endpoint="/api/fetch",
    method="POST",
    evidence="Internal metadata endpoint reachable",
    recommendation="Validate and allow-list outbound URLs",
):
    """Helper to build a Finding with sensible defaults."""
    return Finding(
        id=str(uuid4()),
        scan_id="scan-1",
        category=category,
        owasp_category=owasp_category,
        severity=severity,
        endpoint=endpoint,
        method=method,
        status_code=200,
        response_size=100,
        response_time=0.1,
        evidence=evidence,
        recommendation=recommendation,
    )


class TestSeverityToLevel:
    """Severity to SARIF level mapping."""

    def test_critical_maps_to_error(self):
        assert SARIFFormatter.severity_to_level(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self):
        assert SARIFFormatter.severity_to_level(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self):
        assert SARIFFormatter.severity_to_level(Severity.MEDIUM) == "warning"

    def test_low_maps_to_note(self):
        assert SARIFFormatter.severity_to_level(Severity.LOW) == "note"

    def test_info_maps_to_note(self):
        assert SARIFFormatter.severity_to_level(Severity.INFO) == "note"

    def test_accepts_string_value(self):
        """Defensively handle a plain string severity value."""
        assert SARIFFormatter.severity_to_level("CRITICAL") == "error"
        assert SARIFFormatter.severity_to_level("MEDIUM") == "warning"
        assert SARIFFormatter.severity_to_level("INFO") == "note"


class TestFormat:
    """SARIF document generation."""

    def setup_method(self):
        self.formatter = SARIFFormatter()

    def test_empty_findings_produce_valid_document(self):
        doc = self.formatter.format([])

        assert doc["$schema"] == SARIFFormatter.SCHEMA
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_none_input_produces_valid_document(self):
        doc = self.formatter.format(None)
        assert doc["runs"][0]["results"] == []

    def test_one_result_per_finding(self):
        findings = [
            make_finding(category="SSRF_INTERNAL_ACCESS", owasp_category="API7"),
            make_finding(
                category="BOLA_ANONYMOUS_ACCESS",
                owasp_category="API1",
                severity=Severity.CRITICAL,
                endpoint="/api/users/1",
                method="GET",
            ),
            make_finding(
                category="MISSING_RATE_LIMITING",
                owasp_category="API4",
                severity=Severity.MEDIUM,
                endpoint="/api/login",
            ),
        ]

        doc = self.formatter.format(findings)
        results = doc["runs"][0]["results"]

        assert len(results) == 3

    def test_result_contains_endpoint_method_owasp_and_recommendation(self):
        finding = make_finding()
        doc = self.formatter.format([finding])
        result = doc["runs"][0]["results"][0]

        # Endpoint is carried in the location uri.
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == finding.endpoint

        # Method, OWASP category, and recommendation live in properties.
        props = result["properties"]
        assert props["method"] == finding.method
        assert props["owaspCategory"] == finding.owasp_category
        assert props["recommendation"] == finding.recommendation
        assert props["severity"] == finding.severity.value

        # ruleId reflects the OWASP category.
        assert result["ruleId"] == "API7"
        assert result["level"] == "error"
        # Recommendation is surfaced in the message text too.
        assert finding.recommendation in result["message"]["text"]

    def test_rules_derived_from_distinct_owasp_categories(self):
        findings = [
            make_finding(owasp_category="API7"),
            make_finding(owasp_category="API7"),  # duplicate category
            make_finding(owasp_category="API1", category="BOLA_ANONYMOUS_ACCESS"),
        ]
        doc = self.formatter.format(findings)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        rule_ids = [r["id"] for r in rules]
        assert rule_ids == ["API7", "API1"]
        rule_map = {r["id"]: r["name"] for r in rules}
        assert rule_map["API7"] == "Server Side Request Forgery"
        assert rule_map["API1"] == "Broken Object Level Authorization"

    def test_falls_back_to_category_when_no_owasp_category(self):
        finding = make_finding(category="CUSTOM_FINDING", owasp_category=None)
        doc = self.formatter.format([finding])
        result = doc["runs"][0]["results"][0]

        assert result["ruleId"] == "CUSTOM_FINDING"
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert "CUSTOM_FINDING" in rule_ids

    def test_document_is_json_serializable(self):
        findings = [make_finding(severity=Severity.CRITICAL)]
        json_str = self.formatter.to_json(findings)
        # Round-trip ensures serializability and validity.
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["results"][0]["properties"]["severity"] == "CRITICAL"

    def test_accepts_object_with_findings_attribute(self):
        class Holder:
            def __init__(self, findings):
                self.findings = findings

        holder = Holder([make_finding(), make_finding()])
        doc = self.formatter.format(holder)
        assert len(doc["runs"][0]["results"]) == 2
