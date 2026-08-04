"""
Test suite for categorization of new OWASP finding categories (v0.3.0)

Covers the new Finding_Category values introduced for the API6-API10 modules:
- FILE_PROTOCOL_ACCESS   -> CRITICAL / API7
- BUSINESS_FLOW_NO_LIMIT -> HIGH     / API6
- UNDOCUMENTED_API_VERSION -> LOW    / API9
- UNSAFE_UPSTREAM_DATA   -> HIGH     / API10

Validates: Requirements 7.1, 7.2, 7.3, 7.4
"""

import pytest
from uuid import uuid4

from utils.findings import FindingsCollector
from core.config import Severity


# (category, expected_severity, expected_owasp_category)
NEW_CATEGORY_CASES = [
    ("FILE_PROTOCOL_ACCESS", Severity.CRITICAL, "API7"),
    ("BUSINESS_FLOW_NO_LIMIT", Severity.HIGH, "API6"),
    ("UNDOCUMENTED_API_VERSION", Severity.LOW, "API9"),
    ("UNSAFE_UPSTREAM_DATA", Severity.HIGH, "API10"),
]


class TestNewFindingCategories:
    """Categorization of the new OWASP finding categories"""

    def setup_method(self):
        """Setup test fixtures"""
        self.scan_id = str(uuid4())
        self.collector = FindingsCollector(self.scan_id)

    @pytest.mark.parametrize("category,expected_severity,expected_owasp", NEW_CATEGORY_CASES)
    def test_new_category_resolves_to_expected_severity(
        self, category, expected_severity, expected_owasp
    ):
        """Each new category auto-classifies to the expected severity (Req 7.1, 7.2)"""
        finding = self.collector.add_finding(
            category=category,
            severity=None,  # force auto-classification
            endpoint=f"/api/test/{category.lower()}",
            method="GET",
            evidence=f"Evidence for {category}",
            recommendation=f"Recommendation for {category}",
        )

        assert finding.severity == expected_severity

    @pytest.mark.parametrize("category,expected_severity,expected_owasp", NEW_CATEGORY_CASES)
    def test_new_category_resolves_to_expected_owasp_category(
        self, category, expected_severity, expected_owasp
    ):
        """Each new category auto-assigns to the expected OWASP category (Req 7.3)"""
        finding = self.collector.add_finding(
            category=category,
            severity=None,
            endpoint=f"/api/test/{category.lower()}",
            method="GET",
            evidence=f"Evidence for {category}",
            recommendation=f"Recommendation for {category}",
        )

        assert finding.owasp_category == expected_owasp

    def test_severity_rules_table_contains_new_categories(self):
        """The SEVERITY_RULES table directly maps each new category (Req 7.1, 7.2)"""
        for category, expected_severity, _ in NEW_CATEGORY_CASES:
            assert category in FindingsCollector.SEVERITY_RULES
            assert FindingsCollector.SEVERITY_RULES[category] == expected_severity

    def test_category_to_owasp_table_contains_new_categories(self):
        """The CATEGORY_TO_OWASP table directly maps each new category (Req 7.3)"""
        for category, _, expected_owasp in NEW_CATEGORY_CASES:
            assert category in FindingsCollector.CATEGORY_TO_OWASP
            assert FindingsCollector.CATEGORY_TO_OWASP[category] == expected_owasp

    def test_new_categories_appear_in_owasp_coverage(self):
        """
        When findings with the new categories are present, their OWASP
        categories (API6, API7, API9, API10) are reported as tested in
        get_owasp_coverage() (Req 7.4).
        """
        for category, _, _ in NEW_CATEGORY_CASES:
            self.collector.add_finding(
                category=category,
                severity=None,
                endpoint=f"/api/test/{category.lower()}",
                method="GET",
                evidence=f"Evidence for {category}",
                recommendation=f"Recommendation for {category}",
            )

        coverage = self.collector.get_owasp_coverage()
        categories = coverage["categories"]

        for owasp_category in ("API6", "API7", "API9", "API10"):
            assert categories[owasp_category]["tested"] is True, (
                f"{owasp_category} should be marked tested"
            )
            assert categories[owasp_category]["findings_count"] >= 1
            assert owasp_category not in coverage["untested_categories"]

        # Four distinct OWASP categories should be covered by the new findings.
        assert coverage["tested_categories"] == 4

    def test_new_category_risk_levels_in_coverage(self):
        """
        Coverage risk levels reflect the severity of the new categories:
        API7 (FILE_PROTOCOL_ACCESS) is CRITICAL; API6/API10 are HIGH;
        API9 (UNDOCUMENTED_API_VERSION, LOW) is MEDIUM risk (Req 7.4).
        """
        for category, _, _ in NEW_CATEGORY_CASES:
            self.collector.add_finding(
                category=category,
                severity=None,
                endpoint=f"/api/test/{category.lower()}",
                method="GET",
                evidence=f"Evidence for {category}",
                recommendation=f"Recommendation for {category}",
            )

        categories = self.collector.get_owasp_coverage()["categories"]

        assert categories["API7"]["risk_level"] == "CRITICAL"
        assert categories["API7"]["critical_findings"] == 1
        assert categories["API6"]["risk_level"] == "HIGH"
        assert categories["API6"]["high_findings"] == 1
        assert categories["API10"]["risk_level"] == "HIGH"
        assert categories["API10"]["high_findings"] == 1
        # LOW severity finding -> category tested but no critical/high -> MEDIUM risk
        assert categories["API9"]["risk_level"] == "MEDIUM"


if __name__ == "__main__":
    pytest.main([__file__])
