"""
SARIF Formatter

Converts APILeak security findings into a SARIF 2.1.0 document so that scan
results can be consumed by CI/CD systems and code scanning tools (e.g. GitHub
Code Scanning).

The formatter accepts a flat list of :class:`utils.findings.Finding` objects as
its primary input. For convenience it is also tolerant of an object exposing a
``findings`` attribute (such as a ``FindingsCollector``).
"""

import json
from typing import Any, Dict, List, Optional

from core.config import Severity
from utils.findings import Finding, FindingsCollector


class SARIFFormatter:
    """Format security findings as a SARIF 2.1.0 document."""

    SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    VERSION = "2.1.0"

    TOOL_NAME = "APILeak"
    TOOL_VERSION = "0.2.0"

    @staticmethod
    def severity_to_level(sev: Any) -> str:
        """Map a finding severity to a SARIF result level.

        CRITICAL/HIGH -> "error", MEDIUM -> "warning", LOW/INFO -> "note".

        Accepts either a :class:`core.config.Severity` enum or its string value
        defensively. Unknown values fall back to "note".
        """
        # Normalise to the underlying string value.
        if isinstance(sev, Severity):
            value = sev.value
        else:
            value = str(sev).upper()

        if value in (Severity.CRITICAL.value, Severity.HIGH.value):
            return "error"
        if value == Severity.MEDIUM.value:
            return "warning"
        # LOW, INFO, and anything unexpected map to the lowest level.
        return "note"

    @staticmethod
    def _coerce_findings(results: Any) -> List[Finding]:
        """Extract a list of findings from the supported input shapes."""
        if results is None:
            return []
        # An object exposing a `.findings` attribute (e.g. FindingsCollector).
        if hasattr(results, "findings"):
            return list(results.findings)
        # Assume an iterable of Finding objects.
        return list(results)

    def _build_rules(self, findings: List[Finding]) -> List[Dict[str, str]]:
        """Derive SARIF rules from the distinct OWASP categories present.

        Falls back to the finding category when no OWASP category is set so
        that every referenced ruleId has a corresponding rule definition.
        """
        rule_ids: List[str] = []
        for finding in findings:
            rule_id = finding.owasp_category or finding.category
            if rule_id and rule_id not in rule_ids:
                rule_ids.append(rule_id)

        rules: List[Dict[str, str]] = []
        for rule_id in rule_ids:
            name = FindingsCollector.OWASP_CATEGORIES.get(rule_id, rule_id)
            rules.append({"id": rule_id, "name": name})
        return rules

    def _build_result(self, finding: Finding) -> Dict[str, Any]:
        """Build a single SARIF result entry from a finding."""
        rule_id = finding.owasp_category or finding.category
        severity_value = (
            finding.severity.value
            if isinstance(finding.severity, Severity)
            else str(finding.severity)
        )

        message_text = finding.evidence or ""
        if finding.recommendation:
            message_text = f"{message_text} | Recommendation: {finding.recommendation}"

        return {
            "ruleId": rule_id,
            "level": self.severity_to_level(finding.severity),
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.endpoint}
                    }
                }
            ],
            "properties": {
                "method": finding.method,
                "owaspCategory": finding.owasp_category,
                "severity": severity_value,
                "recommendation": finding.recommendation,
            },
        }

    def format(self, results: Any) -> Dict[str, Any]:
        """Return a SARIF 2.1.0 document (dict) for the given findings.

        Args:
            results: A list of :class:`Finding` objects, or an object exposing a
                ``findings`` attribute.

        Returns:
            A JSON-serializable SARIF 2.1.0 document. Zero findings yields a
            valid document with an empty ``results`` list.
        """
        findings = self._coerce_findings(results)

        return {
            "$schema": self.SCHEMA,
            "version": self.VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "rules": self._build_rules(findings),
                        }
                    },
                    "results": [self._build_result(f) for f in findings],
                }
            ],
        }

    def to_json(self, results: Any) -> str:
        """Return the formatted SARIF document serialized as a JSON string."""
        return json.dumps(self.format(results), indent=2)
