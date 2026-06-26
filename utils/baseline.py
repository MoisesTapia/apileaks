"""
Baseline Comparator

Compares the findings of a scan against a baseline of previously known findings
so that CI/CD pipelines can report and gate on only the newly introduced
findings (New_Findings).

The baseline file format reuses the existing JSON report's ``findings`` list, so
a prior scan's JSON report can be supplied directly as a baseline. Each finding
is reduced to a :class:`FindingKey` of ``(category, endpoint, method)`` for
comparison (Requirement 11.2).
"""

import json
import os
from dataclasses import dataclass
from typing import List, Set, Tuple

from core.logging import get_logger
from utils.findings import Finding


@dataclass(frozen=True)
class FindingKey:
    """Identity of a finding for baseline comparison.

    Two findings are considered the "same" finding when their category,
    endpoint, and method all match (Requirement 11.2).
    """

    category: str
    endpoint: str
    method: str


class BaselineComparator:
    """Classify scan findings as new or known relative to a baseline.

    The baseline is a set of :class:`FindingKey` values, typically loaded from a
    prior scan's JSON report via :meth:`load`.
    """

    def __init__(self):
        self.logger = get_logger(__name__)

    @staticmethod
    def key(f: Finding) -> FindingKey:
        """Build the comparison key for a finding.

        Args:
            f: A :class:`~utils.findings.Finding`.

        Returns:
            The ``(category, endpoint, method)`` :class:`FindingKey`.
        """
        return FindingKey(category=f.category, endpoint=f.endpoint, method=f.method)

    def load(self, path: str) -> Set[FindingKey]:
        """Load baseline finding keys from a JSON report file.

        The baseline file reuses the existing JSON report shape: a top-level
        object containing a ``findings`` list whose entries each expose
        ``category``, ``endpoint``, and ``method``.

        Args:
            path: Path to the baseline JSON report.

        Returns:
            A set of :class:`FindingKey` values. Returns an empty set when the
            path does not exist (Requirement 11.5), so every current finding is
            subsequently treated as a New_Finding.
        """
        if not path or not os.path.exists(path):
            self.logger.info(
                "Baseline file not found; treating all findings as new",
                path=path,
            )
            return set()

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            # An unreadable/unparseable baseline cannot establish prior knowledge;
            # treat the scan as having no baseline so all findings are new.
            self.logger.warning(
                "Baseline file could not be read; treating all findings as new",
                path=path,
                error=str(exc),
            )
            return set()

        findings = self._extract_findings(data)

        keys: Set[FindingKey] = set()
        for entry in findings:
            if not isinstance(entry, dict):
                continue
            keys.add(
                FindingKey(
                    category=entry.get("category", ""),
                    endpoint=entry.get("endpoint", ""),
                    method=entry.get("method", ""),
                )
            )

        self.logger.info(
            "Baseline loaded",
            path=path,
            baseline_findings=len(findings),
            baseline_keys=len(keys),
        )
        return keys

    @staticmethod
    def _extract_findings(data) -> list:
        """Extract the findings list from a parsed baseline document.

        Accepts either the full JSON report object (``{"findings": [...]}``) or a
        bare list of finding entries.
        """
        if isinstance(data, dict):
            findings = data.get("findings", [])
            return findings if isinstance(findings, list) else []
        if isinstance(data, list):
            return data
        return []

    def classify(
        self, findings: List[Finding], baseline: Set[FindingKey]
    ) -> Tuple[List[Finding], List[Finding]]:
        """Partition findings into new and known relative to a baseline.

        A finding whose :class:`FindingKey` is present in ``baseline`` is
        classified as known (Requirement 11.2); otherwise it is a New_Finding
        (Requirement 11.3). The two returned lists partition the input findings:
        every finding appears in exactly one list and their combined length
        equals ``len(findings)``.

        Args:
            findings: The current scan's findings.
            baseline: The set of baseline finding keys (empty set => all new).

        Returns:
            A ``(new_findings, known_findings)`` tuple.
        """
        new_findings: List[Finding] = []
        known_findings: List[Finding] = []

        for finding in findings:
            if self.key(finding) in baseline:
                known_findings.append(finding)
            else:
                new_findings.append(finding)

        self.logger.info(
            "Findings classified against baseline",
            total=len(findings),
            new=len(new_findings),
            known=len(known_findings),
        )
        return new_findings, known_findings
