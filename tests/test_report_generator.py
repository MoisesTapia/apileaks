"""
test_report_generator.py — Tests for ci-cd/scripts/report_generator.py

Tests cover:
- GitLabSASTGenerator: schema v15, empty findings, severity mapping, OWASP IDs,
  write atomicity on I/O error
- JUnitXMLGenerator: per-module generation (failure/skipped/no_findings),
  testsuite attributes, consolidated wrapping, pipeline_id fallback
- CSVGenerator: UTF-8 BOM, header always present, correct columns, delimiter
  handling (default, custom, multi-char fallback), RFC 4180 escaping,
  write atomicity on I/O error
- PDFGenerator: file created, size logged, >500 findings truncated, write atomicity
- ReportWriteError exception class

**Property 6: Report write atomicity** — when os.rename raises mid-write,
the final filename is never present in the output directory.
Validates: Requirements 6.6, 9.6
"""

import csv
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap — ci-cd uses a hyphen so it's not a regular Python package
# ---------------------------------------------------------------------------

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from report_generator import (  # noqa: E402
    CSVGenerator,
    GitLabSASTGenerator,
    JUnitXMLGenerator,
    PDFGenerator,
    ReportGenerator,
    ReportWriteError,
    ScanMeta,
    _REPORTLAB_AVAILABLE,
    _WEASYPRINT_AVAILABLE,
)

_PDF_AVAILABLE = _REPORTLAB_AVAILABLE or _WEASYPRINT_AVAILABLE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_scan_meta(pipeline_id: str = "pipe-001") -> ScanMeta:
    return ScanMeta(
        pipeline_id=pipeline_id,
        project_name="TestProject",
        target_url="https://api.example.com",
        scan_start="2026-07-03T00:00:00Z",
        scan_end="2026-07-03T00:05:00Z",
        apileaks_version="0.2.1",
    )


def make_finding(
    severity: str = "HIGH",
    category: str = "BOLA_OBJECT_ACCESS",
    owasp_category: str = "API1",
    endpoint: str = "/api/users/1",
    method: str = "GET",
    evidence: str = "Unauthorized access detected",
) -> dict:
    return {
        "id": str(uuid4()),
        "scan_id": "scan-1",
        "category": category,
        "owasp_category": owasp_category,
        "severity": severity,
        "endpoint": endpoint,
        "method": method,
        "status_code": 200,
        "response_size": 100,
        "response_time": 0.1,
        "evidence": evidence,
        "recommendation": "Implement authorization checks",
        "timestamp": "2026-07-03T00:01:00Z",
    }


# ===========================================================================
# TestGitLabSASTGenerator
# ===========================================================================


class TestGitLabSASTGenerator:
    def test_generates_valid_schema_v15(self, tmp_path):
        findings = [make_finding()]
        gen = GitLabSASTGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate()

        assert os.path.exists(path)
        doc = json.loads(open(path, encoding="utf-8").read())
        assert doc["version"] == "15.0.0"
        assert isinstance(doc["vulnerabilities"], list)
        assert doc["scan"]["scanner"]["version"] == "0.2.1"

    def test_empty_findings_produces_empty_vulnerabilities_array(self, tmp_path):
        gen = GitLabSASTGenerator([], make_scan_meta(), str(tmp_path))
        path = gen.generate()

        doc = json.loads(open(path, encoding="utf-8").read())
        assert doc["vulnerabilities"] == []

    def test_severity_mapping(self, tmp_path):
        findings = [make_finding(severity="CRITICAL")]
        gen = GitLabSASTGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate()

        doc = json.loads(open(path, encoding="utf-8").read())
        assert doc["vulnerabilities"][0]["severity"] == "Critical"

    def test_severity_mapping_all_levels(self, tmp_path):
        """All standard severity levels must be mapped correctly."""
        expected = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Info",
        }
        for raw, mapped in expected.items():
            findings = [make_finding(severity=raw)]
            gen = GitLabSASTGenerator(findings, make_scan_meta(), str(tmp_path))
            path = gen.generate()
            doc = json.loads(open(path, encoding="utf-8").read())
            assert doc["vulnerabilities"][0]["severity"] == mapped, (
                f"Expected {mapped!r} for severity {raw!r}"
            )

    def test_owasp_identifier_included(self, tmp_path):
        findings = [make_finding(owasp_category="API1")]
        gen = GitLabSASTGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate()

        doc = json.loads(open(path, encoding="utf-8").read())
        vuln = doc["vulnerabilities"][0]
        identifiers = vuln["identifiers"]
        assert len(identifiers) > 0
        id_names = [i["name"] for i in identifiers]
        assert any("API1:2023" in name for name in id_names)

    def test_default_owasp_when_unmapped(self, tmp_path):
        """Finding with owasp_category=None should use API0:2023."""
        finding = make_finding()
        finding["owasp_category"] = None
        gen = GitLabSASTGenerator([finding], make_scan_meta(), str(tmp_path))
        path = gen.generate()

        doc = json.loads(open(path, encoding="utf-8").read())
        vuln = doc["vulnerabilities"][0]
        identifiers = vuln["identifiers"]
        id_values = [i["value"] for i in identifiers]
        assert "API0:2023" in id_values

    def test_write_atomicity_on_io_error(self, tmp_path):
        """Property 6: final filename must NOT exist when os.rename raises OSError."""
        findings = [make_finding()]
        gen = GitLabSASTGenerator(findings, make_scan_meta(), str(tmp_path))

        with patch("os.rename", side_effect=OSError("disk full")):
            with pytest.raises(SystemExit):
                gen.generate()

        final_path = os.path.join(str(tmp_path), "gl-sast-report.json")
        assert not os.path.exists(final_path), (
            "Final report file must not exist after a failed os.rename"
        )

    def test_scan_section_has_required_fields(self, tmp_path):
        gen = GitLabSASTGenerator([], make_scan_meta(), str(tmp_path))
        path = gen.generate()
        doc = json.loads(open(path, encoding="utf-8").read())

        scan = doc["scan"]
        assert scan["type"] == "sast"
        assert scan["status"] == "success"
        assert scan["start_time"] == "2026-07-03T00:00:00Z"
        assert scan["end_time"] == "2026-07-03T00:05:00Z"


# ===========================================================================
# TestJUnitXMLGenerator
# ===========================================================================


class TestJUnitXMLGenerator:
    def test_critical_finding_is_failure(self, tmp_path):
        findings = [make_finding(severity="CRITICAL")]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("bola", findings, 1.5)

        content = open(path, encoding="utf-8").read()
        assert "<failure>" in content

    def test_high_finding_is_failure(self, tmp_path):
        findings = [make_finding(severity="HIGH")]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("auth", findings, 0.5)

        content = open(path, encoding="utf-8").read()
        assert "<failure>" in content

    def test_medium_finding_is_skipped(self, tmp_path):
        findings = [make_finding(severity="MEDIUM")]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("ssrf", findings, 2.0)

        content = open(path, encoding="utf-8").read()
        assert "<skipped>" in content
        assert "<failure>" not in content

    def test_low_finding_is_skipped(self, tmp_path):
        findings = [make_finding(severity="LOW")]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("misc", findings, 0.1)

        content = open(path, encoding="utf-8").read()
        assert "<skipped>" in content
        assert "<failure>" not in content

    def test_info_finding_is_skipped(self, tmp_path):
        findings = [make_finding(severity="INFO")]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("misc", findings, 0.1)

        content = open(path, encoding="utf-8").read()
        assert "<skipped>" in content
        assert "<failure>" not in content

    def test_no_findings_produces_no_findings_testcase(self, tmp_path):
        gen = JUnitXMLGenerator([], make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("empty_module", [], 0.0)

        content = open(path, encoding="utf-8").read()
        assert 'name="no_findings"' in content
        assert "<failure>" not in content
        assert "<skipped>" not in content

    def test_testsuite_attributes_present(self, tmp_path):
        findings = [make_finding(severity="HIGH"), make_finding(severity="MEDIUM")]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("multi", findings, 3.14)

        tree = ET.parse(path)
        suite = tree.getroot()
        assert suite.tag == "testsuite"
        for attr in ("name", "tests", "failures", "time", "timestamp"):
            assert attr in suite.attrib, f"Missing testsuite attribute: {attr}"

    def test_testsuite_name_includes_module(self, tmp_path):
        findings = [make_finding()]
        gen = JUnitXMLGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("jwt_attacks", findings, 1.0)

        tree = ET.parse(path)
        suite = tree.getroot()
        assert "jwt_attacks" in suite.attrib["name"]

    def test_consolidated_wraps_in_testsuites(self, tmp_path):
        findings_a = [make_finding(severity="CRITICAL")]
        findings_b = [make_finding(severity="MEDIUM")]
        gen = JUnitXMLGenerator(
            findings_a + findings_b, make_scan_meta(), str(tmp_path)
        )
        path_a = gen.generate_per_module("module_a", findings_a, 1.0)
        path_b = gen.generate_per_module("module_b", findings_b, 0.5)

        consolidated = gen.generate_consolidated([path_a, path_b])
        tree = ET.parse(consolidated)
        root = tree.getroot()

        assert root.tag == "testsuites"
        suites = root.findall("testsuite")
        assert len(suites) == 2

    def test_pipeline_id_fallback_to_unix_timestamp(self, tmp_path):
        """Empty pipeline_id → filename contains a digits-only timestamp portion."""
        meta = make_scan_meta(pipeline_id="")
        gen = JUnitXMLGenerator([], meta, str(tmp_path))
        path = gen.generate_per_module("fallback_test", [], 0.0)

        basename = os.path.basename(path)
        # Filename: apileak-junit-fallback_test-<digits>.xml
        # The segment after the last hyphen before .xml must be all digits
        name_no_ext = basename.rsplit(".", 1)[0]
        suffix = name_no_ext.split("-")[-1]
        assert suffix.isdigit(), (
            f"Expected a digit-only timestamp in filename, got: {basename!r}"
        )

    def test_failure_text_includes_url(self, tmp_path):
        finding = make_finding(
            severity="CRITICAL",
            endpoint="/api/secret",
            evidence="Data exposed",
        )
        gen = JUnitXMLGenerator([finding], make_scan_meta(), str(tmp_path))
        path = gen.generate_per_module("url_test", [finding], 0.0)

        content = open(path, encoding="utf-8").read()
        assert "/api/secret" in content


# ===========================================================================
# TestCSVGenerator
# ===========================================================================


class TestCSVGenerator:
    def test_utf8_bom_present(self, tmp_path):
        gen = CSVGenerator([make_finding()], make_scan_meta(), str(tmp_path))
        path = gen.generate()

        raw = open(path, "rb").read()
        assert raw[:3] == b"\xef\xbb\xbf", "First 3 bytes must be UTF-8 BOM"

    def test_header_row_always_present(self, tmp_path):
        gen = CSVGenerator([], make_scan_meta(), str(tmp_path))
        path = gen.generate()

        with open(path, encoding="utf-8-sig") as fh:
            lines = [l for l in fh.readlines() if l.strip()]
        assert len(lines) == 1, "Zero findings should produce exactly one line (header)"

    def test_columns_correct(self, tmp_path):
        gen = CSVGenerator([], make_scan_meta(), str(tmp_path))
        path = gen.generate()

        with open(path, encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh, delimiter=";")
            header = next(reader)
        assert header == CSVGenerator.COLUMNS

    def test_default_delimiter_is_semicolon(self, tmp_path):
        env_backup = os.environ.pop("APILEAK_CSV_DELIMITER", None)
        try:
            finding = make_finding(evidence="clean evidence no semicolons")
            gen = CSVGenerator([finding], make_scan_meta(), str(tmp_path))
            path = gen.generate()

            with open(path, encoding="utf-8-sig", newline="") as fh:
                reader = csv.reader(fh, delimiter=";")
                rows = list(reader)
            assert len(rows) == 2  # header + 1 data row
        finally:
            if env_backup is not None:
                os.environ["APILEAK_CSV_DELIMITER"] = env_backup

    def test_custom_single_char_delimiter(self, tmp_path):
        with patch.dict(os.environ, {"APILEAK_CSV_DELIMITER": "|"}):
            finding = make_finding(evidence="pipe safe evidence")
            gen = CSVGenerator([finding], make_scan_meta(), str(tmp_path))
            path = gen.generate()

        with open(path, encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh, delimiter="|")
            rows = list(reader)
        # header + 1 data row
        assert len(rows) == 2
        assert rows[0] == CSVGenerator.COLUMNS

    def test_multi_char_delimiter_falls_back_to_semicolon(self, tmp_path):
        with patch.dict(os.environ, {"APILEAK_CSV_DELIMITER": "||"}):
            finding = make_finding()
            gen = CSVGenerator([finding], make_scan_meta(), str(tmp_path))
            path = gen.generate()

        # File should use semicolon as delimiter (fallback)
        with open(path, encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh, delimiter=";")
            rows = list(reader)
        assert len(rows) == 2

    def test_rfc4180_escaping(self, tmp_path):
        """Evidence containing the delimiter must be double-quoted per RFC 4180."""
        finding = make_finding(evidence="field;with;semicolons")
        env_backup = os.environ.pop("APILEAK_CSV_DELIMITER", None)
        try:
            gen = CSVGenerator([finding], make_scan_meta(), str(tmp_path))
            path = gen.generate()

            raw_text = open(path, encoding="utf-8-sig").read()
            # The semicolons inside the field must be wrapped in quotes
            assert '"field;with;semicolons"' in raw_text
        finally:
            if env_backup is not None:
                os.environ["APILEAK_CSV_DELIMITER"] = env_backup

    def test_write_atomicity_on_io_error(self, tmp_path):
        """Property 6: final CSV must not exist when os.rename fails."""
        finding = make_finding()
        meta = make_scan_meta()
        gen = CSVGenerator([finding], meta, str(tmp_path))

        with patch("os.rename", side_effect=OSError("no space")):
            with pytest.raises(SystemExit):
                gen.generate()

        pipeline_id = meta.pipeline_id
        final_path = os.path.join(str(tmp_path), f"apileak-report-{pipeline_id}.csv")
        assert not os.path.exists(final_path)

    def test_findings_data_in_output(self, tmp_path):
        """Data rows should correspond to findings."""
        findings = [make_finding(severity="CRITICAL"), make_finding(severity="LOW")]
        env_backup = os.environ.pop("APILEAK_CSV_DELIMITER", None)
        try:
            gen = CSVGenerator(findings, make_scan_meta(), str(tmp_path))
            path = gen.generate()

            with open(path, encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.reader(fh, delimiter=";"))
            assert len(rows) == 3  # header + 2 findings
        finally:
            if env_backup is not None:
                os.environ["APILEAK_CSV_DELIMITER"] = env_backup


# ===========================================================================
# TestPDFGenerator
# ===========================================================================


@pytest.mark.skipif(
    not _PDF_AVAILABLE,
    reason="Neither reportlab nor weasyprint is installed",
)
class TestPDFGenerator:
    def test_pdf_file_created(self, tmp_path):
        findings = [make_finding()]
        gen = PDFGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate()

        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_pdf_logs_path_and_size(self, tmp_path, caplog):
        import logging
        findings = [make_finding()]
        gen = PDFGenerator(findings, make_scan_meta(), str(tmp_path))

        with caplog.at_level(logging.INFO):
            path = gen.generate()

        combined = caplog.text
        abs_path = os.path.abspath(path)
        assert abs_path in combined or os.path.basename(path) in combined
        assert "KB" in combined

    def test_more_than_500_findings_truncated(self, tmp_path):
        """With >500 findings, the PDF should still be generated without error."""
        findings = (
            [make_finding(severity="CRITICAL") for _ in range(5)]
            + [make_finding(severity="HIGH") for _ in range(5)]
            + [make_finding(severity="MEDIUM") for _ in range(490)]
            + [make_finding(severity="LOW") for _ in range(5)]
            + [make_finding(severity="INFO") for _ in range(5)]
        )
        assert len(findings) == 510
        gen = PDFGenerator(findings, make_scan_meta(), str(tmp_path))
        path = gen.generate()

        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_write_atomicity_on_io_error(self, tmp_path):
        """Property 6: final PDF must not exist when os.rename fails."""
        findings = [make_finding()]
        meta = make_scan_meta()
        gen = PDFGenerator(findings, meta, str(tmp_path))

        with patch("os.rename", side_effect=OSError("disk full")):
            with pytest.raises(SystemExit):
                gen.generate()

        final_path = os.path.join(str(tmp_path), f"apileak-report-{meta.pipeline_id}.pdf")
        assert not os.path.exists(final_path)


class TestPDFGeneratorNoLibs:
    """Tests that run regardless of library availability."""

    def test_raises_report_write_error_when_no_libs(self, tmp_path):
        """When neither reportlab nor weasyprint is available, raise ReportWriteError."""
        findings = [make_finding()]
        gen = PDFGenerator(findings, make_scan_meta(), str(tmp_path))

        with patch(
            "report_generator._REPORTLAB_AVAILABLE", False
        ), patch(
            "report_generator._WEASYPRINT_AVAILABLE", False
        ):
            # The generate() method should raise ReportWriteError (or SystemExit
            # depending on implementation — both are acceptable)
            with pytest.raises((ReportWriteError, SystemExit)):
                gen.generate()


# ===========================================================================
# TestReportWriteAtomicity — Property 6 consolidated
# ===========================================================================


class TestReportWriteAtomicity:
    """
    Property 6: Report write atomicity.
    For each generator, when os.rename raises OSError, the final filename
    must NOT be present in the output directory.

    Validates: Requirements 6.6, 9.6
    """

    def test_sarif_generator_atomicity(self, tmp_path):
        gen = GitLabSASTGenerator([make_finding()], make_scan_meta(), str(tmp_path))
        with patch("os.rename", side_effect=OSError("forced")):
            with pytest.raises(SystemExit):
                gen.generate()
        assert not os.path.exists(os.path.join(str(tmp_path), "gl-sast-report.json"))

    def test_junit_per_module_atomicity(self, tmp_path):
        meta = make_scan_meta()
        gen = JUnitXMLGenerator([make_finding()], meta, str(tmp_path))
        with patch("os.rename", side_effect=OSError("forced")):
            with pytest.raises(SystemExit):
                gen.generate_per_module("mod", [make_finding()], 0.0)
        xml_files = [f for f in os.listdir(str(tmp_path)) if f.endswith(".xml")]
        assert not xml_files, f"No final XML files should exist, found: {xml_files}"

    def test_csv_generator_atomicity(self, tmp_path):
        meta = make_scan_meta()
        gen = CSVGenerator([make_finding()], meta, str(tmp_path))
        with patch("os.rename", side_effect=OSError("forced")):
            with pytest.raises(SystemExit):
                gen.generate()
        final_path = os.path.join(str(tmp_path), f"apileak-report-{meta.pipeline_id}.csv")
        assert not os.path.exists(final_path)

    @pytest.mark.skipif(
        not _PDF_AVAILABLE,
        reason="Neither reportlab nor weasyprint is installed",
    )
    def test_pdf_generator_atomicity(self, tmp_path):
        meta = make_scan_meta()
        gen = PDFGenerator([make_finding()], meta, str(tmp_path))
        with patch("os.rename", side_effect=OSError("forced")):
            with pytest.raises(SystemExit):
                gen.generate()
        final_path = os.path.join(str(tmp_path), f"apileak-report-{meta.pipeline_id}.pdf")
        assert not os.path.exists(final_path)


# ===========================================================================
# TestReportWriteError
# ===========================================================================


class TestReportWriteError:
    def test_is_subclass_of_ioerror(self):
        err = ReportWriteError("test message")
        assert isinstance(err, IOError)

    def test_message_preserved(self):
        err = ReportWriteError("disk full")
        assert "disk full" in str(err)


# ===========================================================================
# TestReportGenerator (facade)
# ===========================================================================


class TestReportGenerator:
    def test_generate_all_returns_dict(self, tmp_path):
        meta = make_scan_meta()
        findings = [make_finding()]
        gen = ReportGenerator(findings, meta, meta.pipeline_id, str(tmp_path))

        with patch.dict(os.environ, {"APILEAK_REPORT_FORMATS": "sarif,csv"}):
            results = gen.generate_all()

        assert isinstance(results, dict)
        assert "sarif" in results
        assert "csv" in results

    def test_generate_all_sarif_only(self, tmp_path):
        meta = make_scan_meta()
        gen = ReportGenerator([], meta, meta.pipeline_id, str(tmp_path))

        with patch.dict(os.environ, {"APILEAK_REPORT_FORMATS": "sarif"}):
            results = gen.generate_all()

        assert set(results.keys()) == {"sarif"}

    def test_generate_all_ignores_unknown_format(self, tmp_path):
        meta = make_scan_meta()
        gen = ReportGenerator([], meta, meta.pipeline_id, str(tmp_path))

        with patch.dict(os.environ, {"APILEAK_REPORT_FORMATS": "csv,jsonlines"}):
            results = gen.generate_all()

        # Only 'csv' is known; 'jsonlines' is unknown and ignored
        assert "csv" in results
        assert "jsonlines" not in results
