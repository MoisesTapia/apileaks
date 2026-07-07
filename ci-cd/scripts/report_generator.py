#!/usr/bin/env python3
"""
report_generator.py — CI/CD Report Generator for APILeaks pipelines.

Standalone script that reads findings from JSON files in a reports/ directory
and writes output reports in multiple formats: GitLab SAST, JUnit XML, CSV, PDF.

Does NOT import from utils/ or core/ — works with plain dicts parsed from JSON.
"""

import csv
import json
import logging
import os
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# PDF library availability (try/except at import time)
# ---------------------------------------------------------------------------

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False

try:
    import weasyprint as _weasyprint
    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WEASYPRINT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ReportWriteError(IOError):
    """Raised when a report cannot be written to disk."""
    pass


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ScanMeta:
    """Metadata about a pipeline scan run."""
    pipeline_id: str
    project_name: str
    target_url: str
    scan_start: str   # ISO 8601 UTC string
    scan_end: str     # ISO 8601 UTC string
    apileaks_version: str  # from env or "unknown"
    openapi_endpoints_discovered: int = 0
    openapi_endpoints_scanned: int = 0


# ---------------------------------------------------------------------------
# Severity ordering helper
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _severity_sort_key(finding: dict) -> int:
    return _SEVERITY_ORDER.get(str(finding.get("severity", "INFO")).upper(), 99)


# ---------------------------------------------------------------------------
# GitLab SAST Generator
# ---------------------------------------------------------------------------


class GitLabSASTGenerator:
    """Generates a GitLab SAST-compatible report (gl-sast-report.json)."""

    SEVERITY_MAP = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",
    }

    OWASP_MAP = {
        "bola_testing":      "API1:2023",
        "auth_testing":      "API2:2023",
        "property_testing":  "API3:2023",
        "resource_testing":  "API4:2023",
        "function_auth":     "API5:2023",
        "ssrf_testing":      "API7:2023",
        "security_misconfig": "API8:2023",
        "inventory":         "API9:2023",
        "unsafe_consumption": "API10:2023",
        "_default":          "API0:2023",
    }

    def __init__(self, findings: list, scan_meta: ScanMeta, output_dir: str) -> None:
        self.findings = findings
        self.scan_meta = scan_meta
        self.output_dir = output_dir

    def _resolve_owasp_id(self, finding: dict) -> str:
        """Map a finding's owasp_category to an OWASP API Security ID."""
        owasp_cat = finding.get("owasp_category") or ""
        if not owasp_cat:
            return self.OWASP_MAP["_default"]
        # If the category already starts with "API", format as API#:2023
        if str(owasp_cat).upper().startswith("API"):
            # Strip any existing :year suffix, re-format
            base = str(owasp_cat).upper().split(":")[0]  # e.g. "API1"
            return f"{base}:2023"
        # Try a direct lookup in OWASP_MAP by normalized category
        key = str(owasp_cat).lower().replace(" ", "_").replace("-", "_")
        return self.OWASP_MAP.get(key, self.OWASP_MAP["_default"])

    def _map_finding(self, finding: dict) -> dict:
        severity_raw = str(finding.get("severity", "INFO")).upper()
        severity_mapped = self.SEVERITY_MAP.get(severity_raw, "Info")
        owasp_id = self._resolve_owasp_id(finding)

        return {
            "id": str(uuid.uuid4()),
            "category": "sast",
            "name": finding.get("category", "Unknown"),
            "description": finding.get("evidence", ""),
            "severity": severity_mapped,
            "confidence": "High",
            "identifiers": [
                {
                    "type": "owasp",
                    "name": owasp_id,
                    "value": owasp_id,
                    "url": "https://owasp.org/API-Security/",
                }
            ],
            "location": {
                "file": finding.get("endpoint", ""),
                "start_line": 1,
            },
            "scanner": {"id": "apileaks", "name": "APILeaks"},
        }

    def generate(self) -> str:
        """Generate gl-sast-report.json in output_dir. Returns the final path."""
        final_path = os.path.join(self.output_dir, "gl-sast-report.json")

        vulnerabilities = [self._map_finding(f) for f in self.findings]

        report = {
            "version": "15.0.0",
            "vulnerabilities": vulnerabilities,
            "scan": {
                "scanner": {
                    "id": "apileaks",
                    "name": "APILeaks",
                    "version": self.scan_meta.apileaks_version,
                },
                "type": "sast",
                "start_time": self.scan_meta.scan_start,
                "end_time": self.scan_meta.scan_end,
                "status": "success",
            },
        }

        content = json.dumps(report, indent=2, ensure_ascii=False)

        fd, tmp_path = tempfile.mkstemp(dir=self.output_dir, suffix=".tmp")
        os.close(fd)
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.rename(tmp_path, final_path)
            return final_path
        except Exception as exc:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            logging.error("Failed to write report %s: %s", final_path, exc)
            sys.exit(1)


# ---------------------------------------------------------------------------
# JUnit XML Generator
# ---------------------------------------------------------------------------


class JUnitXMLGenerator:
    """Generates JUnit-style XML reports for APILeaks findings."""

    def __init__(self, findings: list, scan_meta: ScanMeta, output_dir: str) -> None:
        self.findings = findings
        self.scan_meta = scan_meta
        self.output_dir = output_dir
        self._pipeline_id = scan_meta.pipeline_id

    def _get_pipeline_id(self) -> str:
        if self._pipeline_id:
            return self._pipeline_id
        return str(int(time.time()))

    def generate_per_module(
        self,
        module_name: str,
        module_findings: list,
        duration: float,
    ) -> str:
        """Generate a per-module JUnit XML file. Returns the final path."""
        pipeline_id = self._get_pipeline_id()
        filename = f"apileak-junit-{module_name}-{pipeline_id}.xml"
        final_path = os.path.join(self.output_dir, filename)

        # Count failures (CRITICAL + HIGH)
        failure_count = sum(
            1 for f in module_findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        )
        now_iso = datetime.now(timezone.utc).isoformat()

        suite = ET.Element(
            "testsuite",
            attrib={
                "name": f"APILeaks-{module_name}",
                "tests": str(max(len(module_findings), 1)),
                "failures": str(failure_count),
                "time": f"{duration:.2f}",
                "timestamp": now_iso,
            },
        )

        if not module_findings:
            ET.SubElement(suite, "testcase", attrib={"name": "no_findings"})
        else:
            for f in module_findings:
                severity = str(f.get("severity", "INFO")).upper()
                classname = f.get("category", "apileaks")
                name = f"{f.get('method', 'GET')} {f.get('endpoint', '/')}"
                tc = ET.SubElement(
                    suite,
                    "testcase",
                    attrib={"classname": classname, "name": name},
                )
                evidence = f.get("evidence", "")
                endpoint = f.get("endpoint", "")
                if severity in ("CRITICAL", "HIGH"):
                    failure_el = ET.SubElement(tc, "failure")
                    failure_el.text = f"{evidence}\nURL: {endpoint}"
                else:
                    skipped_el = ET.SubElement(tc, "skipped")
                    skipped_el.text = evidence

        content = ET.tostring(suite, encoding="unicode", xml_declaration=False)
        content = '<?xml version="1.0" encoding="UTF-8"?>\n' + content

        fd, tmp_path = tempfile.mkstemp(dir=self.output_dir, suffix=".tmp")
        os.close(fd)
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.rename(tmp_path, final_path)
            return final_path
        except Exception as exc:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            logging.error("Failed to write report %s: %s", final_path, exc)
            sys.exit(1)

    def generate_consolidated(self, per_module_paths: list) -> str:
        """Wrap all per-module <testsuite> elements into a <testsuites> root."""
        pipeline_id = self._get_pipeline_id()
        filename = f"apileak-junit-all-{pipeline_id}.xml"
        final_path = os.path.join(self.output_dir, filename)

        root = ET.Element("testsuites")
        for path in per_module_paths:
            try:
                tree = ET.parse(path)
                suite_el = tree.getroot()
                root.append(suite_el)
            except Exception as exc:
                logging.warning("Could not parse JUnit file %s: %s", path, exc)

        content = ET.tostring(root, encoding="unicode", xml_declaration=False)
        content = '<?xml version="1.0" encoding="UTF-8"?>\n' + content

        fd, tmp_path = tempfile.mkstemp(dir=self.output_dir, suffix=".tmp")
        os.close(fd)
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.rename(tmp_path, final_path)
            return final_path
        except Exception as exc:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            logging.error("Failed to write report %s: %s", final_path, exc)
            sys.exit(1)


# ---------------------------------------------------------------------------
# CSV Generator
# ---------------------------------------------------------------------------


class CSVGenerator:
    """Generates a semicolon-delimited CSV report with UTF-8 BOM."""

    COLUMNS = [
        "finding_id",
        "severity",
        "owasp_category",
        "endpoint",
        "method",
        "status_code",
        "parameter",
        "evidence",
        "recommendation",
        "scan_timestamp",
    ]

    def __init__(self, findings: list, scan_meta: ScanMeta, output_dir: str) -> None:
        self.findings = findings
        self.scan_meta = scan_meta
        self.output_dir = output_dir

    def _get_delimiter(self) -> str:
        raw = os.environ.get("APILEAK_CSV_DELIMITER", "")
        if raw:
            if len(raw) == 1:
                return raw
            else:
                logging.warning(
                    "APILEAK_CSV_DELIMITER value %r is not a single character; "
                    "falling back to default ';'.",
                    raw,
                )
        return ";"

    def generate(self) -> str:
        """Generate apileak-report-{pipeline_id}.csv in output_dir."""
        pipeline_id = self.scan_meta.pipeline_id or str(int(time.time()))
        filename = f"apileak-report-{pipeline_id}.csv"
        final_path = os.path.join(self.output_dir, filename)
        delimiter = self._get_delimiter()

        fd, tmp_path = tempfile.mkstemp(dir=self.output_dir, suffix=".tmp")
        os.close(fd)
        try:
            # utf-8-sig writes the BOM automatically
            with open(tmp_path, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh, delimiter=delimiter, quoting=csv.QUOTE_MINIMAL)
                writer.writerow(self.COLUMNS)
                for f in self.findings:
                    row = [
                        f.get("id", ""),
                        str(f.get("severity", "")),
                        str(f.get("owasp_category", "")),
                        f.get("endpoint", ""),
                        f.get("method", ""),
                        str(f.get("status_code", "")),
                        str(f.get("payload", "")),
                        f.get("evidence", ""),
                        f.get("recommendation", ""),
                        str(f.get("timestamp", "")),
                    ]
                    writer.writerow(row)
            os.rename(tmp_path, final_path)
            return final_path
        except Exception as exc:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            logging.error("Failed to write report %s: %s", final_path, exc)
            sys.exit(1)


# ---------------------------------------------------------------------------
# PDF Generator
# ---------------------------------------------------------------------------


class PDFGenerator:
    """Generates a PDF report using reportlab (primary) or weasyprint (fallback)."""

    _SEVERITY_ORDER = _SEVERITY_ORDER

    def __init__(self, findings: list, scan_meta: ScanMeta, output_dir: str) -> None:
        self.findings = findings
        self.scan_meta = scan_meta
        self.output_dir = output_dir

    def generate(self) -> str:
        """Generate apileak-report-{pipeline_id}.pdf in output_dir."""
        pipeline_id = self.scan_meta.pipeline_id or str(int(time.time()))
        filename = f"apileak-report-{pipeline_id}.pdf"
        final_path = os.path.join(self.output_dir, filename)

        if not _REPORTLAB_AVAILABLE and not _WEASYPRINT_AVAILABLE:
            raise ReportWriteError(
                "Neither reportlab nor weasyprint is installed; cannot generate PDF."
            )

        fd, tmp_path = tempfile.mkstemp(dir=self.output_dir, suffix=".tmp")
        os.close(fd)
        try:
            if _REPORTLAB_AVAILABLE:
                self._generate_with_reportlab(tmp_path)
            else:
                self._generate_with_weasyprint(tmp_path)
            os.rename(tmp_path, final_path)
            size_kb = os.path.getsize(final_path) / 1024
            logging.info(
                "PDF report written: %s (%.1f KB)",
                os.path.abspath(final_path),
                size_kb,
            )
            return final_path
        except (ReportWriteError, SystemExit):
            raise
        except Exception as exc:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            logging.error("Failed to write PDF report %s: %s", final_path, exc)
            sys.exit(1)

    # ------------------------------------------------------------------
    # reportlab implementation
    # ------------------------------------------------------------------

    def _generate_with_reportlab(self, out_path: str) -> None:
        MAX_FINDINGS = 500
        findings = sorted(self.findings, key=_severity_sort_key)
        omitted_count = 0

        if len(findings) > MAX_FINDINGS:
            keep = [
                f for f in findings
                if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH", "MEDIUM")
            ]
            omitted_count = len(findings) - len(keep)
            findings = keep

        doc = SimpleDocTemplate(out_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # --- Cover page ---
        story.append(Paragraph("APILeaks Security Report", styles["Title"]))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(f"<b>Project:</b> {self.scan_meta.project_name}", styles["Normal"]))
        story.append(Paragraph(f"<b>Target URL:</b> {self.scan_meta.target_url}", styles["Normal"]))
        story.append(Paragraph(f"<b>Scan Date (UTC):</b> {self.scan_meta.scan_start}", styles["Normal"]))
        story.append(Paragraph(f"<b>APILeaks Version:</b> {self.scan_meta.apileaks_version}", styles["Normal"]))
        story.append(PageBreak())

        # --- Executive summary ---
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = str(f.get("severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            story.append(
                Paragraph(f"{sev}: {counts.get(sev, 0)}", styles["Normal"])
            )
        story.append(Spacer(1, 0.2 * inch))
        story.append(PageBreak())

        # --- Findings table ---
        story.append(Paragraph("Findings", styles["Heading1"]))
        table_data = [["Severity", "Category", "Endpoint", "Method", "Evidence"]]
        for f in findings:
            row = [
                str(f.get("severity", "")),
                str(f.get("category", "")),
                str(f.get("endpoint", "")),
                str(f.get("method", "")),
                str(f.get("evidence", ""))[:100],
            ]
            table_data.append(row)

        col_widths = [1.0 * inch, 1.5 * inch, 2.0 * inch, 0.8 * inch, 2.2 * inch]
        tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.black),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), True),
        ]))
        story.append(tbl)

        if omitted_count > 0:
            story.append(Spacer(1, 0.2 * inch))
            story.append(
                Paragraph(
                    f"* {omitted_count} LOW/INFO finding(s) omitted from this table "
                    "(report exceeds 500 findings threshold).",
                    styles["Normal"],
                )
            )
        story.append(PageBreak())

        # --- Recommendations ---
        story.append(Paragraph("Recommendations", styles["Heading1"]))
        seen_recs: set = set()
        for f in findings:
            rec = f.get("recommendation", "")
            if rec and rec not in seen_recs:
                seen_recs.add(rec)
                story.append(Paragraph(f"• {rec}", styles["Normal"]))

        doc.build(story)

    # ------------------------------------------------------------------
    # weasyprint fallback
    # ------------------------------------------------------------------

    def _generate_with_weasyprint(self, out_path: str) -> None:
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = str(f.get("severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        MAX_FINDINGS = 500
        findings = sorted(self.findings, key=_severity_sort_key)
        omitted_count = 0
        if len(findings) > MAX_FINDINGS:
            keep = [
                f for f in findings
                if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH", "MEDIUM")
            ]
            omitted_count = len(findings) - len(keep)
            findings = keep

        rows_html = ""
        for f in findings:
            rows_html += (
                f"<tr>"
                f"<td>{f.get('severity','')}</td>"
                f"<td>{f.get('category','')}</td>"
                f"<td>{f.get('endpoint','')}</td>"
                f"<td>{f.get('method','')}</td>"
                f"<td>{str(f.get('evidence',''))[:100]}</td>"
                f"</tr>"
            )

        summary_html = "".join(
            f"<p>{sev}: {counts.get(sev, 0)}</p>"
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )

        footnote = ""
        if omitted_count:
            footnote = (
                f"<p>* {omitted_count} LOW/INFO finding(s) omitted "
                "(report exceeds 500 findings threshold).</p>"
            )

        html = f"""<!DOCTYPE html><html><body>
<h1>APILeaks Security Report</h1>
<p><b>Project:</b> {self.scan_meta.project_name}</p>
<p><b>Target URL:</b> {self.scan_meta.target_url}</p>
<p><b>Scan Date (UTC):</b> {self.scan_meta.scan_start}</p>
<p><b>APILeaks Version:</b> {self.scan_meta.apileaks_version}</p>
<h2>Executive Summary</h2>{summary_html}
<h2>Findings</h2>
<table border="1">
<tr><th>Severity</th><th>Category</th><th>Endpoint</th><th>Method</th><th>Evidence</th></tr>
{rows_html}
</table>
{footnote}
</body></html>"""

        _weasyprint.HTML(string=html).write_pdf(out_path)


# ---------------------------------------------------------------------------
# ReportGenerator facade
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Facade that reads APILEAK_REPORT_FORMATS and dispatches to generators."""

    def __init__(
        self,
        findings: list,
        scan_meta: ScanMeta,
        pipeline_id: str,
        output_dir: str,
    ) -> None:
        self.findings = findings
        self.scan_meta = scan_meta
        self.pipeline_id = pipeline_id
        self.output_dir = output_dir

    def generate_all(self) -> Dict[str, str]:
        """Dispatch to each requested format. Returns {format: output_path}."""
        raw_formats = os.environ.get("APILEAK_REPORT_FORMATS", "sarif,junit,csv")
        format_names = [f.strip().lower() for f in raw_formats.split(",") if f.strip()]

        results: Dict[str, str] = {}

        for fmt in format_names:
            try:
                if fmt == "sarif":
                    gen = GitLabSASTGenerator(self.findings, self.scan_meta, self.output_dir)
                    results["sarif"] = gen.generate()
                elif fmt == "junit":
                    gen = JUnitXMLGenerator(self.findings, self.scan_meta, self.output_dir)
                    path = gen.generate_per_module("all", self.findings, 0.0)
                    results["junit"] = path
                elif fmt == "csv":
                    gen = CSVGenerator(self.findings, self.scan_meta, self.output_dir)
                    results["csv"] = gen.generate()
                elif fmt == "pdf":
                    gen = PDFGenerator(self.findings, self.scan_meta, self.output_dir)
                    results["pdf"] = gen.generate()
                else:
                    logging.warning("Unknown report format: %r", fmt)
            except SystemExit:
                raise
            except Exception as exc:
                logging.error("Error generating %s report: %s", fmt, exc)

        return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import glob

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    pipeline_id = os.environ.get("APILEAK_PIPELINE_ID", str(int(time.time())))
    project_name = os.environ.get("APILEAK_PROJECT_NAME", "unknown")
    target_url = os.environ.get("APILEAK_TARGET", "unknown")
    apileaks_version = os.environ.get("APILEAK_VERSION", "unknown")

    # Load findings from reports/*.json
    all_findings: list = []
    for json_file in glob.glob("reports/*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                all_findings.extend(data)
            elif isinstance(data, dict):
                all_findings.extend(data.get("findings", []))
        except Exception as exc:
            logging.warning("Could not load %s: %s", json_file, exc)

    now_iso = datetime.now(timezone.utc).isoformat()
    scan_meta = ScanMeta(
        pipeline_id=pipeline_id,
        project_name=project_name,
        target_url=target_url,
        scan_start=now_iso,
        scan_end=now_iso,
        apileaks_version=apileaks_version,
    )

    os.makedirs("reports", exist_ok=True)
    generator = ReportGenerator(all_findings, scan_meta, pipeline_id, "reports")
    output_paths = generator.generate_all()

    for fmt, path in output_paths.items():
        print(f"{fmt}: {path}")
