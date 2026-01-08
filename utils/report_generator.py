"""
Report Generator
Multi-format report generation for scan results with enterprise-grade features
"""

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from xml.dom import minidom
import base64
import hashlib

from core.logging import get_logger


class ReportGenerator:
    """
    Enterprise-grade Report Generator for multi-format output
    
    Generates comprehensive security reports in XML (Nessus/Burp compatible), 
    JSON (automation-ready), HTML (interactive), and TXT (human-readable) formats
    with precise timestamps, complete metadata, and OWASP API Security Top 10 mapping
    """
    
    def __init__(self, template_dir: str = "templates"):
        """
        Initialize Report Generator
        
        Args:
            template_dir: Directory containing report templates
        """
        self.template_dir = Path(template_dir)
        self.logger = get_logger(__name__)
        
        # Ensure templates directory exists
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # OWASP API Security Top 10 2023 mapping for reports
        self.owasp_categories = {
            "API1": "Broken Object Level Authorization",
            "API2": "Broken Authentication", 
            "API3": "Broken Object Property Level Authorization",
            "API4": "Unrestricted Resource Consumption",
            "API5": "Broken Function Level Authorization",
            "API6": "Unrestricted Access to Sensitive Business Flows",
            "API7": "Server Side Request Forgery",
            "API8": "Security Misconfiguration",
            "API9": "Improper Inventory Management",
            "API10": "Unsafe Consumption of APIs"
        }
        
        self.logger.info("Enterprise Report Generator initialized", 
                        template_dir=template_dir,
                        supported_formats=["XML", "JSON", "HTML", "TXT"])
    
    def generate_xml_report(self, results: Any) -> str:
        """
        Generate XML report compatible with Nessus and Burp Suite
        
        Produces enterprise-grade XML format with complete vulnerability details,
        CVSS-like scoring, and metadata compatible with security tools
        
        Args:
            results: Scan results
            
        Returns:
            XML report content compatible with security tools
        """
        self.logger.info("Generating enterprise XML report compatible with Nessus/Burp Suite")
        
        # Create root element with proper namespaces
        root = ET.Element("apileak_report")
        root.set("version", "1.0")
        root.set("xmlns", "http://apileak.security/schema/v1")
        root.set("generated_by", "APILeak v0.1.0")
        
        # Scan metadata section
        scan_info = ET.SubElement(root, "scan_info")
        ET.SubElement(scan_info, "scan_id").text = results.scan_id
        ET.SubElement(scan_info, "timestamp").text = results.timestamp.isoformat() + "Z"
        ET.SubElement(scan_info, "target").text = results.target_url
        ET.SubElement(scan_info, "duration_seconds").text = str(
            results.performance_metrics.duration.total_seconds() if results.performance_metrics.duration else 0
        )
        ET.SubElement(scan_info, "tool_version").text = "APILeak v0.1.0"
        ET.SubElement(scan_info, "scan_type").text = "API Security Assessment"
        
        # Statistics section
        statistics = ET.SubElement(root, "statistics")
        ET.SubElement(statistics, "total_findings").text = str(results.statistics.findings_count)
        ET.SubElement(statistics, "critical_findings").text = str(results.statistics.critical_findings)
        ET.SubElement(statistics, "high_findings").text = str(results.statistics.high_findings)
        ET.SubElement(statistics, "medium_findings").text = str(results.statistics.medium_findings)
        ET.SubElement(statistics, "low_findings").text = str(results.statistics.low_findings)
        ET.SubElement(statistics, "info_findings").text = str(results.statistics.info_findings)
        ET.SubElement(statistics, "total_requests").text = str(results.statistics.total_requests)
        ET.SubElement(statistics, "endpoints_discovered").text = str(results.statistics.endpoints_discovered)
        
        # Performance metrics
        performance = ET.SubElement(root, "performance_metrics")
        ET.SubElement(performance, "requests_per_second").text = str(results.performance_metrics.requests_per_second)
        ET.SubElement(performance, "average_response_time").text = str(results.performance_metrics.average_response_time)
        
        # OWASP coverage section
        if hasattr(results, 'findings_collector') and results.findings_collector:
            owasp_coverage = results.findings_collector.get_owasp_coverage()
            coverage_elem = ET.SubElement(root, "owasp_coverage")
            ET.SubElement(coverage_elem, "tested_categories").text = str(owasp_coverage["tested_categories"])
            ET.SubElement(coverage_elem, "total_categories").text = str(owasp_coverage["total_categories"])
            ET.SubElement(coverage_elem, "coverage_percentage").text = f"{owasp_coverage['coverage_percentage']:.1f}"
            
            # Individual category coverage
            categories_elem = ET.SubElement(coverage_elem, "categories")
            for category, data in owasp_coverage["categories"].items():
                cat_elem = ET.SubElement(categories_elem, "category")
                cat_elem.set("id", category)
                ET.SubElement(cat_elem, "name").text = data["description"]
                ET.SubElement(cat_elem, "tested").text = str(data["tested"]).lower()
                ET.SubElement(cat_elem, "findings_count").text = str(data["findings_count"])
                ET.SubElement(cat_elem, "risk_level").text = data["risk_level"]
        
        # Findings section (Nessus/Burp compatible format)
        findings_elem = ET.SubElement(root, "findings")
        
        findings_list = []
        if hasattr(results, 'findings_collector') and results.findings_collector:
            findings_list = results.findings_collector.get_prioritized_findings()
        elif hasattr(results, 'findings') and results.findings:
            findings_list = results.findings
        
        for finding in findings_list:
            finding_elem = ET.SubElement(findings_elem, "finding")
            finding_elem.set("id", finding.id)
            
            # Basic finding information
            ET.SubElement(finding_elem, "category").text = finding.category
            ET.SubElement(finding_elem, "owasp_category").text = finding.owasp_category or "N/A"
            ET.SubElement(finding_elem, "severity").text = finding.severity.value
            ET.SubElement(finding_elem, "endpoint").text = finding.endpoint
            ET.SubElement(finding_elem, "method").text = finding.method
            ET.SubElement(finding_elem, "status_code").text = str(finding.status_code)
            ET.SubElement(finding_elem, "timestamp").text = finding.timestamp.isoformat() + "Z"
            
            # Evidence and recommendation (CDATA for special characters)
            evidence_elem = ET.SubElement(finding_elem, "evidence")
            evidence_elem.text = finding.evidence
            
            recommendation_elem = ET.SubElement(finding_elem, "recommendation")
            recommendation_elem.text = finding.recommendation
            
            # Additional metadata
            metadata_elem = ET.SubElement(finding_elem, "metadata")
            ET.SubElement(metadata_elem, "response_size").text = str(finding.response_size)
            ET.SubElement(metadata_elem, "response_time").text = str(finding.response_time)
            
            if finding.payload:
                ET.SubElement(metadata_elem, "payload").text = finding.payload
            
            if finding.response_snippet:
                snippet_elem = ET.SubElement(metadata_elem, "response_snippet")
                snippet_elem.text = finding.response_snippet
            
            # Headers
            if finding.headers:
                headers_elem = ET.SubElement(metadata_elem, "headers")
                for header_name, header_value in finding.headers.items():
                    header_elem = ET.SubElement(headers_elem, "header")
                    header_elem.set("name", header_name)
                    header_elem.text = header_value
        
        # Discovered endpoints section
        if hasattr(results, 'discovered_endpoints') and results.discovered_endpoints:
            endpoints_elem = ET.SubElement(root, "discovered_endpoints")
            for endpoint in results.discovered_endpoints:
                ep_elem = ET.SubElement(endpoints_elem, "endpoint")
                ET.SubElement(ep_elem, "url").text = endpoint.url
                ET.SubElement(ep_elem, "method").text = endpoint.method
                ET.SubElement(ep_elem, "status_code").text = str(endpoint.status_code)
                ET.SubElement(ep_elem, "response_size").text = str(endpoint.response_size)
                ET.SubElement(ep_elem, "response_time").text = str(endpoint.response_time)
                if hasattr(endpoint, 'discovered_via'):
                    ET.SubElement(ep_elem, "discovered_via").text = endpoint.discovered_via
        
        # Convert to pretty-printed XML string
        xml_str = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ")
        
        # Remove empty lines and fix encoding declaration
        lines = [line for line in pretty_xml.split('\n') if line.strip()]
        lines[0] = '<?xml version="1.0" encoding="UTF-8"?>'
        
        return '\n'.join(lines)
    
    def generate_json_report(self, results: Any) -> str:
        """
        Generate structured JSON report for automation and integration
        
        Produces machine-readable JSON with complete metadata, structured findings,
        and comprehensive metrics suitable for CI/CD integration and automated processing
        
        Args:
            results: Scan results
            
        Returns:
            JSON report content with structured metadata
        """
        self.logger.info("Generating structured JSON report for automation")
        
        # Get discovered endpoints with detailed information
        discovered_endpoints = []
        if hasattr(results, 'discovered_endpoints') and results.discovered_endpoints:
            for endpoint in results.discovered_endpoints:
                endpoint_data = {
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "status_code": endpoint.status_code,
                    "response_size": endpoint.response_size,
                    "response_time": endpoint.response_time,
                    "discovered_via": getattr(endpoint, 'discovered_via', 'unknown'),
                    "endpoint_type": getattr(endpoint, 'endpoint_type', 'standard'),
                    "auth_required": getattr(endpoint, 'auth_required', False)
                }
                
                # Add status classification
                if hasattr(endpoint, 'status'):
                    endpoint_data["status"] = endpoint.status.value if hasattr(endpoint.status, 'value') else str(endpoint.status)
                else:
                    # Classify based on status code
                    if 200 <= endpoint.status_code < 300:
                        endpoint_data["status"] = "valid"
                    elif endpoint.status_code in [401, 403]:
                        endpoint_data["status"] = "auth_required"
                    elif endpoint.status_code == 404:
                        endpoint_data["status"] = "not_found"
                    else:
                        endpoint_data["status"] = "other"
                
                discovered_endpoints.append(endpoint_data)
        
        # Get fuzzing results with detailed breakdown
        fuzzing_details = {}
        parameter_details = []
        
        if hasattr(results, 'fuzzing_results') and results.fuzzing_results:
            fuzzing_details = {
                "endpoints_tested": results.fuzzing_results.get("endpoints_tested", 0),
                "endpoints_discovered": results.fuzzing_results.get("endpoints_discovered", 0),
                "parameters_tested": results.fuzzing_results.get("parameters_tested", 0),
                "headers_tested": results.fuzzing_results.get("headers_tested", 0),
                "total_requests": results.fuzzing_results.get("total_requests", 0),
                "success_rate": results.fuzzing_results.get("success_rate", 0.0)
            }
            
            # Include parameter testing details if available
            if 'parameter_details' in results.fuzzing_results:
                parameter_details = results.fuzzing_results['parameter_details']
        
        # Get OWASP coverage analysis
        owasp_coverage = {}
        if hasattr(results, 'findings_collector') and results.findings_collector:
            owasp_coverage = results.findings_collector.get_owasp_coverage()
        
        # Get findings with complete details
        findings_data = []
        findings_list = []
        
        if hasattr(results, 'findings_collector') and results.findings_collector:
            findings_list = results.findings_collector.get_prioritized_findings()
        elif hasattr(results, 'findings') and results.findings:
            findings_list = results.findings
        
        for finding in findings_list:
            finding_data = {
                "id": finding.id,
                "scan_id": finding.scan_id,
                "category": finding.category,
                "owasp_category": finding.owasp_category,
                "owasp_description": self.owasp_categories.get(finding.owasp_category, "Unknown") if finding.owasp_category else None,
                "severity": finding.severity.value,
                "endpoint": finding.endpoint,
                "method": finding.method,
                "status_code": finding.status_code,
                "response_size": finding.response_size,
                "response_time": finding.response_time,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "timestamp": finding.timestamp.isoformat() + "Z",
                "metadata": {
                    "payload": finding.payload,
                    "response_snippet": finding.response_snippet,
                    "headers": finding.headers or {}
                }
            }
            findings_data.append(finding_data)
        
        # Build comprehensive report structure
        report_data = {
            "report_metadata": {
                "format": "JSON",
                "version": "1.0",
                "generated_by": "APILeak v0.1.0",
                "generated_at": datetime.now().isoformat() + "Z",
                "schema_version": "apileak-v1.0"
            },
            "scan_info": {
                "scan_id": results.scan_id,
                "timestamp": results.timestamp.isoformat() + "Z",
                "target": results.target_url,
                "duration_seconds": results.performance_metrics.duration.total_seconds() if results.performance_metrics.duration else 0,
                "scan_type": "API Security Assessment"
            },
            "statistics": {
                "findings": {
                    "total": results.statistics.findings_count,
                    "by_severity": {
                        "critical": results.statistics.critical_findings,
                        "high": results.statistics.high_findings,
                        "medium": results.statistics.medium_findings,
                        "low": results.statistics.low_findings,
                        "info": results.statistics.info_findings
                    }
                },
                "testing": {
                    "total_requests": results.statistics.total_requests,
                    "endpoints_discovered": results.statistics.endpoints_discovered,
                    "unique_endpoints_tested": len(set(f.endpoint for f in findings_list)) if findings_list else 0
                }
            },
            "performance_metrics": {
                "requests_per_second": results.performance_metrics.requests_per_second,
                "average_response_time": results.performance_metrics.average_response_time,
                "start_time": results.performance_metrics.start_time.isoformat() + "Z",
                "end_time": results.performance_metrics.end_time.isoformat() + "Z" if results.performance_metrics.end_time else None
            },
            "owasp_coverage": owasp_coverage,
            "discovered_endpoints": discovered_endpoints,
            "fuzzing_details": fuzzing_details,
            "parameter_testing_details": parameter_details,
            "findings": findings_data,
            "summary": {
                "risk_assessment": self._calculate_risk_assessment(results.statistics),
                "top_vulnerabilities": self._get_top_vulnerability_categories(findings_list),
                "recommendations": self._generate_summary_recommendations(findings_list)
            }
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _calculate_risk_assessment(self, statistics) -> str:
        """Calculate overall risk assessment based on findings"""
        if statistics.critical_findings > 0:
            return "CRITICAL"
        elif statistics.high_findings > 0:
            return "HIGH"
        elif statistics.medium_findings > 0:
            return "MEDIUM"
        elif statistics.low_findings > 0:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_top_vulnerability_categories(self, findings_list) -> List[Dict[str, Any]]:
        """Get top vulnerability categories by frequency and severity"""
        category_counts = {}
        for finding in findings_list:
            category = finding.owasp_category or finding.category
            if category not in category_counts:
                category_counts[category] = {"count": 0, "critical": 0, "high": 0}
            category_counts[category]["count"] += 1
            if finding.severity.value == "CRITICAL":
                category_counts[category]["critical"] += 1
            elif finding.severity.value == "HIGH":
                category_counts[category]["high"] += 1
        
        # Sort by critical findings first, then by total count
        sorted_categories = sorted(
            category_counts.items(),
            key=lambda x: (x[1]["critical"], x[1]["high"], x[1]["count"]),
            reverse=True
        )
        
        return [
            {
                "category": cat,
                "description": self.owasp_categories.get(cat, cat),
                "total_findings": data["count"],
                "critical_findings": data["critical"],
                "high_findings": data["high"]
            }
            for cat, data in sorted_categories[:5]  # Top 5
        ]
    
    def _generate_summary_recommendations(self, findings_list) -> List[str]:
        """Generate high-level recommendations based on findings"""
        recommendations = []
        
        # Check for common vulnerability patterns
        categories = set(f.owasp_category or f.category for f in findings_list)
        
        if "API1" in categories:
            recommendations.append("Implement proper object-level authorization checks")
        if "API2" in categories:
            recommendations.append("Strengthen authentication mechanisms and token validation")
        if "API3" in categories:
            recommendations.append("Review data exposure and implement property-level authorization")
        if "API5" in categories:
            recommendations.append("Implement function-level authorization controls")
        if "API7" in categories:
            recommendations.append("Validate and sanitize all user inputs to prevent SSRF")
        
        # Add general recommendations if no specific patterns found
        if not recommendations:
            recommendations.extend([
                "Review API security configuration",
                "Implement comprehensive input validation",
                "Add security headers and CORS policies"
            ])
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def generate_html_report(self, results: Any) -> str:
        """
        Generate interactive HTML report with charts and navigation
        
        Creates a comprehensive, interactive HTML report with JavaScript charts,
        responsive design, and detailed vulnerability analysis suitable for
        executive and technical audiences
        
        Args:
            results: Scan results
            
        Returns:
            Interactive HTML report content
        """
        self.logger.info("Generating interactive HTML report with charts")
        
        # Get findings and statistics
        findings_list = []
        if hasattr(results, 'findings_collector') and results.findings_collector:
            findings_list = results.findings_collector.get_prioritized_findings()
            owasp_coverage = results.findings_collector.get_owasp_coverage()
        elif hasattr(results, 'findings') and results.findings:
            findings_list = results.findings
            owasp_coverage = {"categories": {}, "coverage_percentage": 0}
        else:
            owasp_coverage = {"categories": {}, "coverage_percentage": 0}
        
        # Prepare data for charts
        severity_data = {
            "Critical": results.statistics.critical_findings,
            "High": results.statistics.high_findings,
            "Medium": results.statistics.medium_findings,
            "Low": results.statistics.low_findings,
            "Info": results.statistics.info_findings
        }
        
        # OWASP category data
        owasp_data = {}
        for category, data in owasp_coverage.get("categories", {}).items():
            if data.get("tested", False):
                owasp_data[f"{category}: {data['description'][:30]}..."] = data["findings_count"]
        
        # Generate findings table HTML
        findings_html = self._generate_findings_table_html(findings_list)
        
        # Generate endpoints table HTML
        endpoints_html = self._generate_endpoints_table_html(results)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary_html(results, findings_list)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APILeak Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .meta-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 5px;
        }}
        
        .meta-item strong {{
            display: block;
            font-size: 1.2em;
            margin-bottom: 5px;
        }}
        
        .nav-tabs {{
            display: flex;
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .nav-tab {{
            flex: 1;
            padding: 15px 20px;
            background: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
            transition: all 0.3s ease;
        }}
        
        .nav-tab:hover {{
            background: #f8f9fa;
        }}
        
        .nav-tab.active {{
            background: #667eea;
            color: white;
        }}
        
        .tab-content {{
            display: none;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        
        .stat-card.critical {{ border-left-color: #dc3545; }}
        .stat-card.high {{ border-left-color: #fd7e14; }}
        .stat-card.medium {{ border-left-color: #ffc107; }}
        .stat-card.low {{ border-left-color: #28a745; }}
        .stat-card.info {{ border-left-color: #17a2b8; }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .chart-container {{
            position: relative;
            height: 400px;
            margin: 30px 0;
        }}
        
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .findings-table th,
        .findings-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        
        .findings-table th {{
            background-color: #f8f9fa;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        
        .findings-table tr:hover {{
            background-color: #f8f9fa;
        }}
        
        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #28a745; color: white; }}
        .severity-info {{ background: #17a2b8; color: white; }}
        
        .owasp-badge {{
            background: #6f42c1;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.7em;
            font-weight: bold;
        }}
        
        .executive-summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
        }}
        
        .risk-indicator {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-medium {{ background: #ffc107; color: black; }}
        .risk-low {{ background: #28a745; color: white; }}
        .risk-minimal {{ background: #6c757d; color: white; }}
        
        .recommendations {{
            background: #e7f3ff;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
        }}
        
        .recommendations li {{
            margin-bottom: 10px;
        }}
        
        @media (max-width: 768px) {{
            .nav-tabs {{
                flex-direction: column;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header .meta {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 APILeak Security Assessment</h1>
            <p>Comprehensive API Security Analysis Report</p>
            <div class="meta">
                <div class="meta-item">
                    <strong>Target</strong>
                    {results.target_url}
                </div>
                <div class="meta-item">
                    <strong>Scan ID</strong>
                    {results.scan_id}
                </div>
                <div class="meta-item">
                    <strong>Generated</strong>
                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </div>
                <div class="meta-item">
                    <strong>Duration</strong>
                    {results.performance_metrics.duration.total_seconds() if results.performance_metrics.duration else 0:.1f}s
                </div>
            </div>
        </div>
        
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('summary')">Executive Summary</button>
            <button class="nav-tab" onclick="showTab('findings')">Security Findings</button>
            <button class="nav-tab" onclick="showTab('endpoints')">Discovered Endpoints</button>
            <button class="nav-tab" onclick="showTab('owasp')">OWASP Coverage</button>
        </div>
        
        <div id="summary" class="tab-content active">
            {executive_summary}
            
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{results.statistics.critical_findings}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{results.statistics.high_findings}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{results.statistics.medium_findings}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{results.statistics.low_findings}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{results.statistics.info_findings}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <div id="findings" class="tab-content">
            <h2>Security Findings ({len(findings_list)} total)</h2>
            {findings_html}
        </div>
        
        <div id="endpoints" class="tab-content">
            <h2>Discovered Endpoints ({results.statistics.endpoints_discovered} total)</h2>
            {endpoints_html}
        </div>
        
        <div id="owasp" class="tab-content">
            <h2>OWASP API Security Top 10 Coverage</h2>
            <p>Coverage: <strong>{owasp_coverage.get('coverage_percentage', 0):.1f}%</strong> 
               ({owasp_coverage.get('tested_categories', 0)}/{owasp_coverage.get('total_categories', 10)} categories tested)</p>
            
            <div class="chart-container">
                <canvas id="owaspChart"></canvas>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {{
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.nav-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }}
        
        // Initialize charts
        document.addEventListener('DOMContentLoaded', function() {{
            // Severity distribution chart
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            new Chart(severityCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {list(severity_data.keys())},
                    datasets: [{{
                        data: {list(severity_data.values())},
                        backgroundColor: [
                            '#dc3545',  // Critical
                            '#fd7e14',  // High
                            '#ffc107',  // Medium
                            '#28a745',  // Low
                            '#17a2b8'   // Info
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Findings by Severity',
                            font: {{ size: 16, weight: 'bold' }}
                        }},
                        legend: {{
                            position: 'bottom',
                            labels: {{ padding: 20 }}
                        }}
                    }}
                }}
            }});
            
            // OWASP coverage chart
            const owaspCtx = document.getElementById('owaspChart').getContext('2d');
            new Chart(owaspCtx, {{
                type: 'bar',
                data: {{
                    labels: {list(owasp_data.keys()) if owasp_data else ['No OWASP findings']},
                    datasets: [{{
                        label: 'Findings Count',
                        data: {list(owasp_data.values()) if owasp_data else [0]},
                        backgroundColor: '#667eea',
                        borderColor: '#5a67d8',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'OWASP API Security Top 10 Findings',
                            font: {{ size: 16, weight: 'bold' }}
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{ stepSize: 1 }}
                        }}
                    }}
                }}
            }});
        }});
    </script>
</body>
</html>"""
        
        return html_content
    
    def _generate_findings_table_html(self, findings_list) -> str:
        """Generate HTML table for findings"""
        if not findings_list:
            return "<p>No security findings detected.</p>"
        
        html = """
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>OWASP</th>
                    <th>Endpoint</th>
                    <th>Method</th>
                    <th>Evidence</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for finding in findings_list:
            severity_class = f"severity-{finding.severity.value.lower()}"
            evidence_preview = finding.evidence[:100] + "..." if len(finding.evidence) > 100 else finding.evidence
            recommendation_preview = finding.recommendation[:100] + "..." if len(finding.recommendation) > 100 else finding.recommendation
            
            html += f"""
                <tr>
                    <td><span class="severity-badge {severity_class}">{finding.severity.value}</span></td>
                    <td>{finding.category}</td>
                    <td>{f'<span class="owasp-badge">{finding.owasp_category}</span>' if finding.owasp_category else 'N/A'}</td>
                    <td><code>{finding.endpoint}</code></td>
                    <td><strong>{finding.method}</strong></td>
                    <td title="{finding.evidence}">{evidence_preview}</td>
                    <td title="{finding.recommendation}">{recommendation_preview}</td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
        
        return html
    
    def _generate_endpoints_table_html(self, results) -> str:
        """Generate HTML table for discovered endpoints"""
        if not hasattr(results, 'discovered_endpoints') or not results.discovered_endpoints:
            return "<p>No endpoints were discovered during the scan.</p>"
        
        html = """
        <table class="findings-table">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Status Code</th>
                    <th>Response Size</th>
                    <th>Response Time</th>
                    <th>Discovered Via</th>
                    <th>Auth Required</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for endpoint in results.discovered_endpoints:
            status_class = ""
            if 200 <= endpoint.status_code < 300:
                status_class = "severity-low"  # Green for success
            elif endpoint.status_code in [401, 403]:
                status_class = "severity-medium"  # Yellow for auth required
            elif endpoint.status_code >= 400:
                status_class = "severity-high"  # Orange for errors
            
            auth_required = getattr(endpoint, 'auth_required', False)
            discovered_via = getattr(endpoint, 'discovered_via', 'unknown')
            
            html += f"""
                <tr>
                    <td><code>{endpoint.url}</code></td>
                    <td><strong>{endpoint.method}</strong></td>
                    <td><span class="severity-badge {status_class}">{endpoint.status_code}</span></td>
                    <td>{endpoint.response_size} bytes</td>
                    <td>{endpoint.response_time:.3f}s</td>
                    <td>{discovered_via}</td>
                    <td>{'Yes' if auth_required else 'No'}</td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
        
        return html
    
    def _generate_executive_summary_html(self, results, findings_list) -> str:
        """Generate executive summary HTML"""
        risk_assessment = self._calculate_risk_assessment(results.statistics)
        risk_class = f"risk-{risk_assessment.lower()}"
        
        # Calculate key metrics
        total_findings = results.statistics.findings_count
        critical_high = results.statistics.critical_findings + results.statistics.high_findings
        
        # Get top vulnerability categories
        top_vulns = self._get_top_vulnerability_categories(findings_list)
        
        # Generate recommendations
        recommendations = self._generate_summary_recommendations(findings_list)
        
        html = f"""
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> <span class="risk-indicator {risk_class}">{risk_assessment}</span></p>
            
            <p>This API security assessment identified <strong>{total_findings}</strong> total findings, 
            with <strong>{critical_high}</strong> requiring immediate attention (Critical/High severity).</p>
            
            <p><strong>Key Statistics:</strong></p>
            <ul>
                <li>Total requests sent: <strong>{results.statistics.total_requests:,}</strong></li>
                <li>Endpoints discovered: <strong>{results.statistics.endpoints_discovered}</strong></li>
                <li>Average response time: <strong>{results.performance_metrics.average_response_time:.3f}s</strong></li>
                <li>Scan duration: <strong>{results.performance_metrics.duration.total_seconds() if results.performance_metrics.duration else 0:.1f}s</strong></li>
            </ul>
        """
        
        if top_vulns:
            html += "<p><strong>Top Vulnerability Categories:</strong></p><ul>"
            for vuln in top_vulns[:3]:  # Top 3
                html += f"<li><strong>{vuln['category']}</strong>: {vuln['total_findings']} findings"
                if vuln['critical_findings'] > 0:
                    html += f" ({vuln['critical_findings']} critical)"
                html += "</li>"
            html += "</ul>"
        
        if recommendations:
            html += f"""
            <div class="recommendations">
                <h3>Priority Recommendations</h3>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in recommendations)}
                </ul>
            </div>
            """
        
        html += "</div>"
        
        return html
    def generate_txt_report(self, results: Any) -> str:
        """
        Generate comprehensive human-readable text report
        
        Creates a detailed, well-formatted text report suitable for technical
        teams, with clear sections, statistics, and actionable findings
        
        Args:
            results: Scan results
            
        Returns:
            Human-readable text report content
        """
        self.logger.info("Generating comprehensive human-readable TXT report")
        
        # Get findings and statistics
        findings_list = []
        if hasattr(results, 'findings_collector') and results.findings_collector:
            findings_list = results.findings_collector.get_prioritized_findings()
            owasp_coverage = results.findings_collector.get_owasp_coverage()
        elif hasattr(results, 'findings') and results.findings:
            findings_list = results.findings
            owasp_coverage = {"categories": {}, "coverage_percentage": 0}
        else:
            owasp_coverage = {"categories": {}, "coverage_percentage": 0}
        
        # Calculate risk assessment
        risk_assessment = self._calculate_risk_assessment(results.statistics)
        
        # Get discovered endpoints with detailed breakdown
        discovered_endpoints_section = ""
        if hasattr(results, 'discovered_endpoints') and results.discovered_endpoints:
            discovered_endpoints_section = "\n" + "="*80 + "\n"
            discovered_endpoints_section += "DISCOVERED ENDPOINTS\n"
            discovered_endpoints_section += "="*80 + "\n"
            
            # Group endpoints by status
            valid_endpoints = []
            auth_required = []
            error_endpoints = []
            other_endpoints = []
            
            for endpoint in results.discovered_endpoints:
                if hasattr(endpoint, 'status_code'):
                    if 200 <= endpoint.status_code < 300:
                        valid_endpoints.append(endpoint)
                    elif endpoint.status_code in [401, 403]:
                        auth_required.append(endpoint)
                    elif endpoint.status_code >= 400:
                        error_endpoints.append(endpoint)
                    else:
                        other_endpoints.append(endpoint)
            
            if valid_endpoints:
                discovered_endpoints_section += f"\n✅ ACCESSIBLE ENDPOINTS ({len(valid_endpoints)}):\n"
                discovered_endpoints_section += "-" * 50 + "\n"
                for endpoint in valid_endpoints:
                    discovered_endpoints_section += f"  {endpoint.method:6} {endpoint.url}\n"
                    discovered_endpoints_section += f"         Status: {endpoint.status_code} | Size: {endpoint.response_size}B | Time: {endpoint.response_time:.3f}s\n"
                    if hasattr(endpoint, 'discovered_via'):
                        discovered_endpoints_section += f"         Found via: {endpoint.discovered_via}\n"
                    discovered_endpoints_section += "\n"
            
            if auth_required:
                discovered_endpoints_section += f"\n🔐 AUTHENTICATION REQUIRED ({len(auth_required)}):\n"
                discovered_endpoints_section += "-" * 50 + "\n"
                for endpoint in auth_required:
                    discovered_endpoints_section += f"  {endpoint.method:6} {endpoint.url} ({endpoint.status_code})\n"
                    if hasattr(endpoint, 'discovered_via'):
                        discovered_endpoints_section += f"         Found via: {endpoint.discovered_via}\n"
                    discovered_endpoints_section += "\n"
            
            if error_endpoints:
                discovered_endpoints_section += f"\n❌ ERROR RESPONSES ({len(error_endpoints)}):\n"
                discovered_endpoints_section += "-" * 50 + "\n"
                for endpoint in error_endpoints[:10]:  # Limit to first 10
                    discovered_endpoints_section += f"  {endpoint.method:6} {endpoint.url} ({endpoint.status_code})\n"
                if len(error_endpoints) > 10:
                    discovered_endpoints_section += f"  ... and {len(error_endpoints) - 10} more error endpoints\n"
                discovered_endpoints_section += "\n"
        
        # Get fuzzing details with comprehensive breakdown
        fuzzing_section = ""
        parameters_section = ""
        
        if hasattr(results, 'fuzzing_results') and results.fuzzing_results:
            fuzzing_section = "\n" + "="*80 + "\n"
            fuzzing_section += "FUZZING ANALYSIS\n"
            fuzzing_section += "="*80 + "\n"
            fuzzing_details = results.fuzzing_results
            
            fuzzing_section += f"Endpoints Tested: {fuzzing_details.get('endpoints_tested', 0)}\n"
            fuzzing_section += f"Parameters Tested: {fuzzing_details.get('parameters_tested', 0)}\n"
            fuzzing_section += f"Headers Tested: {fuzzing_details.get('headers_tested', 0)}\n"
            fuzzing_section += f"Total Requests: {fuzzing_details.get('total_requests', 0)}\n"
            fuzzing_section += f"Success Rate: {fuzzing_details.get('success_rate', 0.0):.1%}\n"
            
            # Add detailed parameter testing information
            if fuzzing_details.get("parameters_tested", 0) > 0:
                parameters_section = "\n" + "-" * 50 + "\n"
                parameters_section += "PARAMETER TESTING DETAILS\n"
                parameters_section += "-" * 50 + "\n"
                
                if 'parameter_details' in fuzzing_details and fuzzing_details['parameter_details']:
                    param_details = fuzzing_details['parameter_details']
                    
                    # Group by status
                    responsive_params = []
                    non_responsive_params = []
                    
                    for param_info in param_details:
                        if param_info.get('status') == 'difference_found':
                            responsive_params.append(param_info)
                        else:
                            non_responsive_params.append(param_info)
                    
                    if responsive_params:
                        parameters_section += f"\n✅ RESPONSIVE PARAMETERS ({len(responsive_params)}):\n"
                        for param_info in responsive_params:
                            param_name = param_info.get('name', 'unknown')
                            baseline_size = param_info.get('baseline_size', 0)
                            test_size = param_info.get('test_size', 0)
                            parameters_section += f"  • {param_name}: Response changed from {baseline_size}B to {test_size}B\n"
                    
                    if non_responsive_params:
                        parameters_section += f"\n❌ NON-RESPONSIVE PARAMETERS ({len(non_responsive_params)}):\n"
                        for param_info in non_responsive_params[:5]:  # Show first 5
                            param_name = param_info.get('name', 'unknown')
                            baseline_size = param_info.get('baseline_size', 0)
                            parameters_section += f"  • {param_name}: No significant response change ({baseline_size}B baseline)\n"
                        if len(non_responsive_params) > 5:
                            parameters_section += f"  ... and {len(non_responsive_params) - 5} more non-responsive parameters\n"
                else:
                    parameters_section += "No detailed parameter results available.\n"
                    parameters_section += "This usually indicates no parameters caused significant response differences.\n"
        
        # Generate OWASP coverage section
        owasp_section = ""
        if owasp_coverage.get("categories"):
            owasp_section = "\n" + "="*80 + "\n"
            owasp_section += "OWASP API SECURITY TOP 10 COVERAGE\n"
            owasp_section += "="*80 + "\n"
            owasp_section += f"Overall Coverage: {owasp_coverage.get('coverage_percentage', 0):.1f}% "
            owasp_section += f"({owasp_coverage.get('tested_categories', 0)}/{owasp_coverage.get('total_categories', 10)} categories)\n\n"
            
            # Show tested categories
            tested_categories = []
            untested_categories = []
            
            for category, data in owasp_coverage["categories"].items():
                if data.get("tested", False):
                    tested_categories.append((category, data))
                else:
                    untested_categories.append((category, data))
            
            if tested_categories:
                owasp_section += "✅ TESTED CATEGORIES:\n"
                owasp_section += "-" * 30 + "\n"
                for category, data in tested_categories:
                    owasp_section += f"  {category}: {data['description']}\n"
                    owasp_section += f"    Findings: {data['findings_count']} (Risk: {data['risk_level']})\n"
                    if data['critical_findings'] > 0:
                        owasp_section += f"    Critical: {data['critical_findings']}\n"
                    if data['high_findings'] > 0:
                        owasp_section += f"    High: {data['high_findings']}\n"
                    owasp_section += "\n"
            
            if untested_categories:
                owasp_section += "❌ UNTESTED CATEGORIES:\n"
                owasp_section += "-" * 30 + "\n"
                for category, data in untested_categories:
                    owasp_section += f"  {category}: {data['description']}\n"
                owasp_section += "\n"
        
        # Generate detailed findings section
        findings_section = ""
        if findings_list:
            findings_section = "\n" + "="*80 + "\n"
            findings_section += "SECURITY FINDINGS DETAILS\n"
            findings_section += "="*80 + "\n"
            
            # Group findings by severity
            findings_by_severity = {}
            for finding in findings_list:
                severity = finding.severity.value
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Display findings by severity (Critical first)
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            severity_icons = {
                "CRITICAL": "🚨",
                "HIGH": "⚠️",
                "MEDIUM": "⚡",
                "LOW": "ℹ️",
                "INFO": "📋"
            }
            
            for severity in severity_order:
                if severity in findings_by_severity:
                    findings_section += f"\n{severity_icons[severity]} {severity} SEVERITY ({len(findings_by_severity[severity])} findings):\n"
                    findings_section += "-" * 60 + "\n"
                    
                    for i, finding in enumerate(findings_by_severity[severity], 1):
                        findings_section += f"\n{i}. {finding.category}"
                        if finding.owasp_category:
                            findings_section += f" ({finding.owasp_category})"
                        findings_section += "\n"
                        findings_section += f"   Endpoint: {finding.method} {finding.endpoint}\n"
                        findings_section += f"   Status: {finding.status_code} | Size: {finding.response_size}B | Time: {finding.response_time:.3f}s\n"
                        findings_section += f"   Evidence: {finding.evidence}\n"
                        findings_section += f"   Recommendation: {finding.recommendation}\n"
                        
                        if finding.payload:
                            findings_section += f"   Payload: {finding.payload}\n"
                        
                        if finding.response_snippet:
                            snippet = finding.response_snippet[:200] + "..." if len(finding.response_snippet) > 200 else finding.response_snippet
                            findings_section += f"   Response: {snippet}\n"
                        
                        findings_section += f"   Timestamp: {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        
        # Generate recommendations section
        recommendations_section = ""
        if findings_list:
            recommendations = self._generate_summary_recommendations(findings_list)
            if recommendations:
                recommendations_section = "\n" + "="*80 + "\n"
                recommendations_section += "PRIORITY RECOMMENDATIONS\n"
                recommendations_section += "="*80 + "\n"
                for i, rec in enumerate(recommendations, 1):
                    recommendations_section += f"{i}. {rec}\n"
        
        # Build the complete report
        txt_content = f"""
{"="*80}
APILEAK SECURITY ASSESSMENT REPORT
{"="*80}

SCAN INFORMATION:
{"-"*20}
Scan ID:           {results.scan_id}
Target:            {results.target_url}
Timestamp:         {results.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Duration:          {results.performance_metrics.duration.total_seconds() if results.performance_metrics.duration else 0:.2f} seconds
Tool Version:      APILeak v0.1.0
Report Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

EXECUTIVE SUMMARY:
{"-"*20}
Overall Risk Level: {risk_assessment}
Total Findings:     {results.statistics.findings_count}
Critical Findings:  {results.statistics.critical_findings}
High Findings:      {results.statistics.high_findings}
Medium Findings:    {results.statistics.medium_findings}
Low Findings:       {results.statistics.low_findings}
Info Findings:      {results.statistics.info_findings}

PERFORMANCE METRICS:
{"-"*20}
Total Requests:     {results.statistics.total_requests:,}
Requests/Second:    {results.performance_metrics.requests_per_second:.2f}
Avg Response Time:  {results.performance_metrics.average_response_time:.3f}s
Endpoints Found:    {results.statistics.endpoints_discovered}
{fuzzing_section}
{parameters_section}
{discovered_endpoints_section}
{owasp_section}
{findings_section}
{recommendations_section}

{"="*80}
END OF REPORT
{"="*80}

Generated by APILeak v0.1.0 - Enterprise API Security Testing Tool
For support and documentation: https://github.com/apileak/apileak
"""
        
        return txt_content
    
    def save_reports(self, results: Any, output_dir: str, scan_type: str = "full", output_filename: str = None) -> List[str]:
        """
        Save comprehensive reports in all configured formats with precise timestamps
        
        Generates and saves reports in XML (Nessus/Burp compatible), JSON (automation-ready),
        HTML (interactive), and TXT (human-readable) formats with complete metadata
        
        Args:
            results: Scan results with findings and statistics
            output_dir: Output directory for reports
            scan_type: Type of scan (dir, param, full) for naming
            output_filename: Custom filename (without extension) for reports
            
        Returns:
            List of generated report file paths with metadata
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        generated_files = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Enhanced report generation with error handling and validation
        formats = {
            "xml": {
                "generator": self.generate_xml_report,
                "description": "XML report compatible with Nessus and Burp Suite",
                "mime_type": "application/xml"
            },
            "json": {
                "generator": self.generate_json_report,
                "description": "Structured JSON report for automation and CI/CD",
                "mime_type": "application/json"
            },
            "html": {
                "generator": self.generate_html_report,
                "description": "Interactive HTML report with charts and navigation",
                "mime_type": "text/html"
            },
            "txt": {
                "generator": self.generate_txt_report,
                "description": "Human-readable text report for technical teams",
                "mime_type": "text/plain"
            }
        }
        
        # Generate metadata file
        metadata = {
            "report_generation": {
                "timestamp": datetime.now().isoformat() + "Z",
                "tool_version": "APILeak v0.1.0",
                "scan_id": results.scan_id,
                "target": results.target_url,
                "scan_type": scan_type,
                "formats_generated": [],
                "total_findings": results.statistics.findings_count,
                "critical_findings": results.statistics.critical_findings,
                "generation_duration_seconds": 0
            }
        }
        
        generation_start = datetime.now()
        
        for format_name, format_info in formats.items():
            try:
                self.logger.info("Generating report", 
                               format=format_name, 
                               description=format_info["description"])
                
                format_start = datetime.now()
                content = format_info["generator"](results)
                format_duration = (datetime.now() - format_start).total_seconds()
                
                # Validate content
                if not content or len(content.strip()) == 0:
                    self.logger.warning("Empty content generated", format=format_name)
                    continue
                
                # Use custom filename if provided, otherwise use default naming
                if output_filename:
                    filename = f"{output_filename}.{format_name}"
                else:
                    filename = f"apileak_report_{scan_type}_{timestamp}.{format_name}"
                
                filepath = output_path / filename
                
                # Write file with proper encoding
                encoding = 'utf-8'
                with open(filepath, 'w', encoding=encoding, newline='') as f:
                    f.write(content)
                
                # Verify file was written correctly
                file_size = filepath.stat().st_size
                if file_size == 0:
                    self.logger.error("Generated file is empty", format=format_name, path=str(filepath))
                    continue
                
                file_info = {
                    "path": str(filepath),
                    "format": format_name,
                    "description": format_info["description"],
                    "mime_type": format_info["mime_type"],
                    "size_bytes": file_size,
                    "generation_time_seconds": format_duration,
                    "encoding": encoding
                }
                
                generated_files.append(file_info)
                metadata["report_generation"]["formats_generated"].append({
                    "format": format_name,
                    "filename": filename,
                    "size_bytes": file_size,
                    "generation_time_seconds": format_duration
                })
                
                self.logger.info("Report generated successfully", 
                               format=format_name, 
                               path=str(filepath),
                               size_mb=file_size / 1024 / 1024,
                               generation_time=format_duration)
                
            except Exception as e:
                self.logger.error("Failed to generate report", 
                                format=format_name, 
                                error=str(e),
                                error_type=type(e).__name__)
                
                # Add error info to metadata
                metadata["report_generation"].setdefault("errors", []).append({
                    "format": format_name,
                    "error": str(e),
                    "error_type": type(e).__name__
                })
        
        # Calculate total generation time
        total_duration = (datetime.now() - generation_start).total_seconds()
        metadata["report_generation"]["generation_duration_seconds"] = total_duration
        
        # Save metadata file
        try:
            metadata_filename = f"apileak_metadata_{scan_type}_{timestamp}.json"
            metadata_filepath = output_path / metadata_filename
            
            with open(metadata_filepath, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            metadata_info = {
                "path": str(metadata_filepath),
                "format": "metadata",
                "description": "Report generation metadata and statistics",
                "mime_type": "application/json",
                "size_bytes": metadata_filepath.stat().st_size,
                "generation_time_seconds": 0,
                "encoding": "utf-8"
            }
            
            generated_files.append(metadata_info)
            
            self.logger.info("Metadata file generated", path=str(metadata_filepath))
            
        except Exception as e:
            self.logger.error("Failed to generate metadata file", error=str(e))
        
        # Generate summary report
        try:
            summary_content = self._generate_summary_report(results, generated_files, total_duration)
            summary_filename = f"apileak_summary_{scan_type}_{timestamp}.txt"
            summary_filepath = output_path / summary_filename
            
            with open(summary_filepath, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            
            summary_info = {
                "path": str(summary_filepath),
                "format": "summary",
                "description": "Executive summary of report generation",
                "mime_type": "text/plain",
                "size_bytes": summary_filepath.stat().st_size,
                "generation_time_seconds": 0,
                "encoding": "utf-8"
            }
            
            generated_files.append(summary_info)
            
        except Exception as e:
            self.logger.error("Failed to generate summary report", error=str(e))
        
        self.logger.info("Report generation completed", 
                        files_generated=len([f for f in generated_files if f["format"] != "metadata"]),
                        total_size_mb=sum(f["size_bytes"] for f in generated_files) / 1024 / 1024,
                        total_duration=total_duration,
                        output_directory=str(output_path))
        
        return generated_files
    
    def _generate_summary_report(self, results: Any, generated_files: List[Dict], generation_duration: float) -> str:
        """Generate executive summary of report generation"""
        
        summary = f"""
APILeak Report Generation Summary
================================

Scan Information:
- Scan ID: {results.scan_id}
- Target: {results.target_url}
- Timestamp: {results.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Duration: {results.performance_metrics.duration.total_seconds() if results.performance_metrics.duration else 0:.2f}s

Report Generation:
- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
- Generation Time: {generation_duration:.2f}s
- Files Created: {len([f for f in generated_files if f['format'] not in ['metadata', 'summary']])}
- Total Size: {sum(f['size_bytes'] for f in generated_files) / 1024 / 1024:.2f} MB

Generated Files:
"""
        
        for file_info in generated_files:
            if file_info["format"] not in ["metadata", "summary"]:
                summary += f"- {file_info['format'].upper()}: {Path(file_info['path']).name} "
                summary += f"({file_info['size_bytes'] / 1024:.1f} KB)\n"
                summary += f"  {file_info['description']}\n"
        
        summary += f"""
Findings Summary:
- Total: {results.statistics.findings_count}
- Critical: {results.statistics.critical_findings}
- High: {results.statistics.high_findings}
- Medium: {results.statistics.medium_findings}
- Low: {results.statistics.low_findings}
- Info: {results.statistics.info_findings}

Performance:
- Requests: {results.statistics.total_requests:,}
- Endpoints: {results.statistics.endpoints_discovered}
- Req/sec: {results.performance_metrics.requests_per_second:.2f}

Generated by APILeak v0.1.0
"""
        
        return summary