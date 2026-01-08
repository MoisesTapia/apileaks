#!/usr/bin/env python3
"""
APILeak CI/CD Consolidated Report Generator
Generates consolidated HTML reports from multiple scan results
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import glob


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APILeak Security Report - {{ project_name }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid #ddd;
        }
        .summary-card.critical { border-left-color: #dc3545; }
        .summary-card.high { border-left-color: #fd7e14; }
        .summary-card.medium { border-left-color: #ffc107; }
        .summary-card.low { border-left-color: #28a745; }
        .summary-card.info { border-left-color: #17a2b8; }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 2em;
            font-weight: bold;
        }
        .summary-card p {
            margin: 0;
            color: #666;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 1px;
        }
        .scan-results {
            margin-top: 30px;
        }
        .scan-result {
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .scan-result-header {
            background: #e9ecef;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
        }
        .scan-result-header h3 {
            margin: 0;
            color: #495057;
        }
        .scan-result-content {
            padding: 20px;
        }
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        .findings-table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; color: white; }
        .severity-info { background: #17a2b8; color: white; }
        .metadata {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
        .metadata h3 {
            margin-top: 0;
            color: #495057;
        }
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .metadata-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #dee2e6;
        }
        .metadata-item:last-child {
            border-bottom: none;
        }
        .metadata-label {
            font-weight: 600;
            color: #495057;
        }
        .metadata-value {
            color: #6c757d;
        }
        .no-findings {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 APILeak Security Report</h1>
            <p>{{ project_name }} - Pipeline {{ pipeline_id }}</p>
            <p>Generated on {{ timestamp }}</p>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="summary-card critical">
                    <h3>{{ total_critical }}</h3>
                    <p>Critical</p>
                </div>
                <div class="summary-card high">
                    <h3>{{ total_high }}</h3>
                    <p>High</p>
                </div>
                <div class="summary-card medium">
                    <h3>{{ total_medium }}</h3>
                    <p>Medium</p>
                </div>
                <div class="summary-card low">
                    <h3>{{ total_low }}</h3>
                    <p>Low</p>
                </div>
                <div class="summary-card info">
                    <h3>{{ total_info }}</h3>
                    <p>Info</p>
                </div>
            </div>
            
            <div class="scan-results">
                {% for scan in scans %}
                <div class="scan-result">
                    <div class="scan-result-header">
                        <h3>{{ scan.name }} - {{ scan.target }}</h3>
                    </div>
                    <div class="scan-result-content">
                        <div class="summary-grid">
                            <div class="summary-card critical">
                                <h3>{{ scan.stats.critical }}</h3>
                                <p>Critical</p>
                            </div>
                            <div class="summary-card high">
                                <h3>{{ scan.stats.high }}</h3>
                                <p>High</p>
                            </div>
                            <div class="summary-card medium">
                                <h3>{{ scan.stats.medium }}</h3>
                                <p>Medium</p>
                            </div>
                            <div class="summary-card low">
                                <h3>{{ scan.stats.low }}</h3>
                                <p>Low</p>
                            </div>
                            <div class="summary-card info">
                                <h3>{{ scan.stats.info }}</h3>
                                <p>Info</p>
                            </div>
                        </div>
                        
                        {% if scan.findings %}
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Category</th>
                                    <th>Endpoint</th>
                                    <th>Evidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for finding in scan.findings[:10] %}
                                <tr>
                                    <td>
                                        <span class="severity-badge severity-{{ finding.severity.lower() }}">
                                            {{ finding.severity }}
                                        </span>
                                    </td>
                                    <td>{{ finding.category }}</td>
                                    <td>{{ finding.endpoint }}</td>
                                    <td>{{ finding.evidence[:100] }}{% if finding.evidence|length > 100 %}...{% endif %}</td>
                                </tr>
                                {% endfor %}
                                {% if scan.findings|length > 10 %}
                                <tr>
                                    <td colspan="4" style="text-align: center; color: #6c757d; font-style: italic;">
                                        ... and {{ scan.findings|length - 10 }} more findings
                                    </td>
                                </tr>
                                {% endif %}
                            </tbody>
                        </table>
                        {% else %}
                        <div class="no-findings">
                            <p>✅ No security findings detected in this scan</p>
                        </div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
            
            <div class="metadata">
                <h3>Scan Metadata</h3>
                <div class="metadata-grid">
                    <div>
                        <div class="metadata-item">
                            <span class="metadata-label">Project:</span>
                            <span class="metadata-value">{{ project_name }}</span>
                        </div>
                        <div class="metadata-item">
                            <span class="metadata-label">Pipeline ID:</span>
                            <span class="metadata-value">{{ pipeline_id }}</span>
                        </div>
                        <div class="metadata-item">
                            <span class="metadata-label">Commit SHA:</span>
                            <span class="metadata-value">{{ commit_sha }}</span>
                        </div>
                    </div>
                    <div>
                        <div class="metadata-item">
                            <span class="metadata-label">Total Scans:</span>
                            <span class="metadata-value">{{ scans|length }}</span>
                        </div>
                        <div class="metadata-item">
                            <span class="metadata-label">Total Findings:</span>
                            <span class="metadata-value">{{ total_findings }}</span>
                        </div>
                        <div class="metadata-item">
                            <span class="metadata-label">Generated:</span>
                            <span class="metadata-value">{{ timestamp }}</span>
                        </div>
                    </div>
                </div>
                {% if build_url %}
                <div class="metadata-item">
                    <span class="metadata-label">Build URL:</span>
                    <span class="metadata-value"><a href="{{ build_url }}">{{ build_url }}</a></span>
                </div>
                {% endif %}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by APILeak v0.1.0 - Enterprise API Security Testing Tool</p>
        </div>
    </div>
</body>
</html>
"""


def load_scan_results(input_dir: str) -> List[Dict[str, Any]]:
    """Load all APILeak scan results from input directory"""
    results = []
    
    # Find all JSON report files
    json_files = glob.glob(f"{input_dir}/**/apileak-*.json", recursive=True)
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                data['_file_path'] = json_file
                results.append(data)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Warning: Could not load {json_file}: {e}")
    
    return results


def process_scan_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Process scan results into consolidated format"""
    
    consolidated = {
        'scans': [],
        'total_critical': 0,
        'total_high': 0,
        'total_medium': 0,
        'total_low': 0,
        'total_info': 0,
        'total_findings': 0
    }
    
    for result in results:
        # Extract scan information
        scan_info = result.get('scan_info', {})
        statistics = result.get('statistics', {})
        findings = result.get('findings', [])
        
        # Determine scan type from file path
        file_path = result.get('_file_path', '')
        if 'endpoints' in file_path:
            scan_type = 'Directory Fuzzing'
        elif 'parameters' in file_path:
            scan_type = 'Parameter Fuzzing'
        elif 'full' in file_path:
            scan_type = 'Full OWASP Scan'
        else:
            scan_type = 'Security Scan'
        
        scan_data = {
            'name': scan_type,
            'target': scan_info.get('target_url', 'Unknown'),
            'scan_id': scan_info.get('scan_id', 'Unknown'),
            'stats': {
                'critical': statistics.get('critical_findings', 0),
                'high': statistics.get('high_findings', 0),
                'medium': statistics.get('medium_findings', 0),
                'low': statistics.get('low_findings', 0),
                'info': statistics.get('info_findings', 0),
                'total': statistics.get('findings_count', 0)
            },
            'findings': []
        }
        
        # Process findings
        for finding in findings:
            scan_data['findings'].append({
                'severity': finding.get('severity', 'UNKNOWN'),
                'category': finding.get('category', 'Unknown'),
                'endpoint': finding.get('endpoint', 'Unknown'),
                'evidence': finding.get('evidence', 'No evidence provided')
            })
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        scan_data['findings'].sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        consolidated['scans'].append(scan_data)
        
        # Update totals
        consolidated['total_critical'] += scan_data['stats']['critical']
        consolidated['total_high'] += scan_data['stats']['high']
        consolidated['total_medium'] += scan_data['stats']['medium']
        consolidated['total_low'] += scan_data['stats']['low']
        consolidated['total_info'] += scan_data['stats']['info']
        consolidated['total_findings'] += scan_data['stats']['total']
    
    return consolidated


def generate_html_report(consolidated: Dict[str, Any], project_name: str, 
                        pipeline_id: str, commit_sha: str, build_url: str = None) -> str:
    """Generate HTML report from consolidated data"""
    
    # Simple template rendering (avoiding jinja2 dependency)
    html = HTML_TEMPLATE
    
    # Replace template variables
    replacements = {
        '{{ project_name }}': project_name,
        '{{ pipeline_id }}': pipeline_id,
        '{{ commit_sha }}': commit_sha[:8] if commit_sha else 'Unknown',
        '{{ timestamp }}': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        '{{ total_critical }}': str(consolidated['total_critical']),
        '{{ total_high }}': str(consolidated['total_high']),
        '{{ total_medium }}': str(consolidated['total_medium']),
        '{{ total_low }}': str(consolidated['total_low']),
        '{{ total_info }}': str(consolidated['total_info']),
        '{{ total_findings }}': str(consolidated['total_findings']),
        '{{ scans|length }}': str(len(consolidated['scans'])),
        '{{ build_url }}': build_url or ''
    }
    
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)
    
    # Generate scans section
    scans_html = ""
    for scan in consolidated['scans']:
        scan_html = f"""
                <div class="scan-result">
                    <div class="scan-result-header">
                        <h3>{scan['name']} - {scan['target']}</h3>
                    </div>
                    <div class="scan-result-content">
                        <div class="summary-grid">
                            <div class="summary-card critical">
                                <h3>{scan['stats']['critical']}</h3>
                                <p>Critical</p>
                            </div>
                            <div class="summary-card high">
                                <h3>{scan['stats']['high']}</h3>
                                <p>High</p>
                            </div>
                            <div class="summary-card medium">
                                <h3>{scan['stats']['medium']}</h3>
                                <p>Medium</p>
                            </div>
                            <div class="summary-card low">
                                <h3>{scan['stats']['low']}</h3>
                                <p>Low</p>
                            </div>
                            <div class="summary-card info">
                                <h3>{scan['stats']['info']}</h3>
                                <p>Info</p>
                            </div>
                        </div>
        """
        
        if scan['findings']:
            scan_html += """
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Category</th>
                                    <th>Endpoint</th>
                                    <th>Evidence</th>
                                </tr>
                            </thead>
                            <tbody>
            """
            
            for finding in scan['findings'][:10]:  # Show first 10 findings
                evidence = finding['evidence'][:100]
                if len(finding['evidence']) > 100:
                    evidence += "..."
                
                scan_html += f"""
                                <tr>
                                    <td>
                                        <span class="severity-badge severity-{finding['severity'].lower()}">
                                            {finding['severity']}
                                        </span>
                                    </td>
                                    <td>{finding['category']}</td>
                                    <td>{finding['endpoint']}</td>
                                    <td>{evidence}</td>
                                </tr>
                """
            
            if len(scan['findings']) > 10:
                scan_html += f"""
                                <tr>
                                    <td colspan="4" style="text-align: center; color: #6c757d; font-style: italic;">
                                        ... and {len(scan['findings']) - 10} more findings
                                    </td>
                                </tr>
                """
            
            scan_html += """
                            </tbody>
                        </table>
            """
        else:
            scan_html += """
                        <div class="no-findings">
                            <p>✅ No security findings detected in this scan</p>
                        </div>
            """
        
        scan_html += """
                    </div>
                </div>
        """
        
        scans_html += scan_html
    
    # Replace scans section
    html = html.replace('{% for scan in scans %}', '').replace('{% endfor %}', '')
    html = html.replace('                {% for scan in scans %}', scans_html)
    
    # Clean up remaining template syntax
    html = html.replace('{% if build_url %}', '')
    html = html.replace('{% endif %}', '')
    
    return html


def main():
    parser = argparse.ArgumentParser(
        description='Generate consolidated APILeak security report'
    )
    parser.add_argument('--input-dir', required=True,
                       help='Directory containing APILeak JSON reports')
    parser.add_argument('--output', required=True,
                       help='Output path for consolidated HTML report')
    parser.add_argument('--pipeline-id', required=True,
                       help='CI/CD pipeline identifier')
    parser.add_argument('--project-name', required=True,
                       help='Project name')
    parser.add_argument('--commit-sha', default='Unknown',
                       help='Git commit SHA')
    parser.add_argument('--build-url',
                       help='CI/CD build URL')
    parser.add_argument('--jenkins-mode', action='store_true',
                       help='Enable Jenkins-specific features')
    
    args = parser.parse_args()
    
    # Load scan results
    print(f"Loading scan results from: {args.input_dir}")
    results = load_scan_results(args.input_dir)
    
    if not results:
        print("Warning: No APILeak scan results found")
        # Create empty report
        consolidated = {
            'scans': [],
            'total_critical': 0,
            'total_high': 0,
            'total_medium': 0,
            'total_low': 0,
            'total_info': 0,
            'total_findings': 0
        }
    else:
        print(f"Found {len(results)} scan result files")
        consolidated = process_scan_results(results)
    
    # Generate HTML report
    print(f"Generating consolidated report: {args.output}")
    html_content = generate_html_report(
        consolidated,
        args.project_name,
        args.pipeline_id,
        args.commit_sha,
        args.build_url
    )
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write HTML report
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Consolidated report generated successfully")
    print(f"   Total findings: {consolidated['total_findings']}")
    print(f"   Critical: {consolidated['total_critical']}")
    print(f"   High: {consolidated['total_high']}")
    print(f"   Medium: {consolidated['total_medium']}")
    print(f"   Low: {consolidated['total_low']}")
    print(f"   Info: {consolidated['total_info']}")


if __name__ == '__main__':
    main()