#!/usr/bin/env python3
"""
APILeak SARIF Report Generator
Generates SARIF (Static Analysis Results Interchange Format) reports for GitHub Security integration
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import glob
import uuid


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


def severity_to_sarif_level(severity: str) -> str:
    """Convert APILeak severity to SARIF level"""
    severity_map = {
        'CRITICAL': 'error',
        'HIGH': 'error', 
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'note'
    }
    return severity_map.get(severity.upper(), 'note')


def category_to_rule_id(category: str) -> str:
    """Convert APILeak category to SARIF rule ID"""
    # Clean category name for rule ID
    rule_id = category.replace(' ', '_').replace('-', '_').lower()
    return f"apileak_{rule_id}"


def generate_sarif_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate SARIF report from APILeak scan results"""
    
    # SARIF 2.1.0 schema
    sarif_report = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": []
    }
    
    # Create a run for each scan result
    for result in results:
        scan_info = result.get('scan_info', {})
        findings = result.get('findings', [])
        
        # Determine scan type from file path
        file_path = result.get('_file_path', '')
        if 'endpoints' in file_path:
            tool_name = 'APILeak Directory Fuzzer'
        elif 'parameters' in file_path:
            tool_name = 'APILeak Parameter Fuzzer'
        elif 'full' in file_path:
            tool_name = 'APILeak OWASP Scanner'
        else:
            tool_name = 'APILeak Security Scanner'
        
        # Create rules from unique categories
        rules = {}
        for finding in findings:
            category = finding.get('category', 'Unknown')
            rule_id = category_to_rule_id(category)
            
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": category,
                    "shortDescription": {
                        "text": f"APILeak {category} Detection"
                    },
                    "fullDescription": {
                        "text": f"APILeak detected a potential {category.lower()} vulnerability"
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(finding.get('severity', 'INFO'))
                    },
                    "properties": {
                        "category": "security",
                        "security-severity": finding.get('severity', 'INFO')
                    }
                }
        
        # Create SARIF results from findings
        sarif_results = []
        for finding in findings:
            rule_id = category_to_rule_id(finding.get('category', 'Unknown'))
            
            # Create location information
            endpoint = finding.get('endpoint', '')
            if endpoint.startswith('http'):
                # Extract path from full URL
                from urllib.parse import urlparse
                parsed = urlparse(endpoint)
                logical_location = parsed.path or '/'
            else:
                logical_location = endpoint
            
            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules.keys()).index(rule_id),
                "level": severity_to_sarif_level(finding.get('severity', 'INFO')),
                "message": {
                    "text": finding.get('evidence', 'Security vulnerability detected')
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": logical_location,
                                "kind": "resource"
                            }
                        ]
                    }
                ],
                "properties": {
                    "endpoint": finding.get('endpoint', ''),
                    "method": finding.get('method', 'GET'),
                    "status_code": finding.get('status_code', 0),
                    "response_time": finding.get('response_time', 0),
                    "severity": finding.get('severity', 'INFO'),
                    "category": finding.get('category', 'Unknown'),
                    "owasp_category": finding.get('owasp_category', ''),
                    "recommendation": finding.get('recommendation', '')
                }
            }
            
            # Add payload information if available
            if finding.get('payload'):
                sarif_result['properties']['payload'] = finding['payload']
            
            # Add response snippet if available
            if finding.get('response_snippet'):
                sarif_result['properties']['response_snippet'] = finding['response_snippet']
            
            sarif_results.append(sarif_result)
        
        # Create the run
        run = {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "0.1.0",
                    "informationUri": "https://github.com/apileak/apileak",
                    "organization": "APILeak Team",
                    "shortDescription": {
                        "text": "Enterprise-grade API fuzzing and OWASP testing tool"
                    },
                    "fullDescription": {
                        "text": "APILeak provides comprehensive API security testing including traditional fuzzing and OWASP API Security Top 10 testing"
                    },
                    "rules": list(rules.values())
                }
            },
            "results": sarif_results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "startTimeUtc": scan_info.get('timestamp', datetime.now().isoformat() + 'Z'),
                    "endTimeUtc": scan_info.get('end_timestamp', datetime.now().isoformat() + 'Z'),
                    "properties": {
                        "target_url": scan_info.get('target_url', ''),
                        "scan_id": scan_info.get('scan_id', ''),
                        "scan_type": tool_name
                    }
                }
            ],
            "properties": {
                "scan_statistics": result.get('statistics', {}),
                "performance_metrics": result.get('performance_metrics', {})
            }
        }
        
        sarif_report["runs"].append(run)
    
    return sarif_report


def main():
    parser = argparse.ArgumentParser(
        description='Generate SARIF report from APILeak scan results'
    )
    parser.add_argument('--input-dir', required=True,
                       help='Directory containing APILeak JSON reports')
    parser.add_argument('--output', required=True,
                       help='Output path for SARIF report')
    
    args = parser.parse_args()
    
    # Load scan results
    print(f"Loading scan results from: {args.input_dir}")
    results = load_scan_results(args.input_dir)
    
    if not results:
        print("Warning: No APILeak scan results found")
        # Create empty SARIF report
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
    else:
        print(f"Found {len(results)} scan result files")
        sarif_report = generate_sarif_report(results)
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write SARIF report
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(sarif_report, f, indent=2, ensure_ascii=False)
    
    print(f"✅ SARIF report generated successfully: {args.output}")
    
    # Print summary
    total_results = sum(len(run.get('results', [])) for run in sarif_report['runs'])
    total_rules = sum(len(run.get('tool', {}).get('driver', {}).get('rules', [])) for run in sarif_report['runs'])
    
    print(f"   Total runs: {len(sarif_report['runs'])}")
    print(f"   Total rules: {total_rules}")
    print(f"   Total results: {total_results}")


if __name__ == '__main__':
    main()