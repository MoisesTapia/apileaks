#!/usr/bin/env python3
"""
APILeak CI/CD Threshold Checker
Validates security scan results against configured thresholds
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any


def load_scan_results(report_path: str) -> Dict[str, Any]:
    """Load scan results from JSON report file"""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: Report file not found: {report_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in report file: {e}")
        sys.exit(1)


def check_thresholds(results: Dict[str, Any], critical_threshold: int, 
                    high_threshold: int, medium_threshold: int) -> Dict[str, Any]:
    """Check if scan results exceed configured thresholds"""
    
    # Extract statistics from results
    stats = results.get('statistics', {})
    critical_count = stats.get('critical_findings', 0)
    high_count = stats.get('high_findings', 0)
    medium_count = stats.get('medium_findings', 0)
    low_count = stats.get('low_findings', 0)
    info_count = stats.get('info_findings', 0)
    total_count = stats.get('findings_count', 0)
    
    # Check thresholds
    threshold_results = {
        'critical_exceeded': critical_count > critical_threshold,
        'high_exceeded': high_count > high_threshold,
        'medium_exceeded': medium_count > medium_threshold,
        'should_fail': False,
        'should_warn': False,
        'counts': {
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'info': info_count,
            'total': total_count
        },
        'thresholds': {
            'critical': critical_threshold,
            'high': high_threshold,
            'medium': medium_threshold
        }
    }
    
    # Determine action based on thresholds
    if threshold_results['critical_exceeded']:
        threshold_results['should_fail'] = True
        threshold_results['reason'] = f"Critical findings ({critical_count}) exceed threshold ({critical_threshold})"
    elif threshold_results['high_exceeded']:
        threshold_results['should_warn'] = True
        threshold_results['reason'] = f"High findings ({high_count}) exceed threshold ({high_threshold})"
    elif threshold_results['medium_exceeded']:
        threshold_results['should_warn'] = True
        threshold_results['reason'] = f"Medium findings ({medium_count}) exceed threshold ({medium_threshold})"
    else:
        threshold_results['reason'] = "All findings within acceptable thresholds"
    
    return threshold_results


def print_summary(results: Dict[str, Any], threshold_results: Dict[str, Any], 
                 jenkins_mode: bool = False) -> None:
    """Print summary of threshold check results"""
    
    scan_info = results.get('scan_info', {})
    target = scan_info.get('target_url', 'Unknown')
    scan_id = scan_info.get('scan_id', 'Unknown')
    
    if jenkins_mode:
        # Jenkins-friendly output format
        print("="*60)
        print("APILeak Security Threshold Check")
        print("="*60)
    else:
        print("\n🔒 APILeak Security Threshold Check")
        print("="*50)
    
    print(f"Target: {target}")
    print(f"Scan ID: {scan_id}")
    print()
    
    # Print findings summary
    counts = threshold_results['counts']
    thresholds = threshold_results['thresholds']
    
    print("Findings Summary:")
    print(f"  Critical: {counts['critical']:>3} (threshold: {thresholds['critical']})")
    print(f"  High:     {counts['high']:>3} (threshold: {thresholds['high']})")
    print(f"  Medium:   {counts['medium']:>3} (threshold: {thresholds['medium']})")
    print(f"  Low:      {counts['low']:>3}")
    print(f"  Info:     {counts['info']:>3}")
    print(f"  Total:    {counts['total']:>3}")
    print()
    
    # Print threshold status
    if threshold_results['should_fail']:
        status_icon = "❌" if not jenkins_mode else "FAIL"
        print(f"{status_icon} THRESHOLD EXCEEDED: {threshold_results['reason']}")
        print("Pipeline should FAIL")
    elif threshold_results['should_warn']:
        status_icon = "⚠️" if not jenkins_mode else "WARN"
        print(f"{status_icon} THRESHOLD WARNING: {threshold_results['reason']}")
        print("Pipeline should continue with WARNING")
    else:
        status_icon = "✅" if not jenkins_mode else "PASS"
        print(f"{status_icon} THRESHOLDS PASSED: {threshold_results['reason']}")
        print("Pipeline should CONTINUE")
    
    print()


def generate_junit_xml(threshold_results: Dict[str, Any], output_path: str) -> None:
    """Generate JUnit XML report for CI/CD integration"""
    
    counts = threshold_results['counts']
    
    # Create JUnit XML content
    junit_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="APILeak Security Thresholds" tests="3" failures="{1 if threshold_results['should_fail'] else 0}" errors="0" time="0">
    <testcase name="Critical Findings Threshold" classname="APILeak.Thresholds">
        {'<failure message="Critical findings exceed threshold">' + threshold_results['reason'] + '</failure>' if threshold_results['critical_exceeded'] else ''}
    </testcase>
    <testcase name="High Findings Threshold" classname="APILeak.Thresholds">
        {'<failure message="High findings exceed threshold">' + threshold_results['reason'] + '</failure>' if threshold_results['high_exceeded'] and not threshold_results['critical_exceeded'] else ''}
    </testcase>
    <testcase name="Medium Findings Threshold" classname="APILeak.Thresholds">
        {'<failure message="Medium findings exceed threshold">' + threshold_results['reason'] + '</failure>' if threshold_results['medium_exceeded'] and not threshold_results['high_exceeded'] and not threshold_results['critical_exceeded'] else ''}
    </testcase>
    <system-out>
Critical: {counts['critical']}
High: {counts['high']}
Medium: {counts['medium']}
Low: {counts['low']}
Info: {counts['info']}
Total: {counts['total']}
    </system-out>
</testsuite>'''
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(junit_xml)


def main():
    parser = argparse.ArgumentParser(
        description='Check APILeak scan results against security thresholds'
    )
    parser.add_argument('--report', required=True, 
                       help='Path to APILeak JSON report file')
    parser.add_argument('--critical-threshold', type=int, default=0,
                       help='Maximum allowed critical findings (default: 0)')
    parser.add_argument('--high-threshold', type=int, default=5,
                       help='Maximum allowed high findings (default: 5)')
    parser.add_argument('--medium-threshold', type=int, default=20,
                       help='Maximum allowed medium findings (default: 20)')
    parser.add_argument('--jenkins-mode', action='store_true',
                       help='Enable Jenkins-friendly output format')
    parser.add_argument('--junit-output', 
                       help='Generate JUnit XML report at specified path')
    parser.add_argument('--fail-on-warning', action='store_true',
                       help='Exit with non-zero code on warnings (not just failures)')
    
    args = parser.parse_args()
    
    # Load scan results
    results = load_scan_results(args.report)
    
    # Check thresholds
    threshold_results = check_thresholds(
        results, 
        args.critical_threshold,
        args.high_threshold, 
        args.medium_threshold
    )
    
    # Print summary
    print_summary(results, threshold_results, args.jenkins_mode)
    
    # Generate JUnit XML if requested
    if args.junit_output:
        generate_junit_xml(threshold_results, args.junit_output)
        print(f"JUnit XML report generated: {args.junit_output}")
    
    # Exit with appropriate code
    if threshold_results['should_fail']:
        print("Exiting with code 2 (FAILURE)")
        sys.exit(2)
    elif threshold_results['should_warn'] and args.fail_on_warning:
        print("Exiting with code 1 (WARNING)")
        sys.exit(1)
    else:
        print("Exiting with code 0 (SUCCESS)")
        sys.exit(0)


if __name__ == '__main__':
    main()