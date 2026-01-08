#!/usr/bin/env python3
"""
APILeak Container Health Check Script
Validates that APILeak container is healthy and ready to accept requests
"""

import sys
import os
import json
from pathlib import Path


def check_python_imports():
    """Check that core APILeak modules can be imported"""
    try:
        from core import APILeakCore
        from core.config import ConfigurationManager
        from core.logging import get_logger
        return True, "Core modules imported successfully"
    except ImportError as e:
        return False, f"Failed to import core modules: {e}"


def check_file_permissions():
    """Check that required directories are writable"""
    required_dirs = ['/app/reports', '/app/logs']
    
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            return False, f"Required directory does not exist: {dir_path}"
        
        if not os.access(dir_path, os.W_OK):
            return False, f"Directory is not writable: {dir_path}"
    
    return True, "File permissions are correct"


def check_wordlists():
    """Check that essential wordlists are available"""
    required_wordlists = [
        '/app/wordlists/endpoints.txt',
        '/app/wordlists/parameters.txt'
    ]
    
    missing_wordlists = []
    for wordlist in required_wordlists:
        if not os.path.exists(wordlist):
            missing_wordlists.append(wordlist)
    
    if missing_wordlists:
        return False, f"Missing wordlists: {', '.join(missing_wordlists)}"
    
    return True, "Essential wordlists are available"


def check_configuration():
    """Check that configuration system is working"""
    try:
        from core.config import ConfigurationManager
        config_manager = ConfigurationManager()
        
        # Test basic configuration loading
        test_config = {
            'target': {
                'base_url': 'https://example.com',
                'timeout': 10
            },
            'fuzzing': {
                'endpoints': {'enabled': True},
                'parameters': {'enabled': True},
                'headers': {'enabled': True}
            },
            'owasp_testing': {
                'enabled_modules': []
            },
            'authentication': {
                'contexts': [{'name': 'test', 'type': 'bearer', 'token': ''}]
            },
            'rate_limiting': {
                'requests_per_second': 10
            },
            'reporting': {
                'formats': ['json']
            }
        }
        
        apileak_config = config_manager.load_config_from_dict(test_config)
        return True, "Configuration system is working"
    except Exception as e:
        return False, f"Configuration system error: {e}"


def check_environment_variables():
    """Check that environment variables are properly set"""
    required_env_vars = ['PYTHONPATH', 'PYTHONUNBUFFERED']
    missing_vars = []
    
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        return False, f"Missing environment variables: {', '.join(missing_vars)}"
    
    return True, "Environment variables are set correctly"


def run_health_checks():
    """Run all health checks and return overall status"""
    checks = [
        ("Python Imports", check_python_imports),
        ("File Permissions", check_file_permissions),
        ("Wordlists", check_wordlists),
        ("Configuration", check_configuration),
        ("Environment Variables", check_environment_variables)
    ]
    
    results = []
    overall_healthy = True
    
    for check_name, check_func in checks:
        try:
            success, message = check_func()
            results.append({
                'check': check_name,
                'status': 'PASS' if success else 'FAIL',
                'message': message
            })
            if not success:
                overall_healthy = False
        except Exception as e:
            results.append({
                'check': check_name,
                'status': 'ERROR',
                'message': f"Health check failed with exception: {e}"
            })
            overall_healthy = False
    
    return overall_healthy, results


def main():
    """Main health check function"""
    # Check if running in verbose mode
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    json_output = '--json' in sys.argv
    
    # Run health checks
    healthy, results = run_health_checks()
    
    if json_output:
        # Output results as JSON
        output = {
            'status': 'healthy' if healthy else 'unhealthy',
            'timestamp': str(Path('/proc/1/stat').stat().st_mtime) if Path('/proc/1/stat').exists() else 'unknown',
            'checks': results
        }
        print(json.dumps(output, indent=2))
    else:
        # Human-readable output
        if healthy:
            print("✅ APILeak container is healthy")
        else:
            print("❌ APILeak container is unhealthy")
        
        if verbose or not healthy:
            print("\nHealth Check Results:")
            print("-" * 40)
            for result in results:
                status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
                print(f"{status_icon} {result['check']}: {result['message']}")
    
    # Exit with appropriate code
    sys.exit(0 if healthy else 1)


if __name__ == '__main__':
    main()