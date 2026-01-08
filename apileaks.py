#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import asyncio
import sys
import json
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
    """
    APILeak v0.1.0 - Enterprise API Fuzzing Tool
    
    Performs comprehensive security testing of APIs including:
    - Traditional endpoint and parameter fuzzing
    - OWASP API Security Top 10 testing
    - Advanced vulnerability detection with framework detection
    - Version fuzzing and subdomain discovery
    - WAF detection and evasion techniques
    - Advanced payload encoding and obfuscation
    - CORS analysis and security headers testing
    - Multi-format reporting with CI/CD integration
    - JWT token manipulation and analysis
    
    Examples:
      # Basic fuzzing modes
      python apileaks.py dir -w /path/wordlist --target https://api.example.com
      python apileaks.py par --target https://api.example.com --user-agent-random
      
      # Full comprehensive scans
      python apileaks.py full --config config/api_config.yaml --target https://api.example.com
      python apileaks.py full --target https://api.example.com --enable-advanced
      
      # Advanced feature examples
      python apileaks.py full --target https://api.example.com --detect-framework --fuzz-versions
      python apileaks.py full --target https://api.example.com --enable-payload-encoding --enable-waf-evasion
      python apileaks.py full --target https://api.example.com --enable-subdomain-discovery --enable-cors-analysis
      
      # CI/CD integration examples
      python apileaks.py full --target https://api.example.com --ci-mode --fail-on high
      python apileaks.py full --target https://api.example.com --ci-mode --fail-on critical --modules bola,auth
      
      # JWT utilities
      python apileaks.py jwt-decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
      python apileaks.py jwt-encode '{"sub":"user123"}' --secret mysecret
      
      # WAF evasion examples
      python apileaks.py full --target https://api.example.com --user-agent-random --enable-waf-evasion
      python apileaks.py full --target https://api.example.com --user-agent-file wordlists/user_agents.txt
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
    """Directory/endpoint fuzzing mode - discover hidden endpoints and directories"""
    
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
    """Parameter fuzzing mode - discover hidden parameters in API endpoints"""
    
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
    """Full comprehensive scan - includes fuzzing and OWASP testing with advanced features"""
    
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


@cli.command('jwt-decode')
@click.argument('token')
@click.pass_context
def jwt_decode_cmd(ctx, token):
    """Decode and analyze a JWT token"""
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


@cli.command('jwt-encode')
@click.argument('payload')
@click.option('--header', default='{"alg":"HS256","typ":"JWT"}', help='JWT header as JSON string')
@click.option('--secret', default='secret', help='Secret key for signing (default: "secret")')
@click.pass_context
def jwt_encode_cmd(ctx, payload, header, secret):
    """Encode a JWT token with custom payload and header"""
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