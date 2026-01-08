"""
APILeak Configuration Manager
Handles YAML/JSON configuration with Pydantic validation
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from pydantic import BaseModel, ValidationError, validator
from enum import Enum

from .logging import get_logger

logger = get_logger(__name__)


class Severity(str, Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AuthType(str, Enum):
    """Authentication types"""
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    JWT = "jwt"


@dataclass
class TargetConfig:
    """Target configuration"""
    base_url: str
    api_version: Optional[str] = None
    default_method: str = "GET"
    timeout: int = 10
    verify_ssl: bool = True


@dataclass
class EndpointFuzzingConfig:
    """Endpoint fuzzing configuration"""
    enabled: bool = True
    wordlist: str = "wordlists/endpoints.txt"
    methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE"])
    follow_redirects: bool = True


@dataclass
class ParameterFuzzingConfig:
    """Parameter fuzzing configuration"""
    enabled: bool = True
    query_wordlist: str = "wordlists/parameters.txt"
    body_wordlist: str = "wordlists/parameters.txt"
    boundary_testing: bool = True


@dataclass
class HeaderFuzzingConfig:
    """Header fuzzing configuration"""
    enabled: bool = True
    wordlist: str = "wordlists/headers.txt"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    random_user_agent: bool = False
    user_agent_list: Optional[List[str]] = None
    user_agent_rotation: bool = False


@dataclass
class FuzzingConfig:
    """Fuzzing configuration"""
    endpoints: EndpointFuzzingConfig = field(default_factory=EndpointFuzzingConfig)
    parameters: ParameterFuzzingConfig = field(default_factory=ParameterFuzzingConfig)
    headers: HeaderFuzzingConfig = field(default_factory=HeaderFuzzingConfig)
    recursive: bool = True
    max_depth: int = 3
    response_filter: List[int] = field(default_factory=list)


@dataclass
class BOLAConfig:
    """BOLA testing configuration"""
    enabled: bool = True
    id_patterns: List[str] = field(default_factory=lambda: ["sequential", "guid", "uuid"])
    test_contexts: List[str] = field(default_factory=lambda: ["anonymous", "user", "admin"])


@dataclass
class AuthTestingConfig:
    """Authentication testing configuration"""
    enabled: bool = True
    jwt_testing: bool = True
    weak_secrets_wordlist: str = "wordlists/jwt_secrets.txt"
    test_logout_invalidation: bool = True


@dataclass
class PropertyTestingConfig:
    """Property level authorization testing configuration"""
    enabled: bool = True
    sensitive_fields: List[str] = field(default_factory=lambda: [
        "password", "api_key", "secret", "token", "ssn", "credit_card"
    ])
    mass_assignment_fields: List[str] = field(default_factory=lambda: [
        "is_admin", "role", "permissions", "user_id"
    ])


@dataclass
class ResourceTestingConfig:
    """Resource consumption testing configuration"""
    enabled: bool = True
    burst_size: int = 100
    large_payload_sizes: List[int] = field(default_factory=lambda: [1024*1024, 10*1024*1024])
    json_depth_limit: int = 1000


@dataclass
class FunctionAuthConfig:
    """Function level authorization testing configuration"""
    enabled: bool = True
    admin_endpoints: List[str] = field(default_factory=lambda: [
        "/admin", "/api/admin", "/management", "/dashboard"
    ])
    dangerous_methods: List[str] = field(default_factory=lambda: ["DELETE", "PUT", "PATCH"])


@dataclass
class SSRFConfig:
    """SSRF testing configuration"""
    enabled: bool = True
    internal_targets: List[str] = field(default_factory=lambda: [
        "127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal"
    ])
    file_protocols: List[str] = field(default_factory=lambda: ["file://", "ftp://"])


@dataclass
class OWASPConfig:
    """OWASP testing configuration"""
    enabled_modules: List[str] = field(default_factory=lambda: [
        "bola", "auth", "property", "resource", "function_auth", "ssrf"
    ])
    bola_testing: BOLAConfig = field(default_factory=BOLAConfig)
    auth_testing: AuthTestingConfig = field(default_factory=AuthTestingConfig)
    property_testing: PropertyTestingConfig = field(default_factory=PropertyTestingConfig)
    resource_testing: ResourceTestingConfig = field(default_factory=ResourceTestingConfig)
    function_auth_testing: FunctionAuthConfig = field(default_factory=FunctionAuthConfig)
    ssrf_testing: SSRFConfig = field(default_factory=SSRFConfig)


@dataclass
class AuthContext:
    """Authentication context"""
    name: str
    type: AuthType
    token: str
    username: Optional[str] = None
    password: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    privilege_level: int = 1


@dataclass
class AuthConfig:
    """Authentication configuration"""
    contexts: List[AuthContext] = field(default_factory=list)
    default_context: Optional[str] = None


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: int = 10
    burst_size: int = 20
    adaptive: bool = True
    respect_retry_after: bool = True
    backoff_factor: float = 2.0


@dataclass
class ReportConfig:
    """Report generation configuration"""
    formats: List[str] = field(default_factory=lambda: ["json", "html", "txt"])
    output_dir: str = "reports"
    output_filename: Optional[str] = None
    include_screenshots: bool = False
    template_dir: str = "templates"


@dataclass
class AdvancedDiscoveryConfig:
    """Advanced discovery configuration"""
    enabled: bool = True
    
    # Framework Detection Configuration
    framework_detection: Dict[str, Any] = field(default_factory=lambda: {
        'enabled': False,
        'adapt_payloads': True,
        'test_framework_endpoints': True,
        'max_error_requests': 5,
        'timeout': 10.0,
        'confidence_threshold': 0.6
    })
    
    # Version Fuzzing Configuration
    version_fuzzing: Dict[str, Any] = field(default_factory=lambda: {
        'enabled': False,
        'version_patterns': [
            "/v1", "/v2", "/v3", "/v4", "/v5",
            "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
            "/api/1", "/api/2", "/api/3",
            "/1", "/2", "/3"
        ],
        'test_endpoints': ["/", "/health", "/status", "/info", "/docs"],
        'max_concurrent_requests': 5,
        'timeout': 10.0,
        'compare_endpoints': True,
        'detect_deprecated': True
    })
    
    # Legacy subdomain discovery (kept for backward compatibility)
    subdomain_discovery: bool = True
    cors_analysis: bool = True
    security_headers: bool = True
    subdomain_wordlist: List[str] = field(default_factory=lambda: [
        "api", "dev", "staging", "test", "qa", "uat", "prod", "production",
        "www", "admin", "management", "dashboard", "portal", "app", "mobile",
        "v1", "v2", "v3", "beta", "alpha", "demo", "sandbox", "internal"
    ])
    cors_test_origins: List[str] = field(default_factory=lambda: [
        "https://evil.com", "https://attacker.com", "http://localhost:3000",
        "https://example.com", "null", "*"
    ])
    max_concurrent: int = 10
    timeout: float = 10.0


@dataclass
class CICDIntegrationConfig:
    """CI/CD integration configuration"""
    enabled: bool = False
    fail_on_severity: str = "critical"  # critical, high, medium, low
    generate_artifacts: bool = True
    exit_codes: Dict[str, int] = field(default_factory=lambda: {
        "critical": 2,
        "high": 1,
        "medium": 0,
        "low": 0
    })
    artifact_formats: List[str] = field(default_factory=lambda: ["json", "xml"])


@dataclass
class HTTPOutputConfig:
    """HTTP output configuration"""
    status_code_filter: Optional[List[int]] = None


@dataclass
class APILeakConfig:
    """Main APILeak configuration"""
    target: TargetConfig
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    owasp_testing: OWASPConfig = field(default_factory=OWASPConfig)
    authentication: AuthConfig = field(default_factory=AuthConfig)
    rate_limiting: RateLimitConfig = field(default_factory=RateLimitConfig)
    reporting: ReportConfig = field(default_factory=ReportConfig)
    advanced_discovery: AdvancedDiscoveryConfig = field(default_factory=AdvancedDiscoveryConfig)
    http_output: HTTPOutputConfig = field(default_factory=HTTPOutputConfig)
    ci_cd_integration: CICDIntegrationConfig = field(default_factory=CICDIntegrationConfig)


class ConfigurationManager:
    """
    Configuration Manager with YAML/JSON support and Pydantic validation
    """
    
    def __init__(self):
        self.config: Optional[APILeakConfig] = None
        self.logger = get_logger(__name__)
    
    def load_config_from_dict(self, config_data: Dict[str, Any]) -> APILeakConfig:
        """
        Load configuration from dictionary
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            Validated APILeakConfig instance
            
        Raises:
            ValidationError: If configuration is invalid
        """
        self.logger.info("Loading configuration from dictionary")
        
        try:
            # Convert dict to APILeakConfig
            self.config = self._dict_to_config(config_data)
            
            self.logger.info("Configuration loaded successfully from dictionary", 
                           modules_enabled=len(self.config.owasp_testing.enabled_modules),
                           auth_contexts=len(self.config.authentication.contexts))
            
            return self.config
            
        except Exception as e:
            self.logger.error("Configuration loading from dictionary failed", error=str(e))
            raise
    
    def load_config(self, config_path: str) -> APILeakConfig:
        """
        Load configuration from YAML or JSON file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Validated APILeakConfig instance
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValidationError: If configuration is invalid
            ValueError: If file format is unsupported
        """
        config_file = Path(config_path)
        
        if not config_file.exists():
            self.logger.error("Configuration file not found", path=config_path)
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        self.logger.info("Loading configuration", path=config_path)
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix.lower() in ['.yaml', '.yml']:
                    config_data = yaml.safe_load(f)
                elif config_file.suffix.lower() == '.json':
                    config_data = json.load(f)
                else:
                    raise ValueError(f"Unsupported config format: {config_file.suffix}")
            
            # Convert dict to APILeakConfig
            self.config = self._dict_to_config(config_data)
            
            self.logger.info("Configuration loaded successfully", 
                           modules_enabled=len(self.config.owasp_testing.enabled_modules),
                           auth_contexts=len(self.config.authentication.contexts))
            
            return self.config
            
        except yaml.YAMLError as e:
            self.logger.error("YAML parsing error", error=str(e))
            raise ValueError(f"Invalid YAML format: {e}")
        except json.JSONDecodeError as e:
            self.logger.error("JSON parsing error", error=str(e))
            raise ValueError(f"Invalid JSON format: {e}")
        except Exception as e:
            self.logger.error("Configuration loading failed", error=str(e))
            raise
    
    def _dict_to_config(self, config_data: Dict[str, Any]) -> APILeakConfig:
        """Convert dictionary to APILeakConfig with validation"""
        try:
            # Extract target config (required)
            target_data = config_data.get('target', {})
            if not target_data.get('base_url'):
                raise ValueError("target.base_url is required")
            
            target = TargetConfig(**target_data)
            
            # Extract optional configs with defaults
            fuzzing_data = config_data.get('fuzzing', {})
            fuzzing = self._build_fuzzing_config(fuzzing_data)
            
            owasp_data = config_data.get('owasp_testing', {})
            owasp = self._build_owasp_config(owasp_data)
            
            auth_data = config_data.get('authentication', {})
            auth = self._build_auth_config(auth_data)
            
            rate_limit_data = config_data.get('rate_limiting', {})
            rate_limiting = RateLimitConfig(**rate_limit_data)
            
            report_data = config_data.get('reporting', {})
            reporting = ReportConfig(**report_data)
            
            advanced_data = config_data.get('advanced_discovery', {})
            advanced_discovery = AdvancedDiscoveryConfig(**advanced_data)
            
            http_output_data = config_data.get('http_output', {})
            http_output = HTTPOutputConfig(**http_output_data)
            
            ci_cd_data = config_data.get('ci_cd_integration', {})
            ci_cd_integration = CICDIntegrationConfig(**ci_cd_data)
            
            return APILeakConfig(
                target=target,
                fuzzing=fuzzing,
                owasp_testing=owasp,
                authentication=auth,
                rate_limiting=rate_limiting,
                reporting=reporting,
                advanced_discovery=advanced_discovery,
                http_output=http_output,
                ci_cd_integration=ci_cd_integration
            )
            
        except Exception as e:
            self.logger.error("Configuration validation failed", error=str(e))
            raise ValueError(f"Configuration validation failed: {e}")
    
    def _build_fuzzing_config(self, data: Dict[str, Any]) -> FuzzingConfig:
        """Build fuzzing configuration from dict"""
        endpoints_data = data.get('endpoints', {})
        endpoints = EndpointFuzzingConfig(**endpoints_data)
        
        params_data = data.get('parameters', {})
        parameters = ParameterFuzzingConfig(**params_data)
        
        headers_data = data.get('headers', {})
        headers = HeaderFuzzingConfig(**headers_data)
        
        return FuzzingConfig(
            endpoints=endpoints,
            parameters=parameters,
            headers=headers,
            recursive=data.get('recursive', True),
            max_depth=data.get('max_depth', 3)
        )
    
    def _build_owasp_config(self, data: Dict[str, Any]) -> OWASPConfig:
        """Build OWASP configuration from dict"""
        return OWASPConfig(
            enabled_modules=data.get('enabled_modules', [
                "bola", "auth", "property", "resource", "function_auth", "ssrf"
            ]),
            bola_testing=BOLAConfig(**data.get('bola_testing', {})),
            auth_testing=AuthTestingConfig(**data.get('auth_testing', {})),
            property_testing=PropertyTestingConfig(**data.get('property_testing', {})),
            resource_testing=ResourceTestingConfig(**data.get('resource_testing', {})),
            function_auth_testing=FunctionAuthConfig(**data.get('function_auth_testing', {})),
            ssrf_testing=SSRFConfig(**data.get('ssrf_testing', {}))
        )
    
    def _build_auth_config(self, data: Dict[str, Any]) -> AuthConfig:
        """Build authentication configuration from dict"""
        contexts_data = data.get('contexts', [])
        contexts = []
        
        for ctx_data in contexts_data:
            auth_type = AuthType(ctx_data.get('type', 'bearer'))
            context = AuthContext(
                name=ctx_data['name'],
                type=auth_type,
                token=ctx_data['token'],
                username=ctx_data.get('username'),
                password=ctx_data.get('password'),
                headers=ctx_data.get('headers', {}),
                privilege_level=ctx_data.get('privilege_level', 1)
            )
            contexts.append(context)
        
        return AuthConfig(
            contexts=contexts,
            default_context=data.get('default_context')
        )
    
    def validate_configuration(self) -> List[str]:
        """
        Validate current configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        if not self.config:
            return ["No configuration loaded"]
        
        errors = []
        
        # Validate target URL
        if not self.config.target.base_url:
            errors.append("target.base_url is required")
        
        # Validate wordlist files exist
        wordlists = [
            self.config.fuzzing.endpoints.wordlist,
            self.config.fuzzing.parameters.query_wordlist,
            self.config.fuzzing.headers.wordlist
        ]
        
        for wordlist in wordlists:
            if not Path(wordlist).exists():
                errors.append(f"Wordlist file not found: {wordlist}")
        
        # Validate auth contexts
        for ctx in self.config.authentication.contexts:
            # Allow anonymous contexts (empty token and no username/password)
            if ctx.name.lower() == "anonymous":
                continue
            if not ctx.token and not (ctx.username and ctx.password):
                errors.append(f"Auth context '{ctx.name}' missing credentials")
        
        return errors
    
    def get_fuzzing_config(self) -> FuzzingConfig:
        """Get fuzzing configuration"""
        if not self.config:
            raise ValueError("No configuration loaded")
        return self.config.fuzzing
    
    def get_owasp_config(self) -> OWASPConfig:
        """Get OWASP testing configuration"""
        if not self.config:
            raise ValueError("No configuration loaded")
        return self.config.owasp_testing
    
    def get_auth_contexts(self) -> List[AuthContext]:
        """Get authentication contexts"""
        if not self.config:
            raise ValueError("No configuration loaded")
        return self.config.authentication.contexts
    
    def merge_cli_overrides(self, cli_args: Dict[str, Any]) -> None:
        """
        Merge CLI arguments with configuration
        
        Args:
            cli_args: Dictionary of CLI arguments to override
        """
        if not self.config:
            raise ValueError("No configuration loaded")
        
        self.logger.debug("Merging CLI overrides", overrides=list(cli_args.keys()))
        
        # Override target URL if provided
        if 'target_url' in cli_args:
            self.config.target.base_url = cli_args['target_url']
        
        # Override rate limiting if provided
        if 'rate_limit' in cli_args:
            self.config.rate_limiting.requests_per_second = cli_args['rate_limit']
        
        # Override output directory if provided
        if 'output_dir' in cli_args:
            self.config.reporting.output_dir = cli_args['output_dir']
        
        # Override enabled modules if provided
        if 'modules' in cli_args:
            self.config.owasp_testing.enabled_modules = cli_args['modules']