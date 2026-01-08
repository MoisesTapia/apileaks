# APILeak Developer Guide

Comprehensive guide for developers working on APILeak, including architecture, development setup, testing strategies, and contribution guidelines.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Architecture Overview](#architecture-overview)
- [Code Organization](#code-organization)
- [Development Workflow](#development-workflow)
- [Testing Framework](#testing-framework)
- [Property-Based Testing](#property-based-testing)
- [Adding New OWASP Modules](#adding-new-owasp-modules)
- [Performance Optimization](#performance-optimization)
- [Debugging and Profiling](#debugging-and-profiling)
- [Contributing Guidelines](#contributing-guidelines)

## Development Environment Setup

### Prerequisites

- Python 3.11 or higher
- Git
- Make (optional, for convenience commands)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/your-org/apileak.git
cd apileak

# Set up development environment
make setup-dev

# Or manual setup:
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Verify setup
python -m pytest tests/ -v
```

### Development Dependencies

```bash
# Core dependencies
pip install httpx aiohttp pydantic pyyaml click structlog

# Testing dependencies
pip install pytest pytest-asyncio pytest-mock hypothesis

# Development tools
pip install black isort flake8 mypy pre-commit

# Documentation
pip install mkdocs mkdocs-material
```

### IDE Configuration

#### VS Code Settings

```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "python.sortImports.args": ["--profile", "black"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

#### PyCharm Configuration

1. Set interpreter to `./venv/bin/python`
2. Enable Black formatter
3. Configure isort with Black profile
4. Enable flake8 linting
5. Set up pytest as test runner

## Architecture Overview

### High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Interface │    │  Configuration   │    │   Report        │
│   (apileaks.py) │◄──►│   Manager        │◄──►│   Generator     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   APILeak Core  │◄──►│   HTTP Request   │◄──►│   Response      │
│   Orchestrator  │    │   Engine         │    │   Analyzer      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Fuzzing       │    │   OWASP Testing  │    │   Advanced      │
│   Orchestrator  │    │   Modules        │    │   Features      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Endpoint      │    │   BOLA Testing   │    │   WAF Detection │
│   Fuzzer        │    │   Auth Testing   │    │   Framework     │
│   Parameter     │    │   Property Auth  │    │   Detection     │
│   Fuzzer        │    │   Function Auth  │    │   Payload Gen   │
│   Header Fuzzer │    │   Resource Test  │    │   Subdomain     │
└─────────────────┘    │   SSRF Testing   │    │   Discovery     │
                       └──────────────────┘    └─────────────────┘
```

### Core Components

#### APILeak Core Orchestrator
- **Purpose**: Central coordination of all testing modules
- **Location**: `core/apileak_core.py`
- **Responsibilities**:
  - Module lifecycle management
  - Configuration distribution
  - Result aggregation
  - Progress tracking

#### HTTP Request Engine
- **Purpose**: Handles all HTTP communications
- **Location**: `core/http_engine.py`
- **Features**:
  - Async request handling with httpx
  - Connection pooling
  - Rate limiting with adaptive backoff
  - Multiple authentication methods
  - Retry logic with exponential backoff

#### Configuration Manager
- **Purpose**: Centralized configuration handling
- **Location**: `core/config_manager.py`
- **Features**:
  - YAML/JSON configuration parsing
  - Pydantic validation
  - Environment variable support
  - Configuration inheritance

#### Response Analyzer
- **Purpose**: Analyzes HTTP responses for vulnerabilities
- **Location**: `core/response_analyzer.py`
- **Features**:
  - Pattern matching with regex
  - Timing analysis
  - Header security analysis
  - Sensitive data detection

## Code Organization

### Directory Structure

```
apileak/
├── core/                    # Core engine components
│   ├── __init__.py
│   ├── apileak_core.py     # Main orchestrator
│   ├── config_manager.py   # Configuration handling
│   ├── http_engine.py      # HTTP request engine
│   ├── response_analyzer.py # Response analysis
│   └── findings_collector.py # Results aggregation
├── modules/                 # Testing modules
│   ├── __init__.py
│   ├── fuzzing/            # Traditional fuzzing modules
│   │   ├── endpoint_fuzzer.py
│   │   ├── parameter_fuzzer.py
│   │   └── header_fuzzer.py
│   ├── owasp/              # OWASP-specific modules
│   │   ├── bola_testing.py
│   │   ├── auth_testing.py
│   │   ├── property_auth.py
│   │   ├── function_auth.py
│   │   ├── resource_testing.py
│   │   └── ssrf_testing.py
│   └── advanced/           # Advanced features
│       ├── waf_detection.py
│       ├── framework_detection.py
│       ├── payload_generator.py
│       └── subdomain_discovery.py
├── utils/                   # Utility functions
│   ├── __init__.py
│   ├── logging_utils.py
│   ├── validation_utils.py
│   └── encoding_utils.py
├── templates/              # Report templates
│   ├── html/
│   ├── xml/
│   └── json/
├── wordlists/              # Testing wordlists
│   ├── endpoints/
│   ├── parameters/
│   ├── headers/
│   └── payloads/
├── tests/                  # Test suite
│   ├── unit/
│   ├── integration/
│   └── property/
├── docs/                   # Documentation
├── config/                 # Configuration examples
└── reports/               # Generated reports
```

### Naming Conventions

#### Files and Directories
- Use snake_case for Python files: `http_engine.py`
- Use lowercase for directories: `modules/owasp/`
- Use descriptive names: `bola_testing.py` not `bt.py`

#### Classes
- Use PascalCase: `HTTPRequestEngine`
- Use descriptive names: `BOLATestingModule`
- Suffix with purpose: `ConfigManager`, `ResponseAnalyzer`

#### Functions and Variables
- Use snake_case: `analyze_response()`
- Use descriptive names: `detect_sensitive_data()`
- Use verbs for functions: `validate_config()`, `parse_response()`

#### Constants
- Use UPPER_SNAKE_CASE: `MAX_RETRY_ATTEMPTS`
- Group related constants in classes or modules

## Development Workflow

### Git Workflow

1. **Feature Development**
   ```bash
   # Create feature branch
   git checkout -b feature/new-owasp-module
   
   # Make changes and commit
   git add .
   git commit -m "feat: add new OWASP testing module"
   
   # Push and create PR
   git push origin feature/new-owasp-module
   ```

2. **Commit Message Format**
   ```
   type(scope): description
   
   feat: new feature
   fix: bug fix
   docs: documentation changes
   test: adding tests
   refactor: code refactoring
   perf: performance improvements
   ```

### Code Quality Checks

```bash
# Run all quality checks
make check

# Individual checks
make lint      # flake8 linting
make format    # black formatting
make type      # mypy type checking
make test      # pytest test suite
```

### Pre-commit Hooks

The project uses pre-commit hooks to ensure code quality:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.0.1
    hooks:
      - id: mypy
```

## Testing Framework

### Test Organization

```
tests/
├── unit/                   # Unit tests
│   ├── test_config_manager.py
│   ├── test_http_engine.py
│   └── test_response_analyzer.py
├── integration/            # Integration tests
│   ├── test_fuzzing_flow.py
│   ├── test_owasp_modules.py
│   └── test_report_generation.py
├── property/              # Property-based tests
│   ├── test_config_properties.py
│   ├── test_http_properties.py
│   └── test_analysis_properties.py
└── fixtures/              # Test fixtures
    ├── sample_configs/
    ├── mock_responses/
    └── test_data/
```

### Unit Testing Guidelines

```python
# Example unit test
import pytest
from unittest.mock import Mock, patch
from core.config_manager import ConfigManager

class TestConfigManager:
    def setup_method(self):
        """Setup for each test method."""
        self.config_manager = ConfigManager()
    
    def test_load_valid_yaml_config(self):
        """Test loading a valid YAML configuration."""
        config_data = {
            'target': 'https://api.example.com',
            'modules': ['bola', 'auth']
        }
        
        with patch('builtins.open', mock_open(read_data=yaml.dump(config_data))):
            config = self.config_manager.load_config('test.yaml')
            
        assert config.target == 'https://api.example.com'
        assert 'bola' in config.modules
    
    def test_invalid_config_raises_validation_error(self):
        """Test that invalid config raises ValidationError."""
        invalid_config = {'invalid': 'config'}
        
        with patch('builtins.open', mock_open(read_data=yaml.dump(invalid_config))):
            with pytest.raises(ValidationError):
                self.config_manager.load_config('invalid.yaml')
```

### Integration Testing

```python
# Example integration test
import pytest
import asyncio
from core.apileak_core import APILeakCore
from modules.owasp.bola_testing import BOLATestingModule

class TestBOLAIntegration:
    @pytest.mark.asyncio
    async def test_bola_testing_flow(self):
        """Test complete BOLA testing flow."""
        # Setup
        config = {
            'target': 'https://api.testserver.com',
            'auth': {'type': 'bearer', 'token': 'test-token'},
            'modules': {'bola': {'enabled': True}}
        }
        
        core = APILeakCore(config)
        bola_module = BOLATestingModule(core.http_engine)
        
        # Execute
        findings = await bola_module.run_tests()
        
        # Verify
        assert len(findings) > 0
        assert any(f.severity == 'CRITICAL' for f in findings)
```

## Property-Based Testing

APILeak uses Hypothesis for property-based testing to ensure robustness across a wide range of inputs.

### Property Test Examples

```python
from hypothesis import given, strategies as st
from core.response_analyzer import ResponseAnalyzer

class TestResponseAnalyzerProperties:
    
    @given(st.text())
    def test_sensitive_data_detection_never_false_positive_on_random_text(self, random_text):
        """Property: Random text should not be detected as sensitive data."""
        analyzer = ResponseAnalyzer()
        
        # Exclude actual sensitive patterns from random text
        assume(not any(pattern in random_text.lower() for pattern in 
                      ['password', 'api_key', 'secret', 'token']))
        
        result = analyzer.detect_sensitive_data(random_text)
        assert not result.has_sensitive_data
    
    @given(st.integers(min_value=200, max_value=599))
    def test_status_code_classification_consistency(self, status_code):
        """Property: Status code classification should be consistent."""
        analyzer = ResponseAnalyzer()
        
        classification1 = analyzer.classify_status_code(status_code)
        classification2 = analyzer.classify_status_code(status_code)
        
        assert classification1 == classification2
    
    @given(st.dictionaries(st.text(), st.text()))
    def test_header_analysis_preserves_original_headers(self, headers):
        """Property: Header analysis should not modify original headers."""
        analyzer = ResponseAnalyzer()
        original_headers = headers.copy()
        
        analyzer.analyze_security_headers(headers)
        
        assert headers == original_headers
```

### Property Test Configuration

```python
# conftest.py
from hypothesis import settings, Verbosity

# Configure Hypothesis for CI/CD
settings.register_profile("ci", max_examples=1000, verbosity=Verbosity.verbose)
settings.register_profile("dev", max_examples=100, verbosity=Verbosity.normal)
settings.register_profile("debug", max_examples=10, verbosity=Verbosity.verbose)

# Load profile based on environment
import os
profile = os.getenv("HYPOTHESIS_PROFILE", "dev")
settings.load_profile(profile)
```

## Adding New OWASP Modules

### Module Template

```python
# modules/owasp/new_module.py
from typing import List, Dict, Any
from dataclasses import dataclass
from core.base_module import BaseTestingModule
from core.findings import Finding

@dataclass
class NewModuleConfig:
    """Configuration for the new OWASP module."""
    enabled: bool = True
    max_attempts: int = 100
    custom_payloads: List[str] = None

class NewOWASPModule(BaseTestingModule):
    """
    New OWASP testing module for [specific vulnerability].
    
    This module tests for [vulnerability description] by [testing approach].
    """
    
    def __init__(self, http_engine, config: NewModuleConfig):
        super().__init__(http_engine)
        self.config = config
        self.module_name = "new_owasp_module"
    
    async def run_tests(self) -> List[Finding]:
        """
        Execute the new OWASP tests.
        
        Returns:
            List of findings discovered during testing.
        """
        findings = []
        
        try:
            # Implement testing logic here
            findings.extend(await self._test_specific_vulnerability())
            
        except Exception as e:
            self.logger.error(f"Error in {self.module_name}: {e}")
            
        return findings
    
    async def _test_specific_vulnerability(self) -> List[Finding]:
        """Test for specific vulnerability patterns."""
        findings = []
        
        # Implementation details
        
        return findings
    
    def _create_finding(self, endpoint: str, details: Dict[str, Any]) -> Finding:
        """Create a standardized finding."""
        return Finding(
            module=self.module_name,
            endpoint=endpoint,
            severity=self._calculate_severity(details),
            title=f"[Vulnerability Name] detected",
            description=details.get('description', ''),
            evidence=details.get('evidence', {}),
            recommendation="Specific remediation steps"
        )
```

### Module Registration

```python
# core/module_registry.py
from modules.owasp.new_module import NewOWASPModule

OWASP_MODULES = {
    'bola': BOLATestingModule,
    'auth': AuthTestingModule,
    'property_auth': PropertyAuthModule,
    'function_auth': FunctionAuthModule,
    'resource': ResourceTestingModule,
    'ssrf': SSRFTestingModule,
    'new_module': NewOWASPModule,  # Add new module here
}
```

### Module Testing

```python
# tests/unit/test_new_module.py
import pytest
from unittest.mock import AsyncMock
from modules.owasp.new_module import NewOWASPModule, NewModuleConfig

class TestNewOWASPModule:
    def setup_method(self):
        self.http_engine = AsyncMock()
        self.config = NewModuleConfig()
        self.module = NewOWASPModule(self.http_engine, self.config)
    
    @pytest.mark.asyncio
    async def test_run_tests_returns_findings(self):
        """Test that run_tests returns a list of findings."""
        findings = await self.module.run_tests()
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_vulnerability_detection(self):
        """Test specific vulnerability detection logic."""
        # Mock HTTP responses
        self.http_engine.request.return_value = MockResponse(
            status_code=200,
            text="vulnerable response"
        )
        
        findings = await self.module._test_specific_vulnerability()
        assert len(findings) > 0
        assert findings[0].severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
```

## Performance Optimization

### Async Programming Guidelines

```python
# Good: Proper async/await usage
async def process_endpoints(self, endpoints: List[str]) -> List[Finding]:
    """Process multiple endpoints concurrently."""
    tasks = []
    semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
    
    for endpoint in endpoints:
        task = self._process_single_endpoint(endpoint, semaphore)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, Finding)]

async def _process_single_endpoint(self, endpoint: str, semaphore: asyncio.Semaphore) -> Finding:
    """Process a single endpoint with rate limiting."""
    async with semaphore:
        response = await self.http_engine.request('GET', endpoint)
        return self._analyze_response(response)

# Bad: Blocking operations in async context
async def bad_example(self):
    time.sleep(1)  # Blocks the event loop
    requests.get(url)  # Synchronous HTTP request
```

### Memory Management

```python
# Good: Generator for large datasets
def generate_payloads(self) -> Iterator[str]:
    """Generate payloads on-demand to save memory."""
    for base_payload in self.base_payloads:
        for encoding in self.encodings:
            yield self._encode_payload(base_payload, encoding)

# Good: Context managers for resource cleanup
class HTTPEngine:
    async def __aenter__(self):
        self.session = httpx.AsyncClient()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.aclose()

# Usage
async with HTTPEngine() as engine:
    response = await engine.request('GET', url)
```

### Caching Strategies

```python
from functools import lru_cache
from typing import Dict, Any

class FrameworkDetector:
    def __init__(self):
        self._detection_cache: Dict[str, str] = {}
    
    @lru_cache(maxsize=1000)
    def detect_framework_by_headers(self, headers_tuple: tuple) -> str:
        """Cache framework detection results."""
        headers = dict(headers_tuple)
        return self._analyze_headers(headers)
    
    async def detect_framework(self, url: str) -> str:
        """Detect framework with caching."""
        if url in self._detection_cache:
            return self._detection_cache[url]
        
        response = await self.http_engine.request('GET', url)
        headers_tuple = tuple(sorted(response.headers.items()))
        
        framework = self.detect_framework_by_headers(headers_tuple)
        self._detection_cache[url] = framework
        
        return framework
```

## Debugging and Profiling

### Logging Configuration

```python
# utils/logging_utils.py
import structlog
import logging
from typing import Any, Dict

def configure_logging(level: str = "INFO", format_json: bool = False) -> None:
    """Configure structured logging for APILeak."""
    
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if format_json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper()),
    )

# Usage in modules
class BOLATestingModule:
    def __init__(self, http_engine):
        self.logger = structlog.get_logger(__name__)
    
    async def run_tests(self):
        self.logger.info("Starting BOLA testing", module="bola", target=self.target)
        
        try:
            findings = await self._execute_tests()
            self.logger.info("BOLA testing completed", 
                           findings_count=len(findings),
                           critical_findings=len([f for f in findings if f.severity == 'CRITICAL']))
            return findings
            
        except Exception as e:
            self.logger.error("BOLA testing failed", 
                            error=str(e), 
                            exc_info=True)
            raise
```

### Performance Profiling

```python
# utils/profiling_utils.py
import cProfile
import pstats
import asyncio
from functools import wraps
from typing import Callable, Any

def profile_async(func: Callable) -> Callable:
    """Decorator to profile async functions."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()
        
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            profiler.disable()
            stats = pstats.Stats(profiler)
            stats.sort_stats('cumulative')
            stats.print_stats(20)  # Top 20 functions
    
    return wrapper

# Usage
class APILeakCore:
    @profile_async
    async def run_all_tests(self):
        """Run all tests with profiling."""
        # Implementation
        pass
```

### Memory Profiling

```python
# Development dependency: memory-profiler
# pip install memory-profiler

from memory_profiler import profile

class ResponseAnalyzer:
    @profile
    def analyze_large_response(self, response_text: str):
        """Analyze response with memory profiling."""
        # Implementation that processes large responses
        pass

# Run with: python -m memory_profiler script.py
```

## Contributing Guidelines

### Code Review Checklist

- [ ] **Functionality**: Does the code work as intended?
- [ ] **Tests**: Are there adequate unit and integration tests?
- [ ] **Performance**: Are there any performance bottlenecks?
- [ ] **Security**: Are there any security vulnerabilities?
- [ ] **Documentation**: Is the code well-documented?
- [ ] **Style**: Does the code follow project conventions?
- [ ] **Error Handling**: Are errors handled appropriately?
- [ ] **Logging**: Is appropriate logging in place?

### Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Property tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No new linting errors

## Related Issues
Closes #[issue_number]
```

### Release Process

1. **Version Bumping**
   ```bash
   # Update version in setup.py and __init__.py
   git add .
   git commit -m "bump: version 1.2.0"
   git tag v1.2.0
   ```

2. **Release Notes**
   ```markdown
   ## v1.2.0 - 2024-01-15
   
   ### Added
   - New SSRF testing module
   - WAF detection capabilities
   
   ### Changed
   - Improved rate limiting algorithm
   - Enhanced report generation
   
   ### Fixed
   - Fixed authentication bypass in JWT module
   - Resolved memory leak in response analyzer
   ```

3. **Distribution**
   ```bash
   # Build distribution
   python setup.py sdist bdist_wheel
   
   # Upload to PyPI (production)
   twine upload dist/*
   
   # Upload to Test PyPI (testing)
   twine upload --repository testpypi dist/*
   ```

### Documentation Standards

- **Docstrings**: Use Google-style docstrings
- **Type Hints**: Include type hints for all public functions
- **Examples**: Provide usage examples in docstrings
- **API Documentation**: Auto-generate with Sphinx
- **User Guides**: Write clear, step-by-step guides

```python
def analyze_response(self, response: httpx.Response, patterns: List[str]) -> AnalysisResult:
    """
    Analyze HTTP response for vulnerability patterns.
    
    Args:
        response: The HTTP response to analyze.
        patterns: List of regex patterns to search for.
    
    Returns:
        AnalysisResult containing findings and metadata.
    
    Raises:
        AnalysisError: If response analysis fails.
    
    Example:
        >>> analyzer = ResponseAnalyzer()
        >>> response = httpx.get("https://api.example.com")
        >>> result = analyzer.analyze_response(response, ["error", "exception"])
        >>> print(f"Found {len(result.findings)} issues")
    """
    # Implementation
    pass
```

This completes the comprehensive developer guide for APILeak. The guide covers all essential aspects of development, from environment setup to contribution guidelines, ensuring that developers can effectively work on and extend the APILeak project.