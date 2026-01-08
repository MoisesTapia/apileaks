# 🛠️ Development Guide

This guide provides comprehensive information for developers who want to contribute to APILeak, set up a development environment, or extend the tool's functionality.

## Prerequisites

Before setting up the development environment, ensure you have the following installed:

- **Python 3.11+** - Required for modern async features and type hints
- **Git** - For version control and repository management
- **Make** - Optional, but recommended for convenience commands
- **Docker** - Optional, for container-based development and testing

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.11 | 3.12+ |
| RAM | 4GB | 8GB+ |
| Storage | 2GB | 5GB+ |
| OS | Linux, macOS, Windows | Linux/macOS |

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub first, then clone your fork
git clone https://github.com/YOUR_USERNAME/apileak.git
cd apileak

# Add upstream remote for syncing
git remote add upstream https://github.com/original-org/apileak.git
```

### 2. Environment Setup

#### Using Make (Recommended)
```bash
# Complete development setup
make setup-dev

# This command will:
# - Create virtual environment
# - Install dependencies
# - Install pre-commit hooks
# - Set up development tools
```

#### Manual Setup
```bash
# Create virtual environment
python -m venv venv

# Activate environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install package in development mode
pip install -e .

# Install pre-commit hooks
pre-commit install
```

### 3. Verify Installation

```bash
# Run tests to verify setup
make test

# Check code quality
make lint

# Run a simple scan to test functionality
python apileaks.py dir --target https://httpbin.org --wordlist wordlists/endpoints.txt
```

## Available Commands

APILeak provides a comprehensive set of Make commands for development workflows:

```bash
make help              # Show all available commands
make setup-dev         # Complete development setup
make test              # Run test suite
make test-coverage     # Run tests with coverage report
make test-watch        # Run tests in watch mode
make lint              # Run linting (flake8, mypy, bandit)
make format            # Format code (black, isort)
make clean             # Clean build artifacts
make docker-build      # Build Docker image
make docker-test       # Test Docker image
make docs              # Generate documentation
make release           # Prepare release
```

### Detailed Command Descriptions

#### Testing Commands
```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific test file
python -m pytest tests/test_http_client.py -v

# Run tests matching pattern
python -m pytest -k "test_status_code" -v

# Run property-based tests only
python -m pytest tests/ -m "property" -v
```

#### Code Quality Commands
```bash
# Run all linting
make lint

# Run specific linters
flake8 .                    # Style and error checking
mypy .                      # Type checking
bandit -r .                 # Security analysis
black --check .             # Code formatting check
isort --check-only .        # Import sorting check

# Auto-format code
make format
black .                     # Format code
isort .                     # Sort imports
```

#### Docker Commands
```bash
# Build development image
make docker-build

# Run tests in container
make docker-test

# Run interactive shell in container
docker run -it --rm apileak:latest /bin/bash

# Mount local code for development
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  apileak:latest /bin/bash
```

## Project Structure

```
apileak/
├── apileaks.py              # Main CLI entry point
├── core/                    # Core engine and configuration
│   ├── __init__.py
│   ├── engine.py           # Main orchestrator
│   ├── config.py           # Configuration management
│   └── logging.py          # Logging setup
├── modules/                 # Testing modules
│   ├── fuzzing/            # Traditional fuzzing
│   ├── owasp/              # OWASP API Security testing
│   └── advanced/           # Advanced discovery
├── utils/                   # Utility modules
│   ├── http_client.py      # HTTP request engine
│   ├── findings.py         # Findings management
│   ├── report_generator.py # Report generation
│   └── jwt_utils.py        # JWT utilities
├── tests/                   # Test suite
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── property/           # Property-based tests
├── docs/                    # Documentation
├── config/                  # Configuration templates
├── wordlists/              # Default wordlists
├── templates/              # Report templates
└── ci-cd/                  # CI/CD integration
```

## Development Workflow

### 1. Feature Development

```bash
# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
make test
make lint

# Commit changes
git add .
git commit -m "feat: add amazing feature"

# Push and create PR
git push origin feature/amazing-feature
```

### 2. Testing Strategy

APILeak uses a comprehensive testing approach:

#### Unit Tests
```bash
# Test individual components
python -m pytest tests/unit/ -v

# Test specific module
python -m pytest tests/unit/test_http_client.py -v
```

#### Integration Tests
```bash
# Test component interactions
python -m pytest tests/integration/ -v

# Test with real HTTP endpoints
python -m pytest tests/integration/test_fuzzing.py -v
```

#### Property-Based Tests
```bash
# Run property-based tests
python -m pytest tests/property/ -v

# Run with more examples
python -m pytest tests/property/ --hypothesis-max-examples=1000 -v
```

### 3. Code Quality Standards

#### Code Style
- **Black** for code formatting
- **isort** for import sorting
- **flake8** for style checking
- **mypy** for type checking

#### Security
- **bandit** for security analysis
- **safety** for dependency vulnerability checking

#### Documentation
- **Docstrings** for all public functions and classes
- **Type hints** for all function signatures
- **README** updates for new features

### 4. Pre-commit Hooks

Pre-commit hooks automatically run quality checks:

```bash
# Install hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files

# Update hooks
pre-commit autoupdate
```

## Adding New Features

### 1. Adding New OWASP Modules

```python
# Create new module in modules/owasp/
class NewOWASPModule(BaseOWASPModule):
    def __init__(self, config, http_client, auth_contexts):
        super().__init__(config, http_client, auth_contexts)
        self.module_name = "new_owasp"
    
    async def execute_tests(self, endpoints):
        findings = []
        # Implementation here
        return findings

# Register in core/engine.py
if "new_owasp" not in self.owasp_modules:
    module = NewOWASPModule(config, http_client, auth_contexts)
    self.register_owasp_module("new_owasp", module)
```

### 2. Adding New Fuzzing Strategies

```python
# Create new fuzzer in modules/fuzzing/
class NewFuzzer(BaseFuzzer):
    def __init__(self, config, http_client):
        super().__init__(config, http_client)
    
    async def fuzz(self, endpoints):
        results = []
        # Implementation here
        return results

# Integrate in fuzzing orchestrator
self.new_fuzzer = NewFuzzer(config, http_client)
```

### 3. Adding New Report Formats

```python
# Create formatter in utils/report_generator.py
class NewFormatter(BaseFormatter):
    def format(self, results):
        # Implementation here
        return formatted_output
    
    def save(self, content, filepath):
        # Save implementation
        pass

# Register formatter
report_generator.register_formatter("new_format", NewFormatter())
```

## Testing Guidelines

### 1. Writing Unit Tests

```python
import pytest
from unittest.mock import Mock, patch
from your_module import YourClass

class TestYourClass:
    def setup_method(self):
        self.mock_http = Mock()
        self.instance = YourClass(self.mock_http)
    
    def test_method_success(self):
        # Arrange
        expected = "expected_result"
        
        # Act
        result = self.instance.method()
        
        # Assert
        assert result == expected
    
    @pytest.mark.asyncio
    async def test_async_method(self):
        # Test async methods
        result = await self.instance.async_method()
        assert result is not None
```

### 2. Writing Property-Based Tests

```python
from hypothesis import given, strategies as st
import pytest

class TestPropertyBased:
    @given(st.text())
    def test_property_holds(self, input_text):
        # Property that should hold for all inputs
        result = process_text(input_text)
        assert len(result) >= 0
    
    @given(st.integers(min_value=1, max_value=1000))
    def test_rate_limiting(self, rate):
        # Test rate limiting with various rates
        limiter = RateLimiter(rate)
        # Test implementation
```

### 3. Writing Integration Tests

```python
@pytest.mark.integration
class TestIntegration:
    @pytest.fixture
    def test_server(self):
        # Setup test server
        server = TestServer()
        server.start()
        yield server
        server.stop()
    
    async def test_full_scan_flow(self, test_server):
        # Test complete scan workflow
        config = create_test_config(test_server.url)
        core = APILeakCore(config)
        results = await core.run_scan(test_server.url)
        
        assert results.statistics.total_requests > 0
        assert len(results.findings) >= 0
```

## Debugging

### 1. Debug Mode

```bash
# Run with debug logging
python apileaks.py dir \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log

# Use debugger
python -m pdb apileaks.py dir --target https://api.example.com
```

### 2. Profiling

```bash
# Profile performance
python -m cProfile -o profile.stats apileaks.py dir --target https://api.example.com

# Analyze profile
python -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(20)"
```

### 3. Memory Analysis

```bash
# Monitor memory usage
python -m memory_profiler apileaks.py dir --target https://api.example.com

# Generate memory report
mprof run apileaks.py dir --target https://api.example.com
mprof plot
```

## Performance Optimization

### 1. Async Best Practices

```python
# Use async/await properly
async def process_endpoints(endpoints):
    tasks = [process_endpoint(ep) for ep in endpoints]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results

# Use semaphores for concurrency control
semaphore = asyncio.Semaphore(10)
async def limited_request():
    async with semaphore:
        return await make_request()
```

### 2. Memory Management

```python
# Use generators for large datasets
def process_large_wordlist(filepath):
    with open(filepath) as f:
        for line in f:
            yield line.strip()

# Clean up resources
async def cleanup_resources():
    await http_client.close()
    await db_connection.close()
```

### 3. Caching Strategies

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def expensive_computation(input_data):
    # Expensive operation
    return result
```

## Release Process

### 1. Version Management

```bash
# Update version in setup.py and __init__.py
# Follow semantic versioning (MAJOR.MINOR.PATCH)

# Create release branch
git checkout -b release/v0.2.0

# Update CHANGELOG.md
# Update documentation
# Run full test suite
make test-coverage

# Create release
make release
```

### 2. Documentation Updates

```bash
# Generate API documentation
make docs

# Update README.md with new features
# Update configuration examples
# Update CLI reference
```

### 3. Quality Gates

Before releasing, ensure:
- [ ] All tests pass
- [ ] Code coverage > 90%
- [ ] No security vulnerabilities
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version numbers updated

## Troubleshooting

### Common Issues

#### Import Errors
```bash
# Ensure package is installed in development mode
pip install -e .

# Check Python path
python -c "import sys; print(sys.path)"
```

#### Test Failures
```bash
# Run specific failing test
python -m pytest tests/test_failing.py::test_method -v -s

# Check test dependencies
pip install -r requirements-dev.txt
```

#### Docker Issues
```bash
# Rebuild image
docker build --no-cache -t apileak:latest .

# Check container logs
docker logs container_id
```

### Getting Help

- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share ideas
- **Documentation**: Check docs/ directory
- **Code Review**: Submit PRs for feedback

---

This development guide provides the foundation for contributing to APILeak. For specific questions or advanced topics, please refer to the project's GitHub repository or contact the maintainers.