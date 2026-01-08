# Testing Guide

This guide covers APILeak's comprehensive testing strategy, including unit tests, integration tests, and property-based testing.

## 📋 Table of Contents

- [Testing Philosophy](#testing-philosophy)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Unit Testing](#unit-testing)
- [Integration Testing](#integration-testing)
- [Property-Based Testing](#property-based-testing)
- [Test Coverage](#test-coverage)
- [Writing Tests](#writing-tests)
- [Continuous Integration](#continuous-integration)

## 🎯 Testing Philosophy

APILeak follows a comprehensive testing approach that ensures:

- **Correctness**: All functionality works as specified
- **Reliability**: System behaves consistently under various conditions
- **Security**: Security features work correctly and don't introduce vulnerabilities
- **Performance**: System meets performance requirements
- **Maintainability**: Tests are easy to understand and maintain

### Testing Pyramid

```
    /\
   /  \     E2E Tests (Few)
  /____\    
 /      \   Integration Tests (Some)
/__________\ Unit Tests (Many)
```

## 🏗️ Test Structure

### Directory Structure

```
tests/
├── unit/                           # Unit tests
│   ├── test_core_engine.py        # Core engine tests
│   ├── test_findings_collector.py # Findings collector tests
│   ├── test_http_client.py        # HTTP client tests
│   └── test_owasp_modules.py      # OWASP module tests
├── integration/                    # Integration tests
│   ├── test_core_engine_integration.py
│   ├── test_fuzzing_integration.py
│   └── test_owasp_integration.py
├── properties/                     # Property-based tests
│   ├── test_property_level_auth_properties.py
│   └── test_bola_properties.py
├── fixtures/                       # Test fixtures and data
│   ├── sample_responses.json
│   └── test_configs.yaml
└── conftest.py                     # Pytest configuration
```

### Test Categories

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions
3. **Property-Based Tests**: Test universal properties with generated data
4. **End-to-End Tests**: Test complete workflows
5. **Performance Tests**: Test performance characteristics

## 🚀 Running Tests

### Basic Test Execution

```bash
# Run all tests
make test

# Run specific test file
python -m pytest tests/test_findings_collector.py -v

# Run tests with specific pattern
python -m pytest tests/ -k "test_bola" -v

# Run tests in parallel
python -m pytest tests/ -n auto
```

### Test Options

```bash
# Verbose output
python -m pytest tests/ -v

# Show test coverage
python -m pytest tests/ --cov=core --cov=utils --cov=modules

# Generate HTML coverage report
python -m pytest tests/ --cov=core --cov-report=html

# Run only failed tests
python -m pytest tests/ --lf

# Stop on first failure
python -m pytest tests/ -x

# Run tests with specific markers
python -m pytest tests/ -m "not slow"
```

### Make Commands

```bash
make test              # Run all tests
make test-coverage     # Run tests with coverage
make test-unit         # Run only unit tests
make test-integration  # Run only integration tests
make test-properties   # Run only property-based tests
```

## 🔧 Unit Testing

Unit tests verify individual components work correctly in isolation.

### Example Unit Test

```python
"""Unit tests for FindingsCollector"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from utils.findings import FindingsCollector, Finding
from core.config import Severity


class TestFindingsCollector:
    """Test cases for FindingsCollector"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.scan_id = "test-scan-123"
        self.collector = FindingsCollector(self.scan_id)
    
    def test_initialization(self):
        """Test collector initialization"""
        assert self.collector.scan_id == self.scan_id
        assert len(self.collector.findings) == 0
        assert len(self.collector._deduplication_cache) == 0
    
    def test_add_finding_with_auto_classification(self):
        """Test adding finding with automatic classification"""
        finding = self.collector.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,  # Will be auto-classified
            endpoint="/api/users/123",
            method="GET",
            evidence="Anonymous access detected",
            recommendation="Implement authentication"
        )
        
        assert finding.severity == Severity.CRITICAL
        assert finding.owasp_category == "API1"
        assert finding.scan_id == self.scan_id
        assert len(self.collector.findings) == 1
    
    @pytest.mark.parametrize("category,expected_severity", [
        ("BOLA_ANONYMOUS_ACCESS", Severity.CRITICAL),
        ("WEAK_JWT_ALGORITHM", Severity.HIGH),
        ("MISSING_RATE_LIMITING", Severity.MEDIUM),
        ("INFORMATION_DISCLOSURE", Severity.LOW),
        ("ENDPOINT_DISCOVERED", Severity.INFO)
    ])
    def test_severity_classification_rules(self, category, expected_severity):
        """Test automatic severity classification"""
        finding = self.collector.add_finding(
            category=category,
            severity=None,
            endpoint="/api/test",
            method="GET",
            evidence="Test evidence",
            recommendation="Test recommendation"
        )
        
        assert finding.severity == expected_severity
```

### Unit Test Best Practices

- **Isolation**: Mock external dependencies
- **Fast**: Tests should run quickly
- **Deterministic**: Same input always produces same output
- **Focused**: Test one thing at a time
- **Clear**: Test names describe what is being tested

## 🔗 Integration Testing

Integration tests verify that components work correctly together.

### Example Integration Test

```python
"""Integration tests for Core Engine"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock

from core.engine import APILeakCore
from core.config import APILeakConfig, TargetConfig


class TestCoreEngineIntegration:
    """Integration tests for APILeak Core Engine"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return APILeakConfig(
            target=TargetConfig(base_url="https://httpbin.org"),
            # ... other config
        )
    
    @pytest.fixture
    def core(self, config):
        """Create APILeak core instance"""
        return APILeakCore(config)
    
    @pytest.mark.asyncio
    async def test_complete_scan_workflow(self, core):
        """Test complete scan workflow"""
        # Mock external dependencies
        with patch('modules.fuzzing.orchestrator.FuzzingOrchestrator') as mock_fuzzer:
            mock_fuzzer.return_value.discover_endpoints = AsyncMock(return_value=[])
            
            # Execute scan
            results = await core.run_scan("https://httpbin.org")
            
            # Verify results
            assert results.scan_id is not None
            assert results.target_url == "https://httpbin.org"
            assert results.findings_collector is not None
    
    @pytest.mark.asyncio
    async def test_findings_integration(self, core):
        """Test findings collection integration"""
        # Add test findings
        core.findings_collector.add_finding(
            category="TEST_FINDING",
            severity=None,
            endpoint="/test",
            method="GET",
            evidence="Test evidence",
            recommendation="Test recommendation"
        )
        
        # Verify integration
        stats = core.findings_collector.get_statistics()
        assert stats["total_findings"] == 1
```

### Integration Test Patterns

- **Real Dependencies**: Use real components where possible
- **Controlled Environment**: Use test databases/services
- **End-to-End Flows**: Test complete user workflows
- **Error Scenarios**: Test error handling and recovery

## 🎲 Property-Based Testing

Property-based tests use generated data to verify universal properties.

### Example Property-Based Test

```python
"""Property-based tests for Property Level Authorization Module"""

from hypothesis import given, strategies as st, settings
import hypothesis

from modules.owasp.property_level_auth import PropertyLevelAuthModule


class TestPropertyLevelAuthProperties:
    """Property-based tests for Property Level Authorization Module"""
    
    @given(
        field_names=st.lists(
            st.text(min_size=1, max_size=30),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=100, deadline=5000)
    def test_undocumented_field_filtering_property(self, field_names):
        """
        **Feature: apileak-owasp-enhancement, Property 9: Undocumented Field Detection**
        **Validates: Requirements 3.4**
        
        For any list of field names, undocumented field filtering should consistently 
        identify potentially undocumented fields while filtering out common metadata fields.
        """
        module = PropertyLevelAuthModule(self.config, self.mock_http_client, self.auth_contexts)
        
        for field_name in field_names:
            result = module._is_potentially_undocumented(field_name)
            
            # Property: Result should always be a boolean
            assert isinstance(result, bool)
            
            # Property: Common metadata fields should always be filtered out
            field_lower = field_name.lower()
            common_fields = ['timestamp', 'created_at', 'updated_at', 'id']
            
            for common_field in common_fields:
                if common_field in field_lower:
                    assert result is False, f"Common field '{field_name}' should be filtered out"
                    break
```

### Property-Based Testing Benefits

- **Comprehensive Coverage**: Tests many more cases than manual examples
- **Edge Case Discovery**: Finds edge cases you might not think of
- **Regression Prevention**: Catches regressions across wide input space
- **Specification Verification**: Verifies properties hold universally

### Property Test Guidelines

- **Clear Properties**: Define clear, testable properties
- **Good Generators**: Create generators that produce valid test data
- **Assume Wisely**: Use `assume()` sparingly to avoid filtering too much
- **Shrinking**: Let Hypothesis find minimal failing examples

## 📊 Test Coverage

### Coverage Goals

- **Unit Tests**: 90%+ coverage for core components
- **Integration Tests**: 80%+ coverage for critical paths
- **Property Tests**: 100% coverage for correctness properties
- **Overall**: 85%+ total coverage

### Measuring Coverage

```bash
# Generate coverage report
python -m pytest tests/ --cov=core --cov=utils --cov=modules --cov-report=html

# View coverage in terminal
python -m pytest tests/ --cov=core --cov-report=term-missing

# Generate XML report for CI
python -m pytest tests/ --cov=core --cov-report=xml
```

### Coverage Analysis

```bash
# View HTML report
open htmlcov/index.html

# Check coverage thresholds
coverage report --fail-under=85
```

## ✍️ Writing Tests

### Test Structure (AAA Pattern)

```python
def test_feature_functionality():
    """Test that feature works correctly"""
    # Arrange - Set up test data and conditions
    config = create_test_config()
    module = TestModule(config)
    test_data = generate_test_data()
    
    # Act - Execute the functionality being tested
    result = module.process_data(test_data)
    
    # Assert - Verify the results
    assert result.is_valid()
    assert result.count == len(test_data)
    assert all(item.processed for item in result.items)
```

### Test Naming Conventions

```python
# Good test names
def test_add_finding_with_valid_data_creates_finding():
def test_mass_assignment_detection_with_dangerous_fields_returns_true():
def test_http_client_with_rate_limiting_respects_limits():

# Poor test names
def test_finding():
def test_mass_assignment():
def test_http():
```

### Fixtures and Mocking

```python
@pytest.fixture
def sample_config():
    """Create sample configuration for tests"""
    return APILeakConfig(
        target=TargetConfig(base_url="https://test.example.com"),
        # ... other config
    )

@pytest.fixture
def mock_http_client():
    """Create mock HTTP client"""
    client = Mock()
    client.request = AsyncMock()
    return client

def test_with_mocked_dependencies(sample_config, mock_http_client):
    """Test using fixtures and mocks"""
    # Configure mock
    mock_http_client.request.return_value = Mock(status_code=200)
    
    # Test functionality
    module = TestModule(sample_config, mock_http_client)
    result = module.process_request()
    
    # Verify mock was called correctly
    mock_http_client.request.assert_called_once()
    assert result.success is True
```

### Parametrized Tests

```python
@pytest.mark.parametrize("input_data,expected_result", [
    ("valid_input", True),
    ("invalid_input", False),
    ("", False),
    (None, False),
])
def test_validation_with_various_inputs(input_data, expected_result):
    """Test validation with various input types"""
    result = validate_input(input_data)
    assert result == expected_result
```

### Async Testing

```python
@pytest.mark.asyncio
async def test_async_functionality():
    """Test asynchronous functionality"""
    client = AsyncHTTPClient()
    
    response = await client.get("https://httpbin.org/get")
    
    assert response.status_code == 200
    assert response.json is not None
```

## 🔄 Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run tests
      run: |
        python -m pytest tests/ --cov=core --cov=utils --cov=modules
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

### Test Automation

- **Pre-commit Hooks**: Run tests before commits
- **Pull Request Checks**: Require tests to pass before merge
- **Coverage Reporting**: Track coverage trends over time
- **Performance Monitoring**: Track test execution time

### Quality Gates

- All tests must pass
- Coverage must meet minimum thresholds
- No new linting errors
- Performance tests within acceptable limits

## 🐛 Debugging Tests

### Common Issues

```python
# Issue: Test is flaky
def test_flaky_behavior():
    # Problem: Depends on timing or external state
    time.sleep(0.1)  # Don't do this
    
    # Solution: Use proper synchronization
    await wait_for_condition(lambda: system.is_ready())

# Issue: Test is too slow
def test_slow_operation():
    # Problem: Does real I/O or computation
    result = expensive_operation()  # Don't do this
    
    # Solution: Mock expensive operations
    with patch('module.expensive_operation') as mock_op:
        mock_op.return_value = expected_result
        result = function_under_test()

# Issue: Test is brittle
def test_brittle_assertion():
    # Problem: Tests implementation details
    assert len(internal_cache) == 5  # Don't do this
    
    # Solution: Test behavior, not implementation
    assert system.can_handle_request()
```

### Debugging Techniques

```python
# Use pytest debugging features
def test_with_debugging():
    import pdb; pdb.set_trace()  # Debugger breakpoint
    
    # Or use pytest's built-in debugging
    pytest.set_trace()

# Capture output for debugging
def test_with_output_capture(capfd):
    function_that_prints()
    captured = capfd.readouterr()
    assert "expected output" in captured.out

# Use temporary directories
def test_with_temp_files(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("test content")
    
    result = process_file(test_file)
    assert result.success
```

## 📚 Additional Resources

- [pytest Documentation](https://docs.pytest.org/)
- [Hypothesis Documentation](https://hypothesis.readthedocs.io/)
- [Python Testing Best Practices](https://docs.python-guide.org/writing/tests/)
- [Test-Driven Development](https://testdriven.io/)

---

Happy Testing! 🧪