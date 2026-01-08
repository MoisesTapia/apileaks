# Contributing to APILeak

Thank you for your interest in contributing to APILeak! 🎉

We welcome contributions from the community and are pleased to have you join us in making APILeak better.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Standards](#code-standards)
- [Documentation](#documentation)
- [Community](#community)

## 🤝 Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

### Our Standards

- **Be respectful**: Treat everyone with respect and kindness
- **Be inclusive**: Welcome newcomers and help them get started
- **Be collaborative**: Work together and share knowledge
- **Be constructive**: Provide helpful feedback and suggestions
- **Be professional**: Maintain a professional and friendly environment

## 🚀 Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- Basic knowledge of Python and API security concepts

### Areas for Contribution

We welcome contributions in these areas:

- **🐛 Bug Fixes**: Fix issues and improve stability
- **✨ New Features**: Add new OWASP modules or fuzzing capabilities
- **📚 Documentation**: Improve docs, examples, and tutorials
- **🧪 Testing**: Add tests and improve test coverage
- **🎨 UI/UX**: Improve CLI interface and report generation
- **⚡ Performance**: Optimize performance and resource usage

## 🛠️ Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/apileak.git
cd apileak

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/apileak.git
```

### 2. Set Up Development Environment

```bash
# Automatic setup (recommended)
make setup-dev

# Manual setup
python3.11 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Verify Setup

```bash
# Run tests to verify everything works
make test

# Run a simple scan to test functionality
python apileaks.py --config config/sample_config.yaml --help
```

## 🔄 Making Changes

### 1. Create a Branch

```bash
# Create and switch to a new branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 2. Branch Naming Convention

- **Features**: `feature/description-of-feature`
- **Bug Fixes**: `fix/issue-description`
- **Documentation**: `docs/what-you-are-documenting`
- **Tests**: `test/what-you-are-testing`

### 3. Make Your Changes

- Follow the existing code style and patterns
- Add tests for new functionality
- Update documentation as needed
- Keep commits focused and atomic

## 🧪 Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
python -m pytest tests/test_specific_module.py -v

# Run with coverage
make test-coverage

# Run linting
make lint

# Format code
make format
```

### Writing Tests

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **Property-Based Tests**: Use Hypothesis for comprehensive testing
- **End-to-End Tests**: Test complete workflows

Example test structure:
```python
def test_feature_functionality():
    """Test that feature works correctly"""
    # Arrange
    setup_test_data()
    
    # Act
    result = call_feature()
    
    # Assert
    assert result.is_valid()
    assert result.meets_expectations()
```

## 📤 Submitting Changes

### 1. Prepare Your Changes

```bash
# Ensure your branch is up to date
git fetch upstream
git rebase upstream/main

# Run tests and linting
make test
make lint

# Commit your changes
git add .
git commit -m "feat: add new OWASP module for API testing"
```

### 2. Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

**Examples:**
```
feat(owasp): add SSRF testing module
fix(http): resolve rate limiting issue
docs(readme): update installation instructions
test(bola): add property-based tests for BOLA module
```

### 3. Create Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub with:
   - **Clear title**: Descriptive title following commit conventions
   - **Description**: What changes you made and why
   - **Testing**: How you tested your changes
   - **Screenshots**: If applicable, add screenshots
   - **Breaking Changes**: Note any breaking changes

### 4. Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated documentation

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings introduced
```

## 📏 Code Standards

### Python Style

- **PEP 8**: Follow Python PEP 8 style guidelines
- **Type Hints**: Use type hints for function parameters and return values
- **Docstrings**: Use Google-style docstrings for all public functions
- **Imports**: Organize imports (standard library, third-party, local)

### Code Quality Tools

```bash
# Format code with black
make format

# Lint with flake8
make lint

# Type checking with mypy (if available)
mypy core/ utils/ modules/
```

### Example Code Style

```python
"""Module docstring describing the module purpose."""

from typing import List, Dict, Optional
import asyncio

from core.config import APILeakConfig
from utils.findings import Finding


class ExampleClass:
    """Example class following project conventions.
    
    This class demonstrates the coding style and patterns
    used throughout the APILeak project.
    """
    
    def __init__(self, config: APILeakConfig) -> None:
        """Initialize the example class.
        
        Args:
            config: APILeak configuration object
        """
        self.config = config
        self.logger = get_logger(__name__)
    
    async def process_data(self, data: List[Dict[str, Any]]) -> List[Finding]:
        """Process data and return findings.
        
        Args:
            data: List of data dictionaries to process
            
        Returns:
            List of findings discovered during processing
            
        Raises:
            ValueError: If data format is invalid
        """
        findings = []
        
        for item in data:
            if not self._validate_item(item):
                raise ValueError(f"Invalid item format: {item}")
            
            finding = await self._analyze_item(item)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _validate_item(self, item: Dict[str, Any]) -> bool:
        """Validate individual data item.
        
        Args:
            item: Data item to validate
            
        Returns:
            True if item is valid, False otherwise
        """
        return isinstance(item, dict) and 'id' in item
```

## 📚 Documentation

### Documentation Standards

- **Clear and Concise**: Write clear, concise documentation
- **Examples**: Include practical examples
- **Up-to-Date**: Keep documentation synchronized with code changes
- **Comprehensive**: Cover all public APIs and features

### Documentation Types

- **API Documentation**: Docstrings for all public functions and classes
- **User Guides**: Step-by-step guides for common tasks
- **Developer Guides**: Technical documentation for contributors
- **Examples**: Practical examples and tutorials

### Writing Documentation

```python
def example_function(param1: str, param2: Optional[int] = None) -> bool:
    """Example function with proper documentation.
    
    This function demonstrates how to write proper documentation
    following the project standards.
    
    Args:
        param1: Description of the first parameter
        param2: Optional second parameter with default value
        
    Returns:
        True if operation successful, False otherwise
        
    Raises:
        ValueError: If param1 is empty
        TypeError: If param2 is not an integer
        
    Example:
        >>> result = example_function("test", 42)
        >>> print(result)
        True
    """
    if not param1:
        raise ValueError("param1 cannot be empty")
    
    if param2 is not None and not isinstance(param2, int):
        raise TypeError("param2 must be an integer")
    
    return True
```

## 🌟 Recognition

Contributors are recognized in several ways:

- **Contributors List**: Listed in project documentation
- **Release Notes**: Mentioned in release notes for significant contributions
- **GitHub**: Contributions visible on GitHub profile
- **Community**: Recognition in community discussions

## 💬 Community

### Getting Help

- **GitHub Issues**: For bug reports and feature requests
- **Discussions**: For questions and general discussion
- **Documentation**: Check existing documentation first

### Communication Guidelines

- **Be Patient**: Maintainers are volunteers with limited time
- **Be Specific**: Provide detailed information about issues
- **Be Respectful**: Treat everyone with respect and kindness
- **Search First**: Check existing issues and documentation

### Maintainer Response Times

- **Bug Reports**: 2-5 business days
- **Feature Requests**: 1-2 weeks
- **Pull Reviews**: 3-7 business days
- **Security Issues**: 24-48 hours

## 🎯 Contribution Ideas

Looking for ways to contribute? Here are some ideas:

### For Beginners
- Fix typos in documentation
- Add examples to existing documentation
- Write tests for existing functionality
- Improve error messages

### For Intermediate Contributors
- Add new OWASP testing modules
- Improve existing fuzzing capabilities
- Add new report formats
- Optimize performance

### For Advanced Contributors
- Design new architecture components
- Add advanced security features
- Implement complex algorithms
- Lead major feature development

## 📞 Questions?

If you have questions about contributing, please:

1. Check the documentation
2. Search existing issues
3. Create a new discussion
4. Reach out to maintainers

Thank you for contributing to APILeak! 🚀