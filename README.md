# APILeak v0.1.0 [Beta][DEVELOPMENT]

<div align="center">
  <img src="images/logo_apileaks.png" alt="APILeak Logo" width="500"/>
</div>

## APILeak v0.1.0 - Enterprise API Fuzzing Tool - by Cl0wnR3v

**Enterprise-grade API security testing tool with comprehensive OWASP API Security Top 10 2023 coverage.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/your-org/apileak/workflows/Tests/badge.svg)](https://github.com/your-org/apileak/actions)
[![Coverage](https://codecov.io/gh/your-org/apileak/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/apileak)

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/your-org/apileak.git
cd apileak
make setup-dev

# Activate environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Run your first scan
python apileaks.py --config config/sample_config.yaml --target https://api.example.com
```

### Basic Usage Examples

```bash
# Directory fuzzing
python apileaks.py dir --target https://api.example.com

# Directory fuzzing with triage: filter by status class, save a session, export Markdown
python apileaks.py dir --target https://api.example.com \
  --status-code 2xx --save-session session.json --export md --export-file results.md

# Reload a saved session and triage interactively (opt-in prompt)
python apileaks.py dir --target https://api.example.com \
  --load-session session.json --interactive

# Parameter fuzzing
python apileaks.py par --target https://api.example.com

# Full security scan
python apileaks.py full --target https://api.example.com

# With WAF evasion
python apileaks.py full --target https://api.example.com --user-agent-random

# With OWASP modules
python apileaks.py full --target https://api.example.com --modules bola,auth,property
```

For comprehensive usage examples, see the [Usage Examples](docs/usage-examples.md) documentation.

## ✨ Key Features

- **🛡️ OWASP API Security Top 10 2023**: Complete coverage of all 10 categories
- **🎯 Advanced Fuzzing**: Endpoint, parameter, and header fuzzing with intelligent discovery
- **🔍 Framework Detection**: Automatic identification of API frameworks (FastAPI, Express, Django, Flask, etc.)
- **📊 Version Fuzzing**: Discovery and comparison of API versions (/v1, /v2, /api/v1, etc.)
- **🌈 Colored HTTP Output**: Real-time colored status indicators for all HTTP requests
- **🥷 WAF Evasion**: Multiple user agent strategies for bypassing Web Application Firewalls
- **🔍 Property-Based Testing**: Comprehensive correctness validation using Hypothesis
- **📊 Smart Analytics**: Automatic severity classification and OWASP categorization
- **📈 Real-time Reporting**: Multi-format reports (XML, JSON, HTML, TXT)
- **⚡ High Performance**: Async HTTP client with adaptive rate limiting
- **🐳 Container Ready**: Docker support for CI/CD integration
- **🔧 Enterprise Grade**: Structured logging, configuration management, and monitoring



## 🔍 Advanced Discovery Features

### Framework Detection

APILeak automatically detects API frameworks and adapts testing strategies accordingly:

| Framework | Detection Method | Specific Payloads | Status |
|-----------|------------------|-------------------|--------|
| **FastAPI** | Headers, OpenAPI, Error patterns | Pydantic injection, Async race conditions | ✅ |
| **Express.js** | Headers, Error patterns, Node.js signatures | Prototype pollution, Path traversal | ✅ |
| **Django** | Headers, Admin pages, Error patterns | Template injection, CSRF bypass | ✅ |
| **Flask** | Headers, Werkzeug signatures, Error patterns | Jinja2 injection, Debug exposure | ✅ |
| **Spring Boot** | Headers, Actuator endpoints, Error patterns | SpEL injection, Actuator exposure | ✅ |
| **ASP.NET** | Headers, ViewState, Error patterns | ViewState manipulation, Config exposure | ✅ |

### API Version Discovery

Comprehensive API version mapping and security analysis:

- **Version Patterns**: `/v1`, `/v2`, `/api/v1`, `/api/v2`, `/version1`, etc.
- **Status Detection**: Active, Deprecated, Development versions
- **Endpoint Comparison**: Identify differences between versions
- **Security Analysis**: Find version-specific vulnerabilities

```bash
# Enable framework detection
python apileaks.py full --target https://api.example.com --detect-framework

# Enable version fuzzing
python apileaks.py full --target https://api.example.com --fuzz-versions

# Combined advanced discovery
python apileaks.py full --target https://api.example.com --df --fv --framework-confidence 0.8
```



## 📖 Documentation

- **[📚 Complete Documentation](docs/README.md)** - Full documentation index
- **[🚀 Installation Guide](docs/installation.md)** - Setup instructions for all platforms
- **[⚙️ Configuration Guide](docs/configuration.md)** - Comprehensive configuration options
- **[💻 CLI Reference](docs/cli-reference.md)** - Command-line interface documentation
- **[🧪 Testing Guide](docs/testing.md)** - Testing strategies and guidelines
- **[🏗️ Architecture](docs/architecture.md)** - System design and architecture overview
- **[🛠️ Development Guide](docs/development.md)** - Development setup and contribution guide
- **[🌈 Colored HTTP Output](docs/colored-http-output.md)** - HTTP output visualization and filtering
- **[🚀 CI/CD Integration](docs/ci-cd-integration.md)** - DevSecOps pipeline integration guide
- **[🎯 Usage Examples](docs/usage-examples.md)** - Comprehensive usage examples and scenarios
- **[🥷 WAF Evasion](docs/waf-evasion.md)** - Web Application Firewall evasion techniques
- **[🐳 Docker Usage](docs/docker-usage.md)** - Container-based deployment and usage
- **[🛡️ OWASP Coverage](docs/owasp-coverage.md)** - OWASP API Security Top 10 2023 coverage

### OWASP Modules
- **[🛡️ OWASP Overview](docs/owasp/README.md)** - Complete OWASP API Security coverage
- **[🔐 BOLA Testing](docs/owasp/bola-testing.md)** - Broken Object Level Authorization
- **[🔑 Auth Testing](docs/owasp/auth-testing.md)** - Authentication vulnerability detection
- **[📋 Property Auth](docs/owasp/property-level-auth.md)** - Property-level authorization testing



## 📊 Sample Output

```
==================================================
APILeak Scan Completed Successfully
==================================================
Target: https://api.example.com
🎨 Status Code Filter: [200, 401, 403]
🎭 WAF Evasion: Random User-Agent enabled
Duration: 0:02:34
Total Endpoints Tested: 1,247
📍 Endpoints Found:
  - GET https://api.example.com/admin (200)
  - POST https://api.example.com/users (201)
  - GET https://api.example.com/debug (200)
Total Findings: 8
Critical: 2 | High: 3 | Medium: 2 | Low: 1
OWASP Coverage: 70.0% (7/10 categories)

Reports generated:
  - reports/security_scan.json
  - reports/security_scan.html
  - reports/security_scan.xml
  - reports/security_scan.txt
```



## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run tests: `make test`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## 🙏 Acknowledgments

- [OWASP API Security Project](https://owasp.org/www-project-api-security/) for the comprehensive security framework
- The Python security community for tools and best practices
- All contributors who help improve APILeak

---

**Built with ❤️ for API security professionals**