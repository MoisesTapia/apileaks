# Installation Guide

This guide covers all installation methods for APILeak, from development setup to production deployment.

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Development Setup](#development-setup)
- [Docker Installation](#docker-installation)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## 🖥️ System Requirements

### Minimum Requirements
- **Python**: 3.11 or higher
- **Memory**: 512 MB RAM
- **Storage**: 100 MB free space
- **Network**: Internet connection for installation

### Recommended Requirements
- **Python**: 3.12+
- **Memory**: 2 GB RAM
- **Storage**: 1 GB free space
- **OS**: Linux, macOS, or Windows 10+

### Supported Platforms
- ✅ Linux (Ubuntu 20.04+, CentOS 8+, Debian 11+)
- ✅ macOS (10.15+)
- ✅ Windows (10+, Windows Server 2019+)
- ✅ Docker (Linux containers)

## 🚀 Quick Start

The fastest way to get APILeak running:

```bash
# Clone repository
git clone https://github.com/your-org/apileak.git
cd apileak

# Automatic setup (recommended)
make setup-dev

# Activate environment and test
source venv/bin/activate  # Linux/macOS
python apileaks.py --help
```

## 📦 Installation Methods

### Method 1: Virtual Environment (Recommended)

This method provides isolation and is recommended for most users.

#### Linux/macOS

```bash
# 1. Clone the repository
git clone https://github.com/your-org/apileak.git
cd apileak

# 2. Create virtual environment
python3.11 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate

# 4. Upgrade pip
python -m pip install --upgrade pip

# 5. Install dependencies
pip install -r requirements.txt

# 6. Verify installation
python apileaks.py --help
```

#### Windows

```cmd
# 1. Clone the repository
git clone https://github.com/your-org/apileak.git
cd apileak

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
venv\Scripts\activate

# 4. Upgrade pip
python -m pip install --upgrade pip

# 5. Install dependencies
pip install -r requirements.txt

# 6. Verify installation
python apileaks.py --help
```

### Method 2: System-wide Installation

⚠️ **Warning**: This method installs packages system-wide and may conflict with other Python projects.

```bash
# Install dependencies system-wide
sudo pip install -r requirements.txt

# Or using package manager (Ubuntu/Debian)
sudo apt update
sudo apt install python3.11 python3.11-pip python3.11-venv
```

### Method 3: Using Make (Development)

For developers, use the provided Makefile:

```bash
# Complete development setup
make setup-dev

# This runs:
# - Creates virtual environment
# - Installs dependencies
# - Sets up pre-commit hooks
# - Runs initial tests
```

## 🛠️ Development Setup

For contributors and developers who want to modify APILeak:

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/apileak.git
cd apileak

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/apileak.git
```

### 2. Development Environment

```bash
# Automatic development setup
make setup-dev

# Manual development setup
python3.11 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

pip install --upgrade pip
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt  # If exists

# Install pre-commit hooks (optional)
pre-commit install
```

### 3. Verify Development Setup

```bash
# Run tests
make test

# Run linting
make lint

# Format code
make format

# Check everything works
python apileaks.py --config config/sample_config.yaml --help
```

### 4. Development Tools

```bash
# Available make commands
make help              # Show all available commands
make setup-dev         # Complete development setup
make test              # Run test suite
make test-coverage     # Run tests with coverage
make lint              # Run code linting
make format            # Format code with black
make clean             # Clean temporary files
make docker-build      # Build Docker image
make docker-run        # Run in Docker
```

## 🐳 Docker Installation

Docker provides complete isolation and consistent environments across platforms.

### Prerequisites

- Docker 20.10+ installed
- Docker Compose 2.0+ (optional)

### Method 1: Docker Build

```bash
# Clone repository
git clone https://github.com/your-org/apileak.git
cd apileak

# Build Docker image
docker build -t apileak:latest .

# Run APILeak in Docker
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest \
  --config config/sample_config.yaml \
  --target https://httpbin.org
```

### Method 2: Docker Compose

```bash
# Using docker-compose
docker-compose build

# Run scan
docker-compose run --rm apileak \
  --config config/sample_config.yaml \
  --target https://api.example.com

# Run with custom configuration
docker-compose run --rm \
  -v /path/to/your/config:/app/config \
  apileak \
  --config config/your_config.yaml
```

### Docker Configuration

Create a `docker-compose.yml` for your environment:

```yaml
version: '3.8'

services:
  apileak:
    build: .
    volumes:
      - ./config:/app/config
      - ./reports:/app/reports
      - ./wordlists:/app/wordlists
    environment:
      - PYTHONUNBUFFERED=1
    networks:
      - apileak-network

networks:
  apileak-network:
    driver: bridge
```

### Docker Best Practices

```bash
# Use specific tags in production
docker build -t apileak:v0.1.0 .

# Run with resource limits
docker run --rm \
  --memory=1g \
  --cpus=1.0 \
  -v $(pwd)/config:/app/config \
  apileak:v0.1.0

# Run in detached mode for long scans
docker run -d \
  --name apileak-scan \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:v0.1.0 \
  --config config/production_config.yaml
```

## ✅ Verification

After installation, verify APILeak works correctly:

### 1. Basic Verification

```bash
# Check version and help
python apileaks.py --help

# Should show:
# APILeak v0.1.0 - Enterprise API Fuzzing Tool
# Usage: apileaks.py [OPTIONS]
```

### 2. Configuration Test

```bash
# Test with sample configuration
python apileaks.py --config config/sample_config.yaml --help

# Should load configuration without errors
```

### 3. Dependency Check

```bash
# Check all dependencies are installed
python -c "
import structlog
import pydantic
import httpx
import click
import yaml
print('All dependencies installed successfully!')
"
```

### 4. Test Scan

```bash
# Run a quick test scan (requires internet)
python apileaks.py \
  --config config/sample_config.yaml \
  --target https://httpbin.org/get \
  --modules "" \
  --no-banner

# Should complete without errors
```

### 5. Run Test Suite

```bash
# Run tests to verify everything works
make test

# Or manually:
python -m pytest tests/ -v
```

## 🔧 Troubleshooting

### Common Issues

#### Python Version Issues

```bash
# Error: Python 3.11+ required
# Solution: Install correct Python version

# Check Python version
python --version
python3 --version
python3.11 --version

# Install Python 3.11 (Ubuntu/Debian)
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-pip

# Install Python 3.11 (macOS with Homebrew)
brew install python@3.11

# Install Python 3.11 (Windows)
# Download from https://www.python.org/downloads/
```

#### Virtual Environment Issues

```bash
# Error: venv module not found
# Solution: Install venv module

# Ubuntu/Debian
sudo apt install python3.11-venv

# Or create without venv
pip install virtualenv
virtualenv venv
```

#### Permission Issues

```bash
# Error: Permission denied
# Solution: Fix permissions or use user install

# Use user install
pip install --user -r requirements.txt

# Fix permissions (Linux/macOS)
sudo chown -R $USER:$USER /path/to/apileak

# Run with sudo (not recommended)
sudo pip install -r requirements.txt
```

#### Dependency Conflicts

```bash
# Error: Dependency conflicts
# Solution: Use fresh virtual environment

# Remove existing environment
rm -rf venv

# Create fresh environment
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Network Issues

```bash
# Error: Cannot download packages
# Solution: Check network and proxy settings

# Test network connectivity
ping pypi.org

# Use proxy if needed
pip install --proxy http://proxy.company.com:8080 -r requirements.txt

# Use alternative index
pip install -i https://pypi.python.org/simple/ -r requirements.txt
```

#### Docker Issues

```bash
# Error: Docker build fails
# Solution: Check Docker setup

# Check Docker version
docker --version

# Check Docker daemon
docker info

# Build with verbose output
docker build --no-cache -t apileak:latest .

# Check for permission issues (Linux)
sudo usermod -aG docker $USER
# Log out and back in
```

### Platform-Specific Issues

#### Windows

```cmd
# Long path issues
git config --system core.longpaths true

# PowerShell execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Use Windows Subsystem for Linux (WSL)
wsl --install
# Then follow Linux instructions in WSL
```

#### macOS

```bash
# Xcode command line tools
xcode-select --install

# Homebrew installation
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Python path issues
export PATH="/usr/local/opt/python@3.11/bin:$PATH"
```

#### Linux

```bash
# Missing system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential python3.11-dev libssl-dev libffi-dev

# Missing system dependencies (CentOS/RHEL)
sudo yum groupinstall "Development Tools"
sudo yum install python3.11-devel openssl-devel libffi-devel
```

### Getting Help

If you encounter issues not covered here:

1. **Check existing issues**: Search [GitHub Issues](https://github.com/your-org/apileak/issues)
2. **Create new issue**: Include:
   - Operating system and version
   - Python version
   - Complete error message
   - Steps to reproduce
3. **Community support**: Join discussions in GitHub Discussions
4. **Documentation**: Check other documentation files in `docs/`

### Diagnostic Information

When reporting issues, include this diagnostic information:

```bash
# System information
python --version
pip --version
git --version

# APILeak information
python apileaks.py --help

# Environment information
pip list | grep -E "(structlog|pydantic|httpx|click|yaml)"

# System resources
free -h  # Linux
df -h    # Disk space
```

## 🎯 Next Steps

After successful installation:

1. **Configuration**: Read the [Configuration Guide](configuration.md)
2. **First Scan**: Follow the [Examples](examples.md)
3. **CLI Reference**: Check the [CLI Reference](cli-reference.md)
4. **Development**: See [Development Setup](development.md) for contributors

---

Welcome to APILeak! 🚀