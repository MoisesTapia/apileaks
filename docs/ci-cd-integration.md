# 🚀 CI/CD Integration - APILeak

This guide covers integrating APILeak into CI/CD pipelines to automate API security testing.

## 📋 Table of Contents

1. [Basic Configuration](#basic-configuration)
2. [GitHub Actions](#github-actions)
3. [GitLab CI](#gitlab-ci)
4. [Jenkins](#jenkins)
5. [Azure DevOps](#azure-devops)
6. [Docker Integration](#docker-integration)
7. [Exit Codes and Error Handling](#exit-codes)
8. [Environment Variables](#environment-variables)
9. [Best Practices](#best-practices)

---

## ⚙️ Basic Configuration

### APILeak Exit Codes

APILeak uses standard exit codes for CI/CD integration:

- **0**: No critical/high vulnerabilities found ✅
- **1**: High severity vulnerabilities found ⚠️
- **2**: Critical vulnerabilities found ❌

### CI Gate Options (`scan`)

The `scan` command drives the CI gate. The following are options of `scan`:

- `--ci-mode`: Enable CI-friendly output and exit-code behavior.
- `--fail-on <severity>`: Minimum severity that fails the pipeline. **The default is now `high` (previously `critical`).** This means a run now fails on high severity findings unless you override it. To keep the old behavior, pass `--fail-on critical` explicitly.
- `--sarif`: Emit a SARIF report for code-scanning integrations.
- `--baseline <file>`: Compare against a baseline to fail only on new findings.
- `--safe-mode`: Run with reduced-risk, non-destructive checks.

> **Note on the `--fail-on` default:** earlier versions defaulted to `critical`. The default is now `high`, so pipelines that relied on the old default will start failing on high severity findings. Set `--fail-on critical` if you intend to keep gating on critical only.

> **Deprecation notice:** `full` and `main` are deprecated, hidden aliases of `scan`. They still work and forward to `scan` (emitting a one-line notice), but should not be used in new pipelines. Use `scan` for discovery plus all OWASP modules, and run a single module in isolation with `apileaks owasp <key>` (for example, `full --modules bola` becomes `apileaks owasp bola`).

### Basic CI/CD Script

```bash
#!/bin/bash
# ci_security_test.sh

set -e

# Configuration
API_ENDPOINT="${API_ENDPOINT:-https://staging-api.example.com}"
JWT_TOKEN="${JWT_TOKEN:-}"
MODULES="${MODULES:-bola,auth,property,resource}"
RATE_LIMIT="${RATE_LIMIT:-3}"
OUTPUT_DIR="${OUTPUT_DIR:-security_reports}"

echo "🔍 Starting APILeak security scan..."
echo "Target: $API_ENDPOINT"
echo "Modules: $MODULES"

# Run APILeak
python apileaks.py scan \
  --target "$API_ENDPOINT" \
  --jwt "$JWT_TOKEN" \
  --modules "$MODULES" \
  --rate-limit "$RATE_LIMIT" \
  --output "$OUTPUT_DIR/scan-$(date +%Y%m%d-%H%M%S)" \
  --log-level ERROR

# Capture exit code
EXIT_CODE=$?

# Interpret results
case $EXIT_CODE in
  0)
    echo "✅ No critical vulnerabilities found. Pipeline continues."
    exit 0
    ;;
  1)
    echo "⚠️ High severity vulnerabilities found. Review required."
    echo "Pipeline continues but requires manual review."
    exit 0  # Do not fail the pipeline for high severity vulnerabilities
    ;;
  2)
    echo "❌ Critical vulnerabilities found! Failing pipeline."
    echo "Fix critical issues before deployment."
    exit 1  # Fail the pipeline for critical vulnerabilities
    ;;
  *)
    echo "❌ Unexpected error occurred during scan."
    exit 1
    ;;
esac
```

---

## 🐙 GitHub Actions

### Basic Workflow

```yaml
# .github/workflows/api-security.yml
name: API Security Testing

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  api-security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run APILeak Security Scan
      env:
        API_ENDPOINT: ${{ secrets.STAGING_API_URL }}
        JWT_TOKEN: ${{ secrets.API_JWT_TOKEN }}
      run: |
        python apileaks.py scan \
          --target "$API_ENDPOINT" \
          --jwt "$JWT_TOKEN" \
          --modules bola,auth,property,resource \
          --rate-limit 3 \
          --output "security-scan-${{ github.run_number }}" \
          --log-level ERROR
    
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: reports/
        retention-days: 30
    
    - name: Comment PR with Results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const path = 'reports/security-scan-${{ github.run_number }}.json';
          
          if (fs.existsSync(path)) {
            const report = JSON.parse(fs.readFileSync(path, 'utf8'));
            const summary = report.summary;
            
            const comment = `## 🛡️ API Security Scan Results
            
            **Target:** ${report.target}
            **Scan ID:** ${report.scan_id}
            
            ### Findings Summary
            - **Critical:** ${summary.critical}
            - **High:** ${summary.high}
            - **Medium:** ${summary.medium}
            - **Low:** ${summary.low}
            - **Info:** ${summary.info}
            
            ${summary.critical > 0 ? '❌ **Critical vulnerabilities found! Review required.**' : 
              summary.high > 0 ? '⚠️ **High severity vulnerabilities found.**' : 
              '✅ **No critical vulnerabilities found.**'}
            
            Full reports available in workflow artifacts.`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
          }
```

### Advanced Workflow with Multiple Environments

```yaml
# .github/workflows/api-security-advanced.yml
name: Advanced API Security Testing

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to test'
        required: true
        default: 'staging'
        type: choice
        options:
        - staging
        - production
      modules:
        description: 'OWASP modules to run'
        required: false
        default: 'bola,auth,property,resource'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    environment: ${{ github.event.inputs.environment }}
    
    strategy:
      matrix:
        scan-type: [endpoints, parameters, full-owasp]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install APILeak
      run: |
        pip install -r requirements.txt
    
    - name: Configure scan parameters
      id: config
      run: |
        case "${{ matrix.scan-type }}" in
          "endpoints")
            echo "command=dir" >> $GITHUB_OUTPUT
            echo "modules=" >> $GITHUB_OUTPUT
            ;;
          "parameters")
            echo "command=par" >> $GITHUB_OUTPUT
            echo "modules=" >> $GITHUB_OUTPUT
            ;;
          "full-owasp")
            echo "command=scan" >> $GITHUB_OUTPUT
            echo "modules=${{ github.event.inputs.modules }}" >> $GITHUB_OUTPUT
            ;;
        esac
    
    - name: Run Security Scan
      env:
        API_ENDPOINT: ${{ secrets[format('{0}_API_URL', github.event.inputs.environment)] }}
        JWT_TOKEN: ${{ secrets[format('{0}_JWT_TOKEN', github.event.inputs.environment)] }}
      run: |
        python apileaks.py ${{ steps.config.outputs.command }} \
          --target "$API_ENDPOINT" \
          --jwt "$JWT_TOKEN" \
          ${{ steps.config.outputs.modules && format('--modules {0}', steps.config.outputs.modules) || '' }} \
          --rate-limit 2 \
          --output "${{ matrix.scan-type }}-${{ github.event.inputs.environment }}-${{ github.run_number }}" \
          --log-level INFO
    
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: ${{ matrix.scan-type }}-reports
        path: reports/
```

---

## 🦊 GitLab CI

### Basic Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - security-test
  - deploy

variables:
  PYTHON_VERSION: "3.9"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/
    - venv/

api-security-scan:
  stage: security-test
  image: python:$PYTHON_VERSION
  
  before_script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install --upgrade pip
    - pip install -r requirements.txt
  
  script:
    - |
      python apileaks.py scan \
        --target "$STAGING_API_URL" \
        --jwt "$API_JWT_TOKEN" \
        --modules bola,auth,property,resource \
        --rate-limit 3 \
        --output "security-scan-$CI_PIPELINE_ID" \
        --log-level ERROR
  
  artifacts:
    when: always
    paths:
      - reports/
    expire_in: 30 days
    reports:
      junit: reports/security-scan-*.xml  # If an XML report is generated
  
  only:
    - main
    - develop
    - merge_requests

# Pipeline for production with restrictions
production-security-scan:
  stage: security-test
  image: python:$PYTHON_VERSION
  
  before_script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -r requirements.txt
  
  script:
    - |
      # Very low rate limiting for production
      python apileaks.py scan \
        --target "$PRODUCTION_API_URL" \
        --jwt "$PRODUCTION_JWT_TOKEN" \
        --modules bola,auth \
        --rate-limit 1 \
        --output "prod-security-scan-$CI_PIPELINE_ID" \
        --log-level ERROR
  
  artifacts:
    when: always
    paths:
      - reports/
    expire_in: 90 days
  
  only:
    - schedules
  
  when: manual
```

### Pipeline with Docker

```yaml
# .gitlab-ci.yml with Docker
api-security-docker:
  stage: security-test
  image: docker:latest
  services:
    - docker:dind
  
  before_script:
    - docker build -t apileak .
  
  script:
    - |
      docker run --rm \
        -e API_ENDPOINT="$STAGING_API_URL" \
        -e JWT_TOKEN="$API_JWT_TOKEN" \
        -v $(pwd)/reports:/app/reports \
        apileak \
        python apileaks.py scan \
          --target "$API_ENDPOINT" \
          --jwt "$JWT_TOKEN" \
          --modules bola,auth,property \
          --rate-limit 3 \
          --output "docker-scan-$CI_PIPELINE_ID"
  
  artifacts:
    paths:
      - reports/
```

---

## 🏗️ Jenkins

### Declarative Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    parameters {
        choice(
            name: 'ENVIRONMENT',
            choices: ['staging', 'production'],
            description: 'Environment to test'
        )
        string(
            name: 'MODULES',
            defaultValue: 'bola,auth,property,resource',
            description: 'OWASP modules to run'
        )
        string(
            name: 'RATE_LIMIT',
            defaultValue: '3',
            description: 'Requests per second'
        )
    }
    
    environment {
        PYTHON_VERSION = '3.9'
        REPORTS_DIR = 'reports'
    }
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('API Security Scan') {
            steps {
                script {
                    def apiUrl = params.ENVIRONMENT == 'production' ? 
                        env.PRODUCTION_API_URL : env.STAGING_API_URL
                    def jwtToken = params.ENVIRONMENT == 'production' ? 
                        env.PRODUCTION_JWT_TOKEN : env.STAGING_JWT_TOKEN
                    
                    sh """
                        . venv/bin/activate
                        python apileaks.py scan \\
                            --target "${apiUrl}" \\
                            --jwt "${jwtToken}" \\
                            --modules ${params.MODULES} \\
                            --rate-limit ${params.RATE_LIMIT} \\
                            --output "jenkins-scan-${BUILD_NUMBER}" \\
                            --log-level INFO
                    """
                }
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'reports/**/*', fingerprint: true
                    
                    script {
                        // Read results and send notification
                        def reportFile = "reports/jenkins-scan-${BUILD_NUMBER}.json"
                        if (fileExists(reportFile)) {
                            def report = readJSON file: reportFile
                            def summary = report.summary
                            
                            def message = """
                            🛡️ API Security Scan Results - Build #${BUILD_NUMBER}
                            
                            Target: ${report.target}
                            Environment: ${params.ENVIRONMENT}
                            
                            Findings:
                            • Critical: ${summary.critical}
                            • High: ${summary.high}
                            • Medium: ${summary.medium}
                            • Low: ${summary.low}
                            
                            Status: ${summary.critical > 0 ? '❌ CRITICAL ISSUES FOUND' : 
                                     summary.high > 0 ? '⚠️ HIGH ISSUES FOUND' : 
                                     '✅ NO CRITICAL ISSUES'}
                            """
                            
                            // Send to Slack, Teams, etc.
                            slackSend(
                                channel: '#security',
                                color: summary.critical > 0 ? 'danger' : 
                                       summary.high > 0 ? 'warning' : 'good',
                                message: message
                            )
                        }
                    }
                }
                
                failure {
                    emailext(
                        subject: "API Security Scan Failed - Build #${BUILD_NUMBER}",
                        body: "The API security scan failed. Check the build logs for details.",
                        to: "${env.SECURITY_TEAM_EMAIL}"
                    )
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    def reportFile = "reports/jenkins-scan-${BUILD_NUMBER}.json"
                    if (fileExists(reportFile)) {
                        def report = readJSON file: reportFile
                        def criticalCount = report.summary.critical
                        
                        if (criticalCount > 0) {
                            error("Critical security vulnerabilities found! Failing build.")
                        } else {
                            echo "✅ Security gate passed. No critical vulnerabilities found."
                        }
                    }
                }
            }
        }
    }
    
    post {
        cleanup {
            sh 'rm -rf venv'
        }
    }
}
```

---

## 🐳 Docker Integration

### Dockerfile for APILeak

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create reports directory
RUN mkdir -p reports

# Entry point
ENTRYPOINT ["python", "apileaks.py"]
CMD ["--help"]
```

### Docker Compose for Testing

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  apileak:
    build: .
    environment:
      - API_ENDPOINT=${API_ENDPOINT}
      - JWT_TOKEN=${JWT_TOKEN}
      - MODULES=${MODULES:-bola,auth,property}
      - RATE_LIMIT=${RATE_LIMIT:-3}
    volumes:
      - ./reports:/app/reports
      - ./config:/app/config
    command: >
      scan
      --target ${API_ENDPOINT}
      --jwt ${JWT_TOKEN}
      --modules ${MODULES:-bola,auth,property}
      --rate-limit ${RATE_LIMIT:-3}
      --output docker-scan-$(date +%Y%m%d-%H%M%S)
      --log-level INFO

  # Service to serve reports
  report-server:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./reports:/usr/share/nginx/html
    depends_on:
      - apileak
```

### Docker Script for CI/CD

```bash
#!/bin/bash
# docker-security-scan.sh

set -e

# Configuration
IMAGE_NAME="apileak:latest"
CONTAINER_NAME="apileak-scan-$(date +%s)"

# Build image
echo "🏗️ Building APILeak Docker image..."
docker build -t $IMAGE_NAME .

# Run scan
echo "🔍 Running security scan..."
docker run --rm \
  --name $CONTAINER_NAME \
  -e API_ENDPOINT="$API_ENDPOINT" \
  -e JWT_TOKEN="$JWT_TOKEN" \
  -v $(pwd)/reports:/app/reports \
  $IMAGE_NAME \
  scan \
  --target "$API_ENDPOINT" \
  --jwt "$JWT_TOKEN" \
  --modules bola,auth,property,resource \
  --rate-limit 3 \
  --output "docker-scan-$(date +%Y%m%d-%H%M%S)" \
  --log-level ERROR

# Check exit code
EXIT_CODE=$?

echo "📊 Scan completed with exit code: $EXIT_CODE"

case $EXIT_CODE in
  0)
    echo "✅ No critical vulnerabilities found."
    ;;
  1)
    echo "⚠️ High severity vulnerabilities found."
    ;;
  2)
    echo "❌ Critical vulnerabilities found!"
    exit 1
    ;;
esac
```

---

## 🔧 Environment Variables

### Standard Variables

```bash
# Basic configuration
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,property,resource"
export APILEAK_RATE_LIMIT="5"
export APILEAK_JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
export APILEAK_OUTPUT_DIR="reports"
export APILEAK_TIMEOUT="30"
export APILEAK_VERIFY_SSL="true"

# Advanced configuration
export APILEAK_MAX_DEPTH="3"
export APILEAK_USER_AGENT="APILeak-CI/0.2.0"
```

### Per-Environment Variables

```bash
# Staging
export STAGING_API_URL="https://staging-api.example.com"
export STAGING_JWT_TOKEN="staging_jwt_token_here"

# Production
export PRODUCTION_API_URL="https://api.example.com"
export PRODUCTION_JWT_TOKEN="production_jwt_token_here"

# Testing
export TEST_API_URL="https://test-api.example.com"
export TEST_JWT_TOKEN="test_jwt_token_here"
```

---

## 📋 Best Practices

### 1. **Per-Environment Configuration**

```bash
# Different configurations depending on the environment
case "$ENVIRONMENT" in
  "production")
    RATE_LIMIT=1
    MODULES="bola,auth"  # Critical modules only
    ;;
  "staging")
    RATE_LIMIT=5
    MODULES="bola,auth,property,resource"
    ;;
  "development")
    RATE_LIMIT=10
    MODULES="bola,auth,property,resource,function_auth"
    ;;
esac
```

### 2. **Secret Management**

```yaml
# GitHub Actions - use secrets
env:
  JWT_TOKEN: ${{ secrets.API_JWT_TOKEN }}
  API_KEY: ${{ secrets.API_KEY }}

# GitLab CI - protected variables
variables:
  JWT_TOKEN: $API_JWT_TOKEN  # Protected variable in GitLab

# Jenkins - credentials binding
environment {
  JWT_TOKEN = credentials('api-jwt-token')
}
```

### 3. **Smart Rate Limiting**

```bash
# Adjust rate limiting based on environment and time of day
HOUR=$(date +%H)
if [ "$ENVIRONMENT" = "production" ]; then
  if [ $HOUR -ge 9 ] && [ $HOUR -le 17 ]; then
    # Business hours - very low rate limiting
    RATE_LIMIT=1
  else
    # Off hours - moderate rate limiting
    RATE_LIMIT=3
  fi
else
  RATE_LIMIT=10
fi
```

### 4. **Smart Notifications**

```bash
# Only notify in important cases
if [ $EXIT_CODE -eq 2 ]; then
  # Critical vulnerabilities - notify immediately
  curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"🚨 Critical API vulnerabilities found in $ENVIRONMENT!\"}"
elif [ $EXIT_CODE -eq 1 ] && [ "$ENVIRONMENT" = "production" ]; then
  # High severity vulnerabilities in production - notify
  curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"⚠️ High severity API vulnerabilities found in production.\"}"
fi
```

### 5. **Report Archiving**

```bash
# Organize reports by date and environment
REPORT_DIR="reports/$ENVIRONMENT/$(date +%Y/%m/%d)"
mkdir -p "$REPORT_DIR"

python apileaks.py scan \
  --target "$API_ENDPOINT" \
  --output "$REPORT_DIR/scan-$(date +%H%M%S)" \
  --modules "$MODULES"
```

### 6. **Timeouts and Retries**

```bash
# Implement timeout and retries
timeout 1800 python apileaks.py scan \
  --target "$API_ENDPOINT" \
  --modules "$MODULES" \
  --rate-limit "$RATE_LIMIT" || {
  
  echo "⏰ Scan timed out or failed. Retrying with reduced scope..."
  
  # Retry with critical modules only
  timeout 900 python apileaks.py scan \
    --target "$API_ENDPOINT" \
    --modules "bola,auth" \
    --rate-limit 1
}
```

---

## 🔍 CI/CD Troubleshooting

### Common Issues

#### 1. **Timeouts in CI/CD**
```bash
# Solution: Reduce scope or increase timeout
timeout 3600 python apileaks.py scan --modules bola,auth --rate-limit 1
```

#### 2. **Server Rate Limiting**
```bash
# Solution: Adaptive rate limiting
python apileaks.py scan --rate-limit 1 --modules bola
```

#### 3. **False Positives**
```bash
# Solution: Configure specific filters
python apileaks.py scan --response 200,201,404 --modules bola,auth
```

#### 4. **Limited Resources in CI**
```bash
# Solution: Run modules separately
for module in bola auth property; do
  python apileaks.py scan --modules $module --target "$API_ENDPOINT"
done
```

---

This guide provides a solid foundation for integrating APILeak into any CI/CD pipeline, ensuring that APIs stay secure throughout the development lifecycle.
