# 🐳 Docker Usage

APILeak provides comprehensive Docker support for containerized security testing, CI/CD integration, and isolated scanning environments.

## Overview

Docker support in APILeak enables:
- **Isolated Testing Environment**: Run scans in containers without affecting host system
- **CI/CD Integration**: Easy integration with containerized build pipelines
- **Consistent Environment**: Same runtime environment across different platforms
- **Resource Management**: Control memory and CPU usage for scans
- **Volume Mounting**: Easy access to configuration files and reports

## Quick Start

```bash
# Pull the latest APILeak image (when available)
docker pull apileak:latest

# Or build locally
docker build -t apileak:latest .

# Run basic help
docker run --rm apileak:latest --help

# Run directory fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --output docker-scan
```

## Docker Image Details

### Base Image
- **Base**: `python:3.11-slim-alpine`
- **Size**: < 200MB (optimized for production)
- **Security**: Non-root user execution
- **Architecture**: Multi-arch support (amd64, arm64)

### Environment Variables

The Docker image supports configuration through environment variables:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `APILEAK_LOG_LEVEL` | Logging level | `INFO` | `DEBUG`, `WARNING` |
| `APILEAK_TARGET` | Target URL to scan | - | `https://api.example.com` |
| `APILEAK_CONFIG_FILE` | Configuration file path | - | `/app/config/api.yaml` |
| `APILEAK_OUTPUT_FILE` | Output filename | - | `my-scan-results` |
| `APILEAK_RATE_LIMIT` | Requests per second | `10` | `20` |
| `APILEAK_MODULES` | OWASP modules to enable | - | `bola,auth,property` |
| `APILEAK_JWT_TOKEN` | JWT token for auth | - | `eyJ0eXAiOiJKV1Q...` |
| `APILEAK_USER_AGENT` | Custom User-Agent | - | `MyScanner/1.0` |
| `APILEAK_TIMEOUT` | Request timeout | `10` | `30` |
| `APILEAK_MAX_DEPTH` | Max recursion depth | `3` | `5` |
| `APILEAK_VERIFY_SSL` | Verify SSL certificates | `true` | `false` |

## Usage Examples

### Directory Fuzzing

```bash
# Basic directory fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --output api-endpoints

# With custom rate limiting and user agent
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --rate-limit 20 \
  --user-agent-custom "Security Scanner" \
  --output fast-scan
```

### Parameter Fuzzing

```bash
# Parameter fuzzing with JWT authentication
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com/users/123 \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --wordlist wordlists/parameters.txt \
  --output param-scan
```

### Full OWASP Security Scan

```bash
# Complete security scan with all OWASP modules
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --modules "bola,auth,property,function_auth,resource,ssrf" \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --output comprehensive-scan

# Using configuration file
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --config config/production_api.yaml
```

### Advanced Features

```bash
# Framework detection and version fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --enable-advanced \
  --output advanced-scan

# WAF evasion techniques
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/wordlists:/app/wordlists \
  apileak:latest full \
  --target https://api.example.com \
  --user-agent-random \
  --enable-waf-evasion \
  --enable-payload-encoding \
  --output waf-evasion-scan
```

## Docker Compose

### Basic Setup

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  apileak:
    build: .
    image: apileak:latest
    environment:
      - APILEAK_LOG_LEVEL=INFO
      - APILEAK_RATE_LIMIT=10
    volumes:
      - ./config:/app/config:ro
      - ./reports:/app/reports:rw
      - ./wordlists:/app/wordlists:ro
    command: ["--help"]

  # Directory scanning service
  apileak-dir:
    extends: apileak
    environment:
      - APILEAK_TARGET=${API_TARGET_URL}
    command: ["dir", "--target", "${API_TARGET_URL}", "--output", "docker-dir-scan"]
    profiles: ["dir"]

  # Full scan service
  apileak-full:
    extends: apileak
    environment:
      - APILEAK_TARGET=${API_TARGET_URL}
      - APILEAK_JWT_TOKEN=${API_JWT_TOKEN}
      - APILEAK_MODULES=${OWASP_MODULES:-bola,auth,property}
    command: ["full", "--target", "${API_TARGET_URL}", "--output", "docker-full-scan"]
    profiles: ["full"]
```

### Usage

```bash
# Build and run help
docker-compose up --build

# Run directory scan
API_TARGET_URL=https://api.example.com docker-compose --profile dir up

# Run full scan with authentication
API_TARGET_URL=https://api.example.com \
API_JWT_TOKEN=eyJ0eXAiOiJKV1Q... \
OWASP_MODULES=bola,auth,property,function_auth \
docker-compose --profile full up

# Run one-off scan
docker-compose run --rm apileak full \
  --target https://api.example.com \
  --output one-off-scan
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run APILeak Security Scan
  run: |
    docker run --rm \
      -v $(pwd)/reports:/app/reports \
      apileak:latest full \
      --target ${{ vars.API_TARGET_URL }} \
      --jwt ${{ secrets.API_JWT_TOKEN }} \
      --output github-scan-${{ github.run_id }} \
      --ci-mode \
      --fail-on critical
```

### GitLab CI

```yaml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t apileak:latest .
    - |
      docker run --rm \
        -v $(pwd)/reports:/app/reports \
        apileak:latest full \
        --target $API_TARGET_URL \
        --jwt $API_JWT_TOKEN \
        --output gitlab-scan-$CI_PIPELINE_ID \
        --ci-mode \
        --fail-on high
```

### Jenkins

```groovy
stage('Security Scan') {
    steps {
        script {
            sh '''
                docker build -t apileak:latest .
                docker run --rm \
                  -v $(pwd)/reports:/app/reports \
                  apileak:latest full \
                  --target ${API_TARGET_URL} \
                  --jwt ${API_JWT_TOKEN} \
                  --output jenkins-scan-${BUILD_ID} \
                  --ci-mode \
                  --fail-on critical
            '''
        }
    }
}
```

## Volume Mounts

### Required Volumes

| Host Path | Container Path | Purpose | Mode |
|-----------|----------------|---------|------|
| `./reports` | `/app/reports` | Scan results and reports | `rw` |

### Optional Volumes

| Host Path | Container Path | Purpose | Mode |
|-----------|----------------|---------|------|
| `./config` | `/app/config` | Configuration files | `ro` |
| `./wordlists` | `/app/wordlists` | Custom wordlists | `ro` |
| `./logs` | `/app/logs` | Application logs | `rw` |

### Example with All Volumes

```bash
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/reports:/app/reports:rw \
  -v $(pwd)/logs:/app/logs:rw \
  -v $(pwd)/wordlists:/app/wordlists:ro \
  apileak:latest full \
  --config config/my-api.yaml \
  --output complete-scan
```

## Resource Management

### Memory and CPU Limits

```bash
# Limit memory to 512MB and CPU to 0.5 cores
docker run --rm \
  --memory=512m \
  --cpus=0.5 \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --output resource-limited-scan
```

### Docker Compose Resource Limits

```yaml
services:
  apileak:
    image: apileak:latest
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.25'
```

## Security Considerations

### Non-Root Execution

The Docker image runs as a non-root user (`apileak:1000`) for security:

```dockerfile
# Image runs as user 'apileak' with UID 1000
USER apileak
```

### Network Security

```bash
# Run with custom network
docker network create apileak-network
docker run --rm \
  --network apileak-network \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://internal-api.company.com \
  --output internal-scan
```

### Secrets Management

```bash
# Use Docker secrets for sensitive data
echo "eyJ0eXAiOiJKV1Q..." | docker secret create jwt-token -

# Use in compose
services:
  apileak:
    image: apileak:latest
    secrets:
      - jwt-token
    environment:
      - APILEAK_JWT_TOKEN_FILE=/run/secrets/jwt-token
```

## Troubleshooting

### Common Issues

#### Permission Denied on Reports Directory

```bash
# Fix permissions
sudo chown -R 1000:1000 reports/

# Or run with user mapping
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir --target https://api.example.com
```

#### Out of Memory Errors

```bash
# Increase memory limit
docker run --rm \
  --memory=2g \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full --target https://api.example.com
```

#### SSL Certificate Issues

```bash
# Disable SSL verification
docker run --rm \
  -e APILEAK_VERIFY_SSL=false \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir --target https://self-signed-api.com
```

### Debug Mode

```bash
# Run with debug logging
docker run --rm \
  -e APILEAK_LOG_LEVEL=DEBUG \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/logs:/app/logs \
  apileak:latest dir \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file logs/debug.log
```

### Health Checks

```bash
# Check container health
docker run --rm \
  --health-cmd="python -c 'from core import APILeakCore; print(\"healthy\")'" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  apileak:latest dir --target https://api.example.com
```

## Best Practices

### Production Usage

1. **Use specific tags**: `apileak:v0.1.0` instead of `latest`
2. **Set resource limits**: Prevent resource exhaustion
3. **Use read-only volumes**: For configuration and wordlists
4. **Enable health checks**: Monitor container health
5. **Use secrets management**: For sensitive tokens
6. **Set appropriate timeouts**: Prevent hanging scans

### Development Usage

1. **Mount source code**: For live development
2. **Use debug logging**: For troubleshooting
3. **Interactive mode**: For testing commands

```bash
# Development container with source mount
docker run -it --rm \
  -v $(pwd):/app \
  -v $(pwd)/reports:/app/reports \
  --entrypoint /bin/sh \
  apileak:latest
```

### CI/CD Best Practices

1. **Use CI mode**: `--ci-mode` for appropriate exit codes
2. **Set failure thresholds**: `--fail-on critical`
3. **Generate artifacts**: Save reports for review
4. **Use caching**: Cache Docker layers
5. **Parallel execution**: Run different scan types in parallel

## Integration Examples

### Kubernetes Deployment

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: apileak-security-scan
spec:
  template:
    spec:
      containers:
      - name: apileak
        image: apileak:latest
        args: ["full", "--target", "https://api.example.com", "--ci-mode"]
        env:
        - name: APILEAK_JWT_TOKEN
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: jwt-token
        volumeMounts:
        - name: reports
          mountPath: /app/reports
        resources:
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: reports
        persistentVolumeClaim:
          claimName: apileak-reports
      restartPolicy: Never
```

### AWS ECS Task Definition

```json
{
  "family": "apileak-security-scan",
  "taskRoleArn": "arn:aws:iam::account:role/apileak-task-role",
  "containerDefinitions": [
    {
      "name": "apileak",
      "image": "apileak:latest",
      "command": ["full", "--target", "https://api.example.com", "--ci-mode"],
      "environment": [
        {
          "name": "APILEAK_LOG_LEVEL",
          "value": "INFO"
        }
      ],
      "secrets": [
        {
          "name": "APILEAK_JWT_TOKEN",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:api-jwt-token"
        }
      ],
      "memory": 1024,
      "cpu": 512
    }
  ]
}
```

This comprehensive Docker usage guide ensures that APILeak can be effectively deployed and used in containerized environments across different platforms and CI/CD systems.
- **Scalable Deployment**: Deploy multiple scanner instances across infrastructure
- **Consistent Environment**: Ensure consistent scanning environment across teams
- **Resource Management**: Control resource usage and limits

## Quick Start

### Pull and Run
```bash
# Pull the latest APILeak image
docker pull apileak:latest

# Run a basic scan
docker run --rm apileak:latest dir --target https://api.example.com --help
```

### Build from Source
```bash
# Clone repository
git clone https://github.com/your-org/apileak.git
cd apileak

# Build Docker image
docker build -t apileak:latest .

# Verify build
docker run --rm apileak:latest --help
```

## Basic Usage Examples

### Directory Fuzzing
```bash
# Basic directory fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --output docker_dir_scan

# With custom wordlist
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --output custom_wordlist_scan
```

### Parameter Fuzzing
```bash
# Basic parameter fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com \
  --output docker_param_scan

# With authentication
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --output authenticated_param_scan
```

### Full Security Scan
```bash
# Basic full scan
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --output docker_full_scan

# With configuration file
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --output config_based_scan
```

## Advanced Docker Usage

### WAF Evasion with Docker

#### Random User Agent Rotation
```bash
# Directory fuzzing with random user agents
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --status-code 200-299,401,403 \
  --output waf_evasion_dir_scan

# Parameter fuzzing with random user agents
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com \
  --wordlist wordlists/parameters.txt \
  --user-agent-random \
  --status-code 200,500-599 \
  --output waf_evasion_param_scan
```

#### Custom User Agent
```bash
# Directory fuzzing with custom user agent
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-custom "Docker Security Scanner v1.0" \
  --output custom_agent_scan

# Parameter fuzzing with custom user agent
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "Docker Security Scanner" \
  --status-code 200,500-599 \
  --output custom_agent_param_scan
```

#### User Agent File Rotation
```bash
# Directory fuzzing with user agent file
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 200-299,401,403 \
  --output user_agent_file_scan

# Full scan with user agent rotation
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 200,401,403,500 \
  --output full_user_agent_rotation
```

### OWASP Security Testing
```bash
# OWASP BOLA testing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --modules bola \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output docker_bola_test

# Multiple OWASP modules
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --output docker_owasp_comprehensive

# All available OWASP modules
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --modules all \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --user-agent-random \
  --rate-limit 8 \
  --output docker_all_owasp_modules
```

### Framework Detection and Version Fuzzing
```bash
# Framework detection
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --detect-framework \
  --framework-confidence 0.8 \
  --user-agent-random \
  --output docker_framework_detection

# Version fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --fuzz-versions \
  --version-patterns "/v1,/v2,/api/v1,/api/v2" \
  --user-agent-random \
  --output docker_version_fuzzing

# Combined framework detection and version fuzzing
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.7 \
  --user-agent-random \
  --output docker_advanced_discovery
```

## Docker Compose

### Basic Docker Compose Setup
```yaml
# docker-compose.yml
version: '3.8'

services:
  apileak:
    build: .
    volumes:
      - ./reports:/app/reports
      - ./wordlists:/app/wordlists
      - ./config:/app/config
    environment:
      - API_TARGET=https://api.example.com
      - APILEAK_RATE_LIMIT=10
    command: >
      full
      --target $API_TARGET
      --user-agent-random
      --modules bola,auth,property
      --output docker_compose_scan
```

### Advanced Docker Compose with Multiple Services
```yaml
# docker-compose.advanced.yml
version: '3.8'

services:
  apileak-dir:
    build: .
    volumes:
      - ./reports:/app/reports
      - ./wordlists:/app/wordlists
    environment:
      - API_TARGET=https://api.example.com
    command: >
      dir
      --target $API_TARGET
      --wordlist wordlists/endpoints.txt
      --user-agent-random
      --status-code 200-299,401,403
      --output compose_dir_scan

  apileak-param:
    build: .
    volumes:
      - ./reports:/app/reports
      - ./wordlists:/app/wordlists
    environment:
      - API_TARGET=https://api.example.com
      - JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    command: >
      par
      --target $API_TARGET
      --wordlist wordlists/parameters.txt
      --jwt $JWT_TOKEN
      --user-agent-random
      --output compose_param_scan

  apileak-owasp:
    build: .
    volumes:
      - ./reports:/app/reports
    environment:
      - API_TARGET=https://api.example.com
      - JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    command: >
      full
      --target $API_TARGET
      --modules bola,auth,property
      --jwt $JWT_TOKEN
      --user-agent-random
      --output compose_owasp_scan

  report-processor:
    build: .
    depends_on:
      - apileak-dir
      - apileak-param
      - apileak-owasp
    volumes:
      - ./reports:/app/reports
    command: >
      python scripts/process_reports.py
      --input /app/reports
      --output /app/reports/processed
```

### Running Docker Compose
```bash
# Run basic compose setup
docker-compose up

# Run advanced multi-service setup
docker-compose -f docker-compose.advanced.yml up

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## CI/CD Integration with Docker

### GitHub Actions
```yaml
# .github/workflows/api-security-docker.yml
name: API Security Testing with Docker

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  api-security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Build APILeak Docker Image
      run: docker build -t apileak:ci .
    
    - name: Run Directory Fuzzing
      run: |
        docker run --rm \
          -v ${{ github.workspace }}/reports:/app/reports \
          -v ${{ github.workspace }}/wordlists:/app/wordlists \
          apileak:ci dir \
          --target ${{ secrets.API_TARGET }} \
          --wordlist wordlists/endpoints.txt \
          --user-agent-random \
          --status-code 200-299,401,403 \
          --output github_docker_dir_scan
    
    - name: Run Parameter Fuzzing
      run: |
        docker run --rm \
          -v ${{ github.workspace }}/reports:/app/reports \
          -v ${{ github.workspace }}/wordlists:/app/wordlists \
          apileak:ci par \
          --target ${{ secrets.API_TARGET }} \
          --wordlist wordlists/parameters.txt \
          --user-agent-custom "GitHub Actions Docker Scanner" \
          --status-code 200,500-599 \
          --output github_docker_param_scan
    
    - name: Run Full Security Scan
      run: |
        docker run --rm \
          -v ${{ github.workspace }}/reports:/app/reports \
          apileak:ci full \
          --target ${{ secrets.API_TARGET }} \
          --modules bola,auth,property \
          --user-agent-random \
          --status-code 200,401,403,500 \
          --output github_docker_full_scan
    
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: docker-security-reports
        path: reports/
```

### GitLab CI
```yaml
# .gitlab-ci.yml
stages:
  - build
  - security-test

variables:
  DOCKER_IMAGE: apileak:$CI_COMMIT_SHA

build:
  stage: build
  script:
    - docker build -t $DOCKER_IMAGE .
  only:
    - main
    - develop
    - merge_requests

security-test:
  stage: security-test
  script:
    # Directory fuzzing
    - |
      docker run --rm \
        -v $CI_PROJECT_DIR/reports:/app/reports \
        -v $CI_PROJECT_DIR/wordlists:/app/wordlists \
        $DOCKER_IMAGE dir \
        --target $API_TARGET \
        --wordlist wordlists/endpoints.txt \
        --user-agent-random \
        --status-code 200-299,401,403 \
        --output gitlab_docker_dir_scan
    
    # Parameter fuzzing
    - |
      docker run --rm \
        -v $CI_PROJECT_DIR/reports:/app/reports \
        -v $CI_PROJECT_DIR/wordlists:/app/wordlists \
        $DOCKER_IMAGE par \
        --target $API_TARGET \
        --wordlist wordlists/parameters.txt \
        --user-agent-custom "GitLab CI Docker Scanner" \
        --status-code 200,500-599 \
        --output gitlab_docker_param_scan
    
    # Full security scan
    - |
      docker run --rm \
        -v $CI_PROJECT_DIR/reports:/app/reports \
        $DOCKER_IMAGE full \
        --target $API_TARGET \
        --modules bola,auth,property \
        --user-agent-random \
        --status-code 200,401,403,500 \
        --output gitlab_docker_full_scan
  
  artifacts:
    when: always
    paths:
      - reports/
    expire_in: 30 days
  
  dependencies:
    - build
  only:
    - main
    - develop
    - merge_requests
```

### Jenkins Pipeline
```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        DOCKER_IMAGE = "apileak:${env.BUILD_NUMBER}"
        API_TARGET = credentials('api-target-url')
    }
    
    stages {
        stage('Build Docker Image') {
            steps {
                script {
                    docker.build(env.DOCKER_IMAGE)
                }
            }
        }
        
        stage('Directory Fuzzing') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}/reports:/app/reports \
                        -v ${WORKSPACE}/wordlists:/app/wordlists \
                        ${DOCKER_IMAGE} dir \
                        --target ${API_TARGET} \
                        --wordlist wordlists/endpoints.txt \
                        --user-agent-random \
                        --status-code 200-299,401,403 \
                        --output jenkins_docker_dir_scan
                '''
            }
        }
        
        stage('Parameter Fuzzing') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}/reports:/app/reports \
                        -v ${WORKSPACE}/wordlists:/app/wordlists \
                        ${DOCKER_IMAGE} par \
                        --target ${API_TARGET} \
                        --wordlist wordlists/parameters.txt \
                        --user-agent-custom "Jenkins Docker Scanner" \
                        --status-code 200,500-599 \
                        --output jenkins_docker_param_scan
                '''
            }
        }
        
        stage('Full Security Scan') {
            steps {
                sh '''
                    docker run --rm \
                        -v ${WORKSPACE}/reports:/app/reports \
                        ${DOCKER_IMAGE} full \
                        --target ${API_TARGET} \
                        --modules bola,auth,property \
                        --user-agent-random \
                        --status-code 200,401,403,500 \
                        --output jenkins_docker_full_scan
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', fingerprint: true
        }
    }
}
```

## Environment Variables

### Docker Environment Configuration
```bash
# Core Configuration
export API_TARGET="https://api.example.com"
export APILEAK_RATE_LIMIT="10"
export APILEAK_TIMEOUT="30"
export APILEAK_VERIFY_SSL="true"

# Authentication
export JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
export API_KEY="your-api-key"

# Output Configuration
export APILEAK_OUTPUT_DIR="/app/reports"
export APILEAK_LOG_LEVEL="WARNING"
export APILEAK_JSON_LOGS="true"

# WAF Evasion
export APILEAK_USER_AGENT="Docker Security Scanner v1.0"
export APILEAK_USER_AGENT_STRATEGY="random"

# Run with environment variables
docker run --rm \
  -e API_TARGET \
  -e JWT_TOKEN \
  -e APILEAK_RATE_LIMIT \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target $API_TARGET \
  --jwt $JWT_TOKEN \
  --user-agent-random \
  --output env_configured_scan
```

## Volume Mounting

### Essential Volume Mounts
```bash
# Reports directory (always recommended)
-v $(pwd)/reports:/app/reports

# Wordlists directory
-v $(pwd)/wordlists:/app/wordlists

# Configuration files
-v $(pwd)/config:/app/config

# Custom user agent files
-v $(pwd)/user_agents:/app/user_agents

# Complete volume mounting example
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/user_agents:/app/user_agents \
  apileak:latest full \
  --config config/comprehensive.yaml \
  --target https://api.example.com \
  --user-agent-file user_agents/custom_agents.txt \
  --output comprehensive_docker_scan
```

## Resource Management

### Memory and CPU Limits
```bash
# Set memory limit
docker run --rm \
  --memory="1g" \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --output memory_limited_scan

# Set CPU limit
docker run --rm \
  --cpus="2.0" \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --output cpu_limited_scan

# Combined resource limits
docker run --rm \
  --memory="2g" \
  --cpus="1.5" \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --modules bola,auth,property \
  --output resource_limited_scan
```

## Troubleshooting

### Common Docker Issues

#### Permission Issues
```bash
# Fix permission issues with volume mounts
sudo chown -R $(id -u):$(id -g) reports/
sudo chown -R $(id -u):$(id -g) wordlists/

# Run with user mapping
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --output user_mapped_scan
```

#### Network Issues
```bash
# Use host networking for local targets
docker run --rm \
  --network host \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target http://localhost:8080 \
  --output host_network_scan

# Custom network configuration
docker network create apileak-network
docker run --rm \
  --network apileak-network \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --output custom_network_scan
```

#### Debug Mode
```bash
# Run with debug logging
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file /app/reports/debug.log \
  --output debug_scan

# Interactive debugging
docker run -it --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest /bin/bash
```

## Best Practices

### 1. Always Use Volume Mounts for Reports
```bash
# Always mount reports directory
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:latest [command] \
  --output scan_results
```

### 2. Use Specific Tags
```bash
# Use specific version tags instead of latest
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  apileak:v0.1.0 dir \
  --target https://api.example.com
```

### 3. Set Resource Limits
```bash
# Always set appropriate resource limits
docker run --rm \
  --memory="1g" \
  --cpus="1.0" \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com
```

### 4. Use Environment Variables for Sensitive Data
```bash
# Use environment variables for tokens
docker run --rm \
  -e JWT_TOKEN \
  -v $(pwd)/reports:/app/reports \
  apileak:latest full \
  --target https://api.example.com \
  --jwt $JWT_TOKEN
```

---

For more information about Docker deployment and container orchestration, see the [CI/CD Integration](ci-cd-integration.md) and [Architecture](architecture.md) documentation.