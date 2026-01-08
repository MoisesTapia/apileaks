# APILeak CI/CD Integration

This directory contains templates and scripts for integrating APILeak OWASP Enhancement into CI/CD pipelines.

## Overview

APILeak provides enterprise-grade API security testing capabilities that can be seamlessly integrated into your DevSecOps workflows. The CI/CD integration supports:

- **Automated Security Scanning**: Run APILeak scans on every commit, pull request, or scheduled basis
- **Threshold-Based Pipeline Control**: Configure security thresholds to fail pipelines on critical findings
- **Multi-Format Reporting**: Generate reports in HTML, JSON, XML, and SARIF formats
- **Container-Based Execution**: Run scans in isolated Docker containers
- **Multi-Platform Support**: Support for GitLab CI, GitHub Actions, and Jenkins

## Supported CI/CD Platforms

### GitLab CI/CD
- **Template**: `gitlab-ci.yml`
- **Features**: 
  - Multi-stage pipeline with build, test, and security scan stages
  - Parallel execution of different scan types
  - GitLab Security Dashboard integration
  - Merge request security scanning
  - Artifact management and reporting

### GitHub Actions
- **Template**: `github-actions.yml`
- **Features**:
  - Matrix builds for multiple scan types
  - GitHub Security tab integration (SARIF)
  - Pull request comments with scan results
  - Multi-architecture Docker builds
  - Workflow dispatch for manual scans

### Jenkins
- **Template**: `Jenkinsfile`
- **Features**:
  - Declarative pipeline with parallel stages
  - Blue Ocean compatible
  - Email notifications
  - HTML report publishing
  - Parameter-driven execution

## Quick Start

### 1. Choose Your Platform

Copy the appropriate template to your repository:

```bash
# For GitLab CI/CD
cp ci-cd/gitlab-ci.yml .gitlab-ci.yml

# For GitHub Actions
mkdir -p .github/workflows
cp ci-cd/github-actions.yml .github/workflows/apileak-security.yml

# For Jenkins
cp ci-cd/Jenkinsfile Jenkinsfile
```

### 2. Configure Environment Variables

Set the following variables in your CI/CD platform:

#### Required Variables
- `API_TARGET_URL`: The target API URL to scan
- `APILEAK_RATE_LIMIT`: Requests per second limit (default: 10)

#### Optional Variables
- `API_JWT_TOKEN`: JWT token for authenticated scanning
- `API_CONFIG_FILE`: Path to custom APILeak configuration file
- `OWASP_MODULES`: Comma-separated list of OWASP modules to enable
- `ENABLE_FULL_SCAN`: Enable comprehensive OWASP security scanning
- `CRITICAL_THRESHOLD`: Maximum critical findings before pipeline fails (default: 0)
- `HIGH_THRESHOLD`: Maximum high findings before pipeline fails (default: 5)
- `MEDIUM_THRESHOLD`: Maximum medium findings before pipeline fails (default: 20)

### 3. Copy Supporting Scripts

Copy the scripts directory to your repository:

```bash
cp -r ci-cd/scripts/ ci-cd/scripts/
```

### 4. Customize Configuration

Edit the template to match your specific requirements:

- Adjust security thresholds
- Configure notification settings
- Modify scan types and wordlists
- Set up custom reporting

## Configuration Examples

### Basic Directory Fuzzing

```yaml
# GitLab CI example
security-scan:
  script:
    - docker run --rm apileak:latest dir --target $API_TARGET_URL
```

### Authenticated Parameter Scanning

```yaml
# GitHub Actions example
- name: Run Parameter Scan
  run: |
    docker run --rm \
      -e APILEAK_JWT_TOKEN="${{ secrets.API_JWT_TOKEN }}" \
      apileak:latest par \
      --target ${{ vars.API_TARGET_URL }} \
      --jwt ${{ secrets.API_JWT_TOKEN }}
```

### Full OWASP Security Scan

```groovy
// Jenkins example
stage('Full Security Scan') {
    steps {
        sh '''
            docker run --rm \
                -e APILEAK_MODULES="bola,auth,property,function_auth" \
                -v $(pwd)/reports:/app/reports \
                apileak:latest full \
                --target "${API_TARGET_URL}" \
                --modules "bola,auth,property,function_auth"
        '''
    }
}
```

## Security Thresholds

Configure pipeline behavior based on finding severity:

| Threshold | Default | Description |
|-----------|---------|-------------|
| Critical  | 0       | Pipeline fails if any critical findings |
| High      | 5       | Pipeline fails if more than 5 high findings |
| Medium    | 20      | Pipeline warns if more than 20 medium findings |

### Threshold Configuration Examples

```yaml
# GitLab CI
variables:
  CRITICAL_THRESHOLD: "0"
  HIGH_THRESHOLD: "3"
  MEDIUM_THRESHOLD: "10"
```

```yaml
# GitHub Actions
env:
  CRITICAL_THRESHOLD: 0
  HIGH_THRESHOLD: 3
  MEDIUM_THRESHOLD: 10
```

```groovy
// Jenkins
environment {
    CRITICAL_THRESHOLD = '0'
    HIGH_THRESHOLD = '3'
    MEDIUM_THRESHOLD = '10'
}
```

## Report Generation

APILeak generates multiple report formats:

### HTML Reports
- **Purpose**: Human-readable reports with interactive elements
- **Location**: `reports/consolidated-security-report-{pipeline-id}.html`
- **Features**: Executive summary, detailed findings, OWASP coverage

### JSON Reports
- **Purpose**: Machine-readable data for automation
- **Location**: `reports/apileak-{scan-type}-{pipeline-id}.json`
- **Features**: Structured data, API integration, custom processing

### SARIF Reports
- **Purpose**: GitHub Security tab integration
- **Location**: `apileak-results.sarif`
- **Features**: Code scanning alerts, security dashboard

### JUnit XML
- **Purpose**: Test result integration
- **Location**: `reports/apileak-junit-{pipeline-id}.xml`
- **Features**: Test status, pipeline integration

## Advanced Configuration

### Custom Wordlists

Mount custom wordlists for specialized scanning:

```yaml
volumes:
  - ./custom-wordlists:/app/wordlists:ro
```

### Configuration Files

Use custom APILeak configuration:

```yaml
volumes:
  - ./config/apileak-config.yaml:/app/config/apileak-config.yaml:ro
command: ["full", "--config", "config/apileak-config.yaml"]
```

### WAF Evasion

Enable WAF evasion techniques:

```bash
docker run --rm apileak:latest dir \
  --target $API_TARGET_URL \
  --user-agent-random \
  --rate-limit 5
```

## Troubleshooting

### Common Issues

1. **Container Permission Errors**
   - Ensure Docker daemon is accessible
   - Check volume mount permissions
   - Verify non-root user execution

2. **Network Connectivity**
   - Verify target URL accessibility from CI/CD environment
   - Check firewall and proxy settings
   - Validate DNS resolution

3. **Rate Limiting**
   - Reduce `APILEAK_RATE_LIMIT` value
   - Enable adaptive throttling
   - Use WAF evasion techniques

4. **Memory Issues**
   - Increase container memory limits
   - Reduce concurrent scan modules
   - Use smaller wordlists for large targets

### Debug Mode

Enable debug logging for troubleshooting:

```bash
docker run --rm \
  -e APILEAK_LOG_LEVEL=DEBUG \
  apileak:latest dir --target $API_TARGET_URL
```

### Health Checks

Verify APILeak container health:

```bash
docker run --rm apileak:latest --help
```

## Security Considerations

### Secrets Management
- Store JWT tokens and API keys as encrypted secrets
- Use CI/CD platform secret management features
- Rotate authentication tokens regularly

### Network Security
- Run scans from secure CI/CD environments
- Use VPN or private networks for internal APIs
- Implement IP whitelisting where appropriate

### Data Protection
- Ensure scan reports don't contain sensitive data
- Configure appropriate artifact retention policies
- Use secure artifact storage

## Support and Documentation

- **Main Documentation**: [README.md](../README.md)
- **Configuration Guide**: [docs/configuration.md](../docs/configuration.md)
- **OWASP Testing Guide**: [docs/owasp/README.md](../docs/owasp/README.md)
- **Issue Tracker**: GitHub Issues
- **Security Reports**: security@apileak.com

## Contributing

Contributions to CI/CD templates and scripts are welcome:

1. Fork the repository
2. Create a feature branch
3. Test your changes with multiple CI/CD platforms
4. Submit a pull request with detailed description

## License

APILeak CI/CD integration templates are provided under the same license as the main project.