# 🚀 Integración CI/CD - APILeak

Esta guía cubre la integración de APILeak en pipelines de CI/CD para automatizar las pruebas de seguridad de APIs.

## 📋 Tabla de Contenidos

1. [Configuración Básica](#configuración-básica)
2. [GitHub Actions](#github-actions)
3. [GitLab CI](#gitlab-ci)
4. [Jenkins](#jenkins)
5. [Azure DevOps](#azure-devops)
6. [Docker Integration](#docker-integration)
7. [Exit Codes y Manejo de Errores](#exit-codes)
8. [Variables de Entorno](#variables-de-entorno)
9. [Mejores Prácticas](#mejores-prácticas)

---

## ⚙️ Configuración Básica

### Exit Codes de APILeak

APILeak utiliza exit codes estándar para integración con CI/CD:

- **0**: Sin vulnerabilidades críticas/altas encontradas ✅
- **1**: Vulnerabilidades altas encontradas ⚠️
- **2**: Vulnerabilidades críticas encontradas ❌

### Script Básico de CI/CD

```bash
#!/bin/bash
# ci_security_test.sh

set -e

# Configuración
API_ENDPOINT="${API_ENDPOINT:-https://staging-api.example.com}"
JWT_TOKEN="${JWT_TOKEN:-}"
MODULES="${MODULES:-bola,auth,property,resource}"
RATE_LIMIT="${RATE_LIMIT:-3}"
OUTPUT_DIR="${OUTPUT_DIR:-security_reports}"

echo "🔍 Starting APILeak security scan..."
echo "Target: $API_ENDPOINT"
echo "Modules: $MODULES"

# Ejecutar APILeak
python apileaks.py full \
  --target "$API_ENDPOINT" \
  --jwt "$JWT_TOKEN" \
  --modules "$MODULES" \
  --rate-limit "$RATE_LIMIT" \
  --output "$OUTPUT_DIR/scan-$(date +%Y%m%d-%H%M%S)" \
  --log-level ERROR

# Capturar exit code
EXIT_CODE=$?

# Interpretar resultados
case $EXIT_CODE in
  0)
    echo "✅ No critical vulnerabilities found. Pipeline continues."
    exit 0
    ;;
  1)
    echo "⚠️ High severity vulnerabilities found. Review required."
    echo "Pipeline continues but requires manual review."
    exit 0  # No fallar pipeline por vulnerabilidades altas
    ;;
  2)
    echo "❌ Critical vulnerabilities found! Failing pipeline."
    echo "Fix critical issues before deployment."
    exit 1  # Fallar pipeline por vulnerabilidades críticas
    ;;
  *)
    echo "❌ Unexpected error occurred during scan."
    exit 1
    ;;
esac
```

---

## 🐙 GitHub Actions

### Workflow Básico

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
        python apileaks.py full \
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

### Workflow Avanzado con Múltiples Entornos

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
            echo "command=full" >> $GITHUB_OUTPUT
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

### Pipeline Básico

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
      python apileaks.py full \
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
      junit: reports/security-scan-*.xml  # Si se genera reporte XML
  
  only:
    - main
    - develop
    - merge_requests

# Pipeline para producción con restricciones
production-security-scan:
  stage: security-test
  image: python:$PYTHON_VERSION
  
  before_script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -r requirements.txt
  
  script:
    - |
      # Rate limiting muy bajo para producción
      python apileaks.py full \
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

### Pipeline con Docker

```yaml
# .gitlab-ci.yml con Docker
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
        python apileaks.py full \
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

### Pipeline Declarativo

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
                        python apileaks.py full \\
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
                        // Leer resultados y enviar notificación
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
                            
                            // Enviar a Slack, Teams, etc.
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

### Dockerfile para APILeak

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos de dependencias
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Crear directorio de reportes
RUN mkdir -p reports

# Punto de entrada
ENTRYPOINT ["python", "apileaks.py"]
CMD ["--help"]
```

### Docker Compose para Testing

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
      full
      --target ${API_ENDPOINT}
      --jwt ${JWT_TOKEN}
      --modules ${MODULES:-bola,auth,property}
      --rate-limit ${RATE_LIMIT:-3}
      --output docker-scan-$(date +%Y%m%d-%H%M%S)
      --log-level INFO

  # Servicio para generar reportes
  report-server:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./reports:/usr/share/nginx/html
    depends_on:
      - apileak
```

### Script de Docker para CI/CD

```bash
#!/bin/bash
# docker-security-scan.sh

set -e

# Configuración
IMAGE_NAME="apileak:latest"
CONTAINER_NAME="apileak-scan-$(date +%s)"

# Construir imagen
echo "🏗️ Building APILeak Docker image..."
docker build -t $IMAGE_NAME .

# Ejecutar scan
echo "🔍 Running security scan..."
docker run --rm \
  --name $CONTAINER_NAME \
  -e API_ENDPOINT="$API_ENDPOINT" \
  -e JWT_TOKEN="$JWT_TOKEN" \
  -v $(pwd)/reports:/app/reports \
  $IMAGE_NAME \
  full \
  --target "$API_ENDPOINT" \
  --jwt "$JWT_TOKEN" \
  --modules bola,auth,property,resource \
  --rate-limit 3 \
  --output "docker-scan-$(date +%Y%m%d-%H%M%S)" \
  --log-level ERROR

# Verificar exit code
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

## 🔧 Variables de Entorno

### Variables Estándar

```bash
# Configuración básica
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,property,resource"
export APILEAK_RATE_LIMIT="5"
export APILEAK_JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
export APILEAK_OUTPUT_DIR="reports"
export APILEAK_TIMEOUT="30"
export APILEAK_VERIFY_SSL="true"

# Configuración avanzada
export APILEAK_MAX_DEPTH="3"
export APILEAK_USER_AGENT="APILeak-CI/0.1.0"
```

### Variables por Entorno

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

## 📋 Mejores Prácticas

### 1. **Configuración por Entorno**

```bash
# Diferentes configuraciones según el entorno
case "$ENVIRONMENT" in
  "production")
    RATE_LIMIT=1
    MODULES="bola,auth"  # Solo módulos críticos
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

### 2. **Manejo de Secretos**

```yaml
# GitHub Actions - usar secrets
env:
  JWT_TOKEN: ${{ secrets.API_JWT_TOKEN }}
  API_KEY: ${{ secrets.API_KEY }}

# GitLab CI - variables protegidas
variables:
  JWT_TOKEN: $API_JWT_TOKEN  # Variable protegida en GitLab

# Jenkins - credentials binding
environment {
  JWT_TOKEN = credentials('api-jwt-token')
}
```

### 3. **Rate Limiting Inteligente**

```bash
# Ajustar rate limiting según el entorno y hora
HOUR=$(date +%H)
if [ "$ENVIRONMENT" = "production" ]; then
  if [ $HOUR -ge 9 ] && [ $HOUR -le 17 ]; then
    # Horario comercial - rate limiting muy bajo
    RATE_LIMIT=1
  else
    # Fuera de horario - rate limiting moderado
    RATE_LIMIT=3
  fi
else
  RATE_LIMIT=10
fi
```

### 4. **Notificaciones Inteligentes**

```bash
# Solo notificar en casos importantes
if [ $EXIT_CODE -eq 2 ]; then
  # Vulnerabilidades críticas - notificar inmediatamente
  curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"🚨 Critical API vulnerabilities found in $ENVIRONMENT!\"}"
elif [ $EXIT_CODE -eq 1 ] && [ "$ENVIRONMENT" = "production" ]; then
  # Vulnerabilidades altas en producción - notificar
  curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"⚠️ High severity API vulnerabilities found in production.\"}"
fi
```

### 5. **Archivado de Reportes**

```bash
# Organizar reportes por fecha y entorno
REPORT_DIR="reports/$ENVIRONMENT/$(date +%Y/%m/%d)"
mkdir -p "$REPORT_DIR"

python apileaks.py full \
  --target "$API_ENDPOINT" \
  --output "$REPORT_DIR/scan-$(date +%H%M%S)" \
  --modules "$MODULES"
```

### 6. **Timeouts y Reintentos**

```bash
# Implementar timeout y reintentos
timeout 1800 python apileaks.py full \
  --target "$API_ENDPOINT" \
  --modules "$MODULES" \
  --rate-limit "$RATE_LIMIT" || {
  
  echo "⏰ Scan timed out or failed. Retrying with reduced scope..."
  
  # Retry con módulos críticos solamente
  timeout 900 python apileaks.py full \
    --target "$API_ENDPOINT" \
    --modules "bola,auth" \
    --rate-limit 1
}
```

---

## 🔍 Troubleshooting CI/CD

### Problemas Comunes

#### 1. **Timeouts en CI/CD**
```bash
# Solución: Reducir scope o aumentar timeout
timeout 3600 python apileaks.py full --modules bola,auth --rate-limit 1
```

#### 2. **Rate Limiting del Servidor**
```bash
# Solución: Rate limiting adaptativo
python apileaks.py full --rate-limit 1 --modules bola
```

#### 3. **Falsos Positivos**
```bash
# Solución: Configurar filtros específicos
python apileaks.py full --response 200,201,404 --modules bola,auth
```

#### 4. **Recursos Limitados en CI**
```bash
# Solución: Ejecutar módulos por separado
for module in bola auth property; do
  python apileaks.py full --modules $module --target "$API_ENDPOINT"
done
```

---

Esta guía proporciona una base sólida para integrar APILeak en cualquier pipeline de CI/CD, asegurando que las APIs se mantengan seguras a lo largo del ciclo de desarrollo.