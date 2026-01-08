# Advanced Discovery Module

The **Advanced Discovery** module of APILeak provides advanced attack surface mapping capabilities that go beyond traditional fuzzing. This module includes subdomain discovery, CORS policy analysis, and security header verification.

## 📋 Table of Contents

- [Overview](#overview)
- [Components](#components)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [Practical Examples](#practical-examples)
- [Results Interpretation](#results-interpretation)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

Advanced Discovery extends APILeak's capabilities to provide complete attack surface mapping, including:

### 🎯 **Main Objectives**
- **Complete Mapping**: Discover all infrastructure related to the API
- **Security Analysis**: Evaluate security configurations at infrastructure level
- **Risk Detection**: Identify dangerous configurations in CORS and headers
- **Attack Surface**: Provide a complete view of entry points

### 🔍 **Capabilities**
- Automatic subdomain discovery
- Comprehensive CORS policy analysis
- Critical security header verification
- Insecure configuration detection
- Finding generation with appropriate severity

## Components

### 1. 🌐 **Subdomain Discovery**

Discovers subdomains related to the target domain.

**Features:**
- Tests common subdomains (api, dev, staging, test, qa, admin, etc.)
- DNS verification and HTTP accessibility
- Detection of sensitive subdomains (dev, staging, admin)
- Concurrent processing with rate limiting

**Tested Subdomain Patterns:**
```
api, www, dev, staging, test, qa, uat, prod, production,
admin, management, dashboard, portal, app, mobile,
v1, v2, v3, beta, alpha, demo, sandbox, internal
```

### 2. 🔒 **CORS Analyzer**

Analyzes CORS policies to detect insecure configurations.

**Tests Performed:**
- Wildcard origins (`*`)
- Suspicious origins (`evil.com`, `attacker.com`)
- Dangerous methods (DELETE, PUT, PATCH)
- Credentials with wildcard (CRITICAL)
- Permissive configurations

**Test Origins:**
```
https://evil.com
https://attacker.com
http://localhost:3000
https://example.com
null
*
```

### 3. 🛡️ **Security Headers Analyzer**

Verifies the presence and configuration of critical security headers.

**Analyzed Headers:**
- `X-Frame-Options` - Clickjacking protection
- `Content-Security-Policy` - Content security policy
- `Strict-Transport-Security` - HSTS for forced HTTPS
- `X-Content-Type-Options` - MIME sniffing prevention
- `Referrer-Policy` - Referrer information control
- `Permissions-Policy` - Browser permissions control
- `X-XSS-Protection` - XSS protection (legacy)
- `Cache-Control` - Cache control
- `X-Permitted-Cross-Domain-Policies` - Cross-domain policies

## Configuration

### Basic Configuration

```yaml
# Minimal configuration
advanced_discovery:
  enabled: true
  subdomain_discovery: true
  cors_analysis: true
  security_headers: true
```

### Configuración Completa

```yaml
advanced_discovery:
  enabled: true
  
  # Configuración de descubrimiento de subdominios
  subdomain_discovery: true
  subdomain_wordlist:
    - "api"
    - "www"
    - "dev"
    - "staging"
    - "test"
    - "qa"
    - "uat"
    - "prod"
    - "production"
    - "admin"
    - "management"
    - "dashboard"
    - "portal"
    - "app"
    - "mobile"
    - "v1"
    - "v2"
    - "v3"
    - "beta"
    - "alpha"
    - "demo"
    - "sandbox"
    - "internal"
  
  # Configuración de análisis CORS
  cors_analysis: true
  cors_test_origins:
    - "https://evil.com"
    - "https://attacker.com"
    - "http://localhost:3000"
    - "https://example.com"
    - "null"
    - "*"
  
  # Configuración de headers de seguridad
  security_headers: true
  
  # Configuración de rendimiento
  max_concurrent: 10
  timeout: 10.0
```

### Configuración Solo Advanced Discovery

```yaml
# Para ejecutar solo Advanced Discovery sin fuzzing tradicional
target:
  base_url: "https://api.example.com"

advanced_discovery:
  enabled: true
  subdomain_discovery: true
  cors_analysis: true
  security_headers: true

# Deshabilitar otros módulos
fuzzing:
  endpoints:
    enabled: false
  parameters:
    enabled: false
  headers:
    enabled: false

owasp_testing:
  enabled_modules: []
```

## Uso desde CLI

### 1. **Ejecución Básica**

```bash
# Escaneo completo con Advanced Discovery habilitado
python apileaks.py full --target https://api.example.com
```

### 2. **Con Archivo de Configuración**

```bash
# Usar configuración personalizada
python apileaks.py full --config config/advanced_discovery.yaml
```

### 3. **Con Parámetros Adicionales**

```bash
# Con rate limiting y autenticación
python apileaks.py full \
  --target https://api.example.com \
  --rate-limit 5 \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --output advanced_scan
```

### 4. **Con Evasión de WAF**

```bash
# Con User-Agent aleatorio para evadir WAF
python apileaks.py full \
  --target https://api.example.com \
  --user-agent-random \
  --rate-limit 3
```

### 5. **Con Logging Detallado**

```bash
# Con logging para debugging
python apileaks.py full \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file advanced_discovery.log
```

## Ejemplos Prácticos

### Ejemplo 1: Escaneo de API Corporativa

```bash
# Configuración para API corporativa con múltiples subdominios
python apileaks.py full \
  --config config/corporate_api.yaml \
  --target https://api.company.com \
  --rate-limit 5 \
  --output corporate_scan_$(date +%Y%m%d)
```

**Archivo de configuración (`config/corporate_api.yaml`):**
```yaml
target:
  base_url: "https://api.company.com"
  timeout: 15

advanced_discovery:
  enabled: true
  subdomain_discovery: true
  subdomain_wordlist:
    - "api"
    - "api-dev"
    - "api-staging"
    - "api-prod"
    - "dev"
    - "staging"
    - "test"
    - "qa"
    - "admin"
    - "management"
    - "internal"
  cors_analysis: true
  security_headers: true
  max_concurrent: 5
  timeout: 15.0

rate_limiting:
  requests_per_second: 5
  burst_size: 10
  adaptive: true
```

### Ejemplo 2: Análisis de Seguridad Rápido

```bash
# Solo análisis de seguridad sin fuzzing
python apileaks.py full \
  --config config/security_only.yaml \
  --target https://api.example.com
```

**Archivo de configuración (`config/security_only.yaml`):**
```yaml
target:
  base_url: "https://api.example.com"

advanced_discovery:
  enabled: true
  subdomain_discovery: false  # Deshabilitar para escaneo rápido
  cors_analysis: true
  security_headers: true
  max_concurrent: 10
  timeout: 5.0

fuzzing:
  endpoints:
    enabled: false
  parameters:
    enabled: false
  headers:
    enabled: false

owasp_testing:
  enabled_modules: []
```

### Ejemplo 3: Descubrimiento Completo de Infraestructura

```bash
# Descubrimiento exhaustivo con wordlist personalizada
python apileaks.py full \
  --config config/infrastructure_discovery.yaml \
  --target https://example.com \
  --rate-limit 3 \
  --output infrastructure_scan
```

## Interpretación de Resultados

### Salida de Consola

```
🎯 Target: https://api.example.com
⚡ Rate Limit: 10 req/sec

2026-01-07 [info] Phase 1: Starting subdomain discovery
2026-01-07 [info] Generated subdomain candidates count=23 domain=example.com
2026-01-07 [info] Accessible subdomain found subdomain=api.example.com status_code=200
2026-01-07 [info] Accessible subdomain found subdomain=dev.example.com status_code=200

2026-01-07 [info] Phase 3: Starting CORS analysis
2026-01-07 [info] CORS analysis completed endpoints_analyzed=3

2026-01-07 [info] Phase 4: Starting security headers analysis
2026-01-07 [info] Security headers analysis completed endpoints_analyzed=3

==================================================
APILeak Scan Completed Successfully
==================================================
Target: https://api.example.com
Discovered Subdomains: 2
Total Findings: 15
Critical: 0
High: 3
Medium: 8
Low: 4
Info: 0
```

### Tipos de Findings

#### 🔴 **CRITICAL**
- `CORS_WILDCARD_WITH_CREDENTIALS`: CORS con wildcard (*) y credenciales habilitadas

#### 🟠 **HIGH**
- `CORS_WILDCARD_ORIGIN`: CORS con wildcard origin
- `CORS_SUSPICIOUS_ORIGINS`: Orígenes sospechosos permitidos
- `MISSING_SECURITY_HEADERS`: Múltiples headers críticos faltantes

#### 🟡 **MEDIUM**
- `SENSITIVE_SUBDOMAIN_EXPOSURE`: Subdominios sensibles expuestos (dev, staging)
- `CORS_DANGEROUS_METHODS`: Métodos peligrosos permitidos via CORS
- `INSECURE_SECURITY_HEADERS`: Headers con configuración insegura
- `LOW_SECURITY_HEADERS_SCORE`: Puntuación baja de headers de seguridad

#### 🔵 **INFO**
- `SUBDOMAIN_DISCOVERY`: Subdominios descubiertos

### Reporte HTML

El reporte HTML incluye:
- **Dashboard**: Vista general con métricas
- **Subdominios Descubiertos**: Lista completa con estado
- **Análisis CORS**: Resultados por endpoint
- **Headers de Seguridad**: Puntuación y recomendaciones
- **Findings Detallados**: Con evidencia y recomendaciones

### Reporte JSON

```json
{
  "scan_id": "12345678-1234-1234-1234-123456789012",
  "target": "https://api.example.com",
  "advanced_results": {
    "target_domain": "example.com",
    "discovered_subdomains": ["api.example.com", "www.example.com"],
    "total_findings": 15,
    "high_risk_findings": 3
  },
  "findings": [
    {
      "category": "CORS_WILDCARD_ORIGIN",
      "severity": "HIGH",
      "endpoint": "https://api.example.com",
      "evidence": "CORS policy allows wildcard origin (*)",
      "recommendation": "Specify explicit allowed origins"
    }
  ]
}
```

## Integración CI/CD

### GitHub Actions

```yaml
name: APILeak Advanced Discovery
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      
      - name: Install APILeak
        run: |
          pip install -r requirements.txt
      
      - name: Run Advanced Discovery
        run: |
          python apileaks.py full \
            --config config/ci_advanced_discovery.yaml \
            --target ${{ secrets.API_TARGET }} \
            --output ci_scan_${{ github.run_number }} \
            --log-level WARNING \
            --json-logs
      
      - name: Upload Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

### GitLab CI

```yaml
stages:
  - security-scan

advanced-discovery:
  stage: security-scan
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - |
      python apileaks.py full \
        --config config/ci_advanced_discovery.yaml \
        --target $API_TARGET \
        --output ci_scan_$CI_PIPELINE_ID \
        --rate-limit 5 \
        --log-level WARNING
  artifacts:
    reports:
      junit: reports/ci_scan_$CI_PIPELINE_ID.xml
    paths:
      - reports/
  only:
    - main
    - develop
```

### Variables de Entorno

```bash
# Configuración via variables de entorno
export APILEAK_TARGET="https://api.example.com"
export APILEAK_RATE_LIMIT="5"
export APILEAK_OUTPUT_DIR="reports"
export APILEAK_TIMEOUT="15"

# Ejecutar con variables
python apileaks.py full --config config/advanced_discovery.yaml
```

## Troubleshooting

### Problemas Comunes

#### 1. **DNS Resolution Failed**
```
Error: DNS resolution failed for subdomain
```
**Solución:**
- Verificar conectividad de red
- Usar `dns_resolution: false` en configuración para omitir verificación DNS
- Verificar que el dominio objetivo sea válido

#### 2. **Rate Limiting Detectado**
```
Warning: Rate limit detected, backing off
```
**Solución:**
- Reducir `requests_per_second` en configuración
- Aumentar `timeout` para requests
- Habilitar `adaptive: true` en rate limiting

#### 3. **Timeouts en CORS Analysis**
```
Error: CORS test failed - timeout
```
**Solución:**
- Aumentar `timeout` en configuración CORS
- Reducir `max_concurrent` para menos concurrencia
- Verificar que el endpoint responda a OPTIONS requests

#### 4. **No Subdomains Found**
```
Info: No accessible subdomains found
```
**Posibles Causas:**
- Dominio no tiene subdominios públicos
- Wordlist muy limitada
- Rate limiting muy agresivo del servidor

**Solución:**
- Expandir `subdomain_wordlist`
- Verificar manualmente algunos subdominios
- Ajustar rate limiting

### Configuración de Debug

```yaml
# Configuración para debugging
advanced_discovery:
  enabled: true
  subdomain_discovery: true
  cors_analysis: true
  security_headers: true
  max_concurrent: 1  # Reducir concurrencia
  timeout: 30.0      # Aumentar timeout

rate_limiting:
  requests_per_second: 1  # Muy lento para debugging
  burst_size: 1
```

```bash
# Ejecutar con debug completo
python apileaks.py full \
  --config config/debug_advanced_discovery.yaml \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log
```

### Logs Útiles

```bash
# Filtrar logs de Advanced Discovery
grep "advanced_discovery" debug.log

# Ver solo errores
grep "ERROR" debug.log | grep "advanced_discovery"

# Ver estadísticas finales
grep "statistics" debug.log
```

## Mejores Prácticas

### 1. **Rate Limiting Responsable**
- Usar `requests_per_second: 5-10` para APIs públicas
- Habilitar `adaptive: true` para ajuste automático
- Respetar `Retry-After` headers

### 2. **Configuración de Timeouts**
- `timeout: 10-15` segundos para la mayoría de casos
- Aumentar para APIs lentas o con alta latencia
- Considerar la ubicación geográfica del servidor

### 3. **Wordlists Personalizadas**
- Adaptar `subdomain_wordlist` según la organización
- Incluir patrones específicos de la empresa
- Considerar convenciones de naming

### 4. **Seguridad Operacional**
- No ejecutar contra APIs de producción sin autorización
- Usar rate limiting conservador
- Monitorear logs del servidor objetivo

### 5. **Interpretación de Resultados**
- Priorizar findings CRITICAL y HIGH
- Verificar manualmente findings de subdominios sensibles
- Correlacionar con otros hallazgos de seguridad

---

## 📚 Referencias Adicionales

- [Configuración General](configuration.md)
- [WAF Evasion](waf-evasion.md)
- [OWASP API Security Top 10](owasp/README.md)
- [CLI Reference](cli-reference.md)

---

**¿Necesitas ayuda?** Consulta nuestra [guía de troubleshooting](advanced/troubleshooting.md) o crea un issue en GitHub.