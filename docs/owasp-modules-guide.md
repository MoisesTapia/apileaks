# 🛡️ Guía Completa de Módulos OWASP - APILeak

Esta guía cubre todos los módulos OWASP implementados en APILeak, desde conceptos básicos hasta ejemplos avanzados de uso.

## 📋 Tabla de Contenidos

1. [Introducción a los Módulos OWASP](#introducción)
2. [Módulos Disponibles](#módulos-disponibles)
3. [Uso Básico](#uso-básico)
4. [Configuración Avanzada](#configuración-avanzada)
5. [Ejemplos Prácticos](#ejemplos-prácticos)
6. [Interpretación de Resultados](#interpretación-de-resultados)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 Introducción

APILeak implementa módulos especializados para cada categoría del **OWASP API Security Top 10 2023**. Cada módulo está diseñado para detectar vulnerabilidades específicas mediante técnicas avanzadas de testing automatizado.

### ¿Por qué usar los módulos OWASP?

- **Cobertura Completa**: Cada módulo cubre una categoría específica del OWASP Top 10
- **Testing Especializado**: Técnicas específicas para cada tipo de vulnerabilidad
- **Automatización**: Detección automática sin intervención manual
- **Reportes Detallados**: Evidencia clara y recomendaciones de remediación

---

## 🧩 Módulos Disponibles

| Módulo | OWASP Category | Descripción | Prioridad |
|--------|----------------|-------------|-----------|
| `bola` | **API1** - Broken Object Level Authorization | Detecta acceso no autorizado a objetos | **P0** |
| `auth` | **API2** - Broken Authentication | Identifica fallas en autenticación JWT | **P0** |
| `property` | **API3** - Broken Object Property Level Authorization | Detecta exposición excesiva de datos | **P0** |
| `resource` | **API4** - Unrestricted Resource Consumption | Identifica ausencia de rate limiting y DoS | **P1** |
| `function_auth` | **API5** - Broken Function Level Authorization | Detecta escalación de privilegios | **P0** |

### Estado de Implementación

✅ **Completamente Implementados**: `bola`, `auth`, `property`, `resource`, `function_auth`  
🚧 **En Desarrollo**: `ssrf` (API7), `business_flows` (API6)  
📋 **Planificados**: `security_misconfig` (API8), `inventory_mgmt` (API9), `unsafe_consumption` (API10)

---

## 🚀 Uso Básico

### Comando Básico

```bash
# Ejecutar TODOS los módulos OWASP
python apileaks.py full --target https://api.example.com

# Ejecutar módulos específicos
python apileaks.py full --target https://api.example.com --modules bola,auth,resource
```

### Módulos por Defecto

Por defecto, APILeak ejecuta estos módulos en modo `full`:
```bash
bola,auth,property,resource,function_auth
```

### Sintaxis de Módulos

```bash
--modules <module1>,<module2>,<module3>
```

**Módulos disponibles:**
- `bola` - BOLA Testing
- `auth` - Authentication Testing  
- `property` - Property Level Authorization
- `resource` - Resource Consumption
- `function_auth` - Function Level Authorization

---

## ⚙️ Configuración Avanzada

### Archivo de Configuración YAML

```yaml
# config/owasp_config.yaml
target:
  base_url: "https://api.example.com"
  timeout: 30

owasp_testing:
  enabled_modules: ["bola", "auth", "property", "resource", "function_auth"]
  
  # Configuración específica por módulo
  bola_testing:
    enabled: true
    id_patterns: ["sequential", "guid", "uuid"]
    test_contexts: ["anonymous", "user", "admin"]
  
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: "wordlists/jwt_secrets.txt"
    test_logout_invalidation: true
  
  property_testing:
    enabled: true
    sensitive_fields: ["password", "api_key", "secret", "ssn"]
    mass_assignment_fields: ["is_admin", "role", "permissions"]
  
  resource_testing:
    enabled: true
    burst_size: 100
    large_payload_sizes: [1048576, 10485760]  # 1MB, 10MB
    json_depth_limit: 1000
  
  function_auth_testing:
    enabled: true
    admin_endpoints: ["/admin", "/api/admin", "/management"]
    dangerous_methods: ["DELETE", "PUT", "PATCH"]

# Autenticación para testing
authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 1
    - name: "admin"
      type: "bearer"
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      privilege_level: 3

rate_limiting:
  requests_per_second: 10
  adaptive: true
  respect_retry_after: true
```

### Variables de Entorno

```bash
# Configuración básica
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,resource"
export APILEAK_RATE_LIMIT="5"
export APILEAK_JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Ejecutar con variables de entorno
python apileaks.py full
```

---

## 📚 Ejemplos Prácticos

### 1. 🔐 BOLA Testing (API1)

**¿Qué detecta?**
- Acceso no autorizado a objetos de otros usuarios
- Enumeración de IDs secuenciales
- Escalación horizontal de privilegios

```bash
# Test básico BOLA
python apileaks.py full --target https://api.example.com --modules bola

# BOLA con múltiples contextos de autenticación
python apileaks.py full --target https://api.example.com --modules bola \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# BOLA con rate limiting bajo para APIs sensibles
python apileaks.py full --target https://api.example.com --modules bola \
  --rate-limit 2
```

**Ejemplo de vulnerabilidad detectada:**
```
🚨 CRITICAL: BOLA_ANONYMOUS_ACCESS
Endpoint: https://api.example.com/users/123
Evidence: Object 123 accessible without authentication. Status: 200, Size: 245 bytes
Recommendation: Implement proper authentication checks for object access.
```

### 2. 🔑 Authentication Testing (API2)

**¿Qué detecta?**
- Algoritmos JWT débiles (none, algorithm confusion)
- Tokens que no expiran correctamente
- Secretos JWT débiles
- Endpoints accesibles sin autenticación

```bash
# Test completo de autenticación
python apileaks.py full --target https://api.example.com --modules auth

# Test con token JWT específico
python apileaks.py full --target https://api.example.com --modules auth \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Test con wordlist personalizada de secretos JWT
python apileaks.py full --config config/auth_config.yaml --target https://api.example.com
```

**Ejemplo de configuración para auth testing:**
```yaml
owasp_testing:
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: "wordlists/custom_jwt_secrets.txt"
    test_logout_invalidation: true
```

### 3. 📊 Property Level Authorization (API3)

**¿Qué detecta?**
- Exposición de campos sensibles (passwords, API keys)
- Vulnerabilidades de mass assignment
- Campos no documentados en respuestas
- Propiedades de solo lectura modificables

```bash
# Test de autorización a nivel de propiedades
python apileaks.py full --target https://api.example.com --modules property

# Con campos sensibles personalizados
python apileaks.py full --config config/property_config.yaml --target https://api.example.com
```

**Configuración personalizada:**
```yaml
owasp_testing:
  property_testing:
    enabled: true
    sensitive_fields: 
      - "password"
      - "api_key" 
      - "secret"
      - "ssn"
      - "credit_card"
      - "bank_account"
    mass_assignment_fields:
      - "is_admin"
      - "role"
      - "permissions"
      - "user_id"
      - "account_type"
```

### 4. ⚡ Resource Consumption (API4)

**¿Qué detecta?**
- Ausencia de rate limiting
- Aceptación de payloads grandes
- JSON profundamente anidado
- Vulnerabilidades ReDoS
- Procesamiento de consultas complejas

```bash
# Test básico de consumo de recursos
python apileaks.py full --target https://api.example.com --modules resource

# Test con burst personalizado
python apileaks.py full --target https://api.example.com --modules resource \
  --rate-limit 20

# Test con configuración avanzada
python apileaks.py full --config config/resource_config.yaml --target https://api.example.com
```

**Configuración avanzada:**
```yaml
owasp_testing:
  resource_testing:
    enabled: true
    burst_size: 150                    # Requests para rate limiting test
    large_payload_sizes: [1048576, 10485760, 104857600]  # 1MB, 10MB, 100MB
    json_depth_limit: 1500             # Profundidad JSON
```

### 5. 🛡️ Function Level Authorization (API5)

**¿Qué detecta?**
- Acceso no autorizado a funciones administrativas
- Bypass por método HTTP
- Bypass por parámetros y headers
- Escalación vertical de privilegios

```bash
# Test de autorización a nivel de función
python apileaks.py full --target https://api.example.com --modules function_auth

# Con endpoints administrativos personalizados
python apileaks.py full --config config/function_auth_config.yaml --target https://api.example.com
```

**Configuración personalizada:**
```yaml
owasp_testing:
  function_auth_testing:
    enabled: true
    admin_endpoints: 
      - "/admin"
      - "/api/admin" 
      - "/management"
      - "/dashboard"
      - "/api/v1/admin"
    dangerous_methods: ["DELETE", "PUT", "PATCH", "POST"]
```

---

## 🎯 Ejemplos de Casos de Uso Reales

### Caso 1: API de E-commerce

```bash
# Testing completo para API de e-commerce
python apileaks.py full --target https://api.shop.example.com \
  --modules bola,auth,property,resource \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --rate-limit 5 \
  --output ecommerce_security_test
```

### Caso 2: API Bancaria (Alta Seguridad)

```bash
# Testing con rate limiting muy bajo para APIs críticas
python apileaks.py full --target https://api.bank.example.com \
  --modules bola,auth,property,function_auth \
  --rate-limit 1 \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --log-level INFO \
  --output banking_security_audit
```

### Caso 3: API de Redes Sociales

```bash
# Testing enfocado en BOLA y property level auth
python apileaks.py full --target https://api.social.example.com \
  --modules bola,property,resource \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... \
  --rate-limit 10 \
  --output social_media_test
```

### Caso 4: Testing en CI/CD

```bash
#!/bin/bash
# ci_security_test.sh

export APILEAK_TARGET="https://staging-api.example.com"
export APILEAK_MODULES="bola,auth,property"
export APILEAK_JWT_TOKEN="${CI_JWT_TOKEN}"
export APILEAK_RATE_LIMIT="3"
export APILEAK_OUTPUT_DIR="security_reports"

python apileaks.py full --log-level ERROR

# Verificar si hay vulnerabilidades críticas
if [ $? -eq 2 ]; then
    echo "❌ Critical vulnerabilities found! Failing CI/CD pipeline."
    exit 1
elif [ $? -eq 1 ]; then
    echo "⚠️ High severity vulnerabilities found. Review required."
    exit 0
else
    echo "✅ No critical vulnerabilities found."
    exit 0
fi
```

---

## 📊 Interpretación de Resultados

### Niveles de Severidad

| Severidad | Descripción | Acción Requerida |
|-----------|-------------|------------------|
| **CRITICAL** | Vulnerabilidades que permiten acceso no autorizado inmediato | Corrección inmediata |
| **HIGH** | Vulnerabilidades significativas que requieren atención urgente | Corrección en 24-48h |
| **MEDIUM** | Vulnerabilidades moderadas que deben ser corregidas | Corrección en 1-2 semanas |
| **LOW** | Problemas menores de seguridad | Corrección en próximo ciclo |
| **INFO** | Información sobre configuración o endpoints encontrados | Revisión opcional |

### Categorías de Findings por Módulo

#### BOLA Module (API1)
- `BOLA_ANONYMOUS_ACCESS` (CRITICAL)
- `BOLA_HORIZONTAL_ESCALATION` (CRITICAL)
- `BOLA_ID_ENUMERATION` (HIGH)
- `BOLA_OBJECT_ACCESS` (HIGH)

#### Auth Module (API2)
- `AUTH_BYPASS` (CRITICAL)
- `WEAK_JWT_ALGORITHM` (HIGH)
- `TOKEN_NOT_EXPIRED` (HIGH)
- `WEAK_JWT_SECRET` (HIGH)

#### Property Module (API3)
- `SENSITIVE_DATA_EXPOSURE` (CRITICAL)
- `MASS_ASSIGNMENT` (HIGH)
- `UNDOCUMENTED_FIELD` (MEDIUM)
- `READONLY_PROPERTY_MODIFIED` (HIGH)

#### Resource Module (API4)
- `MISSING_RATE_LIMITING` (MEDIUM)
- `LARGE_PAYLOAD_ACCEPTED` (MEDIUM/HIGH)
- `REDOS_VULNERABILITY` (HIGH)
- `COMPLEX_QUERY_PROCESSED` (MEDIUM/HIGH)

#### Function Auth Module (API5)
- `ADMIN_ACCESS_ANONYMOUS` (CRITICAL)
- `FUNCTION_LEVEL_BYPASS` (HIGH)
- `HTTP_METHOD_BYPASS` (HIGH)
- `PARAMETER_BYPASS` (MEDIUM)

### Ejemplo de Reporte

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "https://api.example.com",
  "timestamp": "2024-01-08T10:30:00Z",
  "summary": {
    "total_findings": 15,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 2,
    "info": 1
  },
  "owasp_coverage": {
    "tested_categories": 5,
    "total_categories": 10,
    "coverage_percentage": 50.0
  },
  "findings": [
    {
      "id": "finding-001",
      "category": "BOLA_ANONYMOUS_ACCESS",
      "owasp_category": "API1",
      "severity": "CRITICAL",
      "endpoint": "https://api.example.com/users/123",
      "method": "GET",
      "evidence": "Object 123 accessible without authentication. Status: 200, Size: 245 bytes",
      "recommendation": "Implement proper authentication checks for object access."
    }
  ]
}
```

---

## 🔧 Troubleshooting

### Problemas Comunes

#### 1. Rate Limiting del Servidor
```
Error: Too many requests (429)
```
**Solución:**
```bash
# Reducir rate limit
python apileaks.py full --target https://api.example.com --rate-limit 1

# Usar modo adaptativo (por defecto)
python apileaks.py full --target https://api.example.com --modules bola
```

#### 2. Timeouts de Conexión
```
Error: Connection timeout
```
**Solución:**
```yaml
target:
  timeout: 60  # Aumentar timeout a 60 segundos
```

#### 3. JWT Token Inválido
```
Warning: JWT token validation failed
```
**Solución:**
```bash
# Verificar token JWT
python apileaks.py jwt-decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Generar nuevo token
python apileaks.py jwt-encode '{"sub":"user123","role":"user"}' --secret mysecret
```

#### 4. Wordlists No Encontradas
```
Error: Wordlist file not found
```
**Solución:**
```bash
# Verificar que existan los wordlists
ls -la wordlists/

# Usar wordlists personalizadas
python apileaks.py full --config config/custom_wordlists.yaml --target https://api.example.com
```

### Logs de Debug

```bash
# Habilitar logging detallado
python apileaks.py full --target https://api.example.com \
  --modules bola \
  --log-level DEBUG \
  --log-file debug.log
```

### Configuración de Red

```yaml
# Para APIs detrás de proxies o con SSL personalizado
target:
  verify_ssl: false  # Solo para testing, no en producción
  timeout: 30
  
rate_limiting:
  adaptive: true
  respect_retry_after: true
```

---

## 📈 Mejores Prácticas

### 1. **Selección de Módulos**
- **APIs Públicas**: Usar todos los módulos (`bola,auth,property,resource,function_auth`)
- **APIs Internas**: Enfocar en `bola,property,function_auth`
- **APIs de Alto Tráfico**: Usar `resource,auth` con rate limiting bajo

### 2. **Rate Limiting**
- **APIs de Producción**: `--rate-limit 1-5`
- **APIs de Staging**: `--rate-limit 5-10`
- **APIs de Desarrollo**: `--rate-limit 10-20`

### 3. **Autenticación**
- Usar múltiples contextos de autenticación cuando sea posible
- Incluir tokens con diferentes niveles de privilegios
- Probar tanto con tokens válidos como inválidos

### 4. **CI/CD Integration**
```bash
# Script para CI/CD
python apileaks.py full \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --modules bola,auth,property \
  --rate-limit 3 \
  --output "security-scan-${BUILD_NUMBER}" \
  --log-level ERROR

# Verificar exit codes
# 0 = No critical/high findings
# 1 = High severity findings found  
# 2 = Critical findings found (fail pipeline)
```

### 5. **Reporting**
- Usar nombres descriptivos para outputs
- Generar múltiples formatos (JSON para automatización, HTML para humanos)
- Archivar reportes con timestamps

---

## 🚀 Próximos Pasos

### Módulos en Desarrollo
- **SSRF Testing** (API7) - Server Side Request Forgery
- **Business Flows** (API6) - Unrestricted Access to Sensitive Business Flows
- **Security Misconfiguration** (API8)

### Características Futuras
- **Machine Learning**: Detección inteligente de patrones
- **Custom Rules**: Reglas personalizadas por industria
- **Integration APIs**: APIs para integración con SIEM/SOAR
- **Real-time Monitoring**: Monitoreo continuo de APIs

---

## 📞 Soporte

### Documentación Adicional
- **[Referencia Rápida](quick-reference.md)** - Comandos básicos y ejemplos
- **[Integración CI/CD](ci-cd-integration.md)** - Configuración para pipelines automatizados
- **[Guía de Troubleshooting](troubleshooting-guide.md)** - Solución de problemas comunes
- **[Configuraciones de Ejemplo](../config/examples/README.md)** - Ejemplos listos para usar

### Configuraciones de Ejemplo Disponibles
- **[BOLA Testing](../config/examples/bola_testing_config.yaml)** - API1: Broken Object Level Authorization
- **[Auth Testing](../config/examples/auth_testing_config.yaml)** - API2: Broken Authentication
- **[Property Testing](../config/examples/property_testing_config.yaml)** - API3: Broken Object Property Level Authorization
- **[Resource Testing](../config/resource_testing_example.yaml)** - API4: Unrestricted Resource Consumption
- **[Function Auth Testing](../config/examples/function_auth_testing_config.yaml)** - API5: Broken Function Level Authorization

### Reportar Issues
- **Troubleshooting:** Consulta primero la [Guía de Troubleshooting](troubleshooting-guide.md)
- **GitHub Issues:** [APILeak Issues](https://github.com/your-org/apileak/issues)
- **Documentación:** [APILeak Docs](https://docs.apileak.com)

---

*Esta documentación cubre la versión 0.1.0 de APILeak. Para actualizaciones, consulta el [CHANGELOG](../CHANGELOG.md).*