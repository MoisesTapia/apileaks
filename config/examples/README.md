# 📁 Configuraciones de Ejemplo - APILeak

Este directorio contiene configuraciones de ejemplo para diferentes casos de uso de APILeak.

> **Nota de deprecación:** `full` y `main` son alias ocultos y deprecados de `scan`. Usa `scan` en su lugar. Para ejecutar un único módulo OWASP en aislamiento, usa `apileaks owasp <key> --target URL` (por ejemplo, `full --modules bola` → `apileaks owasp bola`).

## 📋 Configuraciones Disponibles

### 🔐 BOLA Testing (API1)
**Archivo:** `bola_testing_config.yaml`
**Descripción:** Configuración específica para detectar vulnerabilidades de Broken Object Level Authorization.

```bash
# Uso
python apileaks.py scan --config config/examples/bola_testing_config.yaml --target https://api.example.com
```

**Características:**
- Múltiples contextos de autenticación (anonymous, user1, user2, admin)
- Rate limiting conservador (5 req/sec)
- Patrones de ID específicos (sequential, guid, uuid)
- Solo módulo BOLA habilitado

---

### 🔑 Authentication Testing (API2)
**Archivo:** `auth_testing_config.yaml`
**Descripción:** Configuración para probar vulnerabilidades de autenticación JWT.

```bash
# Uso
python apileaks.py scan --config config/examples/auth_testing_config.yaml --target https://api.example.com
```

**Características:**
- Testing de JWT con secretos débiles
- Pruebas de invalidación de logout
- Tokens válidos y expirados para comparación
- Wordlist personalizada para secretos JWT

---

### 📊 Property Level Authorization (API3)
**Archivo:** `property_testing_config.yaml`
**Descripción:** Configuración para detectar exposición excesiva de datos y mass assignment.

```bash
# Uso
python apileaks.py scan --config config/examples/property_testing_config.yaml --target https://api.example.com
```

**Características:**
- Lista extensa de campos sensibles
- Detección de mass assignment
- Múltiples niveles de privilegios
- Testing de propiedades de solo lectura

---

### ⚡ Resource Consumption (API4)
**Archivo:** `resource_testing_example.yaml`
**Descripción:** Configuración para probar límites de recursos y DoS.

```bash
# Uso
python apileaks.py scan --config config/resource_testing_example.yaml --target https://api.example.com
```

**Características:**
- Testing de rate limiting con burst de 100 requests
- Payloads grandes (1MB, 10MB, 100MB)
- JSON profundamente anidado
- Detección de patrones ReDoS

---

### 🛡️ Function Level Authorization (API5)
**Archivo:** `function_auth_testing_config.yaml`
**Descripción:** Configuración para detectar escalación de privilegios.

```bash
# Uso
python apileaks.py scan --config config/examples/function_auth_testing_config.yaml --target https://api.example.com
```

**Características:**
- Endpoints administrativos específicos
- Métodos HTTP peligrosos
- Múltiples niveles de privilegios
- Rate limiting muy bajo para endpoints sensibles

---

## 🚀 Casos de Uso por Industria

### E-commerce API
```bash
# Configuración recomendada para APIs de e-commerce
python apileaks.py scan \
  --config config/examples/bola_testing_config.yaml \
  --target https://api.shop.example.com \
  --modules bola,auth,property \
  --rate-limit 5
```

### Banking API
```bash
# Configuración para APIs bancarias (alta seguridad)
python apileaks.py scan \
  --config config/examples/function_auth_testing_config.yaml \
  --target https://api.bank.example.com \
  --modules bola,auth,function_auth \
  --rate-limit 1
```

### Social Media API
```bash
# Configuración para APIs de redes sociales
python apileaks.py scan \
  --config config/examples/property_testing_config.yaml \
  --target https://api.social.example.com \
  --modules bola,property,resource \
  --rate-limit 10
```

### Healthcare API
```bash
# Configuración para APIs de salud (datos sensibles)
python apileaks.py scan \
  --config config/examples/property_testing_config.yaml \
  --target https://api.health.example.com \
  --modules bola,auth,property \
  --rate-limit 2
```

---

## 🔧 Personalización de Configuraciones

### Modificar Tokens JWT

```yaml
# En cualquier configuración, actualizar los tokens:
authentication:
  contexts:
    - name: "user"
      type: "bearer"
      token: "TU_JWT_TOKEN_AQUI"  # ← Cambiar aquí
      privilege_level: 1
```

### Ajustar Rate Limiting

```yaml
# Para APIs más sensibles:
rate_limiting:
  requests_per_second: 1  # Muy conservador
  burst_size: 2

# Para APIs de desarrollo:
rate_limiting:
  requests_per_second: 20  # Más agresivo
  burst_size: 50
```

### Personalizar Campos Sensibles

```yaml
# En property_testing_config.yaml:
owasp_testing:
  property_testing:
    sensitive_fields:
      - "password"
      - "api_key"
      - "tu_campo_personalizado"  # ← Agregar campos específicos
      - "internal_id"
      - "private_data"
```

### Configurar Endpoints Administrativos

```yaml
# En function_auth_testing_config.yaml:
owasp_testing:
  function_auth_testing:
    admin_endpoints:
      - "/admin"
      - "/api/admin"
      - "/tu-endpoint-admin"  # ← Agregar endpoints específicos
      - "/internal/management"
```

---

## 📝 Crear Configuraciones Personalizadas

### Plantilla Básica

```yaml
# config/examples/mi_configuracion.yaml
target:
  base_url: "https://mi-api.example.com"
  timeout: 30
  verify_ssl: true

owasp_testing:
  enabled_modules: ["bola", "auth"]  # Módulos a ejecutar

authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "mi_jwt_token"
      privilege_level: 1

rate_limiting:
  requests_per_second: 5
  adaptive: true

reporting:
  formats: ["json", "html"]
  output_dir: "reports"
  output_filename: "mi_scan"
```

### Configuración Solo para Discovery

```yaml
# config/examples/discovery_only.yaml
target:
  base_url: "https://api.example.com"

# Solo fuzzing, sin módulos OWASP
owasp_testing:
  enabled_modules: []

fuzzing:
  endpoints:
    enabled: true
    wordlist: "wordlists/endpoints.txt"
    methods: ["GET", "POST"]
  parameters:
    enabled: true
  headers:
    enabled: false

rate_limiting:
  requests_per_second: 10
```

### Configuración para CI/CD

```yaml
# config/examples/ci_cd_config.yaml
target:
  base_url: "${API_ENDPOINT}"  # Variable de entorno
  timeout: 60

owasp_testing:
  enabled_modules: ["bola", "auth", "property"]

authentication:
  contexts:
    - name: "ci_user"
      type: "bearer"
      token: "${JWT_TOKEN}"  # Variable de entorno
      privilege_level: 1

rate_limiting:
  requests_per_second: 3  # Conservador para CI/CD
  respect_retry_after: true

reporting:
  formats: ["json"]  # Solo JSON para parsing automático
  output_dir: "ci_reports"
```

---

## 🔍 Testing de Configuraciones

### Validar Configuración

```bash
# Verificar sintaxis YAML
python -c "import yaml; print('✅ YAML válido' if yaml.safe_load(open('config/examples/mi_config.yaml')) else '❌ YAML inválido')"

# Test de conectividad
curl -I https://api.example.com

# Dry run (si estuviera disponible)
python apileaks.py scan --config config/examples/mi_config.yaml --target https://api.example.com --dry-run
```

### Debug de Configuración

```bash
# Ejecutar con logging detallado
python apileaks.py scan \
  --config config/examples/mi_config.yaml \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log

# Ver configuración cargada
grep -A 20 "Configuration loaded" debug.log
```

---

## 📚 Documentación Relacionada

- **[Guía Completa de Módulos OWASP](../../docs/owasp-modules-guide.md)** - Documentación detallada de todos los módulos
- **[Referencia Rápida](../../docs/quick-reference.md)** - Comandos y ejemplos básicos
- **[Integración CI/CD](../../docs/ci-cd-integration.md)** - Configuración para pipelines
- **[Troubleshooting](../../docs/troubleshooting-guide.md)** - Solución de problemas comunes

---

## 💡 Tips y Mejores Prácticas

### 1. **Empezar Simple**
```bash
# Comenzar con un módulo
python apileaks.py scan --config config/examples/bola_testing_config.yaml --target https://api.example.com
```

### 2. **Rate Limiting Progresivo**
```bash
# Empezar conservador, luego aumentar si es necesario
--rate-limit 1  # Primer intento
--rate-limit 5  # Si no hay problemas
--rate-limit 10 # Para APIs robustas
```

### 3. **Testing por Módulos**
```bash
# Probar módulos individualmente primero
for module in bola auth property; do
  python apileaks.py owasp $module --target https://api.example.com
done
```

### 4. **Backup de Configuraciones**
```bash
# Versionar configuraciones importantes
cp config/examples/production_config.yaml config/examples/production_config_backup_$(date +%Y%m%d).yaml
```

### 5. **Variables de Entorno**
```bash
# Usar variables para datos sensibles
export API_ENDPOINT="https://api.example.com"
export JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
python apileaks.py scan --config config/examples/ci_cd_config.yaml
```

---

*Estas configuraciones están diseñadas como punto de partida. Personalízalas según las necesidades específicas de tu API y entorno.*