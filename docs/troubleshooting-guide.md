# 🔧 Guía de Troubleshooting - APILeak

Esta guía cubre los problemas más comunes al usar APILeak y sus soluciones.

## 📋 Tabla de Contenidos

1. [Problemas de Conexión](#problemas-de-conexión)
2. [Problemas de Autenticación](#problemas-de-autenticación)
3. [Rate Limiting y Timeouts](#rate-limiting-y-timeouts)
4. [Problemas de Configuración](#problemas-de-configuración)
5. [Problemas de Wordlists](#problemas-de-wordlists)
6. [Problemas de Reportes](#problemas-de-reportes)
7. [Problemas de Módulos OWASP](#problemas-de-módulos-owasp)
8. [Problemas de Performance](#problemas-de-performance)
9. [Logs y Debugging](#logs-y-debugging)

---

## 🌐 Problemas de Conexión

### Error: Connection timeout

**Síntomas:**
```
Error: Connection timeout
requests.exceptions.ConnectTimeout: HTTPSConnectionPool(host='api.example.com', port=443)
```

**Causas Comunes:**
- API no disponible o lenta
- Firewall bloqueando conexiones
- Proxy o VPN interfiriendo
- Timeout muy bajo

**Soluciones:**

```bash
# 1. Aumentar timeout
python apileaks.py full --target https://api.example.com --config config/high_timeout.yaml
```

```yaml
# config/high_timeout.yaml
target:
  timeout: 60  # Aumentar a 60 segundos
  verify_ssl: true
```

```bash
# 2. Verificar conectividad básica
curl -I https://api.example.com
ping api.example.com

# 3. Probar con rate limiting muy bajo
python apileaks.py full --target https://api.example.com --rate-limit 1
```

### Error: SSL Certificate verification failed

**Síntomas:**
```
requests.exceptions.SSLError: HTTPSConnectionPool(host='api.example.com', port=443): 
Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError))
```

**Soluciones:**

```yaml
# config/no_ssl_verify.yaml (solo para testing)
target:
  verify_ssl: false  # ⚠️ Solo usar en entornos de desarrollo
```

```bash
# Mejor solución: Agregar certificado al trust store
python apileaks.py full --target https://api.example.com --config config/no_ssl_verify.yaml
```

### Error: Name resolution failed

**Síntomas:**
```
requests.exceptions.ConnectionError: Failed to establish a new connection: 
[Errno -2] Name or service not known
```

**Soluciones:**

```bash
# 1. Verificar DNS
nslookup api.example.com
dig api.example.com

# 2. Usar IP directa si es necesario
python apileaks.py full --target https://192.168.1.100

# 3. Verificar /etc/hosts (Linux/Mac)
cat /etc/hosts
```

---

## 🔐 Problemas de Autenticación

### Error: JWT token validation failed

**Síntomas:**
```
Warning: JWT token validation failed
Invalid JWT token format
```

**Soluciones:**

```bash
# 1. Verificar formato del token
python apileaks.py jwt-decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# 2. Generar token de prueba
python apileaks.py jwt-encode '{"sub":"user123","role":"user"}' --secret mysecret

# 3. Verificar que el token no esté expirado
python apileaks.py jwt-decode $JWT_TOKEN | grep exp
```

### Error: 401 Unauthorized en todos los endpoints

**Síntomas:**
```
All endpoints returning 401 Unauthorized
Authentication context 'anonymous' failed
```

**Soluciones:**

```bash
# 1. Verificar token manualmente
curl -H "Authorization: Bearer $JWT_TOKEN" https://api.example.com/

# 2. Probar sin autenticación primero
python apileaks.py full --target https://api.example.com --modules bola

# 3. Usar configuración con múltiples contextos
```

```yaml
# config/multi_auth.yaml
authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "tu_jwt_token_aqui"
      privilege_level: 1
```

### Error: Token expired

**Síntomas:**
```
JWT token expired
exp claim validation failed
```

**Soluciones:**

```bash
# 1. Generar nuevo token
# Contactar al equipo de desarrollo para obtener un token válido

# 2. Usar token con expiración larga para testing
python apileaks.py jwt-encode '{"sub":"user123","exp":2000000000}' --secret mysecret

# 3. Configurar renovación automática (si la API lo soporta)
```

---

## ⚡ Rate Limiting y Timeouts

### Error: Too many requests (429)

**Síntomas:**
```
HTTP 429: Too Many Requests
Rate limit exceeded
```

**Soluciones:**

```bash
# 1. Reducir rate limiting drásticamente
python apileaks.py full --target https://api.example.com --rate-limit 1

# 2. Usar modo adaptativo (por defecto)
python apileaks.py full --target https://api.example.com --modules bola
```

```yaml
# config/conservative_rate.yaml
rate_limiting:
  requests_per_second: 1
  burst_size: 2
  adaptive: true
  respect_retry_after: true
  backoff_factor: 3.0  # Backoff más agresivo
```

### Error: Request timeout

**Síntomas:**
```
requests.exceptions.ReadTimeout: HTTPSConnectionPool read timed out
```

**Soluciones:**

```yaml
# config/extended_timeout.yaml
target:
  timeout: 120  # 2 minutos

rate_limiting:
  requests_per_second: 2  # Más lento pero más confiable
```

### Error: Server overloaded

**Síntomas:**
```
HTTP 503: Service Unavailable
Server temporarily overloaded
```

**Soluciones:**

```bash
# 1. Esperar y reintentar
sleep 300  # 5 minutos
python apileaks.py full --target https://api.example.com --rate-limit 1

# 2. Ejecutar módulos por separado
python apileaks.py full --target https://api.example.com --modules bola --rate-limit 1
python apileaks.py full --target https://api.example.com --modules auth --rate-limit 1
```

---

## ⚙️ Problemas de Configuración

### Error: Configuration validation failed

**Síntomas:**
```
Configuration validation failed
Error: target.base_url is required
```

**Soluciones:**

```bash
# 1. Verificar configuración YAML
python -c "import yaml; yaml.safe_load(open('config/my_config.yaml'))"

# 2. Usar configuración mínima válida
```

```yaml
# config/minimal_valid.yaml
target:
  base_url: "https://api.example.com"
  timeout: 30

owasp_testing:
  enabled_modules: ["bola"]

rate_limiting:
  requests_per_second: 5
```

### Error: Invalid YAML format

**Síntomas:**
```
yaml.scanner.ScannerError: while scanning for the next token
found character '\t' that cannot start any token
```

**Soluciones:**

```bash
# 1. Verificar sintaxis YAML
yamllint config/my_config.yaml

# 2. Convertir tabs a espacios
sed -i 's/\t/  /g' config/my_config.yaml

# 3. Usar editor con validación YAML
```

### Error: Module not found

**Síntomas:**
```
Error: Unknown module 'invalid_module'
Available modules: bola, auth, property, resource, function_auth
```

**Soluciones:**

```bash
# 1. Verificar módulos disponibles
python apileaks.py full --help

# 2. Usar solo módulos válidos
python apileaks.py full --target https://api.example.com --modules bola,auth,property

# 3. Verificar ortografía
# Correcto: bola, auth, property, resource, function_auth
# Incorrecto: BOLA, authentication, properties
```

---

## 📝 Problemas de Wordlists

### Error: Wordlist file not found

**Síntomas:**
```
Error: Wordlist file not found: wordlists/custom.txt
FileNotFoundError: [Errno 2] No such file or directory
```

**Soluciones:**

```bash
# 1. Verificar que el archivo existe
ls -la wordlists/
find . -name "*.txt" -path "*/wordlists/*"

# 2. Usar wordlists por defecto
python apileaks.py dir --target https://api.example.com  # Usa wordlists/endpoints.txt

# 3. Crear wordlist personalizada
echo -e "/api\n/admin\n/users" > wordlists/custom.txt
```

### Error: Empty wordlist

**Síntomas:**
```
Warning: Wordlist is empty or contains no valid entries
No endpoints to test
```

**Soluciones:**

```bash
# 1. Verificar contenido del wordlist
head -10 wordlists/endpoints.txt
wc -l wordlists/endpoints.txt

# 2. Filtrar líneas vacías y comentarios
grep -v '^#' wordlists/endpoints.txt | grep -v '^$' > wordlists/clean_endpoints.txt

# 3. Usar wordlist conocido
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt -O wordlists/api-endpoints.txt
```

### Error: Wordlist encoding issues

**Síntomas:**
```
UnicodeDecodeError: 'utf-8' codec can't decode byte
```

**Soluciones:**

```bash
# 1. Convertir a UTF-8
iconv -f ISO-8859-1 -t UTF-8 wordlists/original.txt > wordlists/utf8.txt

# 2. Verificar encoding
file wordlists/endpoints.txt
chardet wordlists/endpoints.txt

# 3. Limpiar caracteres problemáticos
sed 's/[^[:print:]]//g' wordlists/original.txt > wordlists/clean.txt
```

---

## 📊 Problemas de Reportes

### Error: Permission denied writing reports

**Síntomas:**
```
PermissionError: [Errno 13] Permission denied: 'reports/scan.json'
```

**Soluciones:**

```bash
# 1. Verificar permisos del directorio
ls -la reports/
chmod 755 reports/

# 2. Crear directorio si no existe
mkdir -p reports
chmod 755 reports

# 3. Usar directorio alternativo
python apileaks.py full --target https://api.example.com --output /tmp/apileak-reports
```

### Error: Disk space full

**Síntomas:**
```
OSError: [Errno 28] No space left on device
```

**Soluciones:**

```bash
# 1. Verificar espacio disponible
df -h

# 2. Limpiar reportes antiguos
find reports/ -name "*.json" -mtime +7 -delete

# 3. Usar directorio con más espacio
python apileaks.py full --target https://api.example.com --output /var/tmp/apileak-reports
```

### Error: Invalid JSON in report

**Síntomas:**
```
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

**Soluciones:**

```bash
# 1. Verificar si el archivo está completo
tail reports/scan.json

# 2. Verificar si el scan terminó correctamente
grep -i "error\|exception" apileak.log

# 3. Re-ejecutar el scan
python apileaks.py full --target https://api.example.com --log-level DEBUG
```

---

## 🛡️ Problemas de Módulos OWASP

### Error: BOLA module failed

**Síntomas:**
```
BOLA testing failed: No valid endpoints found for testing
```

**Soluciones:**

```bash
# 1. Ejecutar discovery primero
python apileaks.py dir --target https://api.example.com

# 2. Verificar que hay endpoints válidos
curl https://api.example.com/users/1
curl https://api.example.com/api/v1/users/1

# 3. Usar configuración específica para BOLA
python apileaks.py full --config config/examples/bola_testing_config.yaml --target https://api.example.com
```

### Error: Auth module - JWT secrets not found

**Síntomas:**
```
Warning: JWT secrets wordlist not found: wordlists/jwt_secrets.txt
```

**Soluciones:**

```bash
# 1. Crear wordlist de secretos JWT
cat > wordlists/jwt_secrets.txt << EOF
secret
password
123456
admin
jwt_secret
your_secret_key
EOF

# 2. Descargar wordlist común
wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list -O wordlists/jwt_secrets.txt

# 3. Deshabilitar testing de secretos débiles
```

```yaml
# config/auth_no_secrets.yaml
owasp_testing:
  auth_testing:
    enabled: true
    jwt_testing: true
    weak_secrets_wordlist: ""  # Deshabilitar
```

### Error: Resource module - Large payload failed

**Síntomas:**
```
Resource consumption test failed: Payload too large
MemoryError: Unable to allocate memory for payload
```

**Soluciones:**

```yaml
# config/smaller_payloads.yaml
owasp_testing:
  resource_testing:
    enabled: true
    large_payload_sizes: [1024, 10240, 102400]  # 1KB, 10KB, 100KB en lugar de MB
```

```bash
# Ejecutar con límites de memoria
ulimit -v 1000000  # Limitar memoria virtual
python apileaks.py full --target https://api.example.com --modules resource
```

---

## 🚀 Problemas de Performance

### Error: Scan taking too long

**Síntomas:**
```
Scan has been running for over 2 hours
No progress visible
```

**Soluciones:**

```bash
# 1. Usar módulos específicos
python apileaks.py full --target https://api.example.com --modules bola,auth

# 2. Reducir scope
python apileaks.py dir --target https://api.example.com --wordlist wordlists/small_endpoints.txt

# 3. Aumentar rate limiting si el servidor lo permite
python apileaks.py full --target https://api.example.com --rate-limit 20
```

### Error: High memory usage

**Síntomas:**
```
Process killed (OOM - Out of Memory)
Memory usage exceeding system limits
```

**Soluciones:**

```bash
# 1. Limitar memoria del proceso
ulimit -v 2000000  # 2GB virtual memory limit

# 2. Ejecutar módulos por separado
for module in bola auth property; do
  python apileaks.py full --target https://api.example.com --modules $module
done

# 3. Usar configuración con menos concurrencia
```

```yaml
# config/low_memory.yaml
rate_limiting:
  requests_per_second: 2  # Menos concurrencia

owasp_testing:
  resource_testing:
    large_payload_sizes: [1024]  # Solo payloads pequeños
```

### Error: Too many open files

**Síntomas:**
```
OSError: [Errno 24] Too many open files
```

**Soluciones:**

```bash
# 1. Aumentar límite de archivos abiertos
ulimit -n 4096

# 2. Verificar límites actuales
ulimit -a

# 3. Configurar límites permanentes (Linux)
echo "* soft nofile 4096" >> /etc/security/limits.conf
echo "* hard nofile 8192" >> /etc/security/limits.conf
```

---

## 🔍 Logs y Debugging

### Habilitar Logging Detallado

```bash
# Logging completo
python apileaks.py full --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug.log \
  --json-logs

# Ver logs en tiempo real
tail -f debug.log

# Filtrar logs por módulo
grep "bola" debug.log
grep "ERROR" debug.log
```

### Debugging de Requests HTTP

```bash
# Habilitar logging de requests
export PYTHONPATH=$PYTHONPATH:.
python -c "
import logging
import http.client as http_client
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger('requests.packages.urllib3')
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
" && python apileaks.py full --target https://api.example.com --modules bola
```

### Debugging de Configuración

```python
# debug_config.py
import yaml
from core import ConfigurationManager

# Cargar y validar configuración
config_manager = ConfigurationManager()
config = config_manager.load_config('config/my_config.yaml')

# Mostrar configuración cargada
print("Configuración cargada:")
print(yaml.dump(config.__dict__, default_flow_style=False))

# Validar configuración
errors = config_manager.validate_configuration()
if errors:
    print("Errores de validación:")
    for error in errors:
        print(f"  - {error}")
else:
    print("✅ Configuración válida")
```

### Debugging de Módulos OWASP

```bash
# Test individual de módulos
python -c "
from modules.owasp import BOLATestingModule
from core import APILeakCore
import asyncio

async def test_bola():
    # Configuración mínima para testing
    config = type('Config', (), {
        'target': type('Target', (), {'base_url': 'https://api.example.com'})(),
        'authentication': type('Auth', (), {'contexts': []})(),
        'rate_limiting': type('Rate', (), {'requests_per_second': 5})()
    })()
    
    module = BOLATestingModule()
    print('BOLA module initialized successfully')

asyncio.run(test_bola())
"
```

---

## 🆘 Obtener Ayuda

### Información del Sistema

```bash
# Información de versión
python apileaks.py --version

# Información del sistema
python --version
pip list | grep -E "(requests|aiohttp|click)"

# Información de red
curl -I https://httpbin.org/get
```

### Reportar Issues

Cuando reportes un issue, incluye:

1. **Comando ejecutado:**
```bash
python apileaks.py full --target https://api.example.com --modules bola --log-level DEBUG
```

2. **Configuración utilizada:**
```yaml
# config/my_config.yaml
target:
  base_url: "https://api.example.com"
# ... resto de la configuración
```

3. **Logs de error:**
```
ERROR: Connection timeout
Traceback (most recent call last):
  File "apileaks.py", line 123, in main
# ... stack trace completo
```

4. **Información del entorno:**
```bash
# Sistema operativo
uname -a

# Versión de Python
python --version

# Dependencias
pip freeze
```

### Recursos Adicionales

- **Documentación:** [docs/owasp-modules-guide.md](owasp-modules-guide.md)
- **Ejemplos:** [config/examples/](../config/examples/)
- **Issues:** GitHub Issues del proyecto
- **Logs:** Siempre usar `--log-level DEBUG` para troubleshooting

---

*Esta guía cubre los problemas más comunes. Si encuentras un issue no documentado aquí, por favor repórtalo para ayudar a mejorar esta guía.*