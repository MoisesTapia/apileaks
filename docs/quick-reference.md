# 🚀 APILeak - Referencia Rápida de Módulos OWASP

## Comandos Básicos

```bash
# Escaneo completo (todos los módulos)
python apileaks.py full --target https://api.example.com

# Módulos específicos
python apileaks.py full --target https://api.example.com --modules bola,auth,resource

# Con autenticación JWT
python apileaks.py full --target https://api.example.com --jwt YOUR_JWT_TOKEN

# Con rate limiting personalizado
python apileaks.py full --target https://api.example.com --rate-limit 5
```

## Módulos Disponibles

| Código | Módulo | OWASP | Descripción |
|--------|--------|-------|-------------|
| `bola` | BOLA Testing | API1 | Acceso no autorizado a objetos |
| `auth` | Authentication | API2 | Fallas en autenticación JWT |
| `property` | Property Level Auth | API3 | Exposición excesiva de datos |
| `resource` | Resource Consumption | API4 | Rate limiting y DoS |
| `function_auth` | Function Level Auth | API5 | Escalación de privilegios |

## Ejemplos por Tipo de API

### API de E-commerce
```bash
python apileaks.py full --target https://api.shop.com \
  --modules bola,auth,property \
  --jwt eyJ0eXAi... \
  --rate-limit 5
```

### API Bancaria
```bash
python apileaks.py full --target https://api.bank.com \
  --modules bola,auth,function_auth \
  --jwt eyJ0eXAi... \
  --rate-limit 1
```

### API de Redes Sociales
```bash
python apileaks.py full --target https://api.social.com \
  --modules bola,property,resource \
  --jwt eyJ0eXAi... \
  --rate-limit 10
```

## Configuración Rápida YAML

```yaml
# config/quick_config.yaml
target:
  base_url: "https://api.example.com"

owasp_testing:
  enabled_modules: ["bola", "auth", "property", "resource"]

authentication:
  contexts:
    - name: "user"
      type: "bearer"
      token: "YOUR_JWT_TOKEN"
      privilege_level: 1

rate_limiting:
  requests_per_second: 10
```

```bash
python apileaks.py full --config config/quick_config.yaml
```

## Variables de Entorno

```bash
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,resource"
export APILEAK_JWT_TOKEN="eyJ0eXAi..."
export APILEAK_RATE_LIMIT="5"

python apileaks.py full
```

## Interpretación de Resultados

### Exit Codes
- `0` - Sin vulnerabilidades críticas/altas
- `1` - Vulnerabilidades altas encontradas
- `2` - Vulnerabilidades críticas encontradas

### Severidades
- **CRITICAL** - Corrección inmediata
- **HIGH** - Corrección en 24-48h
- **MEDIUM** - Corrección en 1-2 semanas
- **LOW** - Próximo ciclo de desarrollo

## Troubleshooting Rápido

### Rate Limiting del Servidor
```bash
python apileaks.py full --target URL --rate-limit 1
```

### Timeouts
```bash
python apileaks.py full --target URL --log-level DEBUG
```

### JWT Issues
```bash
python apileaks.py jwt-decode YOUR_JWT_TOKEN
```

## CI/CD Integration

```bash
#!/bin/bash
python apileaks.py full \
  --target "${API_ENDPOINT}" \
  --jwt "${JWT_TOKEN}" \
  --modules bola,auth,property \
  --rate-limit 3 \
  --log-level ERROR

if [ $? -eq 2 ]; then
    echo "❌ Critical vulnerabilities found!"
    exit 1
fi
```

---

Para documentación completa, ver: [docs/owasp-modules-guide.md](owasp-modules-guide.md)