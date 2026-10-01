# APILeak — Auditoría de Calidad de Código / Technical Debt

**Fecha:** 2026-09-30
**Alcance:** código de producción de `apileaks` (excluye `venv/`, `tests/`, `.hypothesis/`)
**Versión auditada:** 0.3.0

---

## Estado de remediación (actualizado 2026-09-30)

| Issue | Estado |
|---|---|
| #1 Funciones duplicadas en `apileaks.py` (9 módulo-nivel) | ✅ Resueltas — 871 líneas de código muerto eliminadas |
| Duplicado adicional `_normalise_catalogue` en `utils/wordlist_manager.py` | ✅ Resuelto (stub muerto eliminado) |
| #2 Gate de CI (`ruff`) en rojo (2427 errores) | ✅ **Verde** — `ruff check` y `ruff format --check` pasan |
| #4 Imports duplicados/muertos (F401/F811) | ✅ Resueltos |
| #5 `except Exception` que silencian con `pass` | ✅ Resuelto — los 8 catches amplios se acotaron a excepciones específicas (+ log debug donde aplica) |
| XXE latente en parseo XML (import_sources + ci-cd) | ✅ Resuelto — `defusedxml` (verificado: bloquea entidades externas) |
| #3 Monolito del entrypoint / funciones > 200 líneas | 🔄 En progreso — 3 extracciones a `cli/` (−~590 LOC); patrón seguro establecido, resto incremental |
| #8 `print()` en producción (33) | ✅ Resuelto — 27 migrados a `click.echo`; 6 en el healthcheck standalone se conservan a propósito |
| #9 Uso extendido de `Any` (206) | ✅ Evaluado — mayormente legítimo (JSON/fuzzing/interfaces desacopladas); sin acción, `mypy` no está enforced |
| #6-#7 (tipado legacy, formato) | ✅ Resueltos vía ruff |

**Verificación:** suite completa en verde (2332 passed, 5 skipped, 0 failed) antes y después de los cambios. Único test excluido: `tests/test_aws_security_hub.py` (requiere `boto3`, dependencia no declarada en `requirements.txt`).

> Nota: `ruff` destapó un bug latente de orden de imports en `utils/import_sources.py` — `ET` resolvía a `xml.etree.ElementTree` (stdlib) en vez de `defusedxml`, dejando el parseo de XML importado sin protección XXE. Corregido: ahora `defusedxml` hace el parseo y stdlib se usa solo para la anotación de tipo `Element`.

---

## Veredicto

**Estado inicial (auditoría):** parcialmente mantenible. Bases sólidas (arquitectura modular por paquetes, ~2337 tests, tipado presente, 0 `TODO/FIXME`, 0 `except:` desnudos) pero con deuda técnica significativa: gate de CI en rojo (2427 errores de `ruff`), monolito `apileaks.py` con código muerto duplicado y divergente, y un XXE latente en el parseo de XML.

**Estado tras remediación:** sustancialmente más mantenible. El gate de CI está **verde**, se eliminó el código muerto duplicado, se acotó el manejo de errores silencioso y se reparó el XXE. Queda como principal deuda estructural pendiente la **descomposición del monolito `apileaks.py`** (refactor mayor, recomendado por separado).

Conclusión: el núcleo funcional está saneado y el proyecto pasa su propio gate de calidad; la única pieza que impide calificarlo de "plenamente mantenible" es el tamaño del entrypoint, que es un refactor arquitectónico a planificar aparte.

---

## Métricas generales (antes → después)

| Métrica | Antes | Después |
|---|---|---|
| Errores de `ruff` (scope del CI) | 2427 | **0** ✅ |
| `ruff format --check` | falla | **pasa** ✅ |
| Funciones duplicadas a nivel de módulo | 10 (9 en `apileaks.py` + 1 en `wordlist_manager.py`) | **0** ✅ |
| Código muerto duplicado eliminado | — | ~871 líneas |
| `except Exception: pass` (silenciosos amplios) | 8 | **0** ✅ |
| XXE en parseo de XML no confiable | presente | **mitigado** (`defusedxml`) ✅ |
| Imports duplicados/muertos (F401/F811) | 151 | **0** ✅ |
| LOC de producción (sin venv/tests) | ~58 600 | ~59 400¹ |
| Archivo más grande | `apileaks.py` 8334 LOC | `apileaks.py` 8925 LOC¹ |
| Funciones > 200 líneas | 13 | 14¹ |
| Suite de tests | 2337 colectados | **2332 passed, 5 skipped, 0 failed** ✅ |

¹ El aumento de LOC/funciones largas se debe al reformateo de `ruff format` (un argumento por línea en llamadas largas, literales expandidos), no a lógica nueva: el código muerto sí se eliminó (0 duplicados verificado por AST). El tamaño del monolito sigue siendo deuda pendiente.

---

## Issues por severidad

### 🔴 Alta

#### 1. Funciones duplicadas (y divergentes) en `apileaks.py` — ✅ RESUELTO
Hay **12 funciones definidas dos veces** en el mismo archivo; Python se queda con la última definición, dejando la primera como **código muerto**:

```
_brute_spec_async, _echo_fuzzing_stats, _load_spec_brute_wordlist,
_looks_like_spec, _probe, _run, _run_dir_core, _run_dir_multi_target,
_run_par_multi_target, _run_scan_multi_target, _run_spec_brute, _scan_one
```

Lo más grave: las dos copias de `_run_dir_core` (líneas **3376** y **3853**, ~284 líneas cada una) **ya no son idénticas** (difieren en `zip(..., strict=False)`). Esto significa que un fix se aplicó a una copia y no a la otra. Riesgo real de corregir la versión equivocada.

**Acción:** eliminar las copias muertas, consolidar en una sola definición y verificar con tests.

> **Resuelto:** del listado inicial de 12 nombres, el análisis por *scope* reveló que `_run`, `_probe` y `_scan_one` **no** eran duplicados reales (helpers anidados en funciones distintas o dentro de padres duplicados). Los **9 duplicados reales a nivel de módulo** se consolidaron conservando la copia viva (la segunda, que Python ejecuta) y eliminando la muerta — en todos los casos la copia viva era igual o superior (p. ej. `_run_spec_brute` tenía 47 líneas extra con el `return` y el resumen que a la muerta le faltaban). Se detectó y eliminó además un 10º duplicado fuera de `apileaks.py` (`_normalise_catalogue` en `utils/wordlist_manager.py`, cuya primera copia era un stub vacío). Verificado por AST (0 duplicados) y con la suite completa.

#### 2. Gate de calidad de CI fallando — ✅ RESUELTO
`.github/workflows/code-quality.yml` ejecuta `ruff check .` y `ruff format --check` con exclusiones `venv,tests,.hypothesis,ci-cd,examples`. Con **2427 errores**, ese job está (o debería estar) en rojo en cada push a `main`. Un gate que no pasa pierde su valor como control de calidad.

**Acción:** aplicar `ruff check . --fix` (2137 autofijables) y revisar manualmente el resto, luego mantener el gate verde.

> **Resuelto:** `ruff check . --fix` + `ruff format .` + ~20 arreglos manuales → **0 errores**; `ruff check` y `ruff format --check` pasan con el scope exacto del CI.

#### S1. XXE latente en el parseo de XML no confiable — ✅ RESUELTO (seguridad)
`utils/import_sources.py` parsea exports XML de Burp Suite **subidos por el usuario** (entrada no confiable). Por un orden de imports accidental, el alias `ET` resolvía a `xml.etree.ElementTree` (stdlib) en vez de `defusedxml`, dejando el parseo expuesto a **XXE / expansión de entidades externas** (p. ej. exfiltración de `file:///etc/passwd` o SSRF vía entidades). El import de `defusedxml` estaba presente pero quedaba sombreado y sin uso.

**Acción / Resuelto:** el parseo ahora usa `defusedxml.ElementTree` (bloquea DTD y entidades externas por defecto); `xml.etree.ElementTree` se conserva únicamente para la anotación de tipo `Element`. Se endureció también `ci-cd/scripts/report_generator.py` (parseo de JUnit XML) con `defusedxml` como defensa en profundidad. `utils/report_generator.py` solo serializa XML generado por nosotros (no es vector) y queda igual. **Verificado**: un payload con entidad externa es rechazado con `EntitiesForbidden`.

### 🟠 Media

#### 3. Monolito del entrypoint — 🔄 EN PROGRESO (refactor incremental)

> **Avance (decomposición segura, verificada test-a-test):** se estableció un patrón de extracción seguro — mover helpers a módulos de `cli/` y re-importarlos en `apileaks.py` para preservar la superficie pública (incluidos los targets de monkeypatch de los tests). Restricción clave respetada: los tests parchean muchos símbolos vía el namespace `apileaks`, así que solo se extraen funciones **no parcheadas** y que **no llaman** a otros locales de `apileaks`, re-importando por nombre.
>
> Incrementos aplicados (cada uno con la suite completa en verde, 2332 passed):
> 1. `cli/parsers.py` — 13 helpers puros de parseo/validación de entrada CLI.
> 2. `cli/output.py` — 7 helpers de salida/render de consola (banner, resúmenes, listados).
> 3. `cli/shared_options.py` — 5 *option groups* de Click reubicados junto a sus `_validate_*`.
>
> **Resultado:** `apileaks.py` 8925 → ~8331 LOC. **Pendiente:** continuar extrayendo clusters más acoplados (builders de engine JWT, resolución de módulos OWASP, helpers de spec-schema) y partir las funciones de comando > 200 líneas. Es trabajo incremental; mantener la regla de "no extraer símbolos parcheados sin re-exportarlos" (un fallo de este tipo lo detectó la suite y se corrigió re-exportando los `_validate_*`).

#### 3-bis. (original) Monolito del entrypoint
`apileaks.py` concentra 8334 líneas, 127 funciones y una sola clase. Varias funciones son enormes:

| Función | Líneas |
|---|---|
| `report_generator.py:generate_html_report` | 468 |
| `apileaks.py:_run_dir_triage` | 386 |
| `apileaks.py:par` | 376 |
| `apileaks.py:jwt_attack_test` | 327 |
| `apileaks.py:_build_and_run` | 324 |
| `apileaks.py:create_enhanced_config` | 299 |

84 funciones superan las 100 líneas. Funciones de este tamaño son difíciles de testear de forma aislada y de razonar.

**Acción:** extraer la lógica de los comandos CLI a los paquetes `cli/`, `core/` y `modules/` (que ya existen), dejando `apileaks.py` como capa delgada de orquestación.

#### 4. Imports duplicados y muertos — ✅ RESUELTO
- **F811** (redefinición de import sin usar): 45 casos. Bloques de import enteros aparecen repetidos — por ejemplo en `apileaks.py` (`import_schema`, `import_postman_schema` listados dos veces) y en `modules/owasp/function_level_auth.py` (todo el bloque `json, re, uuid, dataclass, ...` re-importado en las líneas 43-49). Son artefactos de merge.
- **F401** (imports sin usar): 106 casos. Peores ofensores: `modules/owasp/auth_testing.py` (10), `utils/replay.py` (7), `modules/owasp/bola_testing.py` (7).

#### 5. Manejo de errores demasiado amplio — ✅ RESUELTO (los silenciosos)
333 bloques `except Exception`, de los cuales 8 silencian con `pass` (`except Exception: pass`). Capturar `Exception` de forma genérica oculta fallos reales y complica el debugging. (Positivo: no hay `except:` desnudos.)

**Acción:** acotar a excepciones específicas donde sea posible y, como mínimo, loguear antes de continuar.

> **Resuelto:** los **8** `except Exception: pass` amplios se acotaron a excepciones específicas (`jwt_utils` → `(ValueError, TypeError, UnsupportedAlgorithm)`; `apileaks.py` → `OSError` / `(ValueError, TypeError, OverflowError, OSError)` + log debug; `payload_generator` → `(ValueError, TypeError, AttributeError)`). Los ~323 `except Exception` restantes **sí** manejan el error (logean o retornan) y no se tocaron. Los `except` con excepción específica + `pass` (p. ej. `except json.JSONDecodeError: pass`) son un patrón best-effort legítimo y se dejaron como están.

### 🟡 Baja

#### 6. API de tipado obsoleta (pre-PEP 585/604) — ✅ RESUELTO (vía `ruff`)
- **UP006** (622): `Dict`/`List` de `typing` en vez de `dict`/`list`.
- **UP045** (208) / **UP007** (3): `Optional[X]`/`Union` en vez de `X | None`.
- **UP035** (126): imports deprecados de `typing`.

El proyecto declara `requires-python = ">=3.11"`, así que la sintaxis moderna está disponible. Mayormente autofijable.

#### 7. Ruido de formato — ✅ RESUELTO (vía `ruff format`)
- **W293** (1122): líneas en blanco con espacios.
- **W291/W292** (92): espacios finales / falta newline al final del archivo.
- **I001** (44): imports sin ordenar.

Todo autofijable con `ruff` + `ruff format`.

#### 8. `print()` en producción — ⏳ PENDIENTE (bajo impacto)
33 `print()` fuera de `examples/`/`ci-cd/`. El proyecto usa `structlog`; conviene centralizar la salida en el logger.

#### 9. Uso extendido de `Any` — ✅ EVALUADO (sin acción: mayormente legítimo)
~206 apariciones de `Any`/`dict[str, Any]` en firmas.

> **Evaluado:** tras revisar la distribución, el uso de `Any` aquí es **mayoritariamente legítimo y deliberado**, no deuda:
> - `dict[str, Any]` (147): payloads JSON / metadata de findings / config genuinamente heterogéneos.
> - Valores de inyección/fuzzing (`candidate_id`, `test_value`, `_generate_*_value() -> Any`, `_parse_json_body() -> Any`): BOLA y property-fuzzing inyectan y retornan valores de *cualquier* tipo (str/int/bool/uuid); `Any` es la anotación correcta.
> - Interfaces desacopladas (`core_engine: Any`, `response: Any`, `get_fuzzing_stats() -> Any`): laxas a propósito para evitar imports circulares y permitir acceso defensivo vía `getattr`.
>
> Además **`mypy` no está configurado ni se ejecuta en CI** (solo figura como dependencia de dev; no hay sección `[tool.mypy]`), por lo que un cambio masivo de anotaciones sería *churn* alto, de valor nulo en runtime y **sin red de seguridad** para detectar errores, con riesgo de introducir imports circulares. **Decisión:** no se tocan. Si se quiere seguridad de tipos real, el verdadero *lever* es configurar `mypy` + un baseline y endurecer incrementalmente — una iniciativa aparte y acotada.

---

## Fortalezas (lo que sí ayuda a mantener)

- Arquitectura modular clara: `cli/`, `core/`, `modules/{owasp,advanced,fuzzing}/`, `utils/`.
- Suite de tests amplia: 197 archivos, 2337 tests.
- Configuración de tooling presente: `ruff`, `black`, `mypy`, `pytest` en `pyproject.toml`, con CI por workflow.
- 0 `TODO/FIXME/HACK` y 0 `except:` desnudos.
- Documentación extensa en `docs/`.

---

## Plan de remediación (estado)

1. ✅ **Eliminar las funciones duplicadas de `apileaks.py`** y verificar con la suite (9 reales consolidadas + 1 en `wordlist_manager.py`).
2. ✅ **`ruff check . --fix` + `ruff format .`** → CI en verde (0 errores).
3. ✅ Resolver manualmente F401/F811 restantes y los imports duplicados.
4. ✅ Acotar los `except Exception: pass` (8 casos) y añadir logging donde aplica.
5. ✅ **(Seguridad)** Reparar el XXE en el parseo de XML no confiable (`defusedxml`).
6. 🔄 **En progreso:** descomponer `apileaks.py` moviendo lógica a `cli/` (3 incrementos hechos, −~590 LOC, suite verde). Resto incremental: clusters acoplados (JWT engine, resolución OWASP, spec-schema) y funciones de comando > 200 líneas.
7. ✅ Migrar los `print()` de producción a `click.echo` (27; el healthcheck standalone conserva `print`).
8. ✅ Evaluar el uso de `Any` → mayormente legítimo; sin acción (ver #9). Pendiente real opcional: configurar `mypy` + baseline si se quiere seguridad de tipos.

> Nota: los puntos 1-5, 7 y 8 ya están aplicados/evaluados (bajo riesgo, suite verde). El punto 6 (descomponer el monolito) es el único refactor mayor pendiente; conviene hacerlo con la suite de tests delante.
