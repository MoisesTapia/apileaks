# APILeak — Auditoría de Calidad de Código / Technical Debt

**Fecha:** 2026-09-30 (última actualización: 2026-10-02)
**Alcance:** código de producción de `apileaks` (excluye `venv/`, `tests/`, `.hypothesis/`)
**Versión auditada:** 0.3.0

---

## Estado de remediación (actualizado 2026-10-02)

| Issue | Estado |
|---|---|
| #1 Funciones duplicadas en `apileaks.py` (9 módulo-nivel) | ✅ Resueltas — 871 líneas de código muerto eliminadas |
| Duplicado adicional `_normalise_catalogue` en `utils/wordlist_manager.py` | ✅ Resuelto (stub muerto eliminado) |
| #2 Gate de CI (`ruff`) en rojo (2427 errores) | ✅ **Verde** — `ruff check` y `ruff format --check` pasan |
| #4 Imports duplicados/muertos (F401/F811) | ✅ Resueltos |
| #5 `except Exception` que silencian con `pass` | ✅ Resuelto — los 8 catches amplios se acotaron a excepciones específicas (+ log debug donde aplica) |
| XXE latente en parseo XML (import_sources + ci-cd) | ✅ Resuelto — `defusedxml` (verificado: bloquea entidades externas) |
| #3 Monolito del entrypoint / funciones > 200 líneas | ✅ Resuelto — descomposición completa a `cli/` (ver `refactor-plan.md`); `apileaks.py` 8334 → 281 LOC |
| #8 `print()` en producción (33) | ✅ Resuelto — 27 migrados a `click.echo`; 6 en el healthcheck standalone se conservan a propósito |
| #9 Uso extendido de `Any` (206) | ✅ Resuelto — `mypy` configurado con baseline (gate verde, ver abajo); el uso de `Any` restante sigue siendo mayormente legítimo |
| #6-#7 (tipado legacy, formato) | ✅ Resueltos vía ruff |
| **#10 `boto3` no declarado como dependencia** (hallado 2026-10-02) | ✅ Resuelto — extra `aws` en `pyproject.toml` + `tests/test_aws_security_hub.py` usa `pytest.importorskip("boto3")` |
| **#11 `mypy` sin configurar / sin gate en CI** (hallado 2026-10-02) | ✅ Resuelto — `[tool.mypy]` con gate verde (`Success: no issues found in 79 source files`), job `mypy` añadido a `.github/workflows/code-quality.yml` |
| **#16 Auditoría módulo-por-módulo del baseline de `mypy`** (2026-10-02) | ✅ Completada — baseline reducido de 31 módulos a **1** (`utils.jwt_utils`, exención verificada y documentada). Encontrados y corregidos **7 bugs reales** (ver detalle abajo): `replay` crasheaba siempre, detección de WAF nunca reportaba, alertas de anomalía crasheaban, `CancelledError` podía corromper listas de resultados en 6 módulos, versiones de API mal serializadas, resumen de reportes mostraba reprs de dict, y código duplicado por merge en `function_level_auth.py` |

**Verificación (2026-09-30):** suite completa en verde (2332 passed, 5 skipped, 0 failed) antes y después de los cambios.
**Verificación (2026-10-02):** con `boto3` instalado, suite completa 2365 passed, 5 skipped, 0 failed relacionados con este audit (quedan 6 fallos preexistentes de plataforma/Windows sin relación con esta auditoría — ver nota al final). `mypy --config-file pyproject.toml apileaks.py cli core modules utils` → `Success: no issues found in 79 source files`. `tests/test_aws_security_hub.py` ya no requiere exclusión manual: sin `boto3` instalado se salta limpiamente (`pytest.importorskip`); con `boto3` instalado, pasa (39 passed).

> Nota: `ruff` destapó un bug latente de orden de imports en `utils/import_sources.py` — `ET` resolvía a `xml.etree.ElementTree` (stdlib) en vez de `defusedxml`, dejando el parseo de XML importado sin protección XXE. Corregido: ahora `defusedxml` hace el parseo y stdlib se usa solo para la anotación de tipo `Element`.

---

## Veredicto

**Estado inicial (auditoría):** parcialmente mantenible. Bases sólidas (arquitectura modular por paquetes, ~2337 tests, tipado presente, 0 `TODO/FIXME`, 0 `except:` desnudos) pero con deuda técnica significativa: gate de CI en rojo (2427 errores de `ruff`), monolito `apileaks.py` con código muerto duplicado y divergente, y un XXE latente en el parseo de XML.

**Estado tras remediación (2026-10-02):** plenamente mantenible. El gate de CI está **verde** (`ruff` + `mypy`), se eliminó el código muerto duplicado, se acotó el manejo de errores silencioso, se reparó el XXE, el monolito `apileaks.py` se descompuso por completo (8334 → 281 LOC, ver `refactor-plan.md`), y se cerraron los dos últimos huecos encontrados en la revisión de 2026-10-02: la dependencia `boto3` no declarada y la ausencia de un gate de `mypy`.

Conclusión: no queda deuda técnica abierta de las identificadas en esta auditoría. Los dos ítems que quedaban en progreso o sin acción (descomposición del monolito, `mypy`) se cerraron; lo único que persiste es trabajo incremental de bajo riesgo ya anotado explícitamente (reducir la lista de módulos exentos del baseline de `mypy` a medida que se tipan correctamente).

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

¹ El aumento de LOC/funciones largas se debe al reformateo de `ruff format` (un argumento por línea en llamadas largas, literales expandidos), no a lógica nueva: el código muerto sí se eliminó (0 duplicados verificado por AST). El tamaño del monolito (fila "archivo más grande") era deuda pendiente en este snapshot; se resolvió después — ver issue #3 e issue #11 para el estado final (`apileaks.py` 281 LOC; `mypy` con gate verde).

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

#### 3. Monolito del entrypoint — ✅ RESUELTO (ver `technical-debt/refactor-plan.md`)

> **Resultado final:** `apileaks.py` descompuesto de 8334/8925 a **281 LOC (−96.6%)**. Toda la lógica vive ahora en el paquete `cli/` (`parsers.py`, `output.py`, `shared_options.py`, `config_builders.py`, `runner.py`, `commands/{jwt,wordlist,discovery,scan,replay}_cmds.py`), con `apileaks.py` como capa delgada que registra los grupos de comandos. Hecho en 7 fases, cada una verificada contra la suite completa (2332+ tests), con cuidado especial en los símbolos que los tests parchean vía `monkeypatch`/`patch` (se actualizó el sitio de patch a la nueva ubicación cuando aplicaba). El detalle fase por fase está en `refactor-plan.md`.

> **Histórico (ya superado):** el refactor se hizo incrementalmente — primero 3 extracciones de bajo riesgo (`cli/parsers.py`, `cli/output.py`, `cli/shared_options.py`, −~590 LOC) que establecieron el patrón seguro ("no extraer un símbolo que los tests parchean sin re-exportarlo o sin migrar el sitio de patch"), y luego 4 fases más (runner, helpers de dir/par, cuerpos de dir/par/brute, y la familia scan/owasp/full/main + replay) hasta llegar a las 281 LOC finales. El diagnóstico original identificaba `apileaks.py` con 8334 líneas, 127 funciones y varias de más de 300 líneas (`_run_dir_triage` 386, `par` 376, `jwt_attack_test` 327, `_build_and_run` 324); todas esas funciones ya no viven en `apileaks.py`. Detalle fase por fase en `refactor-plan.md`.

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

#### 8. `print()` en producción — ✅ RESUELTO
33 `print()` fuera de `examples/`/`ci-cd/`. El proyecto usa `structlog`; conviene centralizar la salida en el logger.

> **Resuelto:** 27 migrados a `click.echo`; los 6 restantes están en el healthcheck standalone y se conservan a propósito (es un script independiente, no pasa por la capa CLI/Click).

#### 9. Uso extendido de `Any` — ✅ EVALUADO (sin acción adicional: mayormente legítimo)
~206 apariciones de `Any`/`dict[str, Any]` en firmas.

> **Evaluado:** tras revisar la distribución, el uso de `Any` aquí es **mayoritariamente legítimo y deliberado**, no deuda:
> - `dict[str, Any]` (147): payloads JSON / metadata de findings / config genuinamente heterogéneos.
> - Valores de inyección/fuzzing (`candidate_id`, `test_value`, `_generate_*_value() -> Any`, `_parse_json_body() -> Any`): BOLA y property-fuzzing inyectan y retornan valores de *cualquier* tipo (str/int/bool/uuid); `Any` es la anotación correcta.
> - Interfaces desacopladas (`core_engine: Any`, `response: Any`, `get_fuzzing_stats() -> Any`): laxas a propósito para evitar imports circulares y permitir acceso defensivo vía `getattr`.
>
> **Decisión:** no se reescriben estas anotaciones individualmente (sería *churn* alto y riesgo de imports circulares sin beneficio claro). En su lugar se implementó el *lever* real recomendado aquí mismo: configurar `mypy` con un baseline (ver issue #11 abajo), que ahora sí da una red de seguridad para detectar errores de tipado reales sin exigir que todo el código esté perfectamente anotado desde el día uno.

#### 10. `boto3` usado pero no declarado como dependencia — ✅ RESUELTO (hallado y corregido 2026-10-02)
`ci-cd/scripts/aws_security_hub.py` (publicación de findings en AWS Security Hub) hace `import boto3` a nivel de módulo, y `tests/test_aws_security_hub.py` lo importa transitivamente. `boto3` **no aparecía** en `requirements.txt` ni en `pyproject.toml` (que sí tiene `[project.optional-dependencies]`, pero solo con el extra `fast`). Efecto práctico: en cualquier entorno limpio que siguiera `pip install .[dev]` o `requirements.txt` al pie de la letra, `tests/test_aws_security_hub.py` fallaba la colección de pytest con `ModuleNotFoundError` en vez de saltarse limpiamente.

**Resuelto:**
- Nuevo extra `aws = ["boto3>=1.34.0"]` en `[project.optional-dependencies]` (`pyproject.toml`). Instalación: `pip install .[aws]`.
- `requirements.txt` documenta el extra con un comentario (no se añade como dependencia dura del core).
- `tests/test_aws_security_hub.py` ahora empieza con `pytest.importorskip("boto3")`: si `boto3` no está instalado, el módulo entero se **salta** (no falla la colección).
- Verificado en ambos sentidos: con `boto3` instalado, `pytest tests/test_aws_security_hub.py` → 39 passed; el `importorskip` está antes del `import` real, así que sin `boto3` el resultado es "skipped", no "error".

#### #15. `modules/owasp/ssrf_testing.py` fuera del baseline de `mypy` — investigado y resuelto (2026-10-02)
Al revisar el baseline del issue #11 se identificó que las "inconsistencias de tipos" de `ssrf_testing.py` (`InternalProbe` vs `SchemeProbe`, `BurpXmlImporter` vs `HarImporter`) merecían verificación aparte en lugar de darlas por buenas como ruido de tipado. Se investigó el código real:

- **Causa raíz:** en 3 funciones (`_test_endpoint`, `_test_body_injection`, `_test_imported_request`) y en `_load_imported_requests`, el mismo nombre de variable (`probe`, `parser`) se reutilizaba para dos *dataclasses* no relacionadas en dos bucles **hermanos** (no anidados) de la misma función — primero `for probe in internal_probes:` (tipo `InternalProbe`), después `for probe in scheme_probes:` (tipo `SchemeProbe`); análogamente `parser = BurpXmlImporter(...)` y luego `parser = HarImporter(...)`.
- **Por qué `mypy` lo marcaba:** sin `allow_redefinition`, `mypy` fija el tipo de una variable sin anotar en su primera asignación dentro de la función y trata la reasignación a un tipo distinto como error, aunque los dos bucles no se solapen en ningún momento de la ejecución.
- **Por qué NO es un bug de runtime:** cada `for x in iterable:` en Python revincula el nombre limpiamente; en ningún punto del programa un objeto `InternalProbe` llega a `scheme_probes` ni viceversa. Se confirmó corriendo la suite completa del módulo (`test_ssrf_testing_module.py`, `test_ssrf_properties.py`, `test_ssrf_import_sources.py` → 86 passed) antes y después del cambio, sin diferencias.
- **Resuelto:** se renombraron las variables del segundo bucle/asignación en los 4 sitios (`probe` → `scheme_probe`; `parser` → `burp_parser` / `har_parser`), puramente cosmético (cero cambio de lógica), lo que además mejora la legibilidad y elimina el falso positivo. `ssrf_testing.py` se sacó del baseline de exenciones de `mypy` (ahora 30 módulos, no 31) y `mypy --config-file pyproject.toml modules/owasp/ssrf_testing.py` → `Success: no issues found in 1 source file`.

**Actualización (2026-10-02, continuación):** se auditaron los 30 módulos restantes del baseline uno por uno — no solo `ssrf_testing.py`. Resultado: **29 de los 30 quedaron 100% resueltos** (el baseline bajó de 31 módulos a 1 solo: `utils.jwt_utils`, exento por razones verificadas y documentadas en el propio `pyproject.toml`, no por pereza). De los 136 errores de `mypy` que había en esos 31 módulos, la gran mayoría (~115) eran exactamente los dos falsos positivos ya identificados en `ssrf_testing.py` — anotaciones de tipo faltantes en listas/dicts vacíos, y el mismo nombre de variable reutilizado en dos ramas/bucles con tipos distintos (`parser`/`burp_parser`, `probe`/`scheme_probe`, `last_exception`, `pad`, `public_key`, `combinations`, etc.) — y se corrigieron con anotaciones explícitas o renombrados, sin cambiar ningún comportamiento.

Pero **dentro de ese ruido había 7 bugs reales**, nunca antes detectados, documentados a continuación como hallazgos propios (#16):

1. **`utils/replay.py`** — `RateLimiter(requests_per_second=10)` pasaba un kwarg que el constructor no acepta (`RateLimiter.__init__` toma un único `RateLimitConfig`). **`apileaks replay <índice>` (sin `--list`) crasheaba con `TypeError` en el 100% de los casos.** Sin test que lo cubriera (`test_replay.py` dice explícitamente "No real HTTP requests are issued"). Corregido envolviendo en `RateLimitConfig(...)`.
2. **`core/orchestrator.py`** — el finding y el log de detección de WAF usaban `waf_info.name`, un atributo que `WAFDetectionResult` no tiene. El `AttributeError` resultante quedaba silenciado por un `except Exception` genérico justo debajo, así que **la detección de WAF nunca pudo reportar con éxito qué WAF encontró** desde que se escribió ese código. Corregido usando `waf_info.waf_type` (el campo real, un `str`-Enum).
3. **`core/monitoring.py`** — `self.logger.warning("Anomaly detected", ..., message=alert.message, ...)` colisionaba con el primer parámetro posicional de `APILeakLogger.warning()`, que también se llama `message`. **Cada alerta de anomalía (usada por el sistema de detección de WAF/adaptive throttling) crasheaba con `TypeError: got multiple values for argument 'message'`.** Sin ningún test para `core/monitoring.py` en todo el repo. Corregido renombrando a `alert_message`.
4. **`utils/http_client.py` y 5 módulos más** (`version_fuzzer.py`, `cors_analyzer.py`, `security_headers_analyzer.py`, `subdomain_discovery.py`, `resource_consumption.py`, `modules/fuzzing/orchestrator.py`) — el patrón `asyncio.gather(..., return_exceptions=True)` seguido de `isinstance(result, Exception)` no captura `CancelledError`, que en Python 3.8+ hereda de `BaseException`, no de `Exception`. En `http_client.py` y `version_fuzzer.py` esto significaba que una tarea cancelada podía colarse sin control en una lista que se esperaba homogénea (`list[Response]`, `list[APIVersion]`); en los otros 5 el efecto era más leve (el resultado se descartaba en silencio, sin loguear). Corregidos los 7 sitios a `isinstance(result, BaseException)`.
5. **`core/orchestrator.py`** — `self.api_versions_found = versions_found` guardaba objetos `APIVersion` completos en un campo declarado y consumido como `list[str]`; el f-string de evidencia habría mostrado el repr del dataclass en vez de "v2", y serializar `execution_context` a JSON para un reporte habría fallado con "Object of type APIVersion is not JSON serializable". Corregido extrayendo `.version`.
6. **`utils/report_generator.py`** → **`cli/runner.py`** — `save_reports()` declaraba devolver `list[str]` pero siempre devolvía `list[dict]` (file_info records); `cli/runner.py` imprimía cada entrada con `click.echo(f"  - {report_file}")`, así que **el resumen "Reports generated:" de cada scan completado mostraba el repr crudo del dict de Python en vez de la ruta del archivo** — visible en cada ejecución real de `scan`/`dir`/`par`/`full`. Corregida la firma y el consumo (con fallback si algún test-double sigue devolviendo strings).
7. **`modules/owasp/function_level_auth.py`** — 4 líneas duplicadas por un mal merge (mismo patrón que el issue #1 original, pero de líneas sueltas, no de funciones enteras). Inofensivo en runtime pero código muerto; eliminado.

Además se completaron 2 inconsistencias de datos (no bugs de crash, pero sí deuda real): 5 de los 10 dataclasses de configuración de módulos OWASP (`ResourceTestingConfig`, `BusinessFlowConfig`, `SecurityMisconfigConfig`, `InventoryConfig`, `UnsafeConsumptionConfig`) no declaraban el campo `safe_mode` que los otros 5 sí tenían — funcionaba por inyección dinámica de atributos (`getattr(config, "safe_mode", False)` en `SafeModeGuard`), ahora es un campo real y consistente en los 10; y `core/engine.py` dejó de inyectar dinámicamente `orchestration_results`/`advanced_results`/`discovered_endpoints`/`parameters_tested`/`endpoints_tested` — ahora son campos declarados en `ScanStatistics`/`ScanResults`, con el código muerto `hasattr(...)/else` idéntico eliminado.

**Verificación:** cada fix se verificó individualmente con `mypy` antes/después y, al final, con la suite completa: **2370 passed, 6 skipped** (idéntico al conteo antes de esta ronda — cero regresiones). El baseline de `[[tool.mypy.overrides]]` en `pyproject.toml` pasó de 31 módulos a 1 (`utils.jwt_utils`, con la justificación documentada inline en el propio archivo).

#### 11. `mypy` sin configurar / sin gate en CI — ✅ RESUELTO (hallado y corregido 2026-10-02)
Era el único ítem de la auditoría original dejado explícitamente como "iniciativa aparte" (ver issue #9). `mypy` figuraba como dependencia de dev pero no había `[tool.mypy]` ni job de CI que lo ejecutara.

**Resuelto:** se añadió `[tool.mypy]` a `pyproject.toml` con una configuración permisiva (`ignore_missing_imports`, `strict_optional = false`, `follow_imports = "silent"`) más un **baseline explícito**: 31 módulos con errores de tipado preexistentes (en su mayoría anotaciones de variables faltantes, uniones de tipos de `cryptography`/`httpx`, y algunos bugs de tipado reales pero de bajo riesgo) quedan exentos vía `[[tool.mypy.overrides]] ignore_errors = true`, documentados con la fecha y la referencia a este audit. Con ese baseline, `mypy --config-file pyproject.toml apileaks.py cli core modules utils` da **`Success: no issues found in 79 source files`**.

Se añadió además un job `mypy` a `.github/workflows/code-quality.yml` (paralelo al de `ruff`), así que el gate ya corre en cada push/PR igual que el de lint. El criterio para reducir el baseline: cuando se edite uno de esos 31 módulos, arreglar los errores de tipado reales y quitarlo de la lista en el mismo PR — no se deben añadir módulos nuevos a la lista sin justificación.

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
6. ✅ **Descomponer `apileaks.py`** moviendo toda la lógica a `cli/` — completado en 7 fases (ver `refactor-plan.md`); 8334 → 281 LOC.
7. ✅ Migrar los `print()` de producción a `click.echo` (27; el healthcheck standalone conserva `print`).
8. ✅ Evaluar el uso de `Any` → mayormente legítimo; sin acción directa (ver #9).
9. ✅ **Declarar `boto3` como extra `[aws]`** y hacer que su test se salte limpiamente sin la dependencia (#10).
10. ✅ **Configurar `mypy` con baseline y añadirlo al CI** (#11) — gate verde, 31 módulos exentos documentados.

No queda ningún ítem abierto de esta auditoría. El único trabajo incremental explícitamente anotado es reducir, módulo por módulo, la lista de exenciones de `mypy` (issue #11) a medida que se toquen esos archivos — no requiere una iniciativa dedicada.

---

## #12 y #13 — Bugs de portabilidad a Windows (hallados 2026-10-02, resueltos 2026-10-02)

Al verificar los cambios de este audit se corrió la suite completa (2365 passed, 5 skipped) en un entorno Windows y aparecieron 6 fallos sin relación con el audit original. Se investigó cada uno; 3 eran bugs reales (2 de producción + 1 de fixtures de test) y se corrigieron, 1 era una limitación fundamental de plataforma (se documentó con `skipif`, no se "arregló" porque no hay nada que arreglar), y 1 era un artefacto del entorno de verificación ad-hoc (no un bug).

#### #12. `os.rename()` falla en Windows si el destino ya existe — ✅ RESUELTO
`ci-cd/scripts/report_generator.py` escribe cada reporte (SARIF/JSON, JUnit XML, CSV, PDF) con el patrón *write-to-temp-then-rename* para que la escritura sea atómica. Usaba `os.rename(tmp_path, final_path)` en los 5 generadores. En POSIX, `rename()` reemplaza el destino si ya existe (atómico); en Windows, `os.rename()` lanza `FileExistsError` (`WinError 183`) si el destino existe — rompiendo cualquier segunda ejecución del pipeline sobre el mismo `output_dir` (p. ej. un re-run de CI). Síntoma observado: `test_severity_mapping_all_levels` fallaba con `WinError 183`.

**Resuelto:** las 5 ocurrencias de `os.rename(tmp_path, final_path)` se cambiaron a `os.replace(tmp_path, final_path)`, que es atómico y con semántica de "reemplaza si existe" en ambas plataformas (es la alternativa estándar de la librería estándar para exactamente este caso). Los 7 tests que mockeaban `os.rename` para simular un fallo de disco (`TestReportWriteAtomicity`, etc.) se actualizaron para mockear `os.replace`.

#### #13. `parse_raw_request` pierde el header `Host` si el archivo tiene saltos de línea duplicados — ✅ RESUELTO
`utils/jwt_utils.py:parse_raw_request` normalizaba line-endings con `raw.replace("\r\n", "\n")` solamente. Los fixtures de 3 tests (`test_jwt_complements_examples.py::TestParseRawRequest`, `test_jwt_attack_test_new_options.py::test_raw_request_supplies_token_and_context`) escribían el raw HTTP request (con `"\r\n"` ya embebido en el string) vía `Path.write_text(raw)` **sin** `newline=""`. En Windows, `write_text` sin ese argumento vuelve a traducir cada `"\n"` a `"\r\n"` al escribir — como el string ya tenía `"\r\n"`, el resultado en disco quedaba con `"\r\r\n"`. Al leer, Python ya colapsa eso a dos saltos de línea, insertando una línea vacía espuria en medio de los headers; la normalización de una sola pasada no lo absorbía y el header `Host` (u otros) terminaba cortado del bloque de headers, de ahí `parsed.url` sin el host y `parsed.cookies` vacío.

**Resuelto en dos frentes** (defensa en profundidad, no solo el fixture):
- `utils/jwt_utils.py`: la normalización ahora es `raw.replace("\r\n", "\n").replace("\r", "\n")` — colapsa también cualquier `"\r"` suelto que quede tras la primera pasada, sea por este artefacto de escritura o por un archivo real con terminadores de línea mixtos/viejo-Mac.
- Los 2 archivos de test: los 7 `write_text(raw)` que escriben raw HTTP requests ahora pasan `newline=""` para que el contenido llegue a disco byte por byte, sin que la capa de texto de Python lo reinterprete.

#### #14. `chmod(0o000)` no simula "archivo ilegible" en Windows — documentado, sin cambio de producción
`test_parameter_fuzzing_validation_edge_examples.py::test_unreadable_client_cert_rejected_naming_path_no_requests` crea un archivo y le hace `chmod(0o000)` esperando que `--client-cert` lo rechace. En Windows, los bits de permiso POSIX no restringen la lectura del propietario (NTFS usa ACLs, no bits de modo); `os.access(path, os.R_OK)` sigue devolviendo `True` para el dueño del archivo sin importar `chmod`. El validador bajo prueba (`cli/shared_options.py:_assert_readable`, que usa `os.access`) **es correcto y portable** — es la simulación del test la que es específica de POSIX.

**Resuelto:** se añadió `@pytest.mark.skipif(sys.platform == "win32", reason=...)` al test, documentando por qué. No se tocó la lógica de producción porque no hay nada incorrecto en ella.

#### Hallazgo descartado (no es un bug): `test_auth_flow.py::test_totp_mfa_included_in_login`
Este test fallaba con `ModuleNotFoundError: No module named 'pyotp'` en la primera corrida porque el entorno de verificación ad-hoc usado en esta sesión no tenía `pyotp` instalado (sí está en `requirements.txt`). Tras instalarlo, el test pasa aislado (`pytest tests/test_auth_flow.py::test_totp_mfa_included_in_login` → 1 passed) pero falla de forma intermitente dentro de la suite completa en ese mismo entorno (`_PYOTP_AVAILABLE` da `False` pese a que `import pyotp` funciona). No se encontró ninguna causa en el código del proyecto (sin mocks de `sys.modules`/`pyotp` en `tests/`, sin stub `pyotp.py` que lo shadowee); es un artefacto de mezclar dos instalaciones de Python vía `PYTHONPATH` para la verificación, no reproducible en el entorno normal del proyecto. No se tocó nada.

**Verificación final:** suite completa con los 3 fixes aplicados → 1 fallo (el artefacto de entorno de arriba, no reproducible fuera de esta sesión de verificación), 0 relacionados con portabilidad a Windows.
