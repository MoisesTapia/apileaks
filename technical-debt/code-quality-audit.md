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
| #5 `except Exception` que silencian con `pass` | ⏳ Pendiente (6 casos) |
| #3 Monolito del entrypoint / funciones > 200 líneas | ⏳ Pendiente (refactor mayor) |
| #6-#9 (tipado legacy, formato, prints, `Any`) | ✅ Autofixables resueltos / ⏳ `Any` y prints pendientes |

**Verificación:** suite completa en verde (2332 passed, 5 skipped, 0 failed) antes y después de los cambios. Único test excluido: `tests/test_aws_security_hub.py` (requiere `boto3`, dependencia no declarada en `requirements.txt`).

> Nota: `ruff` destapó un bug latente de orden de imports en `utils/import_sources.py` — `ET` resolvía a `xml.etree.ElementTree` (stdlib) en vez de `defusedxml`, dejando el parseo de XML importado sin protección XXE. Corregido: ahora `defusedxml` hace el parseo y stdlib se usa solo para la anotación de tipo `Element`.

---

## Veredicto

El proyecto es **parcialmente mantenible**. Tiene bases sólidas (arquitectura modular por paquetes, 2337 tests que colectan, tipado presente, 0 `TODO/FIXME` y 0 `except:` desnudos), pero arrastra **deuda técnica significativa** que degrada la mantenibilidad:

- El **gate de calidad de CI está en rojo**: `ruff check .` reporta **2427 errores** con la misma configuración que usa el workflow `code-quality.yml`.
- El entrypoint `apileaks.py` es un **monolito de 8334 líneas** con **12 funciones definidas dos veces**, y al menos una pareja (`_run_dir_core`) **ya divergió** — es decir, hay código muerto que se desincronizó de su copia activa.

Conclusión: el núcleo funcional es recuperable, pero `apileaks.py` y el linting necesitan intervención antes de considerarlo "mantenible" sin reservas.

---

## Métricas generales

| Métrica | Valor |
|---|---|
| LOC de producción (sin venv/tests) | ~58 600 |
| Archivos Python de producción | 12 archivos > 1000 LOC |
| Archivo más grande | `apileaks.py` — 8334 LOC |
| Funciones de producción | 1217 |
| Funciones > 100 líneas | 84 |
| Funciones > 200 líneas | 13 |
| Errores de `ruff` (config del repo) | 2427 (2137 autofijables) |
| `except Exception` amplios | 333 |
| `except Exception` que silencian con `pass` | 6 |
| `print()` en código de producción | 33 |
| Archivos de test | 197 (2337 tests colectados) |

---

## Issues por severidad

### 🔴 Alta

#### 1. Funciones duplicadas (y divergentes) en `apileaks.py`
Hay **12 funciones definidas dos veces** en el mismo archivo; Python se queda con la última definición, dejando la primera como **código muerto**:

```
_brute_spec_async, _echo_fuzzing_stats, _load_spec_brute_wordlist,
_looks_like_spec, _probe, _run, _run_dir_core, _run_dir_multi_target,
_run_par_multi_target, _run_scan_multi_target, _run_spec_brute, _scan_one
```

Lo más grave: las dos copias de `_run_dir_core` (líneas **3376** y **3853**, ~284 líneas cada una) **ya no son idénticas** (difieren en `zip(..., strict=False)`). Esto significa que un fix se aplicó a una copia y no a la otra. Riesgo real de corregir la versión equivocada.

**Acción:** eliminar las copias muertas, consolidar en una sola definición y verificar con tests.

#### 2. Gate de calidad de CI fallando
`.github/workflows/code-quality.yml` ejecuta `ruff check .` y `ruff format --check` con exclusiones `venv,tests,.hypothesis,ci-cd,examples`. Con **2427 errores**, ese job está (o debería estar) en rojo en cada push a `main`. Un gate que no pasa pierde su valor como control de calidad.

**Acción:** aplicar `ruff check . --fix` (2137 autofijables) y revisar manualmente el resto, luego mantener el gate verde.

### 🟠 Media

#### 3. Monolito del entrypoint
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

#### 4. Imports duplicados y muertos
- **F811** (redefinición de import sin usar): 45 casos. Bloques de import enteros aparecen repetidos — por ejemplo en `apileaks.py` (`import_schema`, `import_postman_schema` listados dos veces) y en `modules/owasp/function_level_auth.py` (todo el bloque `json, re, uuid, dataclass, ...` re-importado en las líneas 43-49). Son artefactos de merge.
- **F401** (imports sin usar): 106 casos. Peores ofensores: `modules/owasp/auth_testing.py` (10), `utils/replay.py` (7), `modules/owasp/bola_testing.py` (7).

#### 5. Manejo de errores demasiado amplio
333 bloques `except Exception`, de los cuales 6 silencian con `pass`. Capturar `Exception` de forma genérica oculta fallos reales y complica el debugging. (Positivo: no hay `except:` desnudos.)

**Acción:** acotar a excepciones específicas donde sea posible y, como mínimo, loguear antes de continuar.

### 🟡 Baja

#### 6. API de tipado obsoleta (pre-PEP 585/604)
- **UP006** (622): `Dict`/`List` de `typing` en vez de `dict`/`list`.
- **UP045** (208) / **UP007** (3): `Optional[X]`/`Union` en vez de `X | None`.
- **UP035** (126): imports deprecados de `typing`.

El proyecto declara `requires-python = ">=3.11"`, así que la sintaxis moderna está disponible. Mayormente autofijable.

#### 7. Ruido de formato
- **W293** (1122): líneas en blanco con espacios.
- **W291/W292** (92): espacios finales / falta newline al final del archivo.
- **I001** (44): imports sin ordenar.

Todo autofijable con `ruff` + `ruff format`.

#### 8. `print()` en producción
33 `print()` fuera de `examples/`/`ci-cd/`. El proyecto usa `structlog`; conviene centralizar la salida en el logger.

#### 9. Uso extendido de `Any`
206 apariciones de `Any`/`Dict[str, Any]` en firmas. Reduce el valor del tipado estático (hay `mypy` en dependencias de dev). Oportunidad de reforzar contratos con modelos Pydantic (ya en uso).

---

## Fortalezas (lo que sí ayuda a mantener)

- Arquitectura modular clara: `cli/`, `core/`, `modules/{owasp,advanced,fuzzing}/`, `utils/`.
- Suite de tests amplia: 197 archivos, 2337 tests.
- Configuración de tooling presente: `ruff`, `black`, `mypy`, `pytest` en `pyproject.toml`, con CI por workflow.
- 0 `TODO/FIXME/HACK` y 0 `except:` desnudos.
- Documentación extensa en `docs/`.

---

## Plan de remediación sugerido (orden recomendado)

1. **Eliminar las 12 funciones duplicadas de `apileaks.py`** y verificar con la suite de tests (alta prioridad: hay divergencia real).
2. **`ruff check . --fix` + `ruff format .`** para liquidar los ~2137 autofijables y poner el CI en verde.
3. Resolver manualmente F401/F811 restantes y los imports duplicados (artefactos de merge).
4. Acotar los `except Exception` que silencian con `pass` (6 casos) y añadir logging.
5. A medio plazo: descomponer `apileaks.py` moviendo lógica a los paquetes existentes y partir las funciones > 200 líneas.
6. Reforzar tipos: reducir `Any`, migrar a PEP 585/604.

> Nota: los puntos 1-4 son de bajo riesgo y alto impacto; el punto 5 es un refactor mayor que conviene hacer con cobertura de tests delante.
