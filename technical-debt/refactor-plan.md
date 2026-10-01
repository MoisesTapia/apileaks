# Refactor mayor — Descomposición de `apileaks.py`

**Objetivo:** reducir el monolito `apileaks.py` (entry point, ~8300 LOC, 81 funciones top-level)
a una capa delgada de ensamblado de la CLI, moviendo las familias de comandos y sus helpers a
`cli/`, sin romper comportamiento ni la suite de tests (2332 passed).

---

## Principios y restricciones

1. **La suite parchea vía el namespace `apileaks`.** Los tests hacen
   `patch("apileaks.X")` / `monkeypatch.setattr(apileaks, "X", ...)` sobre muchos símbolos.
   Regla de oro al mover un símbolo `X`:
   - Si `X` **no** se parchea → moverlo y re-importarlo en `apileaks` (compat de `from apileaks import X`).
   - Si `X` **sí** se parchea → además de moverlo, **actualizar el sitio de patch** del test a la
     nueva ubicación (`patch("cli.commands.<mod>.X")`). Es la práctica correcta ("patch where it's
     looked up"); el test sigue validando el mismo comportamiento.
   - **Nunca** extraer un símbolo parcheado si otra función extraída lo llama por nombre y un test
     espera que el patch en `apileaks.X` afecte esa llamada (quedaría sin efecto). Esos clusters se
     mueven juntos o se difieren.

2. **Cero cambio de comportamiento.** Solo se mueve código; las firmas, docstrings y la lógica se
   preservan verbatim. Verificación con la suite completa tras **cada** fase.

3. **Sin imports circulares.** Los módulos de `cli/commands/` no importan `apileaks`. La raíz
   `cli` (grupo Click) se inyecta por registro: cada familia define su grupo con `@click.group()`
   y `apileaks.py` hace `cli.add_command(<grupo>)`.

4. **Gate verde siempre:** `ruff check` + `ruff format --check` con el scope del CI, y
   `pytest` completo (excepto `test_aws_security_hub.py`, que requiere `boto3` no declarado).

---

## Estructura destino

```
cli/
  shared_options.py     # option groups + validadores (ya poblado)
  parsers.py            # parseo/validación de entrada CLI (hecho)
  output.py             # render de consola (hecho)
  module_options.py     # (existente)
  owasp_descriptors.py  # (existente)
  commands/
    __init__.py
    jwt_cmds.py         # Fase 1: grupo `jwt` + 14 subcomandos + helpers de engine JWT
    wordlist_cmds.py    # Fase 2: grupo `wordlist` + subcomandos
    ...                 # fases siguientes
apileaks.py             # thin: construye `cli`, registra grupos, re-exporta símbolos públicos
```

Registro: `apileaks.py` → `from cli.commands.jwt_cmds import jwt as _jwt_group; cli.add_command(_jwt_group)`.

---

## Fases (orden por cohesión y bajo acoplamiento de patch)

| Fase | Cluster | LOC aprox | Acoplamiento de patch | Estado |
|---|---|---|---|---|
| 1 | Familia **JWT** (`jwt` + 14 subcmds + `_make_jwt_engine`, `_run_jwt_vector`, `_build_jwt_http_engine`, `_load_public_key_material_cli`) | ~1594 | solo `JWTAttackEngine` (3 tests) | ✅ hecho (`cli/commands/jwt_cmds.py`) |
| 2 | Familia **wordlist** (`wordlist` + list/cache/fetch) | ~110 | ninguno | ✅ hecho (`cli/commands/wordlist_cmds.py`) |
| 3 | **Config builders** (`create_enhanced_config`, `create_default_config`, `_collect_module_configs`, `_load_spec_schema`) | ~500 | ninguno (se llaman/importan directo, no se parchean) → re-exportar basta | ✅ hecho (`cli/config_builders.py`) |
| 4 | Familia **dir/par** (`dir`, `par`, `_run_dir_core`, `_run_dir_triage`, `_run_*_multi_target`, `_resolve_*_candidates`) | ~1400 | `run_enhanced_apileak`, `_discover_*`, `_resolve_par_candidates` | pendiente |
| 5 | Familia **scan/owasp** (`scan`, `owasp`, `full`, `_build_and_run`, `_run_scan_multi_target`, `_make_module_subcommand`) | ~700 | `run_enhanced_apileak`, `_run_scoped_owasp_scan` | pendiente |
| 6 | **Triage** (`run_interactive_triage`, `_discover_endpoints_for_triage`, `_select_records`) | ~300 | sí | pendiente |
| — | `run_enhanced_apileak` (núcleo, 36 patches) | ~313 | el más acoplado → se decide al final (posible `core/` o `cli/runner.py` con actualización masiva de patches) | pendiente |

Cada fase: extraer → re-importar/registrar → actualizar patches si aplica → `ruff` + suite → commit.

---

## Fase 1 — JWT (en curso)

- Nuevo módulo `cli/commands/jwt_cmds.py` con las 19 funciones del cluster (verbatim), importando
  de `utils.jwt_*`, `cli.output`, `cli.parsers`, `click`, stdlib.
- `jwt` pasa de `@cli.group()` a `@click.group()`; `apileaks.py` registra con `cli.add_command(jwt)`.
- `apileaks.py` re-exporta `jwt` y `JWTAttackEngine` (compat).
- Actualizar 3 tests que hacen `monkeypatch.setattr(apileaks, "JWTAttackEngine", ...)` →
  `cli.commands.jwt_cmds` (donde ahora se resuelve el símbolo).
- Verificado: cluster 100% autocontenido (0 callers no-cluster), sin imports circulares.

## Progreso

- **Fase 1 (JWT):** ✅ `cli/commands/jwt_cmds.py` (19 funcs). `apileaks.py` 8331 → 6426 LOC.
- **Fase 2 (wordlist):** ✅ `cli/commands/wordlist_cmds.py` (4 funcs, sin acoplamiento de patch). `apileaks.py` 6426 → 6290 LOC.
- **Fase 3 (config builders):** ✅ `cli/config_builders.py` (4 funcs). Resultó más simple de lo previsto: los builders se **llaman/importan directo** (no se parchean) y **no usan `ConfigurationManager`** (que se queda en `apileaks`, usado por dir/par/scan), así que re-exportar bastó, sin tocar tests. `_apply_transversal_overrides` se dejó en `apileaks` (depende de `resolve_max_depth`, evita import circular; es scan-family). `apileaks.py` 6290 → 5783 LOC.
- **Acumulado:** `apileaks.py` 8331 → ~5783 LOC (−~2550, ~31%). Suite 2332 passed en cada fase; gate `ruff` verde.
- **Siguiente:** Fase 4 (familia dir/par) — acoplada a `run_enhanced_apileak`/`_discover_*`; los callers están en el propio cluster, así que requiere mover el cluster junto y actualizar los sitios de patch correspondientes. Tanda cuidadosa aparte.
