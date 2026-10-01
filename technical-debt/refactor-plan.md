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
| 4a | **Runner** (`run_enhanced_apileak`, `evaluate_severity_gate`, `_echo_discovery_control_status`, `SEVERITY_LADDER`) → `cli/runner.py` | ~385 | `run_enhanced_apileak` (36 patch sites) + `APILeakCore` (3) | ✅ hecho |
| 4b-1 | **Helpers compartidos** de dir/par (auth parsers, `resolve_max_depth`, `tls_options`+validators TLS/método, `SUPPORTED_METHODS`) → `cli/parsers.py`, `cli/config_builders.py`, `cli/shared_options.py` | ~320 | ninguno (callers siguen en `apileaks`; solo re-export) | ✅ hecho |
| 4b-2 | Cuerpos de comando **dir/par/brute** + closure (triage/scan helpers, spec-brute) → `cli/commands/discovery_cmds.py` (24 funcs + 5 consts + `ScanScopeError`) | ~3650 | migrados ~56 patch sites (`run_enhanced_apileak`→`cli.runner`, `APILeakCore`→`cli.runner`, y el resto → `cli.commands.discovery_cmds`) | ✅ hecho |
| 5 | Familia **scan/owasp/full/main** (`_build_and_run`, `_run_scan_multi_target`, `_make_module_subcommand`, `_resolve_modules`, etc.) → `cli/commands/scan_cmds.py`; **replay** → `cli/commands/replay_cmds.py` | ~1150 | mínimo (`run_enhanced_apileak` ya en `cli.runner`; `ConfigurationManager` re-exportado) | ✅ hecho |
| 6 | **Triage** interactivo | — | ya movido como parte del closure dir/par (Fase 4b-2) | ✅ incluido en 4b-2 |
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
- **Fase 4a (runner):** ✅ `cli/runner.py` con `run_enhanced_apileak` (+ `evaluate_severity_gate`, `_echo_discovery_control_status`, `SEVERITY_LADDER`). Clave de diseño: como **todos los callers siguen en `apileaks`**, `patch.object(apileaks, "run_enhanced_apileak")` sigue funcionando sin tocar los 36 tests (los callers usan el binding re-exportado de `apileaks`). Sí hubo que migrar 3 sitios `patch.object(apileaks, "APILeakCore")` → `patch("cli.runner.APILeakCore")` en `test_cli_ci_gate.py`, porque esos tests inyectan findings vía `APILeakCore` que ahora resuelve en `cli.runner` (lo detectó la suite). `evaluate_severity_gate`/`SEVERITY_LADDER` se re-exportan con `# noqa: F401`. `apileaks.py` 5783 → 5394 LOC.
- **Acumulado:** `apileaks.py` 8331 → ~5394 LOC (−~2940, ~35%). Suite 2332 passed; gate `ruff` verde.
- **Fase 4b-1 (helpers compartidos de dir/par):** ✅ extraídos los helpers que bloqueaban mover dir/par: auth parsers (`parse_basic_auth`, `parse_header_options`, `validate_basic_auth_options`, `parse_auth_context_option`) → `cli/parsers.py`; `resolve_max_depth` → `cli/config_builders.py`; `tls_options` + `_validate_methods`/`_validate_ca_bundle`/`_validate_client_cert`/`_validate_resolve` + const `SUPPORTED_METHODS` → `cli/shared_options.py`. Sin cambios en tests (callers siguen en `apileaks`; re-export con `# noqa` donde hacía falta). `apileaks.py` 5394 → 5164 LOC.
- **Acumulado:** `apileaks.py` 8331 → ~5164 LOC (−~3170, ~38%). Suite 2332 passed; gate `ruff` verde.
- **Fase 4b-2 (cuerpos dir/par/brute):** ✅ movido todo el closure (24 funcs + 5 constantes + `ScanScopeError`) a `cli/commands/discovery_cmds.py` (~3650 LOC). Dos sub-pasos verificados:
  - **Step A:** `run_enhanced_apileak` patch-location-independent — todos los callers lo invocan como `runner.run_enhanced_apileak(...)` y los 39 patch sites → `cli.runner`.
  - **Step B:** mover el closure, registrar `dir`/`par`/`brute` vía `cli.add_command`, re-exportar nombres públicos (con `# noqa`), y migrar los patch sites restantes (`APILeakCore`→`cli.runner`; `_discover_*`/`_build_discovery_progress`/`_resolve_par_candidates`/`dir`/`par`/`_run_dir_triage`/`run_interactive_triage`/`_run_scoped_owasp_scan`/`_run_targeted_follow_up_scan`/`DEFAULT_PARAMETER_WORDLIST`→`cli.commands.discovery_cmds`), cubriendo las 3 formas (`patch.object`, `setattr`, `patch("...")` incl. multilínea). Fix de `_DEFAULT_SPEC_WORDLIST` (ruta relativa a `__file__`, ahora resuelta al project root).
- **Acumulado:** `apileaks.py` 8331 → **1414 LOC (−83%)**. Suite 2332 passed; gate `ruff` verde.
- **Fase 5 (scan/owasp/full/main + replay):** ✅ movido el cluster scan/owasp (15 funcs + `_ORCHESTRATOR_EXTRA_OPTIONS` + el loop de registro de subcomandos owasp) a `cli/commands/scan_cmds.py`, y `replay` a `cli/commands/replay_cmds.py`. Acoplamiento mínimo (`run_enhanced_apileak` ya canónico en `cli.runner`; `ConfigurationManager` re-exportado para los 28 patches de método de clase). Se arregló además un reverse-import de producción: `utils/discovery_session.py` ahora importa `parse_status_codes` de `cli.parsers` en vez de `apileaks`.
- **RESULTADO FINAL:** `apileaks.py` **8331 → 281 LOC (−96.6%)**. El entrypoint es ya una capa delgada pura: define el grupo raíz `cli`, importa y registra las familias de comandos (`cli.add_command`), y re-exporta la superficie pública. Toda la lógica vive en `cli/` (`parsers`, `output`, `shared_options`, `config_builders`, `runner`, y `cli/commands/{jwt,wordlist,discovery,scan,replay}_cmds.py`). Suite **2332 passed** en cada fase; gate `ruff` verde.

## Estructura final

```
apileaks.py                         # 281 LOC — grupo cli + registro + re-exports
cli/
  parsers.py                        # parseo/validación de entrada CLI
  output.py                         # render de consola
  shared_options.py                 # option groups + validadores + tls
  config_builders.py                # construcción del config dict
  runner.py                         # run_enhanced_apileak + severity gate
  module_options.py / owasp_descriptors.py
  commands/
    jwt_cmds.py                     # familia jwt (14 subcmds)
    wordlist_cmds.py                # familia wordlist
    discovery_cmds.py               # dir / par / brute + triage/spec-brute
    scan_cmds.py                    # scan / owasp / full / main
    replay_cmds.py                  # replay
```
