# HTTP Parameter Pollution Testing

> **Not a strict OWASP API Security Top 10 mapping.** This module is filed under API8 (Security Misconfiguration) as the closest fit — inconsistent/unenforced parameter-resolution handling is a validation misconfiguration, but HTTP Parameter Pollution (HPP) doesn't correspond to a single Top 10 category. It extends APILeak's coverage beyond the Top 10.

## What it detects

HTTP Parameter Pollution occurs when a backend resolves a request that supplies the **same parameter name more than once** inconsistently, or unsafely — for example:

- A query string with the same key twice (`?role=user&role=admin`) resolved as "first wins" by one layer (e.g. a WAF) and "last wins" by another (the application), letting a value the WAF thought it rejected reach the application.
- A JSON API that, when a field is wrapped in an array (`{"role": ["user", "admin"]}`), silently coerces it to one of the values instead of rejecting the malformed input — and resolves it inconsistently with how a plain scalar value would have been handled.

This module issues three requests per candidate parameter — single value A, single value B, and both values together — and compares the three responses to flag:

- **`bypass_via_pollution` (HIGH)** — value B alone was rejected (4xx/5xx), but supplying it duplicated/array-wrapped alongside value A succeeded. The pollution let an otherwise-rejected value through — this is the authorization-bypass-flavored finding.
- **`inconsistent_resolution` (MEDIUM)** — the polluted response's status matches *neither* single-value baseline. The backend parsed the duplicate in a way that produced a genuinely different outcome, not just "picked A or B".

## Two independent probe sources

Unlike every value-based payload test in APILeak, this module is useful with or without live discovery, because it has two independent sources of candidate parameters:

### 1. Discovered endpoints

Any endpoint whose URL already carries a query string is a candidate — each query parameter found there is polluted in turn.

```bash
python apileaks.py owasp parameter_pollution --target https://api.example.com
```

### 2. Captured traffic (Burp Suite / Caido / any HAR-exporting tool)

Reuses the exact same importers `ssrf_testing.py` uses for its Full_Replay_Mode (`utils/import_sources.py`'s `BurpXmlImporter`/`HarImporter`) — **but generalized**: this module is NOT restricted to the "URL-like" field subset SSRF limits itself to. Every query parameter and every JSON/form body field of a captured request is a pollution candidate.

```bash
# Burp Suite XML export (Proxy → HTTP History → Save items)
python apileaks.py owasp parameter_pollution --target https://api.example.com --burp-xml export.xml

# HAR export — works identically whether it came from Caido, Burp Logger,
# Hetty, Chrome DevTools, or Firefox (HAR is a generic format, not tool-specific)
python apileaks.py owasp parameter_pollution --target https://api.example.com --har caido-export.har
```

Original headers, cookies, and the HTTP method of a captured request are preserved untouched; only the one parameter under test is duplicated per probe.

For JSON bodies, since JSON cannot literally carry a duplicate key on the wire, the practical equivalent probe is **array-wrapping**: `{"field": "A"}` → `{"field": ["A", "B"]}`. Many frameworks with a PHP/Node query-parsing heritage silently coerce this instead of rejecting it. For `application/x-www-form-urlencoded` bodies, a true duplicate key (`a=1&a=2`) is used instead, since the wire format genuinely supports it.

## CLI Reference

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--burp-xml` | Path to a Burp Suite XML Proxy-History export file. | — | `--burp-xml export.xml` |
| `--har` | Path to a HAR (HTTP Archive) JSON file — Caido, Burp Logger, Hetty, DevTools, Firefox. | — | `--har caido-export.har` |
| `--pp-max-candidates` | Maximum number of parameters to probe across discovered endpoints and any imported capture combined. Each candidate costs 3 requests. | `40` | `--pp-max-candidates 100` |

Plus the shared transversal options (`--target`, `--jwt`, `--auth-context`, `--safe-mode`, rate limiting, etc.) — see the [OWASP Command Reference](../owasp-command.md#shared-transversal-options).

## Safe Mode

In Safe Mode, any discovered endpoint or captured request whose method is state-changing (`POST`/`PUT`/`PATCH`/`DELETE`) is skipped entirely — this module never issues a state-changing pollution probe under Safe Mode.

## Finding category

| Category | Severity | OWASP category |
|----------|----------|-----------------|
| `HTTP_PARAMETER_POLLUTION` | `HIGH` (bypass via pollution) or `MEDIUM` (inconsistent resolution) | `API8` |

## Example finding

```
Parameter 'role' (query) alone with value 'apileak_pp_b' was rejected
(status 403), but supplying it duplicated/array-wrapped alongside
'apileak_pp_a' succeeded (status 200) — the backend's parameter-pollution
handling let an otherwise-rejected value through.
```

## Related

- [SSRF Testing (API7)](ssrf-testing.md) — the original Full_Replay_Mode this module's capture import generalizes.
- [Spec-Driven Testing](spec-driven-testing.md) — the other module filed under API8 that extends coverage beyond the Top 10.
- [OWASP Command Reference](../owasp-command.md) — full CLI reference for every module.
