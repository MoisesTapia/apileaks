# Spec-Driven Testing

> **Not a strict OWASP API Security Top 10 mapping.** This module is filed under API8 (Security Misconfiguration) as the closest fit — a spec that documents validation the implementation doesn't perform is fundamentally a misconfigured-validation gap, but spec/implementation contract drift doesn't correspond to a single Top 10 category. It extends APILeak's coverage beyond the Top 10.

## What it detects

`utils/spec_import.py` parses an OpenAPI/Swagger (or Postman) document into a rich `SpecSchema`: for every declared parameter it captures the declared `type` (string/integer/number/boolean), the `required` flag, `enum` values, and `example` values — far more than just "this endpoint exists". Before this module existed, nothing in APILeak read that per-parameter metadata to drive test logic; the other spec-aware modules (`bola`, `property`, `ssrf`) only used the spec to look up the raw request-body JSON Schema for building a plausible request body, never the per-parameter constraints.

This module is what consumes that previously-unused metadata. For every declared operation it checks whether the live API actually enforces:

- **Enum membership** — a parameter declares a fixed `enum`; sending a value outside it and getting a successful response means the constraint isn't enforced server-side.
- **Declared type** — a parameter is declared `integer`/`number`/`boolean`; sending a wrong-typed value (a string where a number was declared) and getting success means the backend doesn't validate type.
- **Required presence** — a parameter is declared `required: true`; omitting it entirely and still getting success means the backend doesn't enforce the contract it publishes.

None of these probes are injection payloads. The signal is purely "does the server enforce the contract it itself publishes?" — undeclared/invalid input reaching business logic that assumed the contract held is a real, if often individually low-severity, security-relevant gap (it means the published spec cannot be trusted as a description of what the server actually accepts, which undermines every other tool — including APILeak's own `dir --openapi` seeding — that trusts the spec).

## Drives its attack surface from the spec, not from discovery

This is the one OWASP-registered module in APILeak that does **not** primarily rely on crawled/discovered endpoints for its targets. Every declared operation in the supplied `--openapi`/`--postman` source is audited directly, whether or not the discovery phase ever found it — so it audits the full documented surface, including operations discovery never reached (undocumented-but-crawlable endpoints are the `inventory` module's concern; documented-but-uncrawled endpoints are this module's).

A single discovered endpoint is still required to derive the target's `scheme://host` — this module doesn't take a bare `--target` without at least one endpoint having been found first in a `scan` run, or without `dir` having run before it in the same invocation.

```bash
# Audit every declared operation in an OpenAPI/Swagger document
python apileaks.py owasp spec_driven_testing --target https://api.example.com --openapi openapi.yaml

# Via a Postman collection — only the required-parameter check is meaningful,
# since Postman doesn't declare enum/type metadata
python apileaks.py owasp spec_driven_testing --target https://api.example.com --postman collection.json
```

## Scope and limitations (documented honestly)

- **Path parameters** are filled with a type-appropriate dummy value (or the spec's own `example`) to build a concrete URL. This module does NOT try to match discovered endpoints to resolve real path values — `SpecSchema.operation_for()` matches on the literal declared path template (e.g. `/users/{id}`), not a resolved one.
- **Request bodies** are built from `required` JSON Schema properties only — a minimal "good enough to pass validation" body, not a full schema-conformant payload generator.
- **Probe count is bounded**: at most a handful of requests per operation (one per constrained parameter, plus omission checks where applicable), capped overall by `--sdt-max-operations`, so auditing a large spec cannot explode into an unbounded request count.

## CLI Reference

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--openapi` | OpenAPI/Swagger document (JSON or YAML) to audit. Repeatable; merged with `--postman`. **Required** for this module to have anything to test when run in isolation. | — | `--openapi openapi.yaml` |
| `--postman` | Postman collection (JSON) to audit. Carries no enum/type/required metadata. | — | `--postman collection.json` |
| `--sdt-max-operations` | Maximum number of declared operations audited. | `30` | `--sdt-max-operations 100` |

Plus the shared transversal options — see the [OWASP Command Reference](../owasp-command.md#shared-transversal-options).

## Safe Mode

In Safe Mode, any operation whose declared method is state-changing (`POST`/`PUT`/`PATCH`/`DELETE`) is skipped entirely.

## Finding categories

| Category | Severity | OWASP category | Trigger |
|----------|----------|-----------------|---------|
| `SPEC_ENUM_NOT_ENFORCED` | `MEDIUM` | `API8` | A value outside the declared `enum` was accepted |
| `SPEC_TYPE_NOT_ENFORCED` | `LOW` | `API8` | A wrong-typed value was accepted |
| `SPEC_REQUIRED_PARAM_NOT_ENFORCED` | `MEDIUM` | `API8` | A `required` parameter was accepted when omitted |

## Example finding

```
Parameter 'status' (query) on GET /items declared enum
['active', 'inactive'] but accepted '__apileak_value_outside_declared_enum__',
and the request still succeeded (status 200).
```

## Related

- [Parameter Pollution](parameter-pollution.md) — the other module filed under API8 that extends coverage beyond the Top 10.
- [Advanced Discovery](../advanced-discovery.md) — spec-aware endpoint discovery (`dir --openapi`), which is a different, discovery-focused use of the same spec.
- [OWASP Command Reference](../owasp-command.md) — full CLI reference for every module.
