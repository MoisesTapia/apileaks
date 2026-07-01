# BOLA Testing (API1)

The BOLA Testing Module detects **OWASP API1 - Broken Object Level Authorization** vulnerabilities: cases where an API fails to verify that the caller is allowed to access or modify the specific object referenced by a request identifier.

BOLA is not a standalone command. It runs as an OWASP module inside the `full` command and is selected with `--modules bola`. This page documents the module itself and every BOLA-specific command-line option, each with a title, a description, and an example.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [Enable the module (`--modules bola`)](#enable-the-module---modules-bola)
  - [Multi-user contexts (`--auth-context`)](#multi-user-contexts---auth-context)
  - [Safe Mode (`--safe-mode`)](#safe-mode---safe-mode)
  - [Authorize writes (`--allow-write-bola`)](#authorize-writes---allow-write-bola)
  - [Destructive methods (`--bola-destructive-methods`)](#destructive-methods---bola-destructive-methods)
  - [Composite-key probe (`--bola-composite`)](#composite-key-probe---bola-composite)
  - [ID leakage probe (`--bola-id-leakage`)](#id-leakage-probe---bola-id-leakage)
  - [Verb tampering (`--bola-verb-tampering`)](#verb-tampering---bola-verb-tampering)
  - [Parameter pollution (`--bola-parameter-pollution`)](#parameter-pollution---bola-parameter-pollution)
  - [Dry run (`--bola-dry-run`)](#dry-run---bola-dry-run)
- [Configuration (YAML)](#configuration-yaml)
- [Detection Techniques](#detection-techniques)
- [Finding Categories](#finding-categories)
- [Remediation](#remediation)

## 🎯 Overview

BOLA vulnerabilities occur when an API exposes object identifiers (numeric IDs, UUIDs, composite paths) and authorizes access based on authentication alone, without checking that the authenticated caller owns or may act on the referenced object. The module detects this by substituting identifiers, comparing responses across authentication contexts, and calibrating every decision against a negative-control baseline to keep false positives low.

Key behaviors:

- **Read-only by default.** The module issues only safe methods (`GET`, `HEAD`, `OPTIONS`) unless you explicitly opt in to destructive testing with `--allow-write-bola`.
- **Identity-aware comparison.** Two responses are treated as the same object only when they expose a matching identifying field value, never based on response size or word similarity.
- **Negative-control calibration.** Accessibility is decided by comparing a candidate response to a known-invalid-identifier baseline, so endpoints that return success for any input are not misreported.
- **Ownership-aware enumeration.** An enumeration finding is raised only when an accessed object's identifying field shows it does not belong to the requesting context.

## 🚀 Quick Start

```bash
# Minimal read-only BOLA scan
python apileaks.py full --target https://api.example.com --modules bola

# Multi-user horizontal-escalation testing (two user contexts)
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --auth-context alice:eyJhbGciOi...:1 \
  --auth-context bob:eyJhbGciOi...:1
```

## 📖 Command Reference

All BOLA options are supplied to the `full` command. The following options control BOLA behavior directly.

**Options at a glance:**

| Option | What it controls |
|--------|------------------|
| `--modules bola` | Enable the BOLA module |
| `--auth-context` | Supply one or more authenticated identities (multi-user tests) |
| `--safe-mode` | Force read-only testing across all modules |
| `--allow-write-bola` | Authorize destructive (state-changing) BOLA probes |
| `--bola-destructive-methods` | Which HTTP verbs count as destructive |
| `--bola-composite` | Composite-identifier / cross-tenant probe |
| `--bola-id-leakage` | Harvest and replay leaked identifiers |
| `--bola-verb-tampering` | HTTP method-override technique |
| `--bola-parameter-pollution` | Duplicate-identifier parameter technique |
| `--bola-dry-run` | Plan destructive probes without issuing them |

### Enable the module (`--modules bola`)

**Description.** Selects the BOLA module for a `full` scan. Combine it with other modules in a comma-separated list. With no BOLA-specific flags, the module runs in its safe, read-only default mode.

**Example:**

```bash
# BOLA only
python apileaks.py full --target https://api.example.com --modules bola

# BOLA alongside authentication and property-level testing
python apileaks.py full --target https://api.example.com --modules bola,auth,property
```

### Multi-user contexts (`--auth-context`)

**Description.** Supplies an authenticated identity as `user:token[:privilege]`. The option is **repeatable** — pass it once per user. Horizontal privilege-escalation and cross-context tests require **two or more** user contexts (privilege level `1`); with fewer, those tests are skipped and logged. The token may itself contain `:` characters (the value is split with a maximum of two splits). A value missing the `:` separator is rejected before any request is issued.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --auth-context alice:eyJhbGciOi...:1 \
  --auth-context bob:eyJhbGciOi...:1
```

### Safe Mode (`--safe-mode`)

**Description.** Enables Safe Mode globally: every module, including BOLA, skips state-changing probes (`POST`/`PUT`/`PATCH`/`DELETE`) and restricts requests to safe methods. Safe Mode overrides `--allow-write-bola`; when Safe Mode is on, no destructive probe is ever issued.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --safe-mode
```

### Authorize writes (`--allow-write-bola`)

**Description.** The destructive opt-in. Off by default. When omitted, BOLA issues only safe-method (read-only) probes. When set — and Safe Mode is off — BOLA may issue write-method probes to test object-level authorization on mutations, with success confirmed by re-reading the object (persistence verification) rather than by status code alone.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --auth-context alice:eyJ...:1 \
  --auth-context bob:eyJ...:1 \
  --allow-write-bola
```

### Destructive methods (`--bola-destructive-methods`)

**Description.** Comma-separated list of HTTP methods treated as destructive when `--allow-write-bola` is set. Values are uppercased. Defaults to `PATCH,PUT` (`DELETE` is intentionally excluded) when omitted. The module prefers the least-destructive available method (`PATCH` > `PUT` > `POST`) and only uses `DELETE` when you explicitly include it.

**Example:**

```bash
# Allow PATCH, PUT and DELETE as destructive verbs
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --allow-write-bola \
  --bola-destructive-methods PATCH,PUT,DELETE
```

### Composite-key probe (`--bola-composite`)

**Description.** Enables the composite-identifier probe (off by default). It discovers endpoints with two or more identifier slots (for example `/tenants/{tenant_id}/projects/{project_id}`), substitutes a single slot at a time, and detects parent-child (`BOLA_BROKEN_OBJECT_RELATIONSHIP`) and cross-tenant (`BOLA_CROSS_TENANT`) authorization violations.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --auth-context tenantA:eyJ...:1 \
  --auth-context tenantB:eyJ...:1 \
  --bola-composite
```

### ID leakage probe (`--bola-id-leakage`)

**Description.** Enables the object-identifier leakage probe (off by default). It harvests identifiers exposed by list, public, or feed endpoints and replays them under a lower-privilege or anonymous context. When a harvested identifier grants access it does not deserve, a `BOLA_ID_LEAKAGE` finding is raised. Identifier predictability is also assessed (sequential, timestamp-based, or time-based UUIDs are predictable) and reported as `BOLA_PREDICTABLE_IDENTIFIER`.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --auth-context user:eyJ...:1 \
  --bola-id-leakage
```

### Verb tampering (`--bola-verb-tampering`)

**Description.** Enables the HTTP verb-tampering technique (off by default), including the `X-HTTP-Method-Override` header variant. When the effective method is state-changing, the probe is gated by the destructive guardrails (`--allow-write-bola` and Safe Mode). Every probe preserves all other request components.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --bola-verb-tampering
```

### Parameter pollution (`--bola-parameter-pollution`)

**Description.** Enables the HTTP parameter-pollution technique (off by default). It supplies a duplicated identifier parameter (for example `?id=own&id=victim`) to probe inconsistent server-side parameter resolution, while preserving all other request components.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --bola-parameter-pollution
```

### Dry run (`--bola-dry-run`)

**Description.** Plans every destructive BOLA probe — recording the method, target URL, substituted identifier, and intended body — without issuing the request. Use it to preview exactly what a write-enabled run would send before authorizing it. Off by default.

**Example:**

```bash
python apileaks.py full \
  --target https://api.example.com \
  --modules bola \
  --allow-write-bola \
  --bola-dry-run
```

## ⚙️ Configuration (YAML)

BOLA options can also be set under `owasp_testing.bola_testing`. All fields have safe defaults, so an existing configuration that omits them loads unchanged and resolves to read-only behavior.

```yaml
owasp_testing:
  enabled_modules: ["bola"]

  bola_testing:
    enabled: true

    # Identifier discovery
    id_patterns: ["sequential", "guid", "uuid"]

    # Upper bound for ownership-aware sequential-id enumeration (default 25)
    enumeration_bound: 25

    # Safe Mode (usually set globally via --safe-mode / config.safe_mode)
    safe_mode: false

    # Advanced hardening — all off by default (read-only behavior preserved)
    allow_destructive: false          # opt-in for state-changing probes
    destructive_methods: ["PATCH", "PUT"]  # DELETE excluded by default
    enable_composite: false           # composite-key / cross-tenant probe
    enable_id_leakage: false          # identifier harvesting + predictability
    verb_tampering: false             # HTTP method-override technique
    parameter_pollution: false        # duplicate-identifier technique
    dry_run: false                    # plan destructive probes without sending
```

| Field | CLI equivalent | Default | Purpose |
|-------|----------------|---------|---------|
| `enumeration_bound` | — | `25` | Upper bound for sequential-id enumeration |
| `safe_mode` | `--safe-mode` | `false` | Restrict to safe methods |
| `allow_destructive` | `--allow-write-bola` | `false` | Authorize state-changing probes |
| `destructive_methods` | `--bola-destructive-methods` | `PATCH,PUT` | Verbs treated as destructive |
| `enable_composite` | `--bola-composite` | `false` | Composite / cross-tenant probe |
| `enable_id_leakage` | `--bola-id-leakage` | `false` | ID harvesting + predictability |
| `verb_tampering` | `--bola-verb-tampering` | `false` | Method-override technique |
| `parameter_pollution` | `--bola-parameter-pollution` | `false` | Duplicate-identifier technique |
| `dry_run` | `--bola-dry-run` | `false` | Plan destructive probes only |

## 🔍 Detection Techniques

- **Identifier substitution.** The original identifier is replaced at its exact path segment or query parameter, preserving every other segment and parameter, so each probe genuinely targets a different object.
- **Identity-aware comparison.** Two responses are the same object only when both expose a recognized identifying field with an equal value. Response size and word similarity are never used to decide identity.
- **Negative-control baseline.** Before deciding accessibility, the module requests a known-invalid identifier under the same context. Endpoints that return success for the invalid identifier are treated as non-discriminating, and accessibility findings for them are suppressed and logged.
- **Ownership-aware enumeration.** Sequential enumeration runs only for confirmed sequential integers; a finding is raised only when the accessed object's identifying field shows it belongs to another context. Non-sequential identifiers (GUID/UUID) are skipped with a log.
- **Persistence verification (write BOLA).** A mutation counts as successful only when the exact submitted value appears in a safe GET re-read of the object, independent of status/size/timing.

## 📊 Finding Categories

All BOLA findings map to OWASP **API1**.

| Category | Severity | Meaning |
|----------|----------|---------|
| `BOLA_ANONYMOUS_ACCESS` | CRITICAL | An object is accessible with no authentication |
| `BOLA_HORIZONTAL_ESCALATION` | CRITICAL | One user can access another user's object (identity-confirmed) |
| `BOLA_ACCOUNT_TAKEOVER` | CRITICAL | A credential field was mutated and persisted on a foreign object |
| `BOLA_OBJECT_ACCESS` | HIGH | Unauthorized access to an object |
| `BOLA_ID_ENUMERATION` | HIGH | Sequential enumeration reached objects owned by others |
| `BOLA_WRITE_ESCALATION` | HIGH | A non-credential field was mutated and persisted on a foreign object |
| `BOLA_CROSS_TENANT` | HIGH | Access to a child object belonging to a foreign tenant |
| `BOLA_BROKEN_OBJECT_RELATIONSHIP` | HIGH | Parent-child relationship not enforced across composite identifiers |
| `BOLA_STATE_MANIPULATION` | HIGH | Object state changed via an unauthorized state-manipulation probe |
| `BOLA_GUID_ENUMERATION` | MEDIUM | Enumeration signal on GUID-style identifiers |
| `BOLA_ID_LEAKAGE` | MEDIUM | A leaked identifier granted access under a lower-privilege context |
| `BOLA_PREDICTABLE_IDENTIFIER` | MEDIUM | Object identifiers are predictable (sequential / timestamp / UUIDv1) |

Each finding embeds evidence: the substituted and original identifiers, the matching identifying field and value, the auth context used, the negative-control comparison outcome, and (for writes) the persistence evidence.

## 🛠️ Remediation

- **Enforce object-level authorization on every request.** Check that the authenticated principal owns or is permitted to act on the referenced object — do not rely on authentication alone.
- **Use unpredictable identifiers.** Prefer random UUIDs (v4) over sequential integers, timestamps, or time-based UUIDs (v1).
- **Validate composite relationships.** For nested resources, confirm the child belongs to the parent (and the parent to the caller's tenant) rather than trusting either slot independently.
- **Do not leak identifiers.** Avoid exposing other users' object identifiers in list, public, or feed endpoints that a lower-privilege caller can harvest.
- **Apply consistent authorization across verbs.** Enforce the same ownership checks on write methods and reject method-override headers and duplicated identifier parameters.

---

The BOLA Testing Module provides comprehensive, low-false-positive detection of API1 vulnerabilities, from read-only enumeration to opt-in, persistence-verified write testing. 🛡️
