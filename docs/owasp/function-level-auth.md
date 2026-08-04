# Function Level Authorization Testing (API5)

The Function Level Authorization Module detects **OWASP API5 - Broken Function Level Authorization (BFLA)** vulnerabilities: cases where an API exposes administrative or privileged functions to users who shouldn't have access — either because authorization is missing entirely, tied to the wrong HTTP method, bypassable via header injection, or missing in older API versions.

The module runs in isolation as `apileaks owasp function_auth --target URL` or as part of an orchestrated `scan` run.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Grey-Box Approach](#grey-box-approach)
- [Level 1 — Multi-Token Matrix Replay](#level-1--multi-token-matrix-replay)
- [Level 2a — HTTP Verb Tampering](#level-2a--http-verb-tampering)
- [Level 2b — X-HTTP-Method-Override](#level-2b--x-http-method-override)
- [Level 3 — Mass-Assignment Role Injection](#level-3--mass-assignment-role-injection)
- [Level 4 — API Version Downgrade](#level-4--api-version-downgrade)
- [Command Reference](#command-reference)
- [Safe Mode Behavior](#safe-mode-behavior)
- [BFLA Output Matrix](#bfla-output-matrix)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Attack Scenarios (OWASP API5:2023)](#attack-scenarios-owasp-api52023)
- [Remediation](#remediation)

---

## 🎯 Overview

BFLA is distinct from BOLA (API1): BOLA is about accessing objects belonging to other users at the same privilege level; BFLA is about accessing **functions** reserved for higher privilege levels — admin endpoints, destructive operations, bulk exports, or role-management flows.

Authorization checks at the function level are more complex than object-level checks and are often inconsistently applied: they may be enforced in v3 but absent in v1, enforced for DELETE but not for PATCH, or enforced at the API gateway (method-level) but not in the backend handler.

**Four attack levels, each independently configurable:**

| Level | Attack | Findings |
|-------|--------|---------|
| L1 | Multi-token matrix: replay admin endpoints with low-priv / anonymous tokens | `BFLA_ADMIN_ENDPOINT_EXPOSED` · `BFLA_LOW_PRIV_ACCESS` · `BFLA_ANONYMOUS_ADMIN_ACCESS` |
| L2a | HTTP verb tampering: try DELETE/PUT/PATCH on endpoints only protected for GET | `BFLA_VERB_TAMPERING` |
| L2b | X-HTTP-Method-Override: bypass gateway via override header | `BFLA_METHOD_OVERRIDE` |
| L3 | Mass-assignment role injection: inject `role=admin` in registration / profile update | `BFLA_MASS_ASSIGNMENT_ROLE` |
| L4 | API version downgrade: replay protected v3 functions against unpatched v1 | `BFLA_VERSION_DOWNGRADE` |

---

## 🚀 Quick Start

```bash
# Minimal scan — all four levels, built-in heuristics
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:eyJhbGciOiJSUzI1NiJ9...:100 \
  --auth-context user:eyJhbGciOiJSUzI1NiJ9...:1

# Custom admin path prefixes
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-admin-endpoints /api/v3/admin \
  --bfla-admin-endpoints /management \
  --bfla-admin-endpoints /internal

# Persist the full probe matrix for downstream analysis
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-output-file /tmp/bfla-matrix.json

# Read-only safe mode (GET probes only)
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --safe-mode

# Run alongside other modules
python apileaks.py scan \
  --target https://api.example.com \
  --modules function_auth,bola,auth
```

---

## Grey-Box Approach

The module uses a **two-phase grey-box methodology** requiring at least two auth contexts at different privilege levels:

```
Phase 1 — Mapping (high-privilege token)
  ↓  Probe every discovered endpoint with the HIGHEST-privilege context
  ↓  Score each endpoint for admin indicators (URL path keywords, action words, HTTP method)
  ↓  Collect AdminEndpointRecords for any endpoint with score > 0 or listed in config

Phase 2 — Replay (low-privilege / anonymous tokens)
  ↓  Replay each AdminEndpointRecord with every LOWER-privilege context
  ↓  Replay anonymously (no token) for each record
  ↓  BFLA confirmed when a 2xx response is returned by a non-privileged context
```

**How to supply auth contexts:**

```bash
# Format: --auth-context <name>:<token>:<privilege_level>
# privilege_level: 100 = admin, 1 = regular user, 0 = anonymous
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_JWT:100 \
  --auth-context user:USER_JWT:1
```

The module sorts contexts by privilege level descending: the highest is used for mapping, all others for replay. If only one context is supplied, anonymous replay still runs.

---

## Level 1 — Multi-Token Matrix Replay

**Findings:** `BFLA_ADMIN_ENDPOINT_EXPOSED` (MEDIUM) · `BFLA_LOW_PRIV_ACCESS` (CRITICAL) · `BFLA_ANONYMOUS_ADMIN_ACCESS` (CRITICAL)

### Admin endpoint heuristics

An endpoint is scored as administrative when its URL contains:
- **Path keywords** (`admin`, `administrator`, `management`, `dashboard`, `panel`, `config`, `internal`, `restricted`, `staff`, `operator`, `backstage`, …)
- **Action keywords** (`delete`, `remove`, `purge`, `approve`, `reject`, `ban`, `suspend`, `promote`, `export`, `backup`, …)
- **Privileged HTTP methods** (DELETE, PUT, PATCH, POST raise the score)

The operator can also explicitly list known admin paths via `--bfla-admin-endpoints`.

### Detection logic

```
AdminEndpointRecord found for endpoint?
  → emit BFLA_ADMIN_ENDPOINT_EXPOSED (MEDIUM) — informational surface finding
  → replay with each lower-privilege context:
      → 2xx returned? → BFLA_LOW_PRIV_ACCESS (CRITICAL)
  → replay anonymously (no token):
      → 2xx returned? → BFLA_ANONYMOUS_ADMIN_ACCESS (CRITICAL)
```

### Examples

```bash
# Two-token grey-box scan
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1

# With explicit admin endpoint seeds
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-admin-endpoints /api/v1/admin/users \
  --bfla-admin-endpoints /api/v1/admin/export \
  --bfla-admin-endpoints /management/dashboard
```

---

## Level 2a — HTTP Verb Tampering

**Finding:** `BFLA_VERB_TAMPERING` · **Severity:** HIGH · **OWASP:** API5

Authorization checks that are restricted to a specific HTTP method (e.g. a route only blocks DELETE but allows GET, PUT, and PATCH) allow attackers to perform privileged operations simply by changing the verb.

### What it tests

For each mapped admin endpoint, the module sends each configured `dangerous_methods` (DELETE, PUT, PATCH by default) with a low-privilege token. A 2xx response confirms the check is method-specific.

```bash
# Default — tests DELETE, PUT, PATCH
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1

# Custom method set
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-dangerous-methods DELETE,PUT,PATCH,POST
```

---

## Level 2b — X-HTTP-Method-Override

**Finding:** `BFLA_METHOD_OVERRIDE` · **Severity:** HIGH · **OWASP:** API5

API gateways and load balancers often route on the declared HTTP method. The `X-HTTP-Method-Override` header (and variants) tells the backend to execute a different method. If the gateway allows GET but the backend honors the override header, an attacker can execute DELETE via a GET request.

### Override header variants tested

```
X-HTTP-Method-Override
X-HTTP-Method
X-Method-Override
_method
```

Each variant is tested with DELETE, PATCH, and PUT as the override target. The first confirmed bypass per endpoint stops further probing for that record.

### Example

```bash
# Enabled by default, suppressed in safe mode
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1
```

---

## Level 3 — Mass-Assignment Role Injection

**Finding:** `BFLA_MASS_ASSIGNMENT_ROLE` · **Severity:** CRITICAL · **OWASP:** API5

Some APIs bind the request body to the user model directly without filtering which fields are permitted. An attacker can register as an admin by including `"role": "admin"` in the registration body.

### What it tests

For each endpoint whose URL matches a registration or profile-update pattern (`/register`, `/signup`, `/create-user`, `/users`, `/profile`, `/account`) and whose method carries a body (POST/PUT/PATCH), the module:

1. Captures a **baseline** response with a minimal body (username, email, password — no role field).
2. Injects each combination of `(role_field, role_value)` and compares the response.

A finding is confirmed when the 2xx response echoes the injected role value or field name back, or when the response code differs from the baseline.

```bash
# Default role fields: role, is_admin, admin, privilege, access_level, etc.
# Default role values: admin, administrator, ADMIN, root, owner, etc.
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context user:USER_TOKEN:1

# Custom fields and values for a specific application
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context user:USER_TOKEN:1 \
  --bfla-role-fields account_type \
  --bfla-role-fields tier \
  --bfla-role-values premium \
  --bfla-role-values enterprise
```

> **Note:** Level 3 is automatically skipped when `--safe-mode` is active because it issues state-changing POST/PUT/PATCH probes.

---

## Level 4 — API Version Downgrade

**Finding:** `BFLA_VERSION_DOWNGRADE` · **Severity:** HIGH · **OWASP:** API5

Authorization patches are frequently applied to the latest API version but not backported to older versions. An attacker who finds that `GET /api/v3/admin/users` returns 403 can simply try `GET /api/v1/admin/users` and get a 200.

### What it tests

For each admin endpoint with a versioned URL segment (`/v3/`), the module replays the request against all lower version numbers from the `api_versions` list. A 2xx on any older version confirms that the authorization patch was not backported.

```bash
# Default versions: v0, v1, v2, v3, v4
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1

# Explicit version set
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-api-versions v1,v2,v3,v4,v5
```

---

## 📖 Command Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--bfla-admin-endpoints PATH` | URL path prefix identifying an admin endpoint (repeatable). Replaces the built-in list when any value is supplied. | `/admin`, `/api/admin`, `/management`, `/dashboard` |
| `--bfla-dangerous-methods METHODS` | Comma-separated HTTP methods for L2a verb-tampering probes | `DELETE,PUT,PATCH` |
| `--bfla-role-fields FIELD` | JSON field name for L3 mass-assignment injection (repeatable). Replaces built-in list when any value supplied. | `role`, `is_admin`, `admin`, `privilege`, … |
| `--bfla-role-values VALUE` | Role value to inject in L3 probes (repeatable). Replaces built-in list when any value supplied. | `admin`, `administrator`, `ADMIN`, `root`, … |
| `--bfla-api-versions VERSIONS` | Comma-separated API version strings for L4 downgrade probes | `v0,v1,v2,v3,v4` |
| `--bfla-output-file PATH` | JSON file path for the full BFLA probe matrix | — (not saved) |
| `--allow-destructive-bfla` | Allow state-changing (DELETE/PUT) replay probes against admin endpoints | off |

### `--bfla-admin-endpoints`

Supplements or replaces the heuristic admin-endpoint detection. Pass once per path prefix.

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-admin-endpoints /api/v3/admin \
  --bfla-admin-endpoints /backstage \
  --bfla-admin-endpoints /ops/console
```

### `--bfla-dangerous-methods`

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --bfla-dangerous-methods DELETE,PUT,PATCH,POST
```

### `--bfla-role-fields` and `--bfla-role-values`

```bash
# Domain-specific field/value combinations
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context user:USER_TOKEN:1 \
  --bfla-role-fields account_type \
  --bfla-role-fields subscription_tier \
  --bfla-role-values enterprise \
  --bfla-role-values superuser
```

### `--bfla-output-file`

The output file is a JSON object with `total_probes`, `confirmed_bfla`, and a `results` array of `BFLAProbeResult` objects. Each result records the endpoint, method, probe type, auth context name (never the token), status code, and whether access was confirmed.

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-output-file /tmp/bfla-matrix.json

# Read confirmed BFLA entries
python3 -c "
import json
with open('/tmp/bfla-matrix.json') as f:
    data = json.load(f)
print(f'Total: {data[\"total_probes\"]}  Confirmed: {data[\"confirmed_bfla\"]}')
for r in data['results']:
    if r['is_confirmed']:
        print(f'  [{r[\"probe_type\"]}] {r[\"method\"]} {r[\"endpoint\"]}')
"
```

### `--allow-destructive-bfla`

By default, the L1 replay uses only GET (safe read) probes to confirm that admin endpoints are accessible with lower-privilege tokens. With `--allow-destructive-bfla` the module also issues DELETE/PUT/PATCH replays, confirming write-level BFLA.

```bash
# Read-only replay only (default)
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1

# Destructive replay opt-in
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --allow-destructive-bfla
```

---

## 🔒 Safe Mode Behavior

| Behavior | Normal | Safe mode |
|----------|--------|-----------|
| Admin endpoint mapping (GET/HEAD) | ✅ | ✅ |
| Admin endpoint mapping (state-changing methods) | ✅ | ❌ → downgraded to GET |
| L1 replay (GET) | ✅ | ✅ |
| L1 replay (DELETE/PUT/PATCH) | ✅ with `--allow-destructive-bfla` | ❌ |
| L2a verb tampering (DELETE/PUT/PATCH) | ✅ | ❌ skipped |
| L2b method-override injection | ✅ | ❌ skipped |
| L3 mass-assignment (POST/PUT/PATCH) | ✅ | ❌ skipped entirely |
| L4 version downgrade (GET only) | ✅ | ✅ |
| L4 version downgrade (state-changing) | ✅ | ❌ → downgraded to GET |

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --safe-mode
```

---

## 🗄️ BFLA Output Matrix

When `--bfla-output-file` is set, a JSON file is written after the scan with the full probe matrix. Structure:

```json
{
  "generated_at": "2026-07-11T20:00:00+00:00",
  "total_probes": 42,
  "confirmed_bfla": 7,
  "results": [
    {
      "endpoint": "https://api.example.com/api/v3/admin/users",
      "method": "GET",
      "probe_type": "low_priv",
      "token_context": "user",
      "status_code": 200,
      "response_size": 1024,
      "response_time": 0.12,
      "is_confirmed": true,
      "evidence": "...",
      "payload": null,
      "response_snippet": "..."
    }
  ]
}
```

`probe_type` values: `low_priv`, `anonymous`, `verb_tamper`, `method_override`, `mass_assign`, `version_downgrade`.

`token_context` is always the **auth context name**, never the token value.

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["function_auth"]

  function_auth_testing:
    enabled: true

    # Phase 1: explicit admin path prefixes (additive to heuristics)
    admin_endpoints:
      - "/admin"
      - "/api/admin"
      - "/management"
      - "/dashboard"

    # Level 2a: verb-tampering HTTP methods
    dangerous_methods:
      - "DELETE"
      - "PUT"
      - "PATCH"

    # Safe mode: read-only probes only
    safe_mode: false

    # Opt-in for state-changing (DELETE/PUT/PATCH) replay probes
    allow_destructive: false

    # Level 3: mass-assignment role injection fields and values
    role_fields:
      - "role"
      - "is_admin"
      - "admin"
      - "privilege"
      - "access_level"

    role_values:
      - "admin"
      - "administrator"
      - "ADMIN"
      - "root"
      - "owner"

    # Level 4: API version strings for downgrade probes
    api_versions:
      - "v0"
      - "v1"
      - "v2"
      - "v3"
      - "v4"

    # Persist full probe matrix to JSON (null = disabled)
    bfla_output_file: null
```

**Field reference:**

| Field | CLI equivalent | Default | Purpose |
|-------|----------------|---------|---------|
| `admin_endpoints` | `--bfla-admin-endpoints` | 4 built-in paths | Explicit admin path prefixes for mapping phase |
| `dangerous_methods` | `--bfla-dangerous-methods` | `DELETE,PUT,PATCH` | L2a verb-tamper methods |
| `safe_mode` | `--safe-mode` | `false` | Read-only probes only |
| `allow_destructive` | `--allow-destructive-bfla` | `false` | State-changing L1 replay opt-in |
| `role_fields` | `--bfla-role-fields` | 13 built-in fields | L3 mass-assignment field names |
| `role_values` | `--bfla-role-values` | 8 built-in values | L3 mass-assignment role values |
| `api_versions` | `--bfla-api-versions` | `v0,v1,v2,v3,v4` | L4 version downgrade targets |
| `bfla_output_file` | `--bfla-output-file` | `null` | JSON probe matrix output path |

---

## 📊 Finding Categories

### `BFLA_ADMIN_ENDPOINT_EXPOSED`

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| OWASP | API5 |
| Description | An administrative endpoint was accessible with the highest-privilege token and scored above zero on admin heuristics. Informational — confirms the admin surface exists. |

### `BFLA_ANONYMOUS_ADMIN_ACCESS`

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| OWASP | API5 |
| Description | An administrative endpoint returned 2xx for an unauthenticated request (no token). No authentication required. |
| Recommendation | Require authentication for all administrative endpoints. Deny all access by default; require explicit grants. |

### `BFLA_LOW_PRIV_ACCESS`

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| OWASP | API5 |
| Description | A low-privilege token gained access to an endpoint that should be restricted to higher-privilege roles. |
| Recommendation | Enforce role-based access control at the function level inside each controller/handler, not only at the gateway. |

### `BFLA_VERB_TAMPERING`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API5 |
| Description | An endpoint that restricts access for the original HTTP method allowed a state-changing verb (DELETE/PUT/PATCH) with a low-privilege token. |
| Recommendation | Apply authorization checks independently of the HTTP method. Never restrict protection to a single verb on the same route pattern. |

### `BFLA_METHOD_OVERRIDE`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API5 |
| Description | A GET request with an `X-HTTP-Method-Override` header bypassed gateway authorization and executed a privileged operation. |
| Recommendation | Disable or strictly validate method-override headers. If required for legacy clients, enforce the same authorization for the overridden method in the backend. |

### `BFLA_MASS_ASSIGNMENT_ROLE`

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| OWASP | API5 |
| Description | Injecting a privilege field (`role=admin`) in a registration or profile-update body was accepted and the elevated role was assigned. |
| Recommendation | Use an allowlist (DTO / request schema) to restrict which fields the API accepts. Explicitly block role, admin, and privilege fields from being set by end users. |

### `BFLA_VERSION_DOWNGRADE`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API5 |
| Description | An authorization patch applied to a newer API version was not backported; the same function on an older version (`/v1/`) returns 200 for a low-privilege token. |
| Recommendation | Apply authorization patches to ALL active API versions simultaneously. Decommission unpatched older versions. Use a shared authorization library across all versions. |

---

## 🎭 Attack Scenarios (OWASP API5:2023)

### Scenario 1 — Invite escalation via method change

During registration, a mobile app calls `GET /api/invites/{guid}`. An attacker duplicates the request, changes the method to `POST /api/invites/new`, and sends `{"email": "attacker@example.com", "role": "admin"}`. The endpoint has no function-level authorization check and creates an admin invite.

**What apileaks detects:** `/api/invites/new` (POST) matches action keywords (`new` → `create`). L3 mass-assignment injects `role=admin` into the POST body. The response echoes the role → `BFLA_MASS_ASSIGNMENT_ROLE` CRITICAL.

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context user:USER_TOKEN:1 \
  --bfla-role-fields role \
  --bfla-role-values admin
```

### Scenario 2 — Unauthenticated user list access

`GET /api/admin/v1/users/all` is intended only for administrators but has no authorization check. An attacker guesses the URL structure and accesses it without any token.

**What apileaks detects:** URL contains `admin` keyword → scored as administrative. Admin map confirms 200 with high-priv token. Anonymous replay also returns 200 → `BFLA_ANONYMOUS_ADMIN_ACCESS` CRITICAL.

```bash
python apileaks.py owasp function_auth \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1 \
  --bfla-admin-endpoints /api/admin/v1/users/all
```

---

## 🛡️ Remediation

### Core principle: deny all by default

> "The enforcement mechanism(s) should deny all access by default, requiring explicit grants to specific roles for access to every function." — OWASP API5:2023

### Practical implementation

- **Centralized authorization library:** Use a single authorization component invoked by every handler. Never implement ad-hoc permission checks inline.
- **Abstract admin controller:** All administrative controllers should inherit from an `AdminController` base that enforces the role check before any handler logic executes.
- **Method-independent checks:** The role check must fire regardless of which HTTP method is used. Route-level middleware that only runs for specific methods will be bypassed.
- **Version parity:** When applying an authorization fix, apply it to every active API version in the same deployment. Use feature flags or shared middleware to avoid version drift.
- **Input DTO allowlists:** Registration and profile-update endpoints must accept only explicitly declared fields. Use a strict DTO/schema that omits `role`, `is_admin`, and any other privilege field. Reject unknown fields rather than ignoring them.
- **Gateway + backend defence-in-depth:** The API gateway is not the last line of defence. Always re-check authorization inside the service/controller, assuming the gateway can be bypassed.

---

See also: [OWASP Coverage](README.md) · [BOLA Testing (API1)](bola-testing.md) · [Business Flows (API6)](business-flows.md) · [OWASP Command Reference](../owasp-command.md) · [Scan Guide](../scan-guide.md)
