# Property Level Authorization Testing (API3)

The Property Level Authorization Module detects **OWASP API3 - Broken Object Property Level Authorization** vulnerabilities: cases where an API exposes sensitive fields that should be hidden, accepts privilege-escalation fields in request bodies, allows modification of read-only properties, or returns different fields to different auth contexts without proper justification.

The module runs in isolation as `apileaks owasp property --target URL` or as part of an orchestrated `scan` run.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [How the Module Works](#how-the-module-works)
- [Detector 1 — Sensitive Data Exposure](#detector-1--sensitive-data-exposure)
- [Detector 2 — Mass Assignment](#detector-2--mass-assignment)
- [Detector 3 — Read-Only Property Modification](#detector-3--read-only-property-modification)
- [Detector 4 — Undocumented Field Discovery](#detector-4--undocumented-field-discovery)
- [Command Reference](#command-reference)
- [Safe Mode Behavior](#safe-mode-behavior)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Attack Scenarios (OWASP API3:2023)](#attack-scenarios-owasp-api32023)
- [Remediation](#remediation)

---

## 🎯 Overview

API3 differs from API1 (BOLA) in scope: BOLA is about accessing *another user's object*; API3 is about accessing or manipulating *fields within your own or any object* that should be restricted. The four vulnerability patterns:

| Pattern | Example | Impact |
|---------|---------|--------|
| Sensitive field exposed | `password_hash` in GET /users/me response | Credential theft |
| Mass assignment | `role=admin` accepted in PATCH /users/me body | Privilege escalation |
| Read-only modification | `created_at` changed via PUT /users/123 | Data tampering |
| Undocumented field | `internal_flag` visible only to admin context | Information disclosure |

**Four detectors, all enabled by default:**

| Detector | Finding | Severity |
|----------|---------|----------|
| Sensitive field in response | `SENSITIVE_DATA_EXPOSURE` | CRITICAL |
| Dangerous field accepted in body | `MASS_ASSIGNMENT` | HIGH |
| Read-only field successfully modified | `READONLY_PROPERTY_MODIFICATION` | HIGH |
| Field visible only in certain auth contexts | `UNDOCUMENTED_FIELD` | MEDIUM |

---

## 🚀 Quick Start

```bash
# Single auth context — detects sensitive data exposure and undocumented fields
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Two auth contexts — unlocks all four detectors (recommended)
python apileaks.py owasp property \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1

# Custom sensitive field list
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-sensitive-fields password \
  --property-sensitive-fields api_key \
  --property-sensitive-fields iban \
  --property-sensitive-fields cvv

# Custom mass-assignment field list
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-mass-assignment-fields role \
  --property-mass-assignment-fields is_admin \
  --property-mass-assignment-fields balance

# Safe read-only mode
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --safe-mode

# Run alongside other modules
python apileaks.py scan \
  --target https://api.example.com \
  --modules property,bola,auth
```

---

## How the Module Works

The module runs four sequential detectors against every discovered endpoint. Most detectors require at least one auth context; Detectors 2 and 3 require a state-changing method (POST/PUT/PATCH) and are suppressed in Safe Mode.

**Auth context handling:**
- With **one** context — Detectors 1 and 4 run; 2 and 3 run if the endpoint accepts state-changing methods.
- With **two or more** contexts — all four detectors run. Detector 4 compares fields across contexts to surface undocumented fields.

**Field sources:**
- `sensitive_fields` config → Detector 1 (exposure check against response)
- `mass_assignment_fields` config → Detector 2 (injection into request body)
- Built-in read-only field patterns (`id`, `created_at`, `updated_at`, `version`, `checksum`) → Detector 3
- All contexts compared → Detector 4

---

## Detector 1 — Sensitive Data Exposure

**Finding:** `SENSITIVE_DATA_EXPOSURE` · **Severity:** CRITICAL · **OWASP:** API3

Issues a GET request to each endpoint with each auth context. Parses the JSON response and checks every field name and value against the configured `sensitive_fields` list (case-insensitive). Also detects values whose shape matches known sensitive patterns (API key format, SSN, credit card number).

**Built-in sensitive fields** (overridable with `--property-sensitive-fields`):

```
password   api_key   secret   token   ssn   credit_card
```

The module also detects high-entropy strings that match credential shapes (e.g. `sk_live_...`, `AKIA...`, `-----BEGIN RSA PRIVATE KEY-----`).

```bash
# Default sensitive field check
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Domain-specific sensitive fields (fintech)
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-sensitive-fields password \
  --property-sensitive-fields iban \
  --property-sensitive-fields cvv \
  --property-sensitive-fields swift_code \
  --property-sensitive-fields pin

# Domain-specific sensitive fields (SaaS)
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-sensitive-fields webhook_secret \
  --property-sensitive-fields private_key \
  --property-sensitive-fields client_secret \
  --property-sensitive-fields access_token
```

> **Severity classification:** Severity escalates from MEDIUM → HIGH → CRITICAL based on the privilege level of the auth context that receives the sensitive field and the type of data. A regular user receiving a `password_hash` is CRITICAL; the same field visible to an admin-only context is HIGH.

---

## Detector 2 — Mass Assignment

**Finding:** `MASS_ASSIGNMENT` · **Severity:** HIGH (CRITICAL for privilege fields) · **OWASP:** API3

Sends POST/PUT/PATCH requests to each endpoint, injecting each configured `mass_assignment_fields` value into the request body. Compares the response against a baseline (same body without the dangerous field). If the dangerous field is reflected back, or the response differs from the baseline in ways indicating the field was processed, a finding is emitted.

**Built-in mass-assignment fields** (overridable with `--property-mass-assignment-fields`). The module combines config fields with a built-in set covering common privilege-escalation paths:

```
is_admin    role        permissions    user_id
id          account_id  owner_id       created_by
is_active   enabled     status         verified
balance     credit      points         score
```

```bash
# Default mass-assignment check
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom fields for a specific domain
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-mass-assignment-fields subscription_tier \
  --property-mass-assignment-fields account_type \
  --property-mass-assignment-fields trial_expires_at
```

> **Note:** Detector 2 is automatically skipped when `--safe-mode` is active because it issues state-changing POST/PUT/PATCH requests.

---

## Detector 3 — Read-Only Property Modification

**Finding:** `READONLY_PROPERTY_MODIFICATION` · **Severity:** HIGH · **OWASP:** API3

Issues a baseline GET to capture existing field values, then sends a PUT/PATCH with modified values for known read-only fields (`id`, `created_at`, `updated_at`, `timestamp`, `version`, `checksum`, `created_by`). Re-fetches the object and checks whether the read-only field value changed.

```bash
# Runs automatically as part of the full property scan
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Skip in safe mode (no state-changing probes)
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --safe-mode
```

---

## Detector 4 — Undocumented Field Discovery

**Finding:** `UNDOCUMENTED_FIELD` · **Severity:** MEDIUM · **OWASP:** API3

Issues GET requests to each endpoint with each configured auth context. Compares the set of fields returned across contexts — fields that appear only in higher-privilege responses are flagged as potentially undocumented. Also flags fields that appear inconsistently across multiple requests to the same endpoint.

This detector is most effective with two or more auth contexts at different privilege levels:

```bash
# Compare user vs admin context — surfaces admin-only fields
python apileaks.py owasp property \
  --target https://api.example.com \
  --auth-context admin:ADMIN_TOKEN:100 \
  --auth-context user:USER_TOKEN:1
```

---

## 📖 Command Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--property-sensitive-fields FIELD` | Field name to flag as sensitive in API responses (repeatable). Replaces the built-in list when any value is supplied. | `password`, `api_key`, `secret`, `token`, `ssn`, `credit_card` |
| `--property-mass-assignment-fields FIELD` | Dangerous field name to inject in mass-assignment probes (repeatable). Replaces the built-in list when any value is supplied. | `is_admin`, `role`, `permissions`, `user_id` |

### `--property-sensitive-fields`

Replaces the built-in sensitive-field list when any value is supplied. The module checks response JSON for field names matching (case-insensitive) any configured pattern.

```bash
# Healthcare domain
python apileaks.py owasp property \
  --target https://api.example.com \
  --property-sensitive-fields medical_record_number \
  --property-sensitive-fields diagnosis \
  --property-sensitive-fields prescription

# E-commerce domain
python apileaks.py owasp property \
  --target https://api.example.com \
  --property-sensitive-fields card_number \
  --property-sensitive-fields cvv \
  --property-sensitive-fields billing_address
```

### `--property-mass-assignment-fields`

Replaces the built-in mass-assignment field list when any value is supplied. For each field, the module generates a plausible test value (e.g. `true` for boolean fields, `"admin"` for role-like string fields) and injects it into the request body.

```bash
# Game/platform with custom privilege model
python apileaks.py owasp property \
  --target https://api.example.com \
  --property-mass-assignment-fields vip_status \
  --property-mass-assignment-fields premium \
  --property-mass-assignment-fields coins
```

---

## 🔒 Safe Mode Behavior

| Behavior | Normal | Safe mode |
|----------|--------|-----------|
| Sensitive data exposure (GET) | ✅ | ✅ |
| Undocumented field discovery (GET) | ✅ | ✅ |
| Mass assignment (POST/PUT/PATCH) | ✅ | ❌ skipped |
| Read-only modification (PUT/PATCH) | ✅ | ❌ skipped |

```bash
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --safe-mode
```

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["property"]

  property_testing:
    enabled: true
    safe_mode: false

    # Detector 1: field names flagged as sensitive in responses.
    # The module also detects values whose shape matches known credential
    # patterns (API keys, SSNs, credit card numbers) regardless of field name.
    sensitive_fields:
      - "password"
      - "api_key"
      - "secret"
      - "token"
      - "ssn"
      - "credit_card"

    # Detector 2: field names injected as mass-assignment probes.
    # These are combined with the built-in privilege-escalation field set
    # (is_admin, role, balance, etc.) — config fields are additive.
    mass_assignment_fields:
      - "is_admin"
      - "role"
      - "permissions"
      - "user_id"
```

**Authentication contexts for multi-context testing:**

```yaml
authentication:
  contexts:
    - name: "anonymous"
      type: "bearer"
      token: ""
      privilege_level: 0
    - name: "user"
      type: "bearer"
      token: "${USER_TOKEN}"
      privilege_level: 1
    - name: "admin"
      type: "bearer"
      token: "${ADMIN_TOKEN}"
      privilege_level: 3
```

**Field reference:**

| Field | CLI equivalent | Default | Purpose |
|-------|----------------|---------|---------|
| `sensitive_fields` | `--property-sensitive-fields` | 6 built-in fields | Detector 1 field list |
| `mass_assignment_fields` | `--property-mass-assignment-fields` | 4 built-in fields | Detector 2 injection targets |
| `safe_mode` | `--safe-mode` | `false` | Skip state-changing probes |

---

## 📊 Finding Categories

### `SENSITIVE_DATA_EXPOSURE`

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| OWASP | API3 |
| Description | A sensitive field (password, API key, SSN, credit card number) was returned in an API response to an auth context that should not have access to it. |
| Evidence | Field name, field path in the JSON response, auth context name (never the token value), endpoint, and a truncated value snippet. |
| Recommendation | Apply field-level authorization: filter sensitive fields from response serializers based on the caller's role. Never include passwords, API keys, or credentials in API responses. Use separate DTOs per privilege level. |

### `MASS_ASSIGNMENT`

| Field | Value |
|-------|-------|
| Severity | HIGH (CRITICAL for `role`, `is_admin` and other privilege-escalation fields) |
| OWASP | API3 |
| Description | A dangerous field (`role`, `is_admin`, `balance`, etc.) was accepted in the request body and reflected in the response or caused a detectable change, indicating the server bound the raw request body to the model without filtering. |
| Evidence | Injected field name, injected value, baseline response delta, endpoint and method. |
| Recommendation | Use an allowlist (DTO / request schema) to restrict which fields the API accepts. Never bind the raw request body to the user or account model. Explicitly block privilege, identity, and financial fields from end-user write paths. |

### `READONLY_PROPERTY_MODIFICATION`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API3 |
| Description | A field that should be immutable (`created_at`, `id`, `version`, `checksum`) was successfully changed by a client write request. The re-fetched object confirms the change persisted. |
| Evidence | Field name, original value, new value, endpoint and method used. |
| Recommendation | Strip read-only fields from all update operations before persisting. Use database constraints (`NOT NULL`, triggers, or generated columns) to enforce immutability. Log and alert on attempts to modify immutable fields. |

### `UNDOCUMENTED_FIELD`

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| OWASP | API3 |
| Description | A response field appeared only for higher-privilege auth contexts or inconsistently across requests, indicating the API leaks internal or admin-only data through the same endpoint used by regular users. |
| Evidence | Field name, the context(s) that received it, the context(s) that did not, endpoint. |
| Recommendation | Document all API response fields and implement consistent field filtering based on the caller's role. Use role-based serializers so each privilege level gets a well-defined, stable field set. |

---

## 🎭 Attack Scenarios (OWASP API3:2023)

### Scenario 1 — API key exposure

A mobile app calls `GET /api/users/me` to load the user profile. The API returns the full database model, including the `api_key` field. An attacker who intercepts or replays this request extracts valid API keys and uses them to authenticate as the victim.

**What apileaks detects:** `api_key` matches the built-in sensitive-field list. The GET response is checked for the field name (case-insensitive). `SENSITIVE_DATA_EXPOSURE` CRITICAL is emitted.

```bash
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-sensitive-fields api_key \
  --property-sensitive-fields secret
```

### Scenario 2 — Role escalation via mass assignment

A user sends `PATCH /api/users/me` with `{"name": "Alice", "role": "admin"}`. The server binds the entire request body to the User model without filtering. The `role` field is updated to `admin`, giving the user full administrative access.

**What apileaks detects:** `role` is in the built-in mass-assignment field list. The module sends a PATCH with `{"role": "admin"}` alongside a baseline PATCH without it. The response difference (or re-fetch) confirms the field was applied. `MASS_ASSIGNMENT` CRITICAL is emitted.

```bash
python apileaks.py owasp property \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --property-mass-assignment-fields role \
  --property-mass-assignment-fields is_admin
```

### Scenario 3 — Account takeover via balance manipulation

A fintech API accepts `{"amount": 100, "balance": 99999}` in a transfer endpoint. The `balance` field is bound directly to the account model, allowing the attacker to set their own balance to an arbitrary value.

**What apileaks detects:** `balance` is in the built-in mass-assignment field list. The injected value is reflected back in the response. `MASS_ASSIGNMENT` HIGH is emitted.

---

## 🛡️ Remediation

### Sensitive data exposure

- **Response serializer allowlists:** Define the exact fields each endpoint returns for each role. Never serialize the full model. Use separate DTO classes per privilege level (`UserResponseDTO`, `AdminUserResponseDTO`).
- **Strip by default:** Start from an empty response object and add only the fields the caller is authorized to see, rather than starting from the full model and removing sensitive fields.
- **Never return credentials:** Passwords (hashed or otherwise), API keys, private keys, and session tokens must never appear in API responses. Return them only at creation time (once, over TLS) and never again.
- **Audit regularly:** Automated API response scanning in your CI/CD pipeline catches new sensitive fields added without proper filtering.

### Mass assignment

- **Input DTO allowlists:** Accept only explicitly declared fields. Any field not in the DTO is rejected with a `400 Bad Request` — not silently ignored.
- **Role-gated fields:** For fields that admins can set but users cannot (e.g. `role`, `is_active`), use a separate privileged endpoint or a separate DTO that is only bound when the caller's role is verified.
- **Never bind raw request body:** Framework `mass_assignment` or `auto_bind` features are dangerous. Always use an explicit DTO or field-by-field assignment.

### Read-only property protection

- **Strip on write:** Remove read-only fields from the payload before any persistence operation.
- **Database constraints:** Use `GENERATED ALWAYS` columns, triggers, or application-layer constraints to enforce immutability.
- **Version fields for optimistic locking:** If you use `version` or `revision` fields for concurrency control, verify the client-supplied value matches the stored value — never let the client set it arbitrarily.

### Undocumented field exposure

- **One serializer per role:** Implement `UserSerializer`, `AdminUserSerializer`, etc. that explicitly declare their field set. The field sets must be documented and reviewed at each release.
- **CI/CD API contract tests:** Use snapshot tests or OpenAPI schema validation to catch any new field that appears in production responses without a spec update.

---

See also: [OWASP Coverage](README.md) · [BOLA Testing (API1)](bola-testing.md) · [Function Level Auth (API5)](function-level-auth.md) · [OWASP Command Reference](../owasp-command.md) · [Scan Guide](../scan-guide.md)
