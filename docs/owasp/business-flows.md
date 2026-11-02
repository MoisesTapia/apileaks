# Business Flows Testing (API6)

The Business Flows Testing Module detects **OWASP API6 - Unrestricted Access to Sensitive Business Flows** vulnerabilities: cases where an API exposes sensitive business operations (checkout, ticket booking, referral programs, coupon redemption…) without the controls needed to prevent automated abuse.

The module runs in isolation as `apileaks owasp business_flow --target URL` or as part of an orchestrated `scan` run.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [How the Module Identifies Sensitive Flows](#how-the-module-identifies-sensitive-flows)
- [Detector 1 — Rate-Limit Absence](#detector-1--rate-limit-absence)
- [Detector 2 — Quota / Resource Decrement](#detector-2--quota--resource-decrement)
- [Detector 3 — Multi-Step Flow Bypass](#detector-3--multi-step-flow-bypass)
- [Command Reference](#command-reference)
- [Safe Mode Behavior](#safe-mode-behavior)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Attack Scenarios (OWASP API6:2023)](#attack-scenarios-owasp-api62023)
- [Remediation](#remediation)

---

## 🎯 Overview

API6 is distinct from the other OWASP categories because it typically has **no technical impact** — the exploit doesn't crash the server or leak credentials. The damage is business-level: stock is drained by scalpers, airline seats are hoarded and released at a discount, a referral program is gamed to mint fake credits. Automated abuse of these flows is easy when the API has no controls, and the attacker doesn't need elevated privileges.

An API endpoint is vulnerable when it exposes a sensitive business flow without appropriately restricting automated access to it.

**Three detectors, all enabled by default:**

| Detector | Finding | Severity |
|----------|---------|----------|
| N requests accepted with no throttling | `BUSINESS_FLOW_NO_LIMIT` | HIGH |
| Inventory / quota not decremented across N requests | `BUSINESS_FLOW_QUOTA_NOT_ENFORCED` | HIGH |
| Complete multi-step transaction can be repeated N times | `BUSINESS_FLOW_MULTI_STEP_BYPASS` | HIGH |

---

## 🚀 Quick Start

```bash
# Minimal scan — all three detectors with built-in defaults
python apileaks.py owasp business_flow --target https://api.example.com

# With authentication
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom patterns for your domain
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --flow-patterns /buy \
  --flow-patterns /bid \
  --flow-patterns /claim-offer

# Ramp up repetitions for a higher-confidence result
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --flow-repetitions 100

# Safe read-only mode — no state-changing probes
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --safe-mode

# Run alongside other modules
python apileaks.py scan \
  --target https://api.example.com \
  --modules business_flow,resource,auth
```

---

## How the Module Identifies Sensitive Flows

The module classifies an endpoint as a sensitive business flow when its URL contains any of the configured `sensitive_flow_patterns` (case-insensitive substring match).

**Built-in patterns** (overridable with `--flow-patterns`):

```
/checkout   /purchase   /order      /transfer   /register
/coupon     /payment    /booking    /reserve    /redeem
/vote       /referral   /invite     /subscribe
```

When any `--flow-patterns` value is supplied, it **replaces** the built-in list entirely. Include every pattern you need.

---

## Detector 1 — Rate-Limit Absence

**Finding:** `BUSINESS_FLOW_NO_LIMIT` · **Severity:** HIGH · **OWASP:** API6

### What it tests

Issues `repetition_limit` requests to each sensitive-flow endpoint in rapid succession (no delay by default). Stops early if a protection signal is observed. Emits a finding when all repetitions complete without any signal.

**Protection signals that suppress the finding:**

| Signal | Checked |
|--------|---------|
| HTTP `429 Too Many Requests` | ✅ |
| `Retry-After` header | ✅ |
| `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset` | ✅ |
| `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` | ✅ |
| `X-Rate-Limit-*` variants | ✅ |
| `X-Request-Limit` / `X-Quota-Remaining` | ✅ |

### Detection logic

```
endpoint URL matches sensitive_flow_pattern?
  → YES: issue request 1 of repetition_limit
        → HTTP 429 received? → protected, no finding
        → Anti-automation header present? → protected, no finding
        → 200 again → continue
        → All repetitions complete with no signal → BUSINESS_FLOW_NO_LIMIT (HIGH)
  → NO:  skipped
```

### Examples

```bash
# Default — 50 repetitions
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Raise repetitions for more conclusive evidence
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-repetitions 100

# Add a small delay to detect time-window rate limits (e.g. 1 req/s)
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-repetitions 10 \
  --flow-delay-ms 1100
```

---

## Detector 2 — Quota / Resource Decrement

**Finding:** `BUSINESS_FLOW_QUOTA_NOT_ENFORCED` · **Severity:** HIGH · **OWASP:** API6

This detector addresses the inventory-enforcement gap: an API accepts repeated purchase or booking requests but never reduces the available quantity — the server is not actually checking whether stock exists before confirming the transaction.

### What it tests

After running the `repetition_limit` repetitions, the module compares the value of configured `quota_fields` (stock, remaining, seats, credits, balance…) between the **first** and **last** response. If the value is identical, the quota is not being decremented.

The field lookup is case-insensitive and searches both top-level keys and one level of nesting, so `{"availability": {"seats": 50}}` is matched by `field="seats"`.

**Built-in quota fields** (overridable with `--flow-quota-fields`):

```
stock  quantity  remaining  available  count
seats  quota     credits    balance    limit
```

### Examples

```bash
# Default — uses the built-in quota field list
python apileaks.py owasp business_flow \
  --target https://api.example.com

# Custom fields for your domain
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-quota-fields inventory \
  --flow-quota-fields ticketsLeft \
  --flow-quota-fields unitsAvailable

# Disable quota check (rate-limit + multi-step only)
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --no-flow-check-quota
```

---

## Detector 3 — Multi-Step Flow Bypass

**Finding:** `BUSINESS_FLOW_MULTI_STEP_BYPASS` · **Severity:** HIGH · **OWASP:** API6

Real business transactions are rarely a single endpoint call. The scalping attack in OWASP Scenario #1 requires: browse product → add to cart → checkout → confirm payment. If each individual endpoint has some light rate limiting but there is no flow-level control enforcing the full sequence, a bot can still execute thousands of complete purchases by distributing the load across steps.

This detector executes a user-defined sequence of requests as a unit, repeating the full sequence `repetition_limit` times.

### What it tests

Each `multi_step_flows` entry defines an ordered list of `{method, path, body}` steps. The module executes every step of every iteration in order. A finding is emitted when:
- At least one full iteration completes (all steps return `< 400`)
- No `429` or anti-automation header appears on any step across all iterations

A 4xx/5xx on any step causes that iteration to be counted as failed but does not stop the remaining iterations (in case the endpoint is intermittently protected).

### Configuration

Multi-step flows are defined in YAML only (the CLI doesn't accept inline step definitions):

```yaml
owasp_testing:
  business_flow_testing:
    multi_step_flows:
      - name: "scalping_flow"
        steps:
          - method: POST
            path: https://api.example.com/cart/add
            body:
              product_id: "limited-console-001"
              quantity: 1
          - method: POST
            path: https://api.example.com/checkout
          - method: POST
            path: https://api.example.com/orders/confirm
```

### Example

```bash
# Run with a multi_step_flows YAML config
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --config config/business_flow_config.yaml \
  --flow-repetitions 20
```

---

## 📖 Command Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--flow-patterns PATTERN` | URL substring identifying a sensitive business flow endpoint (repeatable). Replaces the built-in list when any value is supplied. | `/checkout`, `/purchase`, etc. |
| `--flow-repetitions N` | Number of times to repeat each sensitive-flow request | `50` |
| `--flow-check-quota` / `--no-flow-check-quota` | Enable or disable the quota decrement detector | enabled |
| `--flow-quota-fields FIELD` | JSON response field to watch for quota decrement (repeatable). Replaces the built-in list when any value is supplied. | `stock`, `remaining`, etc. |
| `--flow-delay-ms MS` | Delay in milliseconds between repeated requests (0 = no delay) | `0` |

### `--flow-patterns`

Replaces the built-in sensitive-flow pattern list when any value is supplied. Pass once per pattern.

```bash
# Target a ticketing platform
python apileaks.py owasp business_flow \
  --target https://tickets.example.com \
  --flow-patterns /buy-ticket \
  --flow-patterns /reserve-seat \
  --flow-patterns /apply-promo
```

### `--flow-repetitions`

Controls how many requests are sent per sensitive endpoint (and per multi-step flow iteration). Higher values increase detection confidence but also the total request count. The default of 50 is a reasonable balance for most APIs.

```bash
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-repetitions 200
```

### `--flow-check-quota` / `--no-flow-check-quota`

Toggles Detector 2. Disable it when responses don't include inventory fields or when you only want the rate-limit check.

```bash
# Rate-limit check only
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --no-flow-check-quota
```

### `--flow-quota-fields`

Replaces the built-in quota field list when any value is supplied.

```bash
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-quota-fields ticketsAvailable \
  --flow-quota-fields creditsRemaining \
  --flow-quota-fields unitsInStock
```

### `--flow-delay-ms`

Inserts a sleep between each repeated request. Use this to surface time-window-based rate limits (e.g. "max 1 request per second") that a zero-delay probe would never encounter.

```bash
# Simulate a "1 request per second" attacker
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-repetitions 15 \
  --flow-delay-ms 1100

# Simulate a "1 request per minute" attacker (for very aggressive limits)
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --flow-repetitions 5 \
  --flow-delay-ms 61000
```

---

## 🔒 Safe Mode Behavior

| Behavior | Normal | Safe mode |
|----------|--------|-----------|
| GET sensitive-flow endpoints probed | ✅ | ✅ |
| POST/PUT/PATCH/DELETE endpoints | ✅ | ❌ skipped entirely |
| Multi-step flows with GET-only steps | ✅ | ✅ |
| Multi-step flows with any state-changing step | ✅ | ❌ step skipped → iteration fails → no finding |
| Quota decrement check | ✅ | ✅ (on GET endpoints only) |

```bash
python apileaks.py owasp business_flow \
  --target https://api.example.com \
  --safe-mode
```

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["business_flow"]

  business_flow_testing:
    enabled: true

    # Detector 1 & 2: URL patterns that identify sensitive flow endpoints
    sensitive_flow_patterns:
      - "/checkout"
      - "/purchase"
      - "/order"
      - "/transfer"
      - "/register"
      - "/coupon"
      - "/payment"
      - "/booking"
      - "/reserve"
      - "/redeem"
      - "/vote"
      - "/referral"
      - "/invite"
      - "/subscribe"

    # Number of repeated requests per endpoint / per multi-step iteration
    repetition_limit: 50

    # Detector 2: quota / resource decrement check
    check_quota_decrement: true
    quota_fields:
      - "stock"
      - "quantity"
      - "remaining"
      - "available"
      - "count"
      - "seats"
      - "quota"
      - "credits"
      - "balance"
      - "limit"

    # Delay between requests in milliseconds (0 = no delay)
    inter_request_delay_ms: 0

    # Detector 3: multi-step flow sequences (optional)
    multi_step_flows:
      - name: "scalping_flow"
        steps:
          - method: POST
            path: https://api.example.com/cart/add
            body:
              product_id: "limited-console-001"
              quantity: 1
          - method: POST
            path: https://api.example.com/checkout
          - method: POST
            path: https://api.example.com/orders/confirm
      - name: "referral_farming_flow"
        steps:
          - method: POST
            path: https://api.example.com/auth/register
            body:
              username: "bot_user_{{n}}"
              email: "bot{{n}}@example.com"
              referral_code: "ATTACKER_CODE"
          - method: POST
            path: https://api.example.com/referral/apply
```

**Field reference:**

| Field | CLI equivalent | Default | Purpose |
|-------|----------------|---------|---------|
| `sensitive_flow_patterns` | `--flow-patterns` | 14 built-in patterns | URL substrings for flow identification |
| `repetition_limit` | `--flow-repetitions` | `50` | Repetitions per endpoint / flow |
| `check_quota_decrement` | `--flow-check-quota` | `true` | Enable Detector 2 |
| `quota_fields` | `--flow-quota-fields` | 10 built-in fields | Fields to compare for decrement |
| `inter_request_delay_ms` | `--flow-delay-ms` | `0` | Milliseconds between requests |
| `multi_step_flows` | — (YAML only) | `[]` | Ordered step sequences for Detector 3 |

---

## 📊 Finding Categories

### `BUSINESS_FLOW_NO_LIMIT`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API6 |
| Description | Sensitive business flow accepted N repeated requests with no HTTP 429 and no anti-automation headers. |
| Evidence | Number of successful requests, absence of any rate-limit signal, final status code. |
| Recommendation | Implement rate limiting, CAPTCHA, device fingerprinting, or human-interaction detection on sensitive flows. |

### `BUSINESS_FLOW_QUOTA_NOT_ENFORCED`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API6 |
| Description | A resource-quantity field (stock, remaining, seats…) remained unchanged across all N requests, indicating inventory is not being decremented server-side. |
| Evidence | Field names and their unchanged values between first and last response. |
| Recommendation | Decrement inventory atomically using database transactions with pessimistic locking (SELECT FOR UPDATE) or optimistic concurrency control. Validate availability server-side before confirming each transaction. |

### `BUSINESS_FLOW_MULTI_STEP_BYPASS`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API6 |
| Description | A complete multi-step business transaction (e.g. add-to-cart → checkout → confirm) completed N full iterations without any rate-limiting or anti-automation control. |
| Evidence | Flow name, step sequence, number of successful full iterations. |
| Recommendation | Enforce flow-level controls end-to-end, not just on individual endpoints. Use session-bound quotas, workflow tokens, and CAPTCHA gates at transaction initiation. |

---

## 🎭 Attack Scenarios (OWASP API6:2023)

### Scenario 1 — Console scalping

A company announces a limited gaming console. An attacker writes code to automatically buy the entire stock. The API has no rate limiting on `/checkout` or `/orders/confirm`. The attacker runs the code across multiple IPs and buys all units before legitimate customers can.

**What apileaks detects:** `/checkout` and `/orders/confirm` match the sensitive-flow pattern. After 50 rapid-fire requests with no 429 or `X-RateLimit-*` header, `BUSINESS_FLOW_NO_LIMIT` is emitted. If the response includes a `stock` field that never decrements, `BUSINESS_FLOW_QUOTA_NOT_ENFORCED` is also emitted.

```bash
python apileaks.py owasp business_flow \
  --target https://store.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --flow-patterns /checkout \
  --flow-patterns /orders/confirm \
  --flow-quota-fields stock \
  --flow-quota-fields unitsAvailable
```

### Scenario 2 — Airline seat hoarding and release

A malicious user books 90% of the seats on a flight then cancels all at once, forcing the airline to discount prices. The API has no per-user booking limit.

**What apileaks detects:** `/booking` and `/reserve` match the built-in patterns. 50 unthrottled repetitions on `/booking` emit `BUSINESS_FLOW_NO_LIMIT`. The multi-step flow (search → reserve → confirm) completing 50 iterations without interruption emits `BUSINESS_FLOW_MULTI_STEP_BYPASS`.

```yaml
# config/airline_flows.yaml
owasp_testing:
  business_flow_testing:
    repetition_limit: 50
    multi_step_flows:
      - name: "seat_hoarding"
        steps:
          - method: GET
            path: https://flights.example.com/search?from=NYC&to=LAX&date=2026-12-25
          - method: POST
            path: https://flights.example.com/reserve
            body: {flight_id: "AA100", seat: "12A"}
          - method: POST
            path: https://flights.example.com/booking/confirm
```

### Scenario 3 — Referral farming

A ride-sharing app gives credit for each referred friend who joins. An attacker scripts the registration flow, creating thousands of fake accounts, each applying the attacker's referral code. The referral endpoint has no per-referrer cap.

**What apileaks detects:** `/register` and `/referral` match the built-in patterns. 50 unthrottled registrations emit `BUSINESS_FLOW_NO_LIMIT`. The multi-step flow (register → apply-referral) completing end-to-end emits `BUSINESS_FLOW_MULTI_STEP_BYPASS`.

```bash
python apileaks.py owasp business_flow \
  --target https://rides.example.com \
  --flow-patterns /register \
  --flow-patterns /referral \
  --flow-repetitions 100
```

---

## 🛡️ Remediation

### Rate-limit absence (BUSINESS_FLOW_NO_LIMIT)

- **Per-user rate limits:** Apply limits keyed to the authenticated user identity, not the IP address. IP-based limits are trivially bypassed with proxy rotation.
- **Global flow limits:** Set a maximum number of operations per flow per time window at the business logic layer, not just the transport layer.
- **CAPTCHA gates:** Require a CAPTCHA challenge after a configurable number of consecutive sensitive-flow completions.
- **Device fingerprinting:** Reject requests from headless browsers or clients lacking expected browser signals.
- **CAPTCHA on B2B APIs too:** Machine-to-machine APIs are equally vulnerable and rarely protected — apply API key quotas and per-key rate limits.

### Quota not enforced (BUSINESS_FLOW_QUOTA_NOT_ENFORCED)

- **Atomic decrement with locking:** Use `SELECT ... FOR UPDATE` (pessimistic) or version-field CAS (optimistic) to prevent concurrent oversells.
- **Server-side availability check:** Never rely on a client-supplied quantity. Re-validate available inventory inside the transaction.
- **Reserve-then-confirm pattern:** Reserve inventory at add-to-cart, release the reservation if checkout is not completed within a timeout.

### Multi-step flow bypass (BUSINESS_FLOW_MULTI_STEP_BYPASS)

- **Flow-level tokens:** Issue a signed, single-use workflow token at the start of each transaction. Each subsequent step must present the token, and the token is invalidated after use.
- **Session-scoped quotas:** Track how many complete flows a session has executed within a time window, not just how many times a single endpoint was hit.
- **Non-human pattern detection:** Flag sessions that complete the add-to-cart → checkout → confirm sequence in under one second.
- **Tor / known-proxy blocking:** Block requests originating from Tor exit nodes and public proxy lists on sensitive flow endpoints.

---

See also: [OWASP Coverage](README.md) · [Resource Consumption (API4)](../owasp-command.md) · [OWASP Command Reference](../owasp-command.md) · [Scan Guide](../scan-guide.md)
