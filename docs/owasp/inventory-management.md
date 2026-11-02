# Inventory Management Testing (API9)

The Inventory Management Testing Module detects **OWASP API9 - Improper Inventory Management** vulnerabilities: accessible API versions that should have been decommissioned (deprecated, old, or development versions exposed in production). It reuses the existing `VersionFuzzer` component and only issues read (GET) requests.

The module runs in isolation as `apileaks owasp inventory --target URL` or as part of an orchestrated `scan` run.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [How Version Discovery Works](#how-version-discovery-works)
- [Finding Types](#finding-types)
- [Command Reference](#command-reference)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Remediation](#remediation)

---

## 🎯 Overview

APIs accumulate versions over time. A team ships `/api/v1`, patches authorization bugs, ships `/api/v2`, then `/api/v3`. The v1 and v2 endpoints are rarely fully decommissioned — they keep working, often without the security controls added to the newer versions. Attackers who know that `/api/v3/admin/users` returns 403 will try `/api/v1/admin/users` and often find a 200.

Separately, development or beta endpoints (`/api/beta/`, `/api/internal/`) sometimes leak into production environments and expose unfinished, less-secured functionality.

**Three finding types:**

| Type | Finding | Severity |
|------|---------|----------|
| Deprecated version still accessible | `DEPRECATED_API_VERSION` | LOW |
| Development/shadow version exposed | `UNDOCUMENTED_API_VERSION` | LOW |
| Older active version alongside current | `NON_CURRENT_API_VERSION` | LOW |

---

## 🚀 Quick Start

```bash
# Version enumeration with built-in defaults
python apileaks.py owasp inventory --target https://api.example.com

# With authentication
python apileaks.py owasp inventory \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Disable deprecated version detection
python apileaks.py owasp inventory \
  --target https://api.example.com \
  --no-inventory-detect-deprecated

# Run alongside other modules
python apileaks.py scan \
  --target https://api.example.com \
  --modules inventory,function_auth,bola
```

---

## How Version Discovery Works

The module derives a base URL (`scheme://host[:port]`) from each discovered endpoint and passes it to the `VersionFuzzer` component, which probes common API version path patterns:

```
/api/v1/   /api/v2/   /api/v3/   /v1/   /v2/   /v3/
/api/beta/  /api/internal/  /api/dev/  /api/staging/
```

For each responding version, the fuzzer classifies it as `current`, `deprecated`, or `development` based on response codes and version naming patterns. The module then classifies each version into a finding category.

**Current version determination:** The module selects the highest numerically versioned accessible endpoint as the current version. All other accessible versions are reported as non-current.

---

## Finding Types

### `DEPRECATED_API_VERSION`

A version the fuzzer classified as deprecated is still responding. This is a direct inventory management failure — the version should have been blocked or decommissioned.

### `UNDOCUMENTED_API_VERSION`

A development, beta, internal, or staging version endpoint is accessible in the production environment. These endpoints rarely have the same security controls as production versions.

### `NON_CURRENT_API_VERSION`

An older-but-active version is reachable alongside the current highest version. This is informational but critical context for BFLA testing — authorization patches often only land on the current version.

---

## 📖 Command Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--inventory-detect-deprecated` / `--no-inventory-detect-deprecated` | Enable or disable detection of deprecated API versions | enabled |

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["inventory"]

  inventory_testing:
    enabled: true
    detect_deprecated: true
```

---

## 📊 Finding Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `DEPRECATED_API_VERSION` | LOW | A deprecated API version is still accessible |
| `UNDOCUMENTED_API_VERSION` | LOW | A development or shadow API version is exposed in production |
| `NON_CURRENT_API_VERSION` | LOW | An older active version is accessible alongside the current version |

> **Note:** LOW severity does not mean low risk. Non-current and deprecated versions are the most common path for BFLA version-downgrade attacks (see [Function Level Auth](function-level-auth.md) Level 4).

---

## 🛡️ Remediation

- **Decommission old versions:** When a new API version ships, block access to all older versions at the API gateway within a defined sunset window.
- **Remove dev/beta endpoints from production:** Never deploy internal, development, or staging API paths to production infrastructure. Use separate environments.
- **Maintain an inventory:** Keep a documented list of every active API version with its support status. Review it as part of every release.
- **Apply patches to all versions:** When fixing a security issue, apply it to every active version simultaneously. If that is not feasible, decommission the unpatched version immediately.
- **Monitor version traffic:** Alert when requests are made to deprecated endpoints — it may indicate active exploitation.

---

See also: [OWASP Coverage](README.md) · [Function Level Auth (API5)](function-level-auth.md) · [OWASP Command Reference](../owasp-command.md)
