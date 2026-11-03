# Cloud Audit — Adding a New Provider

This guide explains how to add a new cloud provider to `apileaks cloud-audit` by implementing the `CloudGatewayAuditor` abstract base class and registering it with the `CloudAuditOrchestrator`.

---

## Table of Contents

- [Overview](#overview)
- [Step 1 — Implement the SDK client](#step-1--implement-the-sdk-client)
- [Step 2 — Implement `CloudGatewayAuditor`](#step-2--implement-cloudgatewayauditor)
  - [Required methods](#required-methods)
  - [Full example](#full-example)
- [Step 3 — Register in `CloudAuditOrchestrator`](#step-3--register-in-cloudauditorchestrator)
- [Step 4 — Expose CLI options](#step-4--expose-cli-options)
- [Step 5 — Expose YAML config fields](#step-5--expose-yaml-config-fields)
- [Step 6 — Write unit tests](#step-6--write-unit-tests)
- [Design conventions to follow](#design-conventions-to-follow)

---

## Overview

The cloud audit subsystem is built around three layers:

```
CLI / YAML config
       │
       ▼
CloudAuditOrchestrator   (modules/cloud/orchestrator.py)
  builds one auditor per provider × account context
       │
       ▼
CloudGatewayAuditor ABC  (modules/cloud/base.py)
  discover_resources()  ─► list[dict]
  audit()               ─► list[GatewayFinding]
       │
       ▼
GatewayFindingNormalizer (modules/cloud/normalizer.py)
  to_finding()          ─► Finding  (standard APILeak model)
```

To add a provider you need to:

1. Write a thin **SDK client** in `utils/cloud/`.
2. Write an **auditor** in `modules/cloud/` that implements `CloudGatewayAuditor`.
3. **Register** the new auditor in `CloudAuditOrchestrator`.
4. Optionally expose **CLI flags** and **YAML fields** for its credentials.

---

## Step 1 — Implement the SDK client

Create `utils/cloud/<provider>_client.py`. The client's job is to:

- Resolve credentials (SDK chain first, explicit options second).
- Create and cache the underlying SDK clients/sessions.
- Expose helper methods that the auditor calls (e.g. `list_gateways()`, `get_api_config()`).

```python
# utils/cloud/example_client.py
from __future__ import annotations

from modules.cloud.base import CredentialResolutionError


class ExampleGatewayClient:
    """Thin wrapper around the Example Cloud SDK."""

    def __init__(
        self,
        *,
        project_id: str,
        credentials_file: str | None = None,
        account_context: str = "example:default",
    ) -> None:
        self.project_id = project_id
        self.account_context = account_context
        self._credentials_file = credentials_file
        self._client = self._build_client()

    def _build_client(self):
        try:
            import example_sdk  # noqa: F401  (install via extras)
        except ImportError as exc:
            raise CredentialResolutionError(
                "example-cloud SDK not installed. Run: pip install apileaks[example]"
            ) from exc

        # Use explicit credentials file when supplied; fall back to SDK chain.
        if self._credentials_file:
            return example_sdk.Client.from_service_account_file(self._credentials_file)
        return example_sdk.Client()  # SDK default chain

    def list_gateways(self) -> list[dict]:
        """Return all gateway resources for the configured project."""
        return list(self._client.gateways.list(project=self.project_id))
```

Key patterns to follow (see `utils/cloud/aws_client.py` and `utils/cloud/gcp_client.py`):

- Raise `CredentialResolutionError` when the SDK import fails or credentials cannot be resolved.
- Keep credential resolution lazy (in `__init__` or on first use) so the orchestrator can catch the error at construction time.
- Accept all credential options as keyword-only arguments.

---

## Step 2 — Implement `CloudGatewayAuditor`

Create `modules/cloud/<provider>_gateway.py` (or `<provider>_apim.py` for management-plane services). Subclass `CloudGatewayAuditor` from `modules/cloud/base.py`.

### Required methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| `get_provider_name` | `() -> str` | Return a short, stable identifier such as `"example"`. |
| `discover_resources` | `async () -> list[dict]` | Enumerate auditable resources. Returns raw SDK dicts. |
| `audit` | `async () -> list[GatewayFinding]` | Run all checks; return findings. |

`discover_resources` is called by the orchestrator for reporting (how many resources were scanned). `audit` is the main entry point and should call `discover_resources` internally to avoid double API calls.

All checks must be **read-only**. Before any write operation use `self._guard.assert_write_allowed()` to honour the `allow_destructive` flag.

### Full example

```python
# modules/cloud/example_gateway.py
"""Example Cloud API Gateway auditor."""

from __future__ import annotations

from typing import Any

from modules.cloud.base import (
    CloudGatewayAuditor,
    GatewayFinding,
    GatewaySeverity,
    create_permission_denied_finding,
)
from modules.cloud.base import InsufficientPermissionsError, ProviderThrottledError
from utils.cloud.example_client import ExampleGatewayClient
from utils.cloud.readonly_guard import CloudReadOnlyGuard
from core.logging import get_logger

logger = get_logger(__name__)


class ExampleGatewayAuditor(CloudGatewayAuditor):
    """Auditor for Example Cloud API Gateway."""

    def __init__(
        self,
        client: ExampleGatewayClient,
        guard: CloudReadOnlyGuard,
        account_context: str,
    ) -> None:
        self._client = client
        self._guard = guard
        self._account_context = account_context

    # ------------------------------------------------------------------
    # Contract implementation
    # ------------------------------------------------------------------

    def get_provider_name(self) -> str:
        return "example"

    async def discover_resources(self) -> list[dict[str, Any]]:
        """List all gateways in the configured project."""
        return self._client.list_gateways()

    async def audit(self) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        try:
            gateways = await self.discover_resources()
        except (InsufficientPermissionsError, ProviderThrottledError) as exc:
            logger.warning("Could not discover resources", provider="example", error=str(exc))
            findings.append(
                create_permission_denied_finding(
                    resource_id=self._client.project_id,
                    resource_type="example_project",
                    provider="example",
                    account_context=self._account_context,
                    operation="list_gateways",
                )
            )
            return findings

        for gw in gateways:
            findings.extend(self._check_auth_disabled(gw))
            findings.extend(self._check_tls_version(gw))
            # Add more checks here ...

        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_auth_disabled(self, gateway: dict[str, Any]) -> list[GatewayFinding]:
        """Flag gateways with authentication disabled."""
        if gateway.get("auth_enabled"):
            return []
        return [
            GatewayFinding(
                provider="example",
                resource_id=gateway["name"],
                resource_type="example_gateway",
                check_id="example_gateway_auth_disabled",
                title="API Gateway has no authentication configured",
                severity=GatewaySeverity.HIGH,
                evidence={
                    "gateway_name": gateway["name"],
                    "auth_enabled": False,
                },
                remediation=(
                    "Enable authentication on the gateway. "
                    "See https://example-cloud.com/docs/api-gateway/authentication."
                ),
                account_context=self._account_context,
            )
        ]

    def _check_tls_version(self, gateway: dict[str, Any]) -> list[GatewayFinding]:
        """Flag gateways accepting TLS < 1.2."""
        min_tls = gateway.get("min_tls_version", "TLS_1_0")
        if min_tls in ("TLS_1_2", "TLS_1_3"):
            return []
        return [
            GatewayFinding(
                provider="example",
                resource_id=gateway["name"],
                resource_type="example_gateway",
                check_id="example_gateway_weak_tls",
                title=f"API Gateway accepts weak TLS version: {min_tls}",
                severity=GatewaySeverity.MEDIUM,
                evidence={
                    "gateway_name": gateway["name"],
                    "min_tls_version": min_tls,
                },
                remediation=(
                    "Set min_tls_version to TLS_1_2 or TLS_1_3. "
                    "See https://example-cloud.com/docs/api-gateway/tls."
                ),
                account_context=self._account_context,
            )
        ]
```

---

## Step 3 — Register in `CloudAuditOrchestrator`

Open `modules/cloud/orchestrator.py` and make three additions:

**1. Import your auditor and client:**

```python
# modules/cloud/orchestrator.py  (top of file)
from modules.cloud.example_gateway import ExampleGatewayAuditor
from utils.cloud.example_client import ExampleGatewayClient
```

**2. Add a factory method:**

```python
def _build_example_auditors(
    self,
    config: CloudAuditConfig,
    guard: CloudReadOnlyGuard,
) -> list[CloudGatewayAuditor]:
    """Build one ExampleGatewayAuditor per configured project ID."""
    auditors: list[CloudGatewayAuditor] = []
    project_ids = config.example_project_ids or ["default"]
    for project_id in project_ids:
        account_ctx = f"example:{project_id}"
        try:
            client = ExampleGatewayClient(
                project_id=project_id,
                credentials_file=config.example_credentials_file,
                account_context=account_ctx,
            )
            auditors.append(
                ExampleGatewayAuditor(
                    client=client,
                    guard=guard,
                    account_context=account_ctx,
                )
            )
        except CredentialResolutionError as exc:
            logger.warning(
                "Could not build Example auditor",
                project_id=project_id,
                error=str(exc),
            )
    return auditors
```

**3. Call it from `_build_auditors`:**

```python
def _build_auditors(self, config: CloudAuditConfig) -> list[CloudGatewayAuditor]:
    ...
    for provider in config.providers:
        if provider == "aws":
            auditors.extend(self._build_aws_auditors(config, guard))
        elif provider == "gcp":
            auditors.extend(self._build_gcp_auditors(config, guard))
        elif provider == "azure":
            auditors.extend(self._build_azure_auditors(config, guard))
        elif provider == "example":                              # ← add this
            auditors.extend(self._build_example_auditors(config, guard))
        else:
            logger.warning("Unknown provider — skipping", provider=provider)
    return auditors
```

---

## Step 4 — Expose CLI options

Add Click options for the new provider's credential fields in `cli/commands/cloud_audit_cmds.py`:

```python
# In cloud_audit_cmd()

@click.option(
    "--example-project-id",
    "example_project_ids",
    multiple=True,
    default=[],
    metavar="PROJECT_ID",
    help="Example Cloud project ID(s) to audit (repeatable).",
)
@click.option(
    "--example-credentials-file",
    "example_credentials_file",
    default=None,
    metavar="PATH",
    help="Path to an Example Cloud credentials file. Falls back to SDK chain when omitted.",
)
```

Then pass them into `CloudAuditConfig`:

```python
config = CloudAuditConfig(
    ...
    example_project_ids=list(example_project_ids),
    example_credentials_file=example_credentials_file,
)
```

---

## Step 5 — Expose YAML config fields

Add the new fields to `CloudAuditConfig` in `core/config.py`:

```python
@dataclass
class CloudAuditConfig:
    ...
    # Example Cloud
    example_project_ids: list[str] = field(default_factory=list)
    example_credentials_file: str | None = None
```

And parse them in `ConfigurationManager._build_cloud_audit_config`:

```python
return CloudAuditConfig(
    ...
    example_project_ids=_as_list(data.get("example_project_ids")),
    example_credentials_file=data.get("example_credentials_file"),
)
```

Users can then configure the provider in YAML:

```yaml
cloud_audit:
  providers:
    - example
  example_project_ids:
    - my-example-project
  example_credentials_file: /path/to/credentials.json
```

---

## Step 6 — Write unit tests

Create `tests/cloud/test_example_gateway.py`. Follow the existing patterns in `tests/cloud/test_aws_api_gateway.py` and `tests/cloud/test_gcp_api_gateway.py`:

- Use `pytest.importorskip("example_sdk")` so the tests are skipped gracefully when the optional dependency is not installed.
- Mock the SDK client with `unittest.mock.MagicMock` or provider-specific stubbing tools.
- Write at least one **vulnerable case** and one **correctly configured case** per check.

```python
import pytest
from unittest.mock import MagicMock

from modules.cloud.example_gateway import ExampleGatewayAuditor
from modules.cloud.base import GatewaySeverity
from utils.cloud.readonly_guard import CloudReadOnlyGuard


@pytest.fixture
def guard():
    return CloudReadOnlyGuard(allow_destructive=False)


@pytest.fixture
def auditor(guard):
    client = MagicMock()
    client.project_id = "test-project"
    client.list_gateways.return_value = []
    return ExampleGatewayAuditor(
        client=client,
        guard=guard,
        account_context="example:test-project",
    )


class TestCheckAuthDisabled:
    def test_flags_gateway_without_auth(self, auditor):
        gateway = {"name": "my-gateway", "auth_enabled": False}
        findings = auditor._check_auth_disabled(gateway)
        assert len(findings) == 1
        assert findings[0].check_id == "example_gateway_auth_disabled"
        assert findings[0].severity == GatewaySeverity.HIGH

    def test_no_finding_when_auth_enabled(self, auditor):
        gateway = {"name": "my-gateway", "auth_enabled": True}
        findings = auditor._check_auth_disabled(gateway)
        assert findings == []


class TestCheckTLSVersion:
    @pytest.mark.parametrize("weak_tls", ["TLS_1_0", "TLS_1_1"])
    def test_flags_weak_tls(self, auditor, weak_tls):
        gateway = {"name": "my-gateway", "min_tls_version": weak_tls}
        findings = auditor._check_tls_version(gateway)
        assert len(findings) == 1
        assert findings[0].severity == GatewaySeverity.MEDIUM

    @pytest.mark.parametrize("strong_tls", ["TLS_1_2", "TLS_1_3"])
    def test_no_finding_for_strong_tls(self, auditor, strong_tls):
        gateway = {"name": "my-gateway", "min_tls_version": strong_tls}
        findings = auditor._check_tls_version(gateway)
        assert findings == []
```

---

## Design conventions to follow

| Convention | Detail |
|------------|--------|
| **Read-only by default** | Never issue mutating SDK calls unless `self._guard.assert_write_allowed()` succeeds. |
| **Stable `check_id`** | Use `snake_case`, prefixed with the short provider name: `example_gateway_auth_disabled`. These IDs appear in reports and are used by downstream tooling. |
| **Redact secrets in `evidence`** | Call `redact_secrets()` from `utils/redaction.py` on any string in `evidence` that may contain tokens or keys before constructing the `GatewayFinding`. |
| **`account_context` tag** | Always populate `account_context` with a human-readable label so multi-account findings can be traced back to their origin (e.g. `"example:my-project"`). |
| **Graceful degradation** | Catch `InsufficientPermissionsError` and `ProviderThrottledError` per resource or per operation. Use `create_permission_denied_finding()` from `modules/cloud/base.py` to surface the gap without crashing the audit. |
| **Async throughout** | Both `discover_resources` and `audit` are `async def`. Internal sub-calls that are synchronous (most SDKs) are fine to call directly — `asyncio.run()` in the CLI bridges the async boundary. |
| **Optional dependency** | Gate the SDK import inside the client constructor and raise `CredentialResolutionError` with a helpful install message. Add the SDK to `pyproject.toml` as an optional extra (e.g. `[project.optional-dependencies] example = ["example-sdk>=1.0"]`). |
| **`GatewaySeverity` mapping** | Use `CRITICAL` / `HIGH` for authentication and authorization gaps, `MEDIUM` for transport and configuration issues, `LOW` for informational misconfigurations, and `INFO` for non-auditable resources. |
