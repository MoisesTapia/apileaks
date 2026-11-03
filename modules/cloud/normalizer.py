"""
GatewayFindingNormalizer

Converts provider-specific GatewayFinding objects to the standard
APILeak Finding model, filing every finding under owasp_category="API8"
(Security Misconfiguration) so they integrate seamlessly into the existing
reporting and CI/CD gate pipelines.

Secret redaction: the full evidence string is passed through the shared
``BOLATestingModule.redact_secrets`` helper (Requirement 2.9) before being
embedded in the Finding — the same redactor that Auth_Module and the
JWT_Attack_Engine reuse.  A bare ``__new__`` instance is created so that no
scan configuration or HTTP client is needed.
"""

from __future__ import annotations

from uuid import uuid4

from core.config import Severity
from modules.cloud.base import GatewayFinding, GatewaySeverity
from utils.findings import Finding

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[GatewaySeverity, Severity] = {
    GatewaySeverity.CRITICAL: Severity.CRITICAL,
    GatewaySeverity.HIGH: Severity.HIGH,
    GatewaySeverity.MEDIUM: Severity.MEDIUM,
    GatewaySeverity.LOW: Severity.LOW,
    GatewaySeverity.INFO: Severity.INFO,
}


# ---------------------------------------------------------------------------
# Evidence formatting
# ---------------------------------------------------------------------------


def _format_evidence(gf: GatewayFinding) -> str:
    """Build a human-readable evidence string from a GatewayFinding.

    Includes provider, account_context, region_or_location, resource_id,
    resource_type, check_id, and every key/value pair from evidence.
    The result is passed through ``redact_secrets`` by the caller.
    """
    parts = [
        f"Provider: {gf.provider}",
        f"Account/Context: {gf.account_context}",
    ]
    if gf.region_or_location:
        parts.append(f"Region/Location: {gf.region_or_location}")
    parts.append(f"Resource: {gf.resource_id}")
    parts.append(f"Resource type: {gf.resource_type}")
    parts.append(f"Check: {gf.check_id}")
    for key, val in gf.evidence.items():
        parts.append(f"{key}: {val}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class GatewayFindingNormalizer:
    """
    Converts a GatewayFinding to a standard Finding.

    The resulting Finding has:
    - owasp_category = "API8"         (Requirement 7.1)
    - endpoint       = gf.resource_id (Requirement 7.2 — ARN / resource URI)
    - evidence       = formatted string with provider + account_context +
                       region_or_location, redacted via ``redact_secrets``
                       (Requirements 7.2, 2.9)
    - severity       = mapped from GatewaySeverity via SEVERITY_MAP
    - recommendation = gf.remediation  (Requirement 7.3 — provider-specific)
    """

    #: Public alias so tests and the design spec can reference it directly.
    SEVERITY_MAP = _SEVERITY_MAP

    def __init__(self) -> None:
        # Lazily-created bare BOLATestingModule instance used solely for
        # redact_secrets.  Created via __new__ so no config / HTTP client
        # is required (mirrors jwt_attack_engine._redactor pattern, Req 2.9).
        self._secret_redactor: object | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _redactor(self) -> object:
        """Return a reusable BOLATestingModule instance for secret redaction."""
        if self._secret_redactor is None:
            # Local import avoids a circular dependency at module load time.
            from modules.owasp.bola_testing import BOLATestingModule  # noqa: PLC0415

            self._secret_redactor = BOLATestingModule.__new__(BOLATestingModule)
        return self._secret_redactor

    def _redact(self, text: str) -> str:
        """Apply ``BOLATestingModule.redact_secrets`` to *text* (Requirement 2.9).

        Falls back to the original text if redaction raises unexpectedly so
        that evidence emission is never broken.
        """
        try:
            return self._redactor.redact_secrets(text)  # type: ignore[attr-defined]
        except Exception:
            return text

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_finding(
        self,
        gf: GatewayFinding,
        scan_id: str | None = None,
    ) -> Finding:
        """Convert a GatewayFinding to a standard Finding.

        Requirements satisfied:
        - 7.1: owasp_category is always "API8".
        - 7.2: endpoint carries resource_id; evidence includes provider,
               account_context, and region_or_location.
        - 7.3: recommendation carries gf.remediation (provider-specific text).
        - 2.9: evidence string is passed through redact_secrets before storage.
        """
        _scan_id = scan_id or str(uuid4())
        raw_evidence = _format_evidence(gf)
        return Finding(
            id=str(uuid4()),
            scan_id=_scan_id,
            category=gf.check_id,
            owasp_category="API8",
            severity=_SEVERITY_MAP[gf.severity],
            endpoint=gf.resource_id,
            method="N/A",  # management-plane check, not an HTTP call
            status_code=0,
            response_size=0,
            response_time=0.0,
            evidence=self._redact(raw_evidence),
            recommendation=gf.remediation,
        )

    def to_findings(
        self,
        gateway_findings: list[GatewayFinding],
        scan_id: str | None = None,
    ) -> list[Finding]:
        """Batch-convert a list of GatewayFindings, sharing a single scan_id."""
        _scan_id = scan_id or str(uuid4())
        return [self.to_finding(gf, _scan_id) for gf in gateway_findings]
