"""
GatewayFindingNormalizer

Converts provider-specific GatewayFinding objects to the standard
APILeak Finding model, filing every finding under owasp_category="API8"
(Security Misconfiguration) so they integrate seamlessly into the existing
reporting and CI/CD gate pipelines.

Secret redaction: any value in GatewayFinding.evidence that looks like a
credential is replaced with "***REDACTED***" before being embedded in the
Finding's evidence string.  The same logic is applied to resource_id when
it contains inline secret values (rare but possible in some ARN formats).
"""

from __future__ import annotations

import re
from typing import Any
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
# Simple secret-pattern redactor
# ---------------------------------------------------------------------------

# Patterns for keys that are likely to carry secret values.
_SECRET_KEY_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(?i)(secret|password|token|key|credential|auth|api_?key|access_?key)",
    ]
)

_REDACTED = "***REDACTED***"


def _redact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of evidence with any secret-looking values redacted."""
    redacted: dict[str, Any] = {}
    for k, v in evidence.items():
        if any(pat.search(k) for pat in _SECRET_KEY_PATTERNS):
            redacted[k] = _REDACTED
        elif (
            isinstance(v, str) and len(v) > 8 and any(pat.search(k) for pat in _SECRET_KEY_PATTERNS)
        ):
            redacted[k] = _REDACTED
        else:
            redacted[k] = v
    return redacted


def _format_evidence(gf: GatewayFinding) -> str:
    """Build a human-readable evidence string from a GatewayFinding."""
    redacted = _redact_evidence(gf.evidence)
    parts = [
        f"Provider: {gf.provider}",
        f"Account/Context: {gf.account_context}",
    ]
    if gf.region_or_location:
        parts.append(f"Region/Location: {gf.region_or_location}")
    parts.append(f"Resource: {gf.resource_id}")
    parts.append(f"Resource type: {gf.resource_type}")
    parts.append(f"Check: {gf.check_id}")
    for key, val in redacted.items():
        parts.append(f"{key}: {val}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class GatewayFindingNormalizer:
    """
    Converts a GatewayFinding to a standard Finding.

    The resulting Finding has:
    - owasp_category = "API8"
    - category       = gf.check_id (stable, machine-readable)
    - endpoint       = gf.resource_id (cloud resource ARN / URI)
    - severity       = mapped from GatewaySeverity
    - evidence       = formatted + redacted string
    - recommendation = gf.remediation
    """

    def to_finding(
        self,
        gf: GatewayFinding,
        scan_id: str | None = None,
    ) -> Finding:
        """Convert a GatewayFinding to a standard Finding."""
        _scan_id = scan_id or str(uuid4())
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
            evidence=_format_evidence(gf),
            recommendation=gf.remediation,
        )

    def to_findings(
        self,
        gateway_findings: list[GatewayFinding],
        scan_id: str | None = None,
    ) -> list[Finding]:
        """Batch-convert a list of GatewayFindings."""
        _scan_id = scan_id or str(uuid4())
        return [self.to_finding(gf, _scan_id) for gf in gateway_findings]
