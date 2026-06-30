"""
Secret Scanner

Pure, read-only detection of secrets and sensitive data leaked in discovery
responses. The scanner inspects a response's body and headers (already received
by discovery) against a configurable map of named regular expressions and emits
a redacted :class:`SecretFinding` for each match, so leaked API keys, tokens,
and credentials are surfaced as part of discovery (Requirement 30).

This module performs no HTTP I/O: it only inspects content passed to it, which
makes it inherently ``Safe_Mode``-compatible (Requirement 30.5). Matched secret
values are always redacted before being stored on a finding so the full secret
value is never echoed in output (Requirement 30.4).
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Pattern, Union

from core.logging import get_logger

logger = get_logger(__name__)


# Default configurable name -> regex map used when no custom patterns are
# supplied (Requirement 30.6). Patterns intentionally favour high-signal,
# well-known secret shapes to limit false positives.
DEFAULT_SECRET_PATTERNS: Dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws_secret_access_key\W{0,3}[A-Za-z0-9/+]{40}",
    "gcp_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "google_oauth_token": r"ya29\.[0-9A-Za-z_-]+",
    "github_token": r"gh[pousr]_[0-9A-Za-z]{36,}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "bearer_token": r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}=*",
    "basic_auth_header": r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/]{8,}=*",
    "generic_api_key": r"(?i)(?:api[_-]?key|secret|token|password|passwd)\W{0,3}[A-Za-z0-9/+]{16,}",
}


@dataclass(frozen=True)
class SecretFinding:
    """A redacted secret detected in a discovery response.

    Tagged to the endpoint whose response contained the match (Requirement
    30.3). The ``redacted`` field holds a masked representation of the matched
    value; the full secret value is never stored (Requirement 30.4).
    """

    endpoint: str
    method: str
    pattern_name: str
    redacted: str


def redact(value: str) -> str:
    """Mask a matched secret so the full value is never echoed.

    Short values are fully masked. Longer values keep a few leading and
    trailing characters as context while masking the middle. In all cases the
    original ``value`` never appears verbatim in the returned string
    (Requirement 30.4).

    Args:
        value: The raw matched secret value.

    Returns:
        A redacted, masked representation of ``value``.
    """
    if value is None:
        return ""

    length = len(value)
    if length == 0:
        return ""

    # For short secrets, reveal nothing to avoid leaking a meaningful fraction.
    if length <= 8:
        return "*" * length

    # For longer secrets, keep up to 4 leading and 4 trailing characters and
    # mask the middle, ensuring at least one masked character so the full value
    # can never be reconstructed from the redaction.
    lead = value[:4]
    tail = value[-4:]
    masked_len = length - len(lead) - len(tail)
    return f"{lead}{'*' * masked_len}{tail}"


def _compile_patterns(
    patterns: Mapping[str, Union[str, Pattern[str]]]
) -> Dict[str, Pattern[str]]:
    """Compile a name -> regex map into a name -> compiled pattern map.

    Accepts either regex strings (as in :data:`DEFAULT_SECRET_PATTERNS`) or
    already-compiled patterns, so callers may pass the default string map
    directly. Invalid regex strings are skipped with a warning rather than
    aborting the whole scan.
    """
    compiled: Dict[str, Pattern[str]] = {}
    for name, pattern in patterns.items():
        if isinstance(pattern, str):
            try:
                compiled[name] = re.compile(pattern)
            except re.error as exc:
                logger.warning(
                    "Skipping invalid secret pattern",
                    pattern_name=name,
                    error=str(exc),
                )
        else:
            compiled[name] = pattern
    return compiled


def scan_for_secrets(
    body: str,
    headers: Mapping[str, str],
    patterns: Mapping[str, Union[str, Pattern[str]]] = DEFAULT_SECRET_PATTERNS,
    endpoint: str = "",
    method: str = "",
) -> List[SecretFinding]:
    """Scan a discovery response's body and headers for secrets.

    Scans both the response body and response headers against the provided
    ``patterns`` (Requirement 30.2) and emits one redacted :class:`SecretFinding`
    per match, tagged to ``endpoint``/``method`` (Requirements 30.3, 30.4). The
    scan is pure and read-only: it inspects only the content passed in and makes
    no HTTP calls (Requirement 30.5).

    Args:
        body: The response body text to scan.
        headers: The response headers to scan (name -> value).
        patterns: A name -> regex map (regex strings or compiled patterns).
            Defaults to :data:`DEFAULT_SECRET_PATTERNS` (Requirement 30.6).
        endpoint: The endpoint whose response is being scanned.
        method: The HTTP method used for the request.

    Returns:
        A list of redacted :class:`SecretFinding` records, one per match. When
        no pattern matches anywhere, returns ``[]`` (Requirement 30.7).
    """
    compiled = _compile_patterns(patterns)
    findings: List[SecretFinding] = []

    # Build the set of texts to scan: the body plus each header rendered as
    # "Name: value" so header-oriented patterns (e.g. Authorization) match.
    scan_targets: List[str] = []
    if body:
        scan_targets.append(body)
    if headers:
        for header_name, header_value in headers.items():
            scan_targets.append(f"{header_name}: {header_value}")

    for pattern_name, compiled_pattern in compiled.items():
        for text in scan_targets:
            for match in compiled_pattern.finditer(text):
                findings.append(
                    SecretFinding(
                        endpoint=endpoint,
                        method=method,
                        pattern_name=pattern_name,
                        redacted=redact(match.group(0)),
                    )
                )

    if findings:
        logger.info(
            "Secret findings detected in discovery response",
            endpoint=endpoint,
            method=method,
            count=len(findings),
        )

    return findings
