"""
Unit tests for the Secret Scanner (Requirement 30).

**Feature: owasp-complete-purple-teaming-cicd, Task 34.4**

Example-based unit tests for the pure, read-only secret/leak detection in
``utils.secret_scanner`` and the opt-in ``SecretScanConfig`` default. These
cover:

- 30.1: secret detection is disabled by default (``SecretScanConfig().enabled``
  is ``False``).
- 30.2 / 30.3 / 30.4: when scanning a response containing a secret in BOTH the
  body and the headers, ``scan_for_secrets`` produces ``SecretFinding`` records
  tagged to the originating endpoint/method, with the matched value redacted so
  the full secret value never appears in the finding.
- 30.6: passing a custom name -> regex map changes what is detected -- a custom
  pattern detects a custom token that the built-in defaults do not, and a
  custom-only map does not detect a value the defaults would.

The complementary no-match guarantee (Requirement 30.7) is covered by the
property test in ``tests/test_secret_scan_no_match_properties.py``.
"""

import re

from core.config import SecretScanConfig
from utils.secret_scanner import (
    DEFAULT_SECRET_PATTERNS,
    SecretFinding,
    redact,
    scan_for_secrets,
)


# Well-known example secret shapes that match the built-in patterns. These are
# synthetic, non-live values used only to exercise the detectors.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # matches DEFAULT_SECRET_PATTERNS["aws_access_key"]
BEARER_TOKEN_VALUE = "abcdefghijklmnopqrstuvwx"  # 24 chars, >= 16 required
BEARER_HEADER_VALUE = f"Bearer {BEARER_TOKEN_VALUE}"


# ---------------------------------------------------------------------------
# 30.1 - opt-in, disabled by default
# ---------------------------------------------------------------------------

def test_secret_scan_disabled_by_default():
    """``SecretScanConfig`` keeps secret detection off unless explicitly enabled.

    **Validates: Requirement 30.1**
    """
    config = SecretScanConfig()

    assert config.enabled is False
    # Defaults still supply the built-in patterns so that enabling detection
    # without a custom file uses the high-signal defaults (Requirement 30.6).
    assert config.patterns == DEFAULT_SECRET_PATTERNS


# ---------------------------------------------------------------------------
# 30.2 / 30.3 / 30.4 - scan body + headers, tag to endpoint, redact value
# ---------------------------------------------------------------------------

def test_scan_detects_secret_in_body():
    """A secret in the response body is detected and tagged to the endpoint.

    **Validates: Requirements 30.2, 30.3, 30.4**
    """
    body = f'{{"aws_key": "{AWS_KEY}"}}'

    findings = scan_for_secrets(
        body=body,
        headers={},
        endpoint="https://api.example.com/config",
        method="GET",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, SecretFinding)
    # 30.3: tagged to the originating endpoint and method.
    assert finding.endpoint == "https://api.example.com/config"
    assert finding.method == "GET"
    assert finding.pattern_name == "aws_access_key"
    # 30.4: the full secret value is never echoed; a masked form is present.
    assert AWS_KEY not in finding.redacted
    assert "*" in finding.redacted


def test_scan_detects_secret_in_headers():
    """A secret in a response header is detected (30.2) and redacted (30.4).

    **Validates: Requirements 30.2, 30.4**
    """
    headers = {"Authorization": BEARER_HEADER_VALUE}

    findings = scan_for_secrets(
        body="",
        headers=headers,
        endpoint="https://api.example.com/login",
        method="GET",
    )

    assert len(findings) >= 1
    # A bearer token pattern should match the Authorization header value.
    pattern_names = {f.pattern_name for f in findings}
    assert "bearer_token" in pattern_names
    for finding in findings:
        # 30.4: the raw token never appears verbatim in any finding.
        assert BEARER_TOKEN_VALUE not in finding.redacted
        assert "*" in finding.redacted


def test_scan_detects_secrets_in_both_body_and_headers():
    """Secrets in BOTH the body and headers each produce a tagged, redacted finding.

    **Validates: Requirements 30.2, 30.3, 30.4**
    """
    body = f"leaked key: {AWS_KEY}"
    headers = {"Authorization": BEARER_HEADER_VALUE}
    endpoint = "https://api.example.com/debug"
    method = "GET"

    findings = scan_for_secrets(
        body=body,
        headers=headers,
        endpoint=endpoint,
        method=method,
    )

    pattern_names = {f.pattern_name for f in findings}
    # 30.2: both the body secret and the header secret are detected.
    assert "aws_access_key" in pattern_names
    assert "bearer_token" in pattern_names

    for finding in findings:
        # 30.3: every finding is tagged to the originating endpoint/method.
        assert finding.endpoint == endpoint
        assert finding.method == method
        # 30.4: neither full secret value appears in any redacted output.
        assert AWS_KEY not in finding.redacted
        assert BEARER_TOKEN_VALUE not in finding.redacted
        assert "*" in finding.redacted


def test_redact_never_echoes_full_value():
    """``redact`` masks values so the original is never reproduced verbatim.

    **Validates: Requirement 30.4**
    """
    # Short values are fully masked.
    assert redact("short") == "*" * len("short")
    assert set(redact("short")) == {"*"}

    # Longer values keep a little context but mask the middle, and never
    # reproduce the full original string.
    secret = "SuperSecretValue1234567890"
    masked = redact(secret)
    assert secret not in masked
    assert "*" in masked
    assert len(masked) == len(secret)


# ---------------------------------------------------------------------------
# 30.6 - configurable patterns change what is detected
# ---------------------------------------------------------------------------

CUSTOM_TOKEN = "CUSTOM-123456"
CUSTOM_PATTERNS = {"custom_token": r"CUSTOM-[0-9]{6}"}


def test_custom_pattern_detects_token_defaults_miss():
    """A custom pattern detects a token the built-in defaults do not.

    **Validates: Requirement 30.6**
    """
    body = f"the value is {CUSTOM_TOKEN} here"

    # Built-in defaults do not recognize this custom shape.
    default_findings = scan_for_secrets(
        body=body,
        headers={},
        patterns=DEFAULT_SECRET_PATTERNS,
        endpoint="/x",
        method="GET",
    )
    assert all(f.pattern_name != "custom_token" for f in default_findings)
    assert not any(
        CUSTOM_TOKEN in f.redacted or f.pattern_name == "custom_token"
        for f in default_findings
    )

    # The custom pattern map detects it.
    custom_findings = scan_for_secrets(
        body=body,
        headers={},
        patterns=CUSTOM_PATTERNS,
        endpoint="/x",
        method="GET",
    )
    assert len(custom_findings) == 1
    assert custom_findings[0].pattern_name == "custom_token"
    # Still redacted (Requirement 30.4 applies regardless of pattern source).
    assert CUSTOM_TOKEN not in custom_findings[0].redacted
    assert "*" in custom_findings[0].redacted


def test_custom_only_patterns_do_not_detect_default_secrets():
    """A custom-only map does not detect values the built-in defaults would.

    **Validates: Requirement 30.6**
    """
    body = f"aws key {AWS_KEY} and token {CUSTOM_TOKEN}"

    custom_findings = scan_for_secrets(
        body=body,
        headers={},
        patterns=CUSTOM_PATTERNS,
        endpoint="/x",
        method="GET",
    )

    # Only the custom token matches; the AWS key is invisible to this map.
    assert len(custom_findings) == 1
    assert custom_findings[0].pattern_name == "custom_token"
    assert all(f.pattern_name != "aws_access_key" for f in custom_findings)


def test_compiled_patterns_are_accepted():
    """Configurable patterns may be supplied as already-compiled regexes.

    **Validates: Requirement 30.6**
    """
    compiled = {"custom_token": re.compile(r"CUSTOM-[0-9]{6}")}
    findings = scan_for_secrets(
        body=f"value {CUSTOM_TOKEN}",
        headers={},
        patterns=compiled,
        endpoint="/x",
        method="GET",
    )

    assert len(findings) == 1
    assert findings[0].pattern_name == "custom_token"
