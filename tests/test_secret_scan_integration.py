"""
Integration tests for secret/leak detection wiring (Requirement 30).

**Feature: owasp-complete-purple-teaming-cicd, Task 34.4**

These tests exercise secret detection through the real ``EndpointFuzzer``
discovery path and through the ``dir`` Click command, complementing the
unit-level scanner tests in ``tests/test_secret_scanner.py``:

- 30.1: without ``--detect-secrets`` (the default), no secret scanning is
  performed -- discovering a response that contains a secret yields no
  ``SecretFinding`` records, and the threaded config has ``enabled = False``.
- 30.2 / 30.3 / 30.4: when enabled, discovering a response that contains a
  secret in BOTH the body and the headers accumulates ``SecretFinding`` records
  tagged to the originating endpoint/method, with the matched value redacted.
- 30.5: Safe_Mode / read-only -- enabling secret detection issues no extra or
  state-changing requests. Scanning happens against the already-received
  response; the request count and the (read-only) methods used are unchanged by
  toggling detection.
- 30.6: a custom patterns map threaded through the orchestrator changes what is
  detected, and the ``--secret-patterns`` CLI loading path threads the parsed
  map into the discovery configuration.

The fake HTTP client and config-capture style mirror
``tests/test_fuzzing_orchestrator.py`` and ``tests/test_discovery_controls_cli.py``.
"""

import json

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    SecretScanConfig,
)
from modules.fuzzing.orchestrator import EndpointFuzzer
from utils.http_client import Response


# Synthetic example secrets (non-live) that match the built-in patterns.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
BEARER_TOKEN_VALUE = "abcdefghijklmnopqrstuvwx"
BEARER_HEADER_VALUE = f"Bearer {BEARER_TOKEN_VALUE}"
CUSTOM_TOKEN = "CUSTOM-123456"


class RecordingHTTPClient:
    """Fake HTTPRequestEngine that records calls and returns a fixed response.

    The returned response embeds a secret in both its body and its headers so
    discovery has something to scan. Every ``request(...)`` call is recorded so
    tests can assert exactly how many requests were issued and which methods
    were used (Requirement 30.5).
    """

    def __init__(self, body: str, headers: dict, status_code: int = 200):
        self._body = body
        self._headers = headers
        self._status_code = status_code
        self.calls = []  # list of (method, url) in call order

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        content = self._body.encode("utf-8")
        return Response(
            status_code=self._status_code,
            headers=dict(self._headers),
            content=content,
            text=self._body,
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _fuzzing_config():
    """Minimal single-pass discovery config (depth 0, no recursion)."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=None,
        concurrency=50,
    )


def _secret_response_client():
    """A client whose single response leaks a secret in both body and headers."""
    body = f'{{"message": "debug", "aws_key": "{AWS_KEY}"}}'
    headers = {"Content-Type": "application/json", "Authorization": BEARER_HEADER_VALUE}
    return RecordingHTTPClient(body=body, headers=headers)


# ---------------------------------------------------------------------------
# 30.1 - detection off by default => no scanning performed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_scanning_when_detection_disabled():
    """Without secret detection configured, a leaking response yields no findings.

    **Validates: Requirement 30.1**
    """
    client = _secret_response_client()
    # No secret_scan_config supplied -> scanning is a no-op.
    fuzzer = EndpointFuzzer(client, _fuzzing_config())

    endpoint = await fuzzer._test_endpoint("GET", "http://example.com/debug", "debug", 0)

    assert endpoint is not None
    assert fuzzer.secret_findings == []


@pytest.mark.asyncio
async def test_no_scanning_when_config_present_but_disabled():
    """An explicitly disabled SecretScanConfig performs no scanning.

    **Validates: Requirement 30.1**
    """
    client = _secret_response_client()
    fuzzer = EndpointFuzzer(
        client, _fuzzing_config(), secret_scan_config=SecretScanConfig(enabled=False)
    )

    await fuzzer._test_endpoint("GET", "http://example.com/debug", "debug", 0)

    assert fuzzer.secret_findings == []


# ---------------------------------------------------------------------------
# 30.2 / 30.3 / 30.4 - enabled detection scans body + headers, tags + redacts
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enabled_detection_finds_body_and_header_secrets_redacted():
    """Enabled detection accumulates redacted findings tagged to the endpoint.

    The discovered response leaks a secret in BOTH the body (AWS key) and a
    header (bearer token); both are detected, tagged to the originating
    endpoint/method, and redacted.

    **Validates: Requirements 30.2, 30.3, 30.4**
    """
    client = _secret_response_client()
    fuzzer = EndpointFuzzer(
        client, _fuzzing_config(), secret_scan_config=SecretScanConfig(enabled=True)
    )

    url = "http://example.com/debug"
    endpoint = await fuzzer._test_endpoint("GET", url, "debug", 0)

    assert endpoint is not None
    pattern_names = {f.pattern_name for f in fuzzer.secret_findings}
    # 30.2: secrets from both the body and the headers are scanned/detected.
    assert "aws_access_key" in pattern_names
    assert "bearer_token" in pattern_names

    for finding in fuzzer.secret_findings:
        # 30.3: tagged to the originating endpoint and method.
        assert finding.endpoint == url
        assert finding.method == "GET"
        # 30.4: full secret values never appear; a masked form is present.
        assert AWS_KEY not in finding.redacted
        assert BEARER_TOKEN_VALUE not in finding.redacted
        assert "*" in finding.redacted


# ---------------------------------------------------------------------------
# 30.5 - Safe_Mode / read-only: scanning adds no extra/state-changing requests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scanning_issues_no_extra_requests():
    """Enabling secret detection does not change the request count or methods.

    The scan inspects the already-received response, so the number of HTTP
    requests issued is identical whether or not detection is enabled, and only
    the read-only discovery method (GET) is used.

    **Validates: Requirement 30.5**
    """
    url = "http://example.com/debug"

    # Baseline: detection disabled.
    disabled_client = _secret_response_client()
    disabled_fuzzer = EndpointFuzzer(disabled_client, _fuzzing_config())
    await disabled_fuzzer._test_endpoint("GET", url, "debug", 0)

    # Detection enabled against an equivalent response.
    enabled_client = _secret_response_client()
    enabled_fuzzer = EndpointFuzzer(
        enabled_client, _fuzzing_config(), secret_scan_config=SecretScanConfig(enabled=True)
    )
    await enabled_fuzzer._test_endpoint("GET", url, "debug", 0)

    # Enabling detection adds no requests: exactly one Discovery_Request each.
    assert disabled_client.call_count == 1
    assert enabled_client.call_count == 1
    assert enabled_client.call_count == disabled_client.call_count

    # Only safe/read methods were used; scanning issued no state-changing call.
    assert all(method == "GET" for method, _ in enabled_client.calls)

    # The scan still produced findings without any extra traffic.
    assert enabled_fuzzer.secret_findings


# ---------------------------------------------------------------------------
# 30.6 - configurable patterns through the orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_custom_patterns_through_orchestrator_change_detection():
    """A custom patterns map threaded into the fuzzer changes what is detected.

    The custom-only map detects a custom token in the body but not the AWS key
    that the built-in defaults would catch.

    **Validates: Requirement 30.6**
    """
    body = f'{{"aws_key": "{AWS_KEY}", "token": "{CUSTOM_TOKEN}"}}'
    client = RecordingHTTPClient(body=body, headers={"Content-Type": "application/json"})
    config = SecretScanConfig(enabled=True, patterns={"custom_token": r"CUSTOM-[0-9]{6}"})
    fuzzer = EndpointFuzzer(client, _fuzzing_config(), secret_scan_config=config)

    await fuzzer._test_endpoint("GET", "http://example.com/debug", "debug", 0)

    pattern_names = {f.pattern_name for f in fuzzer.secret_findings}
    assert pattern_names == {"custom_token"}
    assert all(CUSTOM_TOKEN not in f.redacted for f in fuzzer.secret_findings)


# ---------------------------------------------------------------------------
# CLI wiring: 30.1 default-off and 30.6 --secret-patterns loading path
# ---------------------------------------------------------------------------

class _ShortCircuit(Exception):
    """Sentinel raised to stop the command once config_dict is captured."""


def _invoke_dir_capturing_config(args):
    """Invoke ``dir`` and capture the threaded ``config_dict`` (no real scan)."""
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    runner = CliRunner()
    with patch_load_config(_capture):
        runner.invoke(
            cli,
            ["--no-banner", "dir", "--target", "https://api.example.com", *args],
        )
    return captured.get("config_dict")


def patch_load_config(replacement):
    """Patch ConfigurationManager.load_config_from_dict with ``replacement``."""
    from unittest.mock import patch

    return patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", replacement
    )


def test_cli_secret_scan_disabled_by_default():
    """Without ``--detect-secrets``, the threaded config keeps detection off.

    **Validates: Requirement 30.1**
    """
    config_dict = _invoke_dir_capturing_config([])

    assert config_dict is not None
    assert config_dict.get("secret_scan", {}).get("enabled") is False
    # No custom patterns are threaded unless --secret-patterns is supplied.
    assert "patterns" not in config_dict.get("secret_scan", {})


def test_cli_secret_patterns_file_threaded_into_config(tmp_path):
    """``--detect-secrets --secret-patterns FILE`` threads the parsed map in.

    The JSON name -> regex map loaded by the ``--secret-patterns`` callback is
    threaded into ``config_dict['secret_scan']['patterns']`` and detection is
    enabled.

    **Validates: Requirements 30.1, 30.6**
    """
    patterns = {"custom_token": r"CUSTOM-[0-9]{6}"}
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text(json.dumps(patterns), encoding="utf-8")

    config_dict = _invoke_dir_capturing_config(
        ["--detect-secrets", "--secret-patterns", str(patterns_file)]
    )

    assert config_dict is not None
    assert config_dict["secret_scan"]["enabled"] is True
    assert config_dict["secret_scan"]["patterns"] == patterns


def test_cli_invalid_secret_patterns_file_rejected_no_discovery(tmp_path):
    """An invalid ``--secret-patterns`` file is rejected before any discovery.

    **Validates: Requirement 30.6**
    """
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")

    runner = CliRunner()
    from unittest.mock import patch

    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                "https://api.example.com",
                "--detect-secrets",
                "--secret-patterns",
                str(bad_file),
            ],
        )

    assert result.exit_code != 0
    assert "--secret-patterns" in result.output
    discovery.assert_not_called()
