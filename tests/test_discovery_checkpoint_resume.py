"""
Unit tests for discovery-checkpoint resume seeding and the CLI "no discovery on
bad --resume" contract.

**Feature: owasp-complete-purple-teaming-cicd, Task 43.4**

These example-based tests cover the gap left by Task 43.1 (which already pins
down ``DiscoveryCheckpoint.save``/``load``): the *resume* behaviour wired into
``EndpointFuzzer`` and surfaced by the ``dir`` command.

- ``EndpointFuzzer.seed_from_checkpoint`` seeds ``tested_urls`` (normalized) and
  ``discovered_endpoints`` (keyed by normalized url) from a checkpoint, so a
  resumed run skips re-issuing already-tested candidates and merges newly
  discovered records with the checkpointed ones with no duplicate
  ``(url, method)`` pair (Requirements 37.3, 37.4, 37.7).
- The ``dir`` command surfaces a missing / malformed ``--resume`` checkpoint as a
  descriptive CLI error naming the artifact and performs NO discovery
  (Requirement 37.5).

No real HTTP requests are made: discovery uses a deterministic in-memory fake
``HTTPRequestEngine`` (following ``test_url_normalization_wiring.py``), and the
CLI tests patch out every discovery entry point so option/resume handling is
exercised in isolation.
"""

import asyncio
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from core.config import (
    EndpointFuzzingConfig,
    FuzzingConfig,
    HeaderFuzzingConfig,
    ParameterFuzzingConfig,
)
from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint, EndpointStatus
from utils.discovery_checkpoint import DiscoveryCheckpoint
from utils.discovery_session import DiscoveryResult
from utils.http_client import HTTPRequestEngine, Response
from utils.url_normalize import normalize_url


# ---------------------------------------------------------------------------
# Test doubles / helpers
# ---------------------------------------------------------------------------


class RecordingFakeClient:
    """Deterministic fake HTTPRequestEngine recording every request as (method, url)."""

    def __init__(self, status_code: int = 200, headers=None):
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.calls = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)
        return Response(
            status_code=self.status_code,
            headers=dict(self.headers),
            content=b'{"ok": true}',
            text='{"ok": true}',
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(methods=None):
    """Build a minimal FuzzingConfig with discovery enabled and no budget."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=methods or ["GET"],
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=None,
        concurrency=50,
    )


def _result(url: str, method: str = "GET", status_code: int = 200,
            endpoint_status: str = "valid") -> DiscoveryResult:
    """Build a DiscoveryResult triage projection."""
    return DiscoveryResult(
        url=url,
        method=method,
        status_code=status_code,
        endpoint_status=endpoint_status,
    )


# ---------------------------------------------------------------------------
# seed_from_checkpoint: tested_urls (Requirement 37.3)
# ---------------------------------------------------------------------------


class TestSeedTestedUrls:
    """seed_from_checkpoint pre-populates tested_urls (normalized) (37.3)."""

    def test_seeds_tested_urls_normalized(self):
        """Every checkpoint 'tested' url seeds tested_urls in canonical form."""
        fuzzer = EndpointFuzzer(RecordingFakeClient(), _make_config())
        # Non-canonical urls: trailing slash + default port both collapse.
        checkpoint = DiscoveryCheckpoint(
            target="http://example.com/",
            timestamp="2025-01-01T00:00:00+00:00",
            tool_version="0.2.0",
            tested=[
                ("http://example.com/users/", "GET"),
                ("http://example.com:80/admin", "POST"),
            ],
        )

        fuzzer.seed_from_checkpoint(checkpoint)

        assert fuzzer.tested_urls == {
            "http://example.com/users",
            "http://example.com/admin",
        }
        # The method that first tested each url is preserved so a subsequent
        # checkpoint write round-trips the (url, method) pair.
        assert fuzzer._tested_methods["http://example.com/users"] == "GET"
        assert fuzzer._tested_methods["http://example.com/admin"] == "POST"

    @pytest.mark.asyncio
    async def test_resume_skips_re_issuing_already_tested_candidates(self):
        """A resumed _fuzz_wordlist does not re-issue a checkpointed candidate (37.3)."""
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(methods=["GET"]))

        checkpoint = DiscoveryCheckpoint(
            target="http://example.com/",
            timestamp="2025-01-01T00:00:00+00:00",
            tool_version="0.2.0",
            tested=[("http://example.com/users", "GET")],
        )
        fuzzer.seed_from_checkpoint(checkpoint)

        # "users" is already tested (seeded); only "admin" should be issued.
        await fuzzer._fuzz_wordlist(
            "http://example.com/", ["users", "admin"], depth=0
        )

        assert fake_client.calls == [("GET", "http://example.com/admin")]
        assert ("GET", "http://example.com/users") not in fake_client.calls


# ---------------------------------------------------------------------------
# seed_from_checkpoint: discovered_endpoints (Requirement 37.4)
# ---------------------------------------------------------------------------


class TestSeedDiscoveredEndpoints:
    """seed_from_checkpoint pre-populates discovered_endpoints (37.4)."""

    def test_seeds_discovered_endpoints_keyed_by_normalized_url(self):
        """Checkpoint results seed discovered_endpoints keyed by normalized url."""
        fuzzer = EndpointFuzzer(RecordingFakeClient(), _make_config())
        checkpoint = DiscoveryCheckpoint(
            target="http://example.com/",
            timestamp="2025-01-01T00:00:00+00:00",
            tool_version="0.2.0",
            results=[
                # Non-canonical url normalizes to .../users.
                _result("http://example.com:80/users/", "GET", 200, "valid"),
                _result("http://example.com/admin", "GET", 401, "auth_required"),
            ],
        )

        fuzzer.seed_from_checkpoint(checkpoint)

        assert set(fuzzer.discovered_endpoints.keys()) == {
            "http://example.com/users",
            "http://example.com/admin",
        }
        users = fuzzer.discovered_endpoints["http://example.com/users"]
        assert users.url == "http://example.com/users"
        assert users.method == "GET"
        assert users.status_code == 200
        assert users.status == EndpointStatus.VALID
        assert users.discovered_via == "checkpoint"

        admin = fuzzer.discovered_endpoints["http://example.com/admin"]
        assert admin.status_code == 401
        assert admin.status == EndpointStatus.AUTH_REQUIRED

    @pytest.mark.asyncio
    async def test_resume_merges_new_with_checkpointed_no_duplicate_url_method(self):
        """A resumed run merges new records with checkpointed ones, no dup (url, method) (37.4, 37.7)."""
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(methods=["GET"]))

        checkpoint = DiscoveryCheckpoint(
            target="http://example.com/",
            timestamp="2025-01-01T00:00:00+00:00",
            tool_version="0.2.0",
            tested=[("http://example.com/users", "GET")],
            results=[_result("http://example.com/users", "GET", 200, "valid")],
        )
        fuzzer.seed_from_checkpoint(checkpoint)

        # Resume discovery: "users" is checkpointed (skipped), "admin" is new.
        await fuzzer._fuzz_wordlist(
            "http://example.com/", ["users", "admin"], depth=0
        )

        # The checkpointed record and the newly discovered one both survive.
        assert set(fuzzer.discovered_endpoints.keys()) == {
            "http://example.com/users",
            "http://example.com/admin",
        }
        # Only the new candidate was actually requested.
        assert fake_client.calls == [("GET", "http://example.com/admin")]

        # No duplicate (url, method) pair across the merged result set (37.7).
        pairs = [
            (e.url, e.method) for e in fuzzer.discovered_endpoints.values()
        ]
        assert len(pairs) == len(set(pairs))
        assert ("http://example.com/users", "GET") in pairs
        assert ("http://example.com/admin", "GET") in pairs


# ---------------------------------------------------------------------------
# CLI: no discovery on a bad --resume checkpoint (Requirement 37.5)
# ---------------------------------------------------------------------------


class TestDirResumeBadCheckpointNoDiscovery:
    """`dir --resume <bad>` errors out and performs no discovery (37.5)."""

    def _invoke_resume(self, resume_path):
        """Invoke `dir --resume <path>` with every discovery entry point patched."""
        runner = CliRunner()
        with patch.object(apileaks, "run_enhanced_apileak") as enhanced, patch.object(
            apileaks, "_discover_endpoints_for_triage"
        ) as triage:
            result = runner.invoke(
                cli,
                [
                    "--no-banner",
                    "dir",
                    "--target",
                    "https://api.example.com",
                    "--resume",
                    str(resume_path),
                ],
            )
        return result, enhanced, triage

    def test_missing_resume_checkpoint_errors_and_no_discovery(self, tmp_path):
        """A missing --resume path errors out naming the artifact and runs no discovery.

        **Validates: Requirements 37.5**
        """
        missing = tmp_path / "does_not_exist.json"

        result, enhanced, triage = self._invoke_resume(missing)

        assert result.exit_code != 0
        assert str(missing) in result.output
        enhanced.assert_not_called()
        triage.assert_not_called()

    def test_malformed_resume_checkpoint_errors_and_no_discovery(self, tmp_path):
        """A malformed --resume checkpoint errors out and runs no discovery.

        **Validates: Requirements 37.5**
        """
        malformed = tmp_path / "malformed.json"
        malformed.write_text("{ this is not valid json", encoding="utf-8")

        result, enhanced, triage = self._invoke_resume(malformed)

        assert result.exit_code != 0
        assert str(malformed) in result.output
        enhanced.assert_not_called()
        triage.assert_not_called()
