"""
Unit tests for Extension_Set CLI wiring and budget/concurrency composition.

**Feature: owasp-complete-purple-teaming-cicd, Task 27.5**

Two complementary concerns are covered here, both deliberately NOT duplicated
from ``tests/test_discovery_controls_cli.py`` (which already asserts the CLI
parses/normalizes ``-x`` / ``--extensions`` into
``config_dict['fuzzing']['endpoints']['extensions']`` for ``dir`` and ``full``):

(a) **Full config-loading path (Requirements 23.1, 23.8).** The existing CLI
    tests stop at the threaded *dict*. These tests carry that dict the rest of
    the way through the real ``ConfigurationManager`` and assert the resulting
    ``EndpointFuzzingConfig.extensions`` field is populated with the normalized
    Extension_Set -- proving the ``extensions`` field defined on
    EndpointFuzzingConfig (23.8) actually receives the CLI-supplied set (23.1)
    end to end for both ``dir`` and ``full``.

(b) **Budget / concurrency composition (Requirement 23.7).** Driving the real
    ``EndpointFuzzer.discover_endpoints`` against an in-memory fake
    HTTPRequestEngine, these tests assert that extension-expanded candidates
    each issue a Discovery_Request that counts toward the Request_Budget (so the
    budget truncates the expanded candidate space) and that in-flight expanded
    Discovery_Requests stay within the Concurrency_Limit. This mirrors the
    fake-client conventions in ``tests/test_fuzzing_orchestrator.py`` and the
    budget/concurrency property tests.

No real HTTP requests are made.
"""

import asyncio
import os
import tempfile
from unittest.mock import patch

import pytest

import apileaks
from apileaks import cli
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from core.config import ConfigurationManager
from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint
from utils.http_client import Response

from click.testing import CliRunner


# ===========================================================================
# (a) CLI -> ConfigurationManager -> EndpointFuzzingConfig.extensions
#     (Requirements 23.1, 23.8)
# ===========================================================================

class _ShortCircuit(Exception):
    """Sentinel raised to stop the command after config_dict is captured."""


def _capture_threaded_config(command, args):
    """Invoke ``command`` (``dir``/``full``) and return the threaded config_dict.

    ConfigurationManager.load_config_from_dict is the first consumer of the fully
    threaded config, so patching it lets us grab the exact dict the CLI built --
    including the normalized Extension_Set -- without running a real scan. We
    re-load that captured dict through a *real* ConfigurationManager below to
    exercise the full config-loading path.
    """
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        runner.invoke(
            cli,
            ["--no-banner", command, "--target", "https://api.example.com", *args],
        )
    return captured.get("config_dict")


@pytest.mark.parametrize("command", ["dir", "full"])
def test_extensions_populate_endpoint_config_through_manager(command):
    """``-x`` flows from the CLI into EndpointFuzzingConfig.extensions.

    The CLI threads ``-x json,php`` into the config dict; loading that dict
    through the real ConfigurationManager must yield an
    ``EndpointFuzzingConfig.extensions`` equal to the normalized Extension_Set.
    This exercises the full config-loading path (not just the dict) and confirms
    the dedicated ``extensions`` field carries the set.

    **Validates: Requirements 23.1, 23.8**
    """
    config_dict = _capture_threaded_config(command, ["-x", "json,php"])
    assert config_dict is not None

    loaded = ConfigurationManager().load_config_from_dict(config_dict)

    assert isinstance(loaded.fuzzing.endpoints, EndpointFuzzingConfig)
    # 23.8: the dedicated field carries the normalized Extension_Set...
    # 23.1: ...populated from the CLI-supplied --extensions / -x option.
    assert loaded.fuzzing.endpoints.extensions == [".json", ".php"]


@pytest.mark.parametrize("command", ["dir", "full"])
def test_absent_extensions_load_to_empty_set_through_manager(command):
    """Without ``-x`` the loaded EndpointFuzzingConfig.extensions is empty.

    Absent option => empty Extension_Set carried through the full config-loading
    path, so no extension expansion is configured.

    **Validates: Requirements 23.1, 23.8**
    """
    config_dict = _capture_threaded_config(command, [])
    assert config_dict is not None

    loaded = ConfigurationManager().load_config_from_dict(config_dict)

    assert loaded.fuzzing.endpoints.extensions == []


# ===========================================================================
# (b) Budget / concurrency composition for expanded candidates
#     (Requirement 23.7)
# ===========================================================================

class PeakCountingFakeClient:
    """In-memory fake HTTPRequestEngine that counts calls and tracks peak concurrency.

    Records every (method, url) call and, by incrementing an in-flight counter
    on entry / decrementing on exit (yielding control in between so sibling
    coroutines dispatched in the same batch overlap), captures the peak number
    of simultaneously in-flight Discovery_Requests. Used to prove expanded
    candidates each issue a counted Discovery_Request bounded by the
    Concurrency_Limit (Requirement 23.7).
    """

    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.calls = []            # list of (method, url) in call order
        self.in_flight = 0
        self.peak_in_flight = 0

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        try:
            await asyncio.sleep(0)  # let concurrent siblings overlap
            return Response(
                status_code=self.status_code,
                headers={"Content-Type": "application/json"},
                content=b'{"ok": true}',
                text='{"ok": true}',
                url=url,
                elapsed=0.01,
                request_method=method,
            )
        finally:
            self.in_flight -= 1


def _make_config(extensions, max_requests=None, concurrency=50):
    """Build a single-method, non-recursive FuzzingConfig with the given controls."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],          # one method => one request per unique path
            follow_redirects=False,
            extensions=extensions,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=max_requests,
        concurrency=concurrency,
    )


def _write_wordlist(words):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run(extensions, words, max_requests=None, concurrency=50):
    fake_client = PeakCountingFakeClient(status_code=200)
    fuzzer = EndpointFuzzer(
        fake_client, _make_config(extensions, max_requests, concurrency)
    )
    wordlist_path = _write_wordlist(words)
    try:
        discovered = await fuzzer.discover_endpoints("http://example.com", wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


@pytest.mark.asyncio
async def test_expanded_candidates_increase_issued_requests():
    """Each expanded candidate issues its own (counted) Discovery_Request.

    With W words and E=2 distinct extensions, depth-0 issues W*(E+1) wordlist
    Discovery_Requests (plus the CATCH_ALL_PROBES catch-all probes). Compared to
    the no-extension run, the extra requests are exactly the expanded
    candidates, and every one flowed through the client -- demonstrating each
    expanded candidate's Discovery_Request is issued and therefore counts toward
    the Request_Budget.

    **Validates: Requirements 23.7**
    """
    words = [f"w{i}" for i in range(4)]
    probes = EndpointFuzzer.CATCH_ALL_PROBES

    plain_client, _, _ = await _run(extensions=[], words=words)
    expanded_client, _, _ = await _run(extensions=["json", "php"], words=words)

    # No extensions: one Discovery_Request per word, plus catch-all probes.
    assert plain_client.call_count == len(words) + probes
    # E=2 extensions: W*(E+1) candidate paths (Requirement 23.9), plus probes.
    assert expanded_client.call_count == len(words) * 3 + probes
    # The expanded candidates (the .json / .php variants) actually hit the wire.
    assert any(url.endswith(".json") for _, url in expanded_client.calls)
    assert any(url.endswith(".php") for _, url in expanded_client.calls)


@pytest.mark.asyncio
async def test_expanded_candidates_counted_toward_request_budget():
    """The Request_Budget truncates the extension-expanded candidate space.

    Four words with two extensions yield W*(E+1)=12 candidate paths, far more
    than the leftover budget after the catch-all probes. The total
    Discovery_Requests issued (probes + wordlist) is capped at exactly the
    budget, budget_reached is set, and the truncated wordlist requests include
    extension-bearing candidates -- proving expanded candidates count toward the
    budget rather than being issued "for free".

    **Validates: Requirements 23.7**
    """
    words = [f"w{i}" for i in range(4)]               # 4 words
    probes = EndpointFuzzer.CATCH_ALL_PROBES
    wordlist_budget = 5                               # < 12 expanded candidates
    max_requests = probes + wordlist_budget

    client, fuzzer, discovered = await _run(
        extensions=["json", "php"], words=words, max_requests=max_requests
    )

    # Budget never exceeded and exactly consumed (12 candidates > leftover).
    assert fuzzer.requests_issued == max_requests
    assert client.call_count == max_requests
    assert fuzzer.budget_reached is True
    # The candidates are generated as [w0, w0.json, w0.php, w1, ...], so the
    # truncated set still contains expanded (extension-bearing) candidates that
    # consumed budget.
    assert any(url.endswith(".json") or url.endswith(".php") for _, url in client.calls)
    # Only real Endpoints are returned (partial set).
    assert all(isinstance(e, Endpoint) for e in discovered)


@pytest.mark.asyncio
async def test_expanded_candidates_stay_within_concurrency_limit():
    """In-flight expanded Discovery_Requests never exceed the Concurrency_Limit.

    With a small Concurrency_Limit and an expanded candidate space far larger
    than it (4 words * 3 = 12 candidates dispatched in one depth-0 batch), the
    semaphore must cap simultaneous in-flight requests at the limit even though
    the extra in-flight work comes from extension expansion.

    **Validates: Requirements 23.7**
    """
    words = [f"w{i}" for i in range(4)]   # 12 expanded candidates at depth 0
    concurrency = 2

    client, fuzzer, _ = await _run(
        extensions=["json", "php"], words=words, concurrency=concurrency
    )

    assert fuzzer.concurrency == concurrency
    # 23.7: peak simultaneous in-flight requests stayed within the limit.
    assert client.peak_in_flight <= concurrency
    # The expanded candidates really were dispatched (non-vacuous).
    assert any(url.endswith(".json") for _, url in client.calls)
    assert client.call_count == len(words) * 3 + EndpointFuzzer.CATCH_ALL_PROBES
