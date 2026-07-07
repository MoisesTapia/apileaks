"""
tests/test_jwt_attack_suite.py
Tests for ci-cd/scripts/jwt_attack_suite.py

Requirements: 3.1–3.10
"""

import asyncio
import dataclasses
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Import path — ci-cd/scripts has a hyphen so we inject the path manually.
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)
# Also ensure apileaks root is on path for utils/ imports
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from jwt_attack_suite import (  # noqa: E402
    ALL_ATTACK_TYPES,
    VALID_ATTACK_NAMES,
    JWTAttackSuite,
    JWTAttackSuiteConfig,
)
from utils.jwt_attack_models import AttackType  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

VALID_NAMES = [k for k in VALID_ATTACK_NAMES if k != "all"]


def _make_config(attacks=None, pipeline_id="test-pipeline") -> JWTAttackSuiteConfig:
    return JWTAttackSuiteConfig(
        token="eyJhbGciOiJIUzI1NiJ9.e30.sig",
        target_url="http://localhost:8080/api",
        attacks=attacks or ["alg_none"],
        wordlist_path="wordlists/jwt_secrets.txt",
        rsa_public_key=None,
        timeout_seconds=30,
        pipeline_id=pipeline_id,
    )


def _make_mock_finding():
    """Return a minimal Finding-like MagicMock."""
    from utils.findings import Finding
    from core.config import Severity
    return Finding(
        id="test-id",
        scan_id="scan-1",
        category="JWT_NONE_ALGORITHM",
        owasp_category="API2",
        severity=Severity.CRITICAL,
        endpoint="http://localhost:8080/api",
        method="GET",
        status_code=200,
        response_size=100,
        response_time=0.5,
        evidence="Test evidence",
        recommendation="Fix it",
    )


def _make_mock_summary():
    """Return a minimal AttackSummary-like MagicMock."""
    from utils.jwt_attack_models import AttackSummary, AttackSession, AttackConfiguration
    session = AttackSession(
        session_id="sess-1",
        configuration=AttackConfiguration(
            target_url="http://localhost:8080/api",
            original_jwt="tok",
        ),
    )
    session.total_attacks = 1
    session.successful_attacks = 0
    summary = AttackSummary(session=session)
    return summary


# ---------------------------------------------------------------------------
# Test a: _build_engine passes correct args to JWTAttackEngine constructor
# ---------------------------------------------------------------------------

class TestBuildEngine:
    def test_passes_token_and_target(self, tmp_path):
        """_build_engine passes token, target_url, and public_key_material to engine."""
        wordlist = tmp_path / "secrets.txt"
        wordlist.write_text("secret1\nsecret2\n")

        config = JWTAttackSuiteConfig(
            token="my-token",
            target_url="http://target/api",
            attacks=["alg_none"],
            wordlist_path=str(wordlist),
            rsa_public_key="rsa-pub-key",
            timeout_seconds=30,
            pipeline_id="pipe-1",
        )
        suite = JWTAttackSuite(config)

        with patch("jwt_attack_suite.JWTAttackEngine") as MockEngine:
            MockEngine.return_value = MagicMock()
            suite._build_engine()

            assert MockEngine.called, "JWTAttackEngine constructor not called"
            _, kwargs = MockEngine.call_args
            assert kwargs.get("target_url") == "http://target/api"
            assert kwargs.get("original_token") == "my-token"
            assert kwargs.get("public_key_material") == "rsa-pub-key"
            # weak_secrets should be a list from the wordlist
            assert kwargs.get("weak_secrets") == ["secret1", "secret2"]

    def test_falls_back_when_wordlist_missing(self):
        """_build_engine passes weak_secrets=None when wordlist file is absent."""
        config = _make_config()
        config.wordlist_path = "/nonexistent/path.txt"
        suite = JWTAttackSuite(config)

        with patch("jwt_attack_suite.JWTAttackEngine") as MockEngine:
            MockEngine.return_value = MagicMock()
            suite._build_engine()

            _, kwargs = MockEngine.call_args
            # Falls back to None → engine uses its own defaults
            assert kwargs.get("weak_secrets") is None


# ---------------------------------------------------------------------------
# Test b: execute_attack called exactly once per vector when attacks is a list
# ---------------------------------------------------------------------------

class TestExecuteAttackPerVector:
    def test_execute_attack_called_once_per_vector(self, tmp_path):
        """When attacks is a list, execute_attack is called once per attack type."""
        attacks = ["alg_none", "null_signature", "weak_secret"]
        config = _make_config(attacks=attacks, pipeline_id="pipe-b")
        suite = JWTAttackSuite(config)
        finding = _make_mock_finding()

        mock_engine = MagicMock()
        mock_engine.execute_attack = AsyncMock(return_value=None)
        mock_engine.to_findings = MagicMock(return_value=[finding])
        mock_engine._initialize_session = MagicMock()
        mock_engine.session = MagicMock(total_attacks=0, successful_attacks=0)
        mock_engine.session.end_time = None
        mock_engine.session.attack_results = []
        mock_engine.attack_results = []
        mock_engine._generate_summary = MagicMock(return_value=_make_mock_summary())

        with patch("jwt_attack_suite.JWTAttackEngine", return_value=mock_engine), \
             tempfile.TemporaryDirectory() as tmp_reports:
            with patch("jwt_attack_suite.os.makedirs"):
                with patch("builtins.open", unittest.mock.mock_open()):
                    asyncio.run(suite.run())

        assert mock_engine.execute_attack.call_count == len(attacks), (
            f"Expected {len(attacks)} calls to execute_attack, "
            f"got {mock_engine.execute_attack.call_count}"
        )
        # execute_all must NOT be called
        assert not mock_engine.execute_all.called


# ---------------------------------------------------------------------------
# Test c: execute_all called when attacks=["all"]
# ---------------------------------------------------------------------------

class TestExecuteAll:
    def test_execute_all_called_for_all(self):
        """When attacks=['all'], execute_all() is called instead of execute_attack()."""
        config = _make_config(attacks=["all"], pipeline_id="pipe-c")
        suite = JWTAttackSuite(config)
        finding = _make_mock_finding()
        summary = _make_mock_summary()

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(return_value=summary)
        mock_engine.execute_attack = AsyncMock(return_value=None)
        mock_engine.to_findings = MagicMock(return_value=[finding])

        with patch("jwt_attack_suite.JWTAttackEngine", return_value=mock_engine), \
             patch("jwt_attack_suite.os.makedirs"), \
             patch("builtins.open", unittest.mock.mock_open()):
            asyncio.run(suite.run())

        assert mock_engine.execute_all.called, "execute_all was not called"
        assert not mock_engine.execute_attack.called, (
            "execute_attack should not be called when attacks=['all']"
        )


# ---------------------------------------------------------------------------
# Test d: invalid attack name → sys.exit(1) with zero engine calls
# ---------------------------------------------------------------------------

class TestInvalidAttackName:
    def test_invalid_name_exits_without_engine(self):
        """An unrecognised attack name must trigger sys.exit(1) with no engine calls."""
        config = _make_config(attacks=["alg_none", "totally_bogus_attack"])
        suite = JWTAttackSuite(config)

        with patch("jwt_attack_suite.JWTAttackEngine") as MockEngine, \
             pytest.raises(SystemExit) as exc_info:
            asyncio.run(suite.run())

        assert exc_info.value.code == 1, "Expected exit code 1"
        assert not MockEngine.called, "JWTAttackEngine should not be instantiated for invalid attack names"

    def test_purely_invalid_name_exits(self):
        """A single invalid name among valid ones still exits 1."""
        config = _make_config(attacks=["bad_name"])
        suite = JWTAttackSuite(config)

        with patch("jwt_attack_suite.JWTAttackEngine") as MockEngine, \
             pytest.raises(SystemExit) as exc_info:
            asyncio.run(suite.run())

        assert exc_info.value.code == 1
        assert not MockEngine.called


# ---------------------------------------------------------------------------
# Property 7 (PBT): Any list containing an invalid name → exit 1 with no engine
#
# Validates: Requirement 3.7
# ---------------------------------------------------------------------------

# Generate strategies: a list that MUST contain at least one invalid name
_invalid_name_st = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_"),
    min_size=1,
).filter(lambda s: s not in VALID_ATTACK_NAMES and s.strip())

_mixed_attacks_st = st.lists(
    st.one_of(
        st.sampled_from(VALID_NAMES),
        _invalid_name_st,
    ),
    min_size=1,
    max_size=10,
).filter(lambda lst: any(a not in VALID_ATTACK_NAMES for a in lst))


class TestProperty7NoAttackWithoutValidation:
    """Property 7: For any list with an invalid name, run() must exit(1) without invoking JWTAttackEngine."""

    @given(attacks=_mixed_attacks_st)
    @settings(max_examples=50, deadline=2000)
    def test_invalid_attacks_exit_1_no_engine(self, attacks):
        """
        **Validates: Requirements 3.7**
        For any list of attacks containing an invalid name, JWTAttackSuite.run()
        must exit 1 without invoking JWTAttackEngine at all.
        """
        config = _make_config(attacks=attacks, pipeline_id="pbt-test")
        suite = JWTAttackSuite(config)

        with patch("jwt_attack_suite.JWTAttackEngine") as MockEngine, \
             pytest.raises(SystemExit) as exc_info:
            asyncio.run(suite.run())

        assert exc_info.value.code == 1, (
            f"Expected exit code 1 for attacks={attacks!r}, got {exc_info.value.code}"
        )
        assert not MockEngine.called, (
            f"JWTAttackEngine should NOT be instantiated for attacks={attacks!r} "
            f"(contains invalid names)"
        )


# ---------------------------------------------------------------------------
# Test e: asyncio.TimeoutError on one vector → logs and continues
# ---------------------------------------------------------------------------

class TestTimeoutHandling:
    def test_timeout_on_one_vector_continues_others(self, capsys):
        """TimeoutError on one vector is logged and the suite continues with others."""
        attacks = ["alg_none", "null_signature", "weak_secret"]
        config = _make_config(attacks=attacks, pipeline_id="pipe-e")
        suite = JWTAttackSuite(config)
        finding = _make_mock_finding()
        summary = _make_mock_summary()

        call_count = 0

        async def _side_effect(attack_type):
            nonlocal call_count
            call_count += 1
            if attack_type == AttackType.NULL_SIGNATURE:
                raise asyncio.TimeoutError()
            return None

        mock_engine = MagicMock()
        mock_engine.execute_attack = AsyncMock(side_effect=_side_effect)
        mock_engine.to_findings = MagicMock(return_value=[finding])
        mock_engine._initialize_session = MagicMock()
        mock_engine.session = MagicMock(total_attacks=0, successful_attacks=0)
        mock_engine.session.end_time = None
        mock_engine.session.attack_results = []
        mock_engine.attack_results = []
        mock_engine._generate_summary = MagicMock(return_value=summary)

        with patch("jwt_attack_suite.JWTAttackEngine", return_value=mock_engine), \
             patch("jwt_attack_suite.os.makedirs"), \
             patch("builtins.open", unittest.mock.mock_open()):
            asyncio.run(suite.run())

        # All 3 vectors should have been attempted
        assert call_count == len(attacks), (
            f"Expected {len(attacks)} execute_attack calls, got {call_count}"
        )
        # to_findings should still be called (run continues after timeout)
        assert mock_engine.to_findings.called


# ---------------------------------------------------------------------------
# Test f: to_findings() result is correctly serialized to output JSON
# ---------------------------------------------------------------------------

class TestFindingsSerialization:
    def test_findings_serialized_to_json(self, tmp_path):
        """to_findings() result is serialized to reports/apileak-jwt-attacks-{id}.json."""
        config = _make_config(attacks=["alg_none"], pipeline_id="pipe-f")
        suite = JWTAttackSuite(config)
        finding = _make_mock_finding()
        summary = _make_mock_summary()

        mock_engine = MagicMock()
        mock_engine.execute_attack = AsyncMock(return_value=None)
        mock_engine.to_findings = MagicMock(return_value=[finding])
        mock_engine._initialize_session = MagicMock()
        mock_engine.session = MagicMock(total_attacks=0, successful_attacks=0)
        mock_engine.session.end_time = None
        mock_engine.session.attack_results = []
        mock_engine.attack_results = []
        mock_engine._generate_summary = MagicMock(return_value=summary)

        reports_dir = str(tmp_path / "reports")

        with patch("jwt_attack_suite.JWTAttackEngine", return_value=mock_engine), \
             patch("jwt_attack_suite.os.makedirs"), \
             patch("jwt_attack_suite.os.path.join", side_effect=os.path.join), \
             patch("jwt_attack_suite.open", unittest.mock.mock_open(), create=True) as mock_open:

            # We need to capture what was written
            written_chunks = []
            mock_open.return_value.__enter__.return_value.write.side_effect = (
                lambda data: written_chunks.append(data)
            )

            asyncio.run(suite.run())

        # Verify to_findings was called with a summary
        assert mock_engine.to_findings.called

        # Verify the call to open included correct filename pattern
        open_calls = mock_open.call_args_list
        assert any("apileak-jwt-attacks-pipe-f" in str(call) for call in open_calls), (
            f"Expected output file 'apileak-jwt-attacks-pipe-f.json'; open calls: {open_calls}"
        )

    def test_findings_json_structure(self, tmp_path):
        """The serialized JSON contains a 'findings' key with a list of finding dicts."""
        config = _make_config(attacks=["alg_none"], pipeline_id="struct-test")
        suite = JWTAttackSuite(config)
        finding = _make_mock_finding()
        summary = _make_mock_summary()

        output_file = tmp_path / "apileak-jwt-attacks-struct-test.json"

        mock_engine = MagicMock()
        mock_engine.execute_attack = AsyncMock(return_value=None)
        mock_engine.to_findings = MagicMock(return_value=[finding])
        mock_engine._initialize_session = MagicMock()
        mock_engine.session = MagicMock(total_attacks=0, successful_attacks=0)
        mock_engine.session.end_time = None
        mock_engine.session.attack_results = []
        mock_engine.attack_results = []
        mock_engine._generate_summary = MagicMock(return_value=summary)

        with patch("jwt_attack_suite.JWTAttackEngine", return_value=mock_engine), \
             patch("jwt_attack_suite.os.makedirs"), \
             patch(
                 "jwt_attack_suite.os.path.join",
                 return_value=str(output_file),
             ):
            asyncio.run(suite.run())

        assert output_file.exists(), "Output JSON file was not created"
        with open(output_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        assert "findings" in data, "Output JSON must have a 'findings' key"
        assert isinstance(data["findings"], list), "'findings' must be a list"
        assert len(data["findings"]) == 1
        f_dict = data["findings"][0]
        assert f_dict["id"] == "test-id"
        assert f_dict["category"] == "JWT_NONE_ALGORITHM"
