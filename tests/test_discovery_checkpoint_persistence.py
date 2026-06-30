"""
Unit tests for discovery-checkpoint persistence.

**Feature: owasp-complete-purple-teaming-cicd, Task 43.1**

These example-based tests pin down the checkpoint save/load contract:

- ``save`` writes the JSON shape from the design (``tested`` + ``results``) and
  round-trips losslessly; an unwritable path raises
  :class:`DiscoveryCheckpointWriteError` naming the path and leaves no partial
  file (Requirement 37.6)
- ``load`` is strict: a missing path, unreadable/corrupt JSON, or a
  wrong-structure document raises :class:`DiscoveryCheckpointError` naming the
  artifact and loads no records (Requirement 37.5)
"""

import json
import os
from unittest import mock

import pytest

from utils.discovery_checkpoint import (
    SCHEMA_VERSION,
    DiscoveryCheckpoint,
    DiscoveryCheckpointError,
    DiscoveryCheckpointWriteError,
)
from utils.discovery_session import DiscoveryResult


def _result(status_code: int, url: str = "https://api.example.com/users") -> DiscoveryResult:
    """Build a DiscoveryResult with the given status code."""
    return DiscoveryResult(
        url=url,
        method="GET",
        status_code=status_code,
        endpoint_status="valid",
    )


def _checkpoint() -> DiscoveryCheckpoint:
    """Build a representative checkpoint with tested candidates and results."""
    return DiscoveryCheckpoint(
        target="https://api.example.com/",
        timestamp="2025-01-01T00:00:00+00:00",
        tool_version="0.2.0",
        tested=[
            ("https://api.example.com/users", "GET"),
            ("https://api.example.com/admin", "GET"),
        ],
        results=[_result(200, "https://api.example.com/users")],
    )


# ---------------------------------------------------------------------------
# save / round-trip
# ---------------------------------------------------------------------------


def test_save_writes_expected_json_shape(tmp_path):
    """save writes schema_version, tested objects, and DiscoveryResult dicts."""
    checkpoint = _checkpoint()
    path = str(tmp_path / "checkpoint.json")

    checkpoint.save(path)

    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["target"] == "https://api.example.com/"
    assert document["timestamp"] == "2025-01-01T00:00:00+00:00"
    assert document["tool_version"] == "0.2.0"
    assert document["tested"] == [
        {"url": "https://api.example.com/users", "method": "GET"},
        {"url": "https://api.example.com/admin", "method": "GET"},
    ]
    assert document["results"] == [
        {
            "url": "https://api.example.com/users",
            "method": "GET",
            "status_code": 200,
            "endpoint_status": "valid",
        }
    ]


def test_save_then_load_round_trips(tmp_path):
    """A saved checkpoint reloads with identical tested pairs and results."""
    checkpoint = _checkpoint()
    path = str(tmp_path / "checkpoint.json")

    checkpoint.save(path)
    reloaded = DiscoveryCheckpoint.load(path)

    assert reloaded.target == checkpoint.target
    assert reloaded.timestamp == checkpoint.timestamp
    assert reloaded.tool_version == checkpoint.tool_version
    assert reloaded.tested == checkpoint.tested
    assert reloaded.results == checkpoint.results


def test_save_empty_checkpoint_round_trips(tmp_path):
    """Empty tested/results arrays are valid and reload as empty."""
    checkpoint = DiscoveryCheckpoint(
        target="https://api.example.com/",
        timestamp="2025-01-01T00:00:00+00:00",
        tool_version="0.2.0",
    )
    path = str(tmp_path / "empty.json")

    checkpoint.save(path)
    reloaded = DiscoveryCheckpoint.load(path)

    assert reloaded.tested == []
    assert reloaded.results == []


def test_save_unwritable_path_raises_and_leaves_no_partial_file(tmp_path):
    """An unwritable path raises a descriptive write error and leaves no temp file (37.6)."""
    checkpoint = _checkpoint()
    path = str(tmp_path / "checkpoint.json")
    tmp_file = f"{path}.tmp"

    with mock.patch(
        "utils.discovery_checkpoint.os.replace",
        side_effect=OSError("permission denied"),
    ):
        with pytest.raises(DiscoveryCheckpointWriteError) as exc_info:
            checkpoint.save(path)

    message = str(exc_info.value)
    assert path in message
    assert "permission denied" in message
    assert not os.path.exists(path)
    assert not os.path.exists(tmp_file)


# ---------------------------------------------------------------------------
# load error handling (Requirement 37.5)
# ---------------------------------------------------------------------------


def test_load_missing_path_raises_error_naming_artifact(tmp_path):
    """Loading a non-existent path raises a checkpoint error naming the path (37.5)."""
    missing = str(tmp_path / "does_not_exist.json")

    with pytest.raises(DiscoveryCheckpointError) as exc_info:
        DiscoveryCheckpoint.load(missing)

    assert missing in str(exc_info.value)


def test_load_corrupt_json_raises_error(tmp_path):
    """Unparseable JSON raises a checkpoint error (37.5)."""
    path = tmp_path / "corrupt.json"
    path.write_text("{ this is not valid json", encoding="utf-8")

    with pytest.raises(DiscoveryCheckpointError) as exc_info:
        DiscoveryCheckpoint.load(str(path))

    assert str(path) in str(exc_info.value)


def test_load_top_level_not_object_raises_error(tmp_path):
    """A non-object top-level value raises a checkpoint error (37.5)."""
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    with pytest.raises(DiscoveryCheckpointError):
        DiscoveryCheckpoint.load(str(path))


def test_load_missing_tested_array_raises_error(tmp_path):
    """A document missing the 'tested' array raises a checkpoint error (37.5)."""
    path = tmp_path / "no_tested.json"
    path.write_text(json.dumps({"results": []}), encoding="utf-8")

    with pytest.raises(DiscoveryCheckpointError):
        DiscoveryCheckpoint.load(str(path))


def test_load_missing_results_array_raises_error(tmp_path):
    """A document missing the 'results' array raises a checkpoint error (37.5)."""
    path = tmp_path / "no_results.json"
    path.write_text(json.dumps({"tested": []}), encoding="utf-8")

    with pytest.raises(DiscoveryCheckpointError):
        DiscoveryCheckpoint.load(str(path))


def test_load_malformed_tested_entry_raises_error(tmp_path):
    """A tested entry without string url/method raises a checkpoint error (37.5)."""
    path = tmp_path / "bad_tested.json"
    path.write_text(
        json.dumps({"tested": [{"url": "u", "method": 5}], "results": []}),
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryCheckpointError):
        DiscoveryCheckpoint.load(str(path))


def test_load_malformed_result_raises_error(tmp_path):
    """A malformed record inside 'results' raises a checkpoint error (37.5)."""
    path = tmp_path / "bad_result.json"
    path.write_text(
        json.dumps(
            {
                "tested": [],
                "results": [
                    {
                        "url": "u",
                        "method": "GET",
                        "status_code": "200",
                        "endpoint_status": "valid",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryCheckpointError):
        DiscoveryCheckpoint.load(str(path))
