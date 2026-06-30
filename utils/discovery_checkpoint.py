"""
Discovery Checkpoint model and persistence.

This module defines the persistent checkpoint artifact (:class:`DiscoveryCheckpoint`)
used to resume an interrupted ``dir`` discovery run without re-requesting
already-tested candidates (Requirement 37).

The checkpoint mirrors :class:`~utils.discovery_session.DiscoverySession`'s
atomic-write and strict-load discipline, but it is a **separate artifact** with
its own shape: in addition to the discovered ``results`` it records the in-flight
``tested`` candidates (the ``(normalized url, method)`` pairs already issued),
which the session file does not store. Writes are atomic
(temp-file-then-``os.replace``) so a failure never leaves a partially written
checkpoint behind (Requirement 37.6), and reload is strict: a missing,
unreadable, or wrong-structure artifact raises a descriptive
:class:`DiscoveryCheckpointError` naming the artifact and loads no records
(Requirement 37.5).

The ``results`` array reuses the exact ``DiscoveryResult.to_dict()`` /
``from_dict()`` shape from :mod:`utils.discovery_session`, so discovered records
round-trip losslessly and can be merged with newly discovered ones.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Tuple

from core.logging import get_logger
from utils.discovery_session import DiscoveryResult

logger = get_logger(__name__)

# Version of the on-disk checkpoint file schema. Bumped if the JSON shape changes.
SCHEMA_VERSION = 1


class DiscoveryCheckpointError(Exception):
    """Raised when a checkpoint artifact cannot be loaded (Requirement 37.5).

    Covers a missing path, an unreadable file, unparseable JSON, or JSON that
    does not match the expected checkpoint structure. The message names the
    offending artifact.
    """


class DiscoveryCheckpointWriteError(DiscoveryCheckpointError):
    """Raised when a checkpoint artifact cannot be written (Requirement 37.6).

    The message names the destination path and no partially written checkpoint
    is left behind.
    """


@dataclass
class DiscoveryCheckpoint:
    """A persisted discovery checkpoint: metadata, tested candidates, and results.

    The checkpoint produced by :meth:`save` is the resume artifact consumed by
    :meth:`load`. ``tested`` carries the ``(normalized url, method)`` candidates
    already issued (the resume seed for ``tested_urls``) and ``results`` carries
    the discovered records (projected via
    :meth:`~utils.discovery_session.DiscoveryResult.from_endpoint`) to be merged
    with newly discovered ones.
    """

    target: str
    timestamp: str
    tool_version: str
    # (normalized url, method) pairs already issued; urls are stored canonical
    # so resume comparison is canonical (Requirement 38).
    tested: List[Tuple[str, str]] = field(default_factory=list)
    results: List[DiscoveryResult] = field(default_factory=list)

    def save(self, path: str) -> None:
        """Atomically write the checkpoint to ``path`` as JSON.

        The document is written to a temporary file in the same directory and
        then moved into place with :func:`os.replace`, so a failure mid-write
        never leaves a partial checkpoint (Requirement 37.6). ``tested`` pairs
        are serialized as ``{"url": ..., "method": ...}`` objects and ``results``
        reuse :meth:`DiscoveryResult.to_dict`.

        Args:
            path: Destination path for the checkpoint JSON file.

        Raises:
            DiscoveryCheckpointWriteError: If the file cannot be written. The
                underlying :class:`OSError` is wrapped with a descriptive
                message naming ``path`` and any temporary file is removed.
        """
        document = {
            "schema_version": SCHEMA_VERSION,
            "target": self.target,
            "timestamp": self.timestamp,
            "tool_version": self.tool_version,
            "tested": [{"url": url, "method": method} for url, method in self.tested],
            "results": [result.to_dict() for result in self.results],
        }

        directory = os.path.dirname(os.path.abspath(path))
        tmp_path = f"{path}.tmp"
        try:
            os.makedirs(directory, exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
            os.replace(tmp_path, path)
        except OSError as exc:
            # Clean up the partial temp file so no partially written checkpoint
            # artifact remains (Requirement 37.6).
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            raise DiscoveryCheckpointWriteError(
                f"failed to write discovery checkpoint '{path}': {exc}"
            ) from exc

        logger.info(
            "Discovery checkpoint saved",
            path=path,
            tested=len(self.tested),
            records=len(self.results),
        )

    @classmethod
    def load(cls, path: str) -> "DiscoveryCheckpoint":
        """Load a discovery checkpoint from its JSON artifact (strict).

        The top-level object must contain a ``tested`` array of
        ``{"url", "method"}`` objects (both strings) and a ``results`` array
        whose every element carries the four
        :class:`~utils.discovery_session.DiscoveryResult` keys with correct
        types. Empty ``tested``/``results`` arrays are valid and yield an empty
        checkpoint.

        Args:
            path: Path to the checkpoint JSON file.

        Returns:
            The reconstructed :class:`DiscoveryCheckpoint`.

        Raises:
            DiscoveryCheckpointError: If ``path`` does not exist, cannot be read,
                is not valid JSON, or does not match the expected checkpoint
                structure (Requirement 37.5). No records are loaded in this case.
        """
        if not path or not os.path.exists(path):
            raise DiscoveryCheckpointError(
                f"discovery checkpoint not found: '{path}'"
            )

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise DiscoveryCheckpointError(
                f"invalid discovery checkpoint '{path}': not readable as JSON ({exc})"
            ) from exc

        if not isinstance(data, dict):
            raise DiscoveryCheckpointError(
                f"invalid discovery checkpoint '{path}': top-level value must be an object"
            )

        raw_tested = data.get("tested")
        if not isinstance(raw_tested, list):
            raise DiscoveryCheckpointError(
                f"invalid discovery checkpoint '{path}': missing 'tested' array"
            )

        raw_results = data.get("results")
        if not isinstance(raw_results, list):
            raise DiscoveryCheckpointError(
                f"invalid discovery checkpoint '{path}': missing 'results' array"
            )

        tested: List[Tuple[str, str]] = []
        for entry in raw_tested:
            if not isinstance(entry, dict):
                raise DiscoveryCheckpointError(
                    f"invalid discovery checkpoint '{path}': each tested entry "
                    "must be a JSON object"
                )
            url = entry.get("url")
            method = entry.get("method")
            if not isinstance(url, str) or not isinstance(method, str):
                raise DiscoveryCheckpointError(
                    f"invalid discovery checkpoint '{path}': each tested entry "
                    "must have string 'url' and 'method'"
                )
            tested.append((url, method))

        # DiscoveryResult.from_dict raises InvalidSessionFileError on a malformed
        # record; wrap it so callers see a single checkpoint-error type naming
        # this artifact (Requirement 37.5).
        try:
            results = [DiscoveryResult.from_dict(entry) for entry in raw_results]
        except Exception as exc:
            raise DiscoveryCheckpointError(
                f"invalid discovery checkpoint '{path}': malformed result ({exc})"
            ) from exc

        checkpoint = cls(
            target=data.get("target", "") if isinstance(data.get("target"), str) else "",
            timestamp=data.get("timestamp", "")
            if isinstance(data.get("timestamp"), str)
            else "",
            tool_version=data.get("tool_version", "")
            if isinstance(data.get("tool_version"), str)
            else "",
            tested=tested,
            results=results,
        )

        logger.info(
            "Discovery checkpoint loaded",
            path=path,
            tested=len(tested),
            records=len(results),
        )
        return checkpoint
