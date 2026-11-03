"""
utils.ai.semantic_dedup — Semantic deduplication of scan findings.

Provides :class:`SemanticDeduplicator`, which groups :class:`~utils.findings.Finding`
objects that describe the same underlying root cause across modules.

Two strategies are supported:

**LLM-assisted** (when an :class:`~utils.ai.provider_base.LLMProvider` is
configured):
  Sends a redacted JSON representation of all findings to the LLM, asking it
  to group semantically similar findings.  The LLM must express a group only
  when it is confident the findings share the same root cause; ambiguous pairs
  are intentionally left as singletons (Requirement 6.3 — prefer false-negative
  of grouping over false-positive).

**Deterministic fallback** (no provider, or provider unavailable):
  Groups findings whose ``(owasp_category, category)`` pair is identical.
  Because both fields must match exactly, this is deliberately conservative —
  only obvious duplicates (same OWASP category AND same vulnerability class)
  are merged.  Any finding with a unique combination remains a singleton.

In both strategies every original :class:`~utils.findings.Finding` object is
**never** modified.  The returned :class:`FindingGroup` objects carry only IDs
as references to the originals (Requirements 6.1, 6.2, 5.2).

Singleton findings (those that could not be grouped with any other finding)
each appear as a :class:`FindingGroup` with a single ``member_finding_ids``
entry so that callers always receive the full set regardless of whether
grouping occurred.

Prompt and response content is logged at **DEBUG level only** (never at INFO
or above) to avoid leaking target data into operator-visible logs.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from utils.ai.provider_base import (
    LLMProvider,
    LLMProviderUnavailableError,
    LLMResponseParseError,
)

if TYPE_CHECKING:
    from utils.findings import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class FindingGroup:
    """A cluster of semantically related :class:`~utils.findings.Finding` objects.

    Each group preserves full references to the original findings via
    ``member_finding_ids`` so no information is lost (Requirement 6.2).
    Singleton groups (a single ungrouped finding) are also represented as a
    ``FindingGroup`` so that callers receive the complete set in a uniform
    format.

    Attributes:
        group_id: Unique identifier for the group (UUID v4 string).
        root_cause_summary: Human-readable description of the shared root
            cause inferred by the LLM or the deterministic fallback.
        member_finding_ids: IDs of every :class:`~utils.findings.Finding`
            that belongs to this group.  Contains exactly one element for
            singleton groups.
    """

    group_id: str
    root_cause_summary: str
    member_finding_ids: list[str]


# ---------------------------------------------------------------------------
# LLM prompt templates
# ---------------------------------------------------------------------------

_DEDUP_SYSTEM_CONTEXT = (
    "You are a security analyst assistant reviewing API penetration test findings.\n"
    "You will receive a JSON array of security findings from an automated scan.\n"
    "Your task is to identify groups of findings that describe the SAME underlying "
    "root cause or vulnerability.\n\n"
    "IMPORTANT RULES:\n"
    "  1. Only group findings when you are HIGHLY CONFIDENT they share the same root cause.\n"
    "  2. When in doubt, DO NOT group. Prefer leaving findings separate over incorrect grouping.\n"
    "  3. Each finding may appear in at most one group.\n"
    "  4. Findings that are not clearly related should each form their own singleton group.\n\n"
    "Respond ONLY with a valid JSON object with exactly one key:\n"
    '  - "groups": array of group objects, where each group object has:\n'
    '      - "root_cause_summary": string — concise description of the shared root cause\n'
    '      - "member_finding_ids": array of finding ID strings (2+ members, NEVER 1)\n\n'
    "Groups with only 1 member are not valid — if a finding cannot be confidently grouped "
    "with another, do NOT include it in the response. Ungrouped findings will be treated "
    "as singletons automatically.\n\n"
    "Do not include any text, explanation, or markdown outside the JSON object."
)

_DEDUP_MAX_TOKENS = 2048
_DEFAULT_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Redaction helpers (shared pattern from triage_assistant)
# ---------------------------------------------------------------------------

_redactor: Any = None


def _get_redactor() -> Any:
    """Return (and lazily create) the shared redaction helper.

    Returns ``None`` and emits a warning if the BOLA module cannot be
    imported (e.g. missing dependency).
    """
    global _redactor  # noqa: PLW0603
    if _redactor is None:
        try:
            from modules.owasp.bola_testing import BOLATestingModule  # noqa: PLC0415

            _redactor = BOLATestingModule.__new__(BOLATestingModule)
        except Exception:
            logger.warning(
                "semantic_dedup_redactor_unavailable: "
                "BOLATestingModule.redact_secrets could not be imported; "
                "secrets will NOT be redacted before sending to LLM "
                "(Requirement 5.5 not satisfied).",
                exc_info=True,
            )
    return _redactor


def _redact(text: str) -> str:
    """Apply ``BOLATestingModule.redact_secrets`` to *text*.

    Falls back to the original *text* if redaction raises unexpectedly,
    emitting a warning so the operator is aware that redaction was skipped.
    Never raises.
    """
    if not text:
        return text
    redactor = _get_redactor()
    if redactor is None:
        return text
    try:
        return redactor.redact_secrets(text)
    except Exception:
        logger.warning(
            "semantic_dedup_redact_secrets_raised: "
            "redact_secrets raised unexpectedly; evidence sent without "
            "redaction (Requirement 5.5 not met).",
            exc_info=True,
        )
        return text


def _redacted_finding_dict(finding: Finding) -> dict[str, Any]:
    """Build a JSON-serialisable dict from *finding* with secrets redacted.

    The original ``Finding`` object is **never** modified.
    """
    return {
        "id": finding.id,
        "category": finding.category,
        "owasp_category": finding.owasp_category,
        "severity": finding.severity.value if finding.severity is not None else None,
        "endpoint": finding.endpoint,
        "method": finding.method,
        "evidence": _redact(finding.evidence or ""),
        "recommendation": finding.recommendation,
        "payload": _redact(finding.payload) if finding.payload else None,
    }


# ---------------------------------------------------------------------------
# SemanticDeduplicator
# ---------------------------------------------------------------------------


class SemanticDeduplicator:
    """Group semantically equivalent findings across scan modules.

    When a :class:`~utils.ai.provider_base.LLMProvider` is configured, it is
    used to identify findings that share the same root cause by semantic
    analysis of their evidence, OWASP categories, and descriptions.  When no
    provider is available the class falls back to a deterministic strategy
    based on ``(owasp_category, category)`` exact matches.

    Both strategies prefer **not** grouping when confidence is insufficient
    (Requirement 6.3).  Every original finding always appears in exactly one
    :class:`FindingGroup` in the returned list — either as a member of a
    multi-finding group or as a singleton group (Requirement 6.1, 6.2).

    Args:
        provider: Configured LLM provider, or ``None`` to force deterministic
            fallback.  Graceful degradation is also applied when the provider
            raises :class:`~utils.ai.provider_base.LLMProviderUnavailableError`
            or :class:`~utils.ai.provider_base.LLMResponseParseError` during a
            call — the fallback is used transparently in those cases.
    """

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def deduplicate(self, findings: list[Finding]) -> list[FindingGroup]:
        """Group *findings* by shared root cause and return a list of groups.

        Each finding in *findings* will appear in exactly one returned
        :class:`FindingGroup`, either as a member of a multi-finding group
        (when confidently grouped) or as a singleton group (Requirement 6.2,
        no information loss).

        Secrets in evidence and payloads are redacted **before** any data
        is sent to the LLM provider (Requirement 5.5).  The original
        :class:`~utils.findings.Finding` objects are **never** modified.

        When no provider is configured, or the provider is unavailable, the
        deterministic fallback strategy is used transparently (Requirement 6.3,
        graceful degradation).

        Args:
            findings: List of findings to deduplicate.  Treated as read-only.

        Returns:
            A list of :class:`FindingGroup` objects.  The length may be
            anywhere from 1 (all findings share a root cause) to
            ``len(findings)`` (all singletons).  Empty input returns ``[]``.
        """
        if not findings:
            return []

        if self.provider is not None:
            try:
                return await self._llm_deduplicate(findings)
            except (LLMProviderUnavailableError, LLMResponseParseError) as exc:
                logger.warning(
                    "semantic_dedup_llm_unavailable: LLM deduplication failed (%s: %s); "
                    "falling back to deterministic strategy.",
                    type(exc).__name__,
                    exc,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "semantic_dedup_llm_unexpected_error: Unexpected error during LLM "
                    "deduplication (%s: %s); falling back to deterministic strategy.",
                    type(exc).__name__,
                    exc,
                )

        return self._deterministic_deduplicate(findings)

    # ------------------------------------------------------------------
    # LLM-assisted strategy
    # ------------------------------------------------------------------

    async def _llm_deduplicate(self, findings: list[Finding]) -> list[FindingGroup]:
        """Use the LLM to group findings by semantic similarity.

        Raises:
            LLMProviderUnavailableError: If the provider cannot be reached.
            LLMResponseParseError: If the LLM response cannot be parsed.
        """
        assert self.provider is not None  # guarded by caller

        # Build redacted representation — originals are never modified.
        redacted_dicts = [_redacted_finding_dict(f) for f in findings]
        findings_json = json.dumps(redacted_dicts, ensure_ascii=False, indent=2)

        prompt = f"{_DEDUP_SYSTEM_CONTEXT}\n\nFindings:\n{findings_json}"

        logger.debug(
            "semantic_dedup_prompt_built: finding_count=%d prompt_length=%d",
            len(findings),
            len(prompt),
        )

        response_text = await self.provider.complete(
            prompt,
            max_tokens=_DEDUP_MAX_TOKENS,
            timeout=_DEFAULT_TIMEOUT,
        )

        logger.debug(
            "semantic_dedup_response_received: response_length=%d",
            len(response_text),
        )

        return self._parse_llm_response(response_text, findings)

    def _parse_llm_response(
        self,
        response_text: str,
        original_findings: list[Finding],
    ) -> list[FindingGroup]:
        """Parse the LLM grouping response into a list of :class:`FindingGroup`.

        Singletons (findings not mentioned in any LLM group) are appended
        automatically so every finding appears in exactly one group.

        Args:
            response_text: Raw text returned by the LLM provider.
            original_findings: Original findings (used to validate IDs and
                fill in singletons for any findings the LLM did not mention).

        Returns:
            Complete list of :class:`FindingGroup` objects.

        Raises:
            LLMResponseParseError: If the response is not valid JSON or lacks
                the expected structure.
        """
        valid_ids: set[str] = {f.id for f in original_findings}

        # Strip markdown code fences that some LLMs add around JSON.
        text = response_text.strip()
        if text.startswith("```"):
            newline_pos = text.find("\n")
            text = text[newline_pos + 1 :] if newline_pos != -1 else text[3:]
        if text.endswith("```"):
            text = text[: text.rfind("```")]
        text = text.strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMResponseParseError(
                f"Deduplication response was not valid JSON: {exc}\n"
                f"Raw response (first 500 chars): {response_text[:500]!r}"
            ) from exc

        if not isinstance(parsed, dict):
            raise LLMResponseParseError(
                f"Deduplication response JSON root was {type(parsed).__name__!r}; "
                "expected a JSON object."
            )

        raw_groups = parsed.get("groups", [])
        if not isinstance(raw_groups, list):
            raw_groups = []

        groups: list[FindingGroup] = []
        claimed_ids: set[str] = set()

        for raw_group in raw_groups:
            if not isinstance(raw_group, dict):
                continue

            summary = raw_group.get("root_cause_summary", "")
            if not isinstance(summary, str):
                summary = str(summary)

            raw_member_ids = raw_group.get("member_finding_ids", [])
            if not isinstance(raw_member_ids, list):
                continue

            # Validate: keep only real IDs; skip IDs already claimed by a
            # prior group (an ID can only appear in one group).
            member_ids = [
                str(mid)
                for mid in raw_member_ids
                if str(mid) in valid_ids and str(mid) not in claimed_ids
            ]

            # Requirement 6.3: only accept groups with 2+ members. A
            # "group" of 1 is just a singleton and is handled below.
            if len(member_ids) < 2:
                logger.debug(
                    "semantic_dedup_group_rejected: group with %d valid member(s) "
                    "discarded (minimum 2 required by Requirement 6.3).",
                    len(member_ids),
                )
                continue

            claimed_ids.update(member_ids)
            groups.append(
                FindingGroup(
                    group_id=str(uuid.uuid4()),
                    root_cause_summary=summary or "Shared root cause identified by AI analysis.",
                    member_finding_ids=member_ids,
                )
            )

        # Append singletons for every finding not included in any group.
        for finding in original_findings:
            if finding.id not in claimed_ids:
                groups.append(
                    FindingGroup(
                        group_id=str(uuid.uuid4()),
                        root_cause_summary=(
                            f"{finding.category}"
                            + (f" ({finding.owasp_category})" if finding.owasp_category else "")
                        ),
                        member_finding_ids=[finding.id],
                    )
                )

        return groups

    # ------------------------------------------------------------------
    # Deterministic fallback strategy
    # ------------------------------------------------------------------

    def _deterministic_deduplicate(self, findings: list[Finding]) -> list[FindingGroup]:
        """Group findings by exact ``(owasp_category, category)`` match.

        This is a conservative strategy: both the OWASP category and the
        vulnerability category must match exactly for two findings to be
        grouped together.  Findings with a unique combination, or whose
        ``owasp_category`` is ``None``, remain as singletons (Requirement 6.3).

        Args:
            findings: Findings to group.

        Returns:
            List of :class:`FindingGroup` objects covering all findings.
        """
        # Map (owasp_category, category) -> list of finding IDs.
        # We only group when owasp_category is not None (a None owasp_category
        # means we cannot determine a shared OWASP root cause, so we leave those
        # as singletons to avoid incorrect grouping — Requirement 6.3).
        bucket: dict[tuple[str, str], list[str]] = {}
        no_owasp: list[Finding] = []

        for finding in findings:
            if finding.owasp_category is None:
                no_owasp.append(finding)
            else:
                key = (finding.owasp_category, finding.category)
                bucket.setdefault(key, []).append(finding.id)

        groups: list[FindingGroup] = []

        for (owasp_cat, vuln_cat), member_ids in bucket.items():
            if len(member_ids) >= 2:
                groups.append(
                    FindingGroup(
                        group_id=str(uuid.uuid4()),
                        root_cause_summary=(
                            f"{vuln_cat} ({owasp_cat}): "
                            "multiple findings share the same OWASP category and "
                            "vulnerability class."
                        ),
                        member_finding_ids=list(member_ids),
                    )
                )
            else:
                # Singleton — find the original finding to build a summary.
                finding = next(
                    f for f in findings if f.id == member_ids[0]
                )
                groups.append(
                    FindingGroup(
                        group_id=str(uuid.uuid4()),
                        root_cause_summary=(
                            f"{finding.category} ({owasp_cat})"
                        ),
                        member_finding_ids=[finding.id],
                    )
                )

        for finding in no_owasp:
            groups.append(
                FindingGroup(
                    group_id=str(uuid.uuid4()),
                    root_cause_summary=finding.category,
                    member_finding_ids=[finding.id],
                )
            )

        return groups

    # ------------------------------------------------------------------
    # Graceful-degradation wrapper
    # ------------------------------------------------------------------

    async def safe_deduplicate(self, findings: list[Finding]) -> list[FindingGroup] | None:
        """Run :meth:`deduplicate` and degrade gracefully on any unexpected failure.

        This is the **preferred call-site entry point** for the ``--ai-dedup``
        CLI flag.  Returns ``None`` only if an entirely unexpected error occurs
        (in practice :meth:`deduplicate` handles its own degradation via the
        deterministic fallback, so ``None`` is a very rare outcome).

        Args:
            findings: List of findings to deduplicate; treated as read-only.

        Returns:
            A list of :class:`FindingGroup` objects on success, or ``None``
            when an unexpected error prevents even the deterministic fallback
            from completing.  Downstream code MUST treat ``None`` as "dedup
            section absent".
        """
        try:
            return await self.deduplicate(findings)
        except Exception as exc:  # noqa: BLE001
            if self.provider is None:
                logger.warning(
                    "ai_dedup_skipped_no_provider: No LLM provider configured. "
                    "Semantic deduplication will be skipped. "
                    "To enable AI-assisted deduplication, set 'ai_provider' in your "
                    "APILeak YAML config (Requirement 7.2). Cause: %s",
                    exc,
                )
            else:
                logger.warning(
                    "ai_dedup_skipped_unexpected_error: Semantic deduplication failed "
                    "unexpectedly (%s: %s) — the dedup section will be omitted.",
                    type(exc).__name__,
                    exc,
                )
            return None
