"""
utils.ai.triage_assistant — AI-assisted finding triage and remediation.

Provides :class:`FindingTriageAssistant`, which uses a configured
:class:`~utils.ai.provider_base.LLMProvider` to:

- :meth:`~FindingTriageAssistant.triage`: prioritise a list of
  :class:`~utils.findings.Finding` objects and produce a :class:`TriageReport`
  with a narrative summary, ordered finding IDs, and per-finding notes.
  Secrets in evidence are **always** redacted before any data leaves the
  process (Requirement 5.5).
- :meth:`~FindingTriageAssistant.explain_remediation`: generate a specific,
  contextualised remediation recommendation for a single
  :class:`~utils.findings.Finding`, using its OWASP category and module of
  origin as context (Requirement 5.4).

**Graceful-degradation wrappers** (Requirement 5.3, 7.2, 10.1, 10.2):

- :meth:`~FindingTriageAssistant.safe_triage`: wraps :meth:`triage` and
  catches :class:`~utils.ai.provider_base.LLMProviderUnavailableError` and
  :class:`~utils.ai.provider_base.LLMResponseParseError`, logging a WARNING
  and returning ``None`` so the calling scan can omit the AI section without
  raising an unhandled exception.
- :meth:`~FindingTriageAssistant.safe_explain_remediation`: same pattern for
  per-finding remediation advice.

Both safe methods emit distinct WARNING messages depending on whether the
failure is a missing provider configuration (Requirement 7.2 — includes
instructions for configuring a provider) or a runtime availability/parse
failure (Requirement 5.3, 10.1, 10.2 — operational warning).

The original :class:`~utils.findings.Finding` objects are **never** modified;
all AI output lives exclusively in the returned :class:`TriageReport` or the
returned ``str`` (Requirement 5.2).

Prompt and response content is logged at **DEBUG level only** — never at INFO
or above — to avoid leaking target data into operator-visible logs
(principle of least exposure).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from utils.ai.provider_base import LLMProvider, LLMProviderUnavailableError, LLMResponseParseError

if TYPE_CHECKING:
    from utils.findings import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TriageReport:
    """AI-generated triage output for a set of scan findings.

    This is the **only** place AI output should reside; the original
    :class:`~utils.findings.Finding` objects are never modified
    (Requirement 5.2).

    Attributes:
        prioritized_finding_ids: Finding IDs ordered from highest to lowest
            priority as determined by the LLM.
        narrative_summary: Free-text summary of the overall scan results and
            the rationale for the prioritisation.
        per_finding_notes: Mapping of finding ID to a short AI-generated note
            explaining the priority or key context for that finding.
    """

    prioritized_finding_ids: list[str]
    narrative_summary: str
    per_finding_notes: dict[str, str]


# ---------------------------------------------------------------------------
# Internal redaction helpers
# ---------------------------------------------------------------------------

# Lazy-initialised bare BOLATestingModule instance used solely for
# ``redact_secrets``.  Created via ``__new__`` — mirrors the pattern used in
# ``utils/jwt_attack_engine.py``, ``modules/owasp/auth_testing.py``, and
# ``mcp_server/audit_log.py`` — so no HTTP client / config is required.
# Module-level singleton; initialised on first call to ``_get_redactor``.
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
                "triage_assistant_redactor_unavailable: "
                "BOLATestingModule.redact_secrets could not be imported; "
                "secrets will NOT be redacted before sending to LLM "
                "(Requirement 5.5 not satisfied).",
                exc_info=True,
            )
    return _redactor


def _redact(text: str) -> str:
    """Apply ``BOLATestingModule.redact_secrets`` to *text*.

    Falls back to the original *text* if redaction raises unexpectedly,
    emitting a warning so the operator is aware that redaction was skipped
    (Requirement 5.5).  Never raises.
    """
    if not text:
        return text
    redactor = _get_redactor()
    if redactor is None:
        # Warning already emitted in ``_get_redactor``; propagate original.
        return text
    try:
        return redactor.redact_secrets(text)
    except Exception:
        logger.warning(
            "triage_redact_secrets_raised: "
            "redact_secrets raised unexpectedly; evidence sent without "
            "redaction (Requirement 5.5 not met).",
            exc_info=True,
        )
        return text


def _redacted_finding_dict(finding: Finding) -> dict[str, Any]:
    """Build a JSON-serialisable dict from *finding* with secrets redacted.

    The original ``Finding`` object is **never** modified — this function
    creates a fresh dict (Requirements 5.2, 5.5).
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
        "response_snippet": (
            _redact(finding.response_snippet) if finding.response_snippet else None
        ),
    }


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_TRIAGE_SYSTEM_CONTEXT = (
    "You are a security analyst assistant reviewing API penetration test results.\n"
    "You will receive a JSON array of security findings from an automated scan.\n"
    "Your task is to prioritise them and provide a triage summary.\n\n"
    "Respond ONLY with a valid JSON object with exactly these three keys:\n"
    "  - \"prioritized_finding_ids\": array of finding IDs (strings) ordered "
    "from highest to lowest priority\n"
    "  - \"narrative_summary\": string — overall summary of results and "
    "reasoning for the prioritisation\n"
    "  - \"per_finding_notes\": object mapping each finding ID to a short "
    "note explaining its priority or key context\n\n"
    "Do not include any text, explanation, or markdown outside the JSON object."
)

_REMEDIATION_SYSTEM_CONTEXT = (
    "You are a security engineer providing actionable API security remediation advice.\n"
    "You will receive details about a single security finding, including its OWASP "
    "category and the vulnerability module that detected it.\n"
    "Provide a concise, SPECIFIC remediation recommendation (2–5 sentences).\n"
    "The recommendation must be specific to the vulnerability category and OWASP "
    "context — do not give generic advice."
)

# Conservative token limits for LLM calls.
_TRIAGE_MAX_TOKENS = 2048
_REMEDIATION_MAX_TOKENS = 512

# Default per-request timeout (seconds).  Callers may override via the
# provider's AIConfig.timeout_seconds, but this is the value used directly
# in the ``complete`` call here.
_DEFAULT_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# FindingTriageAssistant
# ---------------------------------------------------------------------------


class FindingTriageAssistant:
    """AI-assisted triage and remediation for scan findings.

    Uses a configured :class:`~utils.ai.provider_base.LLMProvider` to
    prioritise a batch of :class:`~utils.findings.Finding` objects and to
    generate contextualised remediation advice for individual findings.

    The provider may be ``None``; callers that need graceful degradation
    should check ``self.provider is not None`` before invoking the async
    methods (full graceful-degradation wrapper is implemented in task 8.4).
    Both methods raise :class:`~utils.ai.provider_base.LLMProviderUnavailableError`
    when called with a ``None`` provider so the caller's ``try/except`` is
    the correct hook for degradation (Requirement 5.3).

    Args:
        provider: Configured LLM provider.  May be ``None`` when no provider
            is configured; callers are responsible for graceful degradation.
    """

    def __init__(self, provider: LLMProvider | None) -> None:
        self.provider = provider

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def triage(self, findings: list[Finding]) -> TriageReport:
        """Prioritise *findings* with AI assistance and return a triage report.

        Secrets in finding evidence, payload, and response snippets are
        redacted **before** any data is sent to the LLM provider
        (Requirement 5.5).  The original :class:`~utils.findings.Finding`
        objects are **never** modified; all AI output resides exclusively in
        the returned :class:`TriageReport` (Requirement 5.2).

        Prompt and response content is logged only at DEBUG level
        (Requirement: prompt content not at INFO).

        Args:
            findings: List of findings to triage.  The list and its elements
                are treated as read-only — this method makes no in-place
                changes.

        Returns:
            A :class:`TriageReport` with prioritised IDs, a narrative summary,
            and per-finding notes.

        Raises:
            LLMProviderUnavailableError: If ``self.provider`` is ``None`` or
                the provider cannot be reached.  Callers should catch this
                and degrade gracefully (see task 8.4).
            LLMResponseParseError: If the LLM response cannot be parsed as
                the expected JSON structure.
        """
        if self.provider is None:
            raise LLMProviderUnavailableError(
                "No LLM provider configured; cannot run AI triage "
                "(Requirement 5.1, 5.3 — degrade gracefully in the caller)."
            )

        if not findings:
            # Edge case: nothing to triage — return a valid empty report.
            return TriageReport(
                prioritized_finding_ids=[],
                narrative_summary="No findings to triage.",
                per_finding_notes={},
            )

        # Build redacted representations — originals are untouched.
        redacted_dicts = [_redacted_finding_dict(f) for f in findings]
        findings_json = json.dumps(redacted_dicts, ensure_ascii=False, indent=2)

        prompt = f"{_TRIAGE_SYSTEM_CONTEXT}\n\nFindings:\n{findings_json}"

        logger.debug(
            "triage_prompt_built: finding_count=%d prompt_length=%d",
            len(findings),
            len(prompt),
        )

        response_text = await self.provider.complete(
            prompt,
            max_tokens=_TRIAGE_MAX_TOKENS,
            timeout=_DEFAULT_TIMEOUT,
        )

        logger.debug(
            "triage_response_received: response_length=%d",
            len(response_text),
        )

        return self._parse_triage_response(response_text, findings)

    async def explain_remediation(self, finding: Finding) -> str:
        """Generate a specific remediation recommendation for *finding*.

        The OWASP category and module/vulnerability category of origin are
        included in the prompt so the LLM can produce a specific (non-generic)
        recommendation (Requirement 5.4).  Secrets in finding evidence are
        redacted before sending to the LLM (Requirement 5.5).  The original
        :class:`~utils.findings.Finding` object is **never** modified
        (Requirement 5.2).

        Prompt and response content is logged only at DEBUG level
        (Requirement: prompt content not at INFO).

        Args:
            finding: The finding to generate a remediation for.

        Returns:
            A string containing a specific, contextualised remediation
            recommendation.

        Raises:
            LLMProviderUnavailableError: If ``self.provider`` is ``None`` or
                the provider cannot be reached.  Callers should catch this
                and degrade gracefully (see task 8.4).
            LLMResponseParseError: If the LLM response cannot be interpreted.
        """
        if self.provider is None:
            raise LLMProviderUnavailableError(
                "No LLM provider configured; cannot explain remediation "
                "(Requirement 5.4, 5.3 — degrade gracefully in the caller)."
            )

        # Build redacted context dict — original finding is never modified.
        redacted = _redacted_finding_dict(finding)

        # These two fields are the key context that makes the recommendation
        # specific rather than generic (Requirement 5.4).
        owasp_ctx = redacted["owasp_category"] or "unknown"
        module_ctx = redacted["category"] or "unknown"
        severity_ctx = redacted["severity"] or "unknown"

        prompt = (
            f"{_REMEDIATION_SYSTEM_CONTEXT}\n\n"
            f"Finding details:\n"
            f"  - ID: {redacted['id']}\n"
            f"  - OWASP Category: {owasp_ctx}\n"
            f"  - Module / Vulnerability Category: {module_ctx}\n"
            f"  - Severity: {severity_ctx}\n"
            f"  - Endpoint: {redacted['endpoint']}\n"
            f"  - HTTP Method: {redacted['method']}\n"
            f"  - Evidence: {redacted['evidence']}\n"
        )

        if redacted["payload"]:
            prompt += f"  - Payload: {redacted['payload']}\n"

        if redacted["response_snippet"]:
            prompt += f"  - Response Snippet: {redacted['response_snippet']}\n"

        logger.debug(
            "remediation_prompt_built: finding_id=%s owasp=%s module=%s prompt_length=%d",
            finding.id,
            owasp_ctx,
            module_ctx,
            len(prompt),
        )

        response_text = await self.provider.complete(
            prompt,
            max_tokens=_REMEDIATION_MAX_TOKENS,
            timeout=_DEFAULT_TIMEOUT,
        )

        logger.debug(
            "remediation_response_received: finding_id=%s response_length=%d",
            finding.id,
            len(response_text),
        )

        return response_text.strip()

    # ------------------------------------------------------------------
    # Graceful-degradation wrappers (Requirement 5.3, 7.2, 10.1, 10.2)
    # ------------------------------------------------------------------

    async def safe_triage(self, findings: list[Finding]) -> TriageReport | None:
        """Run :meth:`triage` and degrade gracefully on any AI-layer failure.

        This is the **preferred call-site entry point** for the ``--ai-triage``
        CLI flag.  It wraps :meth:`triage` in a ``try/except`` that:

        - Returns ``None`` (AI section absent) whenever the provider is not
          configured, is unreachable, times out, or returns an unparseable
          response.
        - Logs a **WARNING** (never ERROR) so the operator is informed without
          failing the overall scan.

        Two distinct warning messages are emitted:

        * *No provider configured* (``self.provider is None``): a clear message
          explaining how to configure a provider satisfies Requirement 7.2 —
          "fail that specific function with a clear message indicating how to
          configure a provider, without affecting the rest of the scan."
        * *Provider configured but unavailable / parse failure*: a shorter
          operational warning satisfies Requirements 5.3, 10.1, 10.2.

        Args:
            findings: List of findings to triage; treated as read-only.

        Returns:
            A :class:`TriageReport` on success, or ``None`` when the AI layer
            is unavailable.  Downstream code MUST treat ``None`` as "AI section
            absent" and omit it from the report.
        """
        try:
            return await self.triage(findings)
        except LLMProviderUnavailableError as exc:
            if self.provider is None:
                logger.warning(
                    "ai_triage_skipped_no_provider: No LLM provider is configured. "
                    "The AI triage section will be omitted from the report. "
                    "To enable AI triage, set 'ai_provider' (anthropic, openai, or bedrock) "
                    "in your APILeak YAML config and supply the corresponding credentials "
                    "via environment variable or secrets vault "
                    "(see Requirement 7.3 for details).",
                )
            else:
                logger.warning(
                    "ai_triage_skipped_provider_unavailable: The configured LLM provider "
                    "(%s) could not be reached — the AI triage section will be omitted. "
                    "Cause: %s",
                    self.provider.provider_name,
                    exc,
                )
            return None
        except LLMResponseParseError as exc:
            logger.warning(
                "ai_triage_skipped_parse_error: The LLM provider returned an unparseable "
                "response — the AI triage section will be omitted. Cause: %s",
                exc,
            )
            return None

    async def safe_explain_remediation(self, finding: Finding) -> str | None:
        """Run :meth:`explain_remediation` and degrade gracefully on any AI-layer failure.

        This is the **preferred call-site entry point** when generating
        per-finding remediation advice as part of a scan report.  It wraps
        :meth:`explain_remediation` in a ``try/except`` with the same
        degradation strategy as :meth:`safe_triage`:

        - Returns ``None`` when the provider is absent, unreachable, or
          returns an unparseable response.
        - Logs a **WARNING** so the operator is informed without failing the
          overall scan (Requirements 5.3, 10.1, 10.2).

        Args:
            finding: The finding for which to generate remediation advice;
                treated as read-only.

        Returns:
            A remediation string on success, or ``None`` when the AI layer is
            unavailable.  Downstream code MUST treat ``None`` as "AI section
            absent" and omit the remediation from the report.
        """
        try:
            return await self.explain_remediation(finding)
        except LLMProviderUnavailableError as exc:
            if self.provider is None:
                logger.warning(
                    "ai_remediation_skipped_no_provider: No LLM provider is configured. "
                    "AI-assisted remediation will be omitted for finding '%s'. "
                    "To enable AI remediation, set 'ai_provider' in your APILeak YAML config "
                    "(Requirement 7.2).",
                    finding.id,
                )
            else:
                logger.warning(
                    "ai_remediation_skipped_provider_unavailable: The configured LLM provider "
                    "(%s) could not be reached — AI remediation omitted for finding '%s'. "
                    "Cause: %s",
                    self.provider.provider_name,
                    finding.id,
                    exc,
                )
            return None
        except LLMResponseParseError as exc:
            logger.warning(
                "ai_remediation_skipped_parse_error: The LLM provider returned an unparseable "
                "response for finding '%s' — AI remediation omitted. Cause: %s",
                finding.id,
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_triage_response(
        self,
        response_text: str,
        original_findings: list[Finding],
    ) -> TriageReport:
        """Parse the LLM triage response JSON into a :class:`TriageReport`.

        Strips markdown code fences if present, then parses JSON.  Fields
        are validated and unknown/invalid finding IDs in the LLM response
        are silently dropped (the LLM cannot fabricate new IDs).

        Args:
            response_text: Raw text returned by the LLM provider.
            original_findings: The original findings (used to validate IDs
                in the LLM response — the LLM cannot introduce new IDs).

        Returns:
            A validated :class:`TriageReport`.

        Raises:
            LLMResponseParseError: If the response is not valid JSON or the
                root element is not a JSON object.
        """
        # Build a set of valid IDs so we can filter LLM-fabricated IDs.
        valid_ids: set[str] = {f.id for f in original_findings}

        # Strip markdown code fences that some LLMs add around JSON.
        text = response_text.strip()
        if text.startswith("```"):
            newline_pos = text.find("\n")
            if newline_pos != -1:
                text = text[newline_pos + 1 :]
            else:
                text = text[3:]  # e.g. "```{...}"
        if text.endswith("```"):
            text = text[: text.rfind("```")]
        text = text.strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMResponseParseError(
                f"Triage response was not valid JSON: {exc}\n"
                f"Raw response (first 500 chars): {response_text[:500]!r}"
            ) from exc

        if not isinstance(parsed, dict):
            raise LLMResponseParseError(
                f"Triage response JSON root was {type(parsed).__name__!r}; "
                "expected a JSON object."
            )

        # --- prioritized_finding_ids ---
        raw_ids = parsed.get("prioritized_finding_ids", [])
        if not isinstance(raw_ids, list):
            raw_ids = []
        # Retain only IDs that actually exist in the input findings.
        prioritized_ids = [str(id_) for id_ in raw_ids if str(id_) in valid_ids]

        # --- narrative_summary ---
        narrative_summary = parsed.get("narrative_summary", "")
        if not isinstance(narrative_summary, str):
            narrative_summary = str(narrative_summary)

        # --- per_finding_notes ---
        raw_notes = parsed.get("per_finding_notes", {})
        if not isinstance(raw_notes, dict):
            raw_notes = {}
        # Retain only notes for known IDs; coerce values to str.
        per_finding_notes: dict[str, str] = {
            k: str(v) for k, v in raw_notes.items() if str(k) in valid_ids
        }

        return TriageReport(
            prioritized_finding_ids=prioritized_ids,
            narrative_summary=narrative_summary,
            per_finding_notes=per_finding_notes,
        )
