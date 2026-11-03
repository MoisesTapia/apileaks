"""
modules.mcp_security.poisoning_detector — ToolPoisoningDetector.

Analyzes MCP tool descriptions for Tool-Poisoning patterns: hidden prompt
delimiters, text concealed inside HTML/Markdown comments, and imperative
instructions directed at an AI agent.

Requirement 8.2 / Property 6:
    For any MCP_Tool description containing a known prompt delimiter or hidden
    HTML/Markdown comment text, ``ToolPoisoningDetector.scan_description``
    SHALL generate a Finding.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from core.config import Severity
from core.logging import get_logger
from utils.findings import Finding

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Known prompt-injection delimiters used to hijack an AI agent's context.
# This list covers the most commonly abused patterns found in the wild.
PROMPT_DELIMITERS: list[re.Pattern[str]] = [
    # OpenAI / ChatGPT system/user/assistant role markers
    re.compile(r"<\s*(system|user|assistant)\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    # Anthropic human/assistant turn markers
    re.compile(r"\bHuman\s*:", re.IGNORECASE),
    re.compile(r"\bAssistant\s*:", re.IGNORECASE),
    # Generic "ignore previous instructions" prompt-injection phrase
    re.compile(
        r"ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompt|context)",
        re.IGNORECASE,
    ),
    # "You are …" style role-hijacking preambles
    re.compile(
        r"you\s+are\s+(now\s+)?(an?\s+)?(?!.*API)(?:AI|assistant|agent|bot|LLM|model|GPT)",
        re.IGNORECASE,
    ),
    # XML-style context delimiters used in some prompting frameworks
    re.compile(r"<\s*(context|instructions?|task|prompt)\s*>", re.IGNORECASE),
    re.compile(r"<\s*!\s*--\s*PROMPT", re.IGNORECASE),
    # Markdown "---" horizontal rule used as a section break in prompt injections
    # (only flag when followed by instruction-looking text on the next line)
    re.compile(r"---\s*\n\s*(ignore|disregard|forget|override)", re.IGNORECASE),
    # Common "DAN" / jailbreak preambles
    re.compile(r"\bDAN\b.*mode", re.IGNORECASE),
]

# Pattern that matches HTML/Markdown comments which hide content from the rendered UI.
# These are a common steganographic channel for injecting instructions invisible
# to a human reader but visible to an LLM that receives the raw description.
HTML_COMMENT_PATTERN: re.Pattern[str] = re.compile(
    r"<!--(.*?)-->",
    re.DOTALL | re.IGNORECASE,
)

# Imperative instructions directed at "you are an AI / the model / the agent".
# These cover direct second-person imperatives targeting an AI consumer.
AI_DIRECTED_IMPERATIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(do\s+not|don'?t|never|always|must|shall|should)\b.{0,80}"
        r"\b(reveal|expose|disclose|share|repeat|output|return|show|display)\b.{0,80}"
        r"\b(password|secret|key|token|credential|api.?key)",
        re.IGNORECASE | re.DOTALL,
    ),
    # "Pretend you are" / "Act as" jailbreaks
    re.compile(
        r"\b(pretend|act|behave|roleplay|simulate)\s+(you\s+are|as\s+(an?\s+)?)",
        re.IGNORECASE,
    ),
    # Covert channel: "when called, also execute …"
    re.compile(
        r"\bwhen\s+(this\s+tool\s+is\s+called|invoked|executed)\b.{0,120}\balso\b",
        re.IGNORECASE | re.DOTALL,
    ),
]


# ---------------------------------------------------------------------------
# Dataclass-like container for a detected pattern
# ---------------------------------------------------------------------------


class _DetectionResult:
    """Internal container for a single poisoning pattern match."""

    def __init__(self, pattern_type: str, matched_text: str) -> None:
        self.pattern_type = pattern_type
        self.matched_text = matched_text[:300]  # truncate long matches for evidence


# ---------------------------------------------------------------------------
# ToolPoisoningDetector
# ---------------------------------------------------------------------------


class ToolPoisoningDetector:
    """Detects Tool-Poisoning patterns in MCP tool descriptions.

    Tool-Poisoning is a class of supply-chain attack where the ``description``
    field of an MCP tool contains hidden instructions that manipulate the AI
    agent consuming the tool manifest.

    Usage::

        detector = ToolPoisoningDetector()
        finding = detector.scan_description(tool_spec)
        if finding:
            print(f"Poisoning detected: {finding.evidence}")

    Requirement 8.2 / Property 6
    """

    def __init__(self) -> None:
        self._logger = logger.bind(module="poisoning_detector")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_description(self, tool_spec: Any) -> Finding | None:
        """Scan a single tool's description for poisoning patterns.

        Args:
            tool_spec: Any object with a ``name`` attribute (str) and a
                ``description`` attribute (str).  Accepts both
                :class:`~mcp_server.schemas.MCPToolSpec` and plain
                name/description duck-typed objects (for auditing third-party
                servers whose specs differ from the internal schema).

        Returns:
            A :class:`~utils.findings.Finding` when at least one poisoning
            pattern is detected, or ``None`` when the description is clean.

        **Validates: Requirement 8.2**
        """
        name: str = getattr(tool_spec, "name", "<unknown>")
        description: str = getattr(tool_spec, "description", "") or ""

        detections: list[_DetectionResult] = []

        # --- Check 1: known prompt delimiters ---
        for pattern in PROMPT_DELIMITERS:
            match = pattern.search(description)
            if match:
                detections.append(
                    _DetectionResult("prompt_delimiter", match.group(0))
                )
                break  # one delimiter is sufficient for the finding

        # --- Check 2: HTML/Markdown comments with non-trivial content ---
        for comment_match in HTML_COMMENT_PATTERN.finditer(description):
            comment_body = comment_match.group(1).strip()
            if self._comment_contains_instructions(comment_body):
                detections.append(
                    _DetectionResult("html_comment_hidden_text", comment_body)
                )
                break

        # --- Check 3: AI-directed imperatives ---
        for pattern in AI_DIRECTED_IMPERATIVE_PATTERNS:
            match = pattern.search(description)
            if match:
                detections.append(
                    _DetectionResult("ai_directed_imperative", match.group(0))
                )
                break

        if not detections:
            return None

        evidence = "; ".join(
            f"[{d.pattern_type}] {d.matched_text!r}" for d in detections
        )
        self._logger.warning(
            "tool_poisoning_detected",
            tool_name=name,
            detection_count=len(detections),
            pattern_types=[d.pattern_type for d in detections],
        )

        return Finding(
            id=str(uuid.uuid4()),
            scan_id="mcp_audit",
            category="MCP_TOOL_POISONING",
            owasp_category="API8",  # Security Misconfiguration / injection risk
            severity=Severity.HIGH,
            endpoint=f"mcp://tool/{name}",
            method="DESCRIBE",
            status_code=0,
            response_size=len(description),
            response_time=0.0,
            evidence=evidence,
            recommendation=(
                "Remove all prompt-injection instructions from the tool description. "
                "Tool descriptions MUST contain only plain-language documentation "
                "of the tool's purpose and parameters. Any text that attempts to "
                "direct the AI agent's behaviour beyond tool invocation should be "
                "treated as a supply-chain attack."
            ),
            payload=description[:500],
            timestamp=datetime.now(UTC),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _comment_contains_instructions(comment_body: str) -> bool:
        """Return True when an HTML/Markdown comment body looks like hidden
        AI instructions rather than a legitimate developer comment."""
        if not comment_body or len(comment_body) < 5:
            return False

        # If the hidden text contains any imperative phrase targeting an AI
        # it is almost certainly a poisoning attempt.
        suspicious_phrases = [
            "ignore",
            "disregard",
            "forget",
            "you are",
            "you must",
            "do not",
            "always",
            "never",
            "instead",
            "override",
            "system prompt",
            "assistant",
            "human",
            "[inst]",
            "act as",
            "pretend",
        ]
        lower = comment_body.lower()
        return any(phrase in lower for phrase in suspicious_phrases)
