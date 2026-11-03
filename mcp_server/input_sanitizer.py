"""
mcp_server.input_sanitizer — Prompt-injection detection in tool parameters.

Requirement 4.4: When any MCP_Tool receives an input value that looks like an
instruction directed at the AI agent rather than an operation parameter, the
system SHALL treat it as literal data and NEVER as an executable instruction
by the server itself.

This module provides the heuristic detector :func:`flag_prompt_injection_attempt`
which scans the string values in a params dict for known prompt-injection
patterns (role-play triggers, delimiter tokens, system-prompt overrides, etc.).

The detector is intentionally *non-blocking*: a positive detection only emits
a WARNING log entry so operators can monitor for injection attempts.  The
parameters are passed through unmodified to the tool handler — the server's
Python dispatch architecture already ensures params are never executed as
instructions; this module makes such attempts *visible*.
"""

from __future__ import annotations

import re
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Injection-pattern catalogue
# ---------------------------------------------------------------------------
# Patterns are matched case-insensitively against every string value found in
# the parameter dict (including nested strings reached by a shallow walk of
# list/dict values).
#
# The goal is high recall on known prompt-injection idioms with low false
# positives on legitimate API security testing payloads (URLs, headers, etc.).

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Role/identity overrides
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+(now\s+)?an?\s+ai", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+you\s+(were|are)\s+)?an?\s+(ai|llm|bot|agent|assistant|gpt|language\s+model)", re.IGNORECASE),
    re.compile(r"your\s+new\s+(role|persona|identity|task)\s+is", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+(you|your)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all\s+previous)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"override\s+(your\s+)?(previous\s+)?instructions?", re.IGNORECASE),
    # Common prompt delimiters / template tokens used in injection
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    re.compile(r"<<SYS>>", re.IGNORECASE),
    re.compile(r"<</SYS>>", re.IGNORECASE),
    re.compile(r"###\s*(system|instruction|human|assistant)\b", re.IGNORECASE),
    # Explicit system/instruction prefix tricks
    re.compile(r"^system\s*:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^instruction\s*:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^<system>", re.IGNORECASE | re.MULTILINE),
    # Jailbreak / DAN-style openers
    re.compile(r"\bDAN\b.*mode", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"prompt\s+injection", re.IGNORECASE),
    # Indirect injection via data smuggling
    re.compile(r"</?(human|assistant|user|model)\s*>", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def flag_prompt_injection_attempt(params: dict[str, Any]) -> bool:
    """Detect whether any parameter value looks like a prompt-injection attempt.

    Walks all string values in *params* (shallow-walking nested lists/dicts
    one level deep) and checks each against the catalogue of known
    prompt-injection patterns.

    When a match is found:
    - A **WARNING** is logged (including the key and a sanitised excerpt of
      the offending value) so operators can detect and investigate attempts.
    - The function returns ``True``.
    - The *params dict is not modified* — the value is treated as opaque data.

    The tool handler will still be called with the original params;
    the server never executes string values as instructions regardless.

    Args:
        params: The raw input parameter dict received by a tool invocation.

    Returns:
        ``True`` if at least one injection-like pattern was detected;
        ``False`` otherwise.
    """
    detected = False
    for key, value in params.items():
        # Collect string candidates: the value itself, or strings inside a
        # list/dict value (one extra level of depth covers common cases like
        # lists of headers, body dicts, etc.).
        candidates: list[str] = []
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, str))
        elif isinstance(value, dict):
            candidates.extend(v for v in value.values() if isinstance(v, str))

        for candidate in candidates:
            match = _first_matching_pattern(candidate)
            if match is not None:
                # Sanitise excerpt: limit to 120 chars to avoid log flooding
                excerpt = candidate[:120].replace("\n", "\\n")
                logger.warning(
                    "prompt_injection_attempt_detected",
                    param_key=key,
                    pattern=match.pattern,
                    value_excerpt=excerpt,
                )
                detected = True
                # Continue checking remaining keys so ALL attempts are logged.
                break

    return detected


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _first_matching_pattern(text: str) -> re.Pattern[str] | None:
    """Return the first catalogue pattern that matches *text*, or ``None``."""
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return pattern
    return None
