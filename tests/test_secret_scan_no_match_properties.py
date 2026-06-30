"""
Property-Based Tests for the Secret Scanner no-match safety guarantee

**Feature: owasp-complete-purple-teaming-cicd**

Validates one correctness property of ``utils.secret_scanner.scan_for_secrets``
from design.md:

Property 15 (Secret scan no-match safety, Requirement 30.7):
    FOR ALL discovery responses whose body and headers contain no content
    matching any configured ``Secret_Pattern``, ``scan_for_secrets`` yields zero
    ``SecretFinding`` records (returns ``[]``).

Strategy / safe-alphabet reasoning
----------------------------------
Every pattern in :data:`DEFAULT_SECRET_PATTERNS` requires at least one
*alphabetic* literal or keyword before it can match:

* ``aws_access_key``        -> literal ``AKIA``
* ``aws_secret_key``        -> keyword ``aws_secret_access_key``
* ``gcp_api_key``           -> literal ``AIza``
* ``google_oauth_token``    -> literal ``ya29.`` (letters + ``.``)
* ``github_token``          -> ``gh[pousr]_``
* ``slack_token``           -> ``xox[baprs]-``
* ``jwt``                   -> literal ``eyJ``
* ``private_key``           -> ``-----BEGIN ... PRIVATE KEY-----`` (dashes + letters)
* ``bearer_token``          -> keyword ``bearer``
* ``basic_auth_header``     -> keyword ``authorization: ... basic``
* ``generic_api_key``       -> one of ``api``/``key``/``secret``/``token``/
                               ``password``/``passwd`` BEFORE the 16+ char run

If the generated text contains **no ASCII letters at all**, none of these
literals/keywords can ever appear, so no pattern can match -- regardless of
length. The length-based generic patterns are gated behind a keyword, so a long
run of digits alone is harmless. We therefore restrict the generated alphabet to
ASCII digits, the single safest, provably-non-matching choice. The scanner also
renders each header as ``"Name: value"``; the inserted ``": "`` adds only a
colon and a space, neither of which introduces a letter, so header text stays
provably non-matching too.

This test mirrors the established style in ``tests/test_baseline_properties.py``
and ``tests/test_merge_candidate_dedup_properties.py``.
"""

from hypothesis import given, settings, strategies as st

from utils.secret_scanner import (
    DEFAULT_SECRET_PATTERNS,
    scan_for_secrets,
)


# A provably safe alphabet: ASCII digits contain no letters, so they can never
# form any pattern's required literal prefix (AKIA, AIza, eyJ, ...) nor any
# keyword token (api/key/secret/token/password/passwd/bearer/basic/...). Every
# configured pattern needs at least one such letter, so digit-only text -- of
# any length -- cannot match.
SAFE_ALPHABET = "0123456789"

safe_text = st.text(alphabet=SAFE_ALPHABET, min_size=0, max_size=64)

# Header maps drawn from the same safe alphabet for both names and values. When
# rendered as "Name: value" the only added characters are ':' and ' ', neither
# of which is a letter, so the rendered header text remains non-matching.
safe_headers = st.dictionaries(
    keys=st.text(alphabet=SAFE_ALPHABET, min_size=0, max_size=16),
    values=st.text(alphabet=SAFE_ALPHABET, min_size=0, max_size=64),
    max_size=8,
)


@given(body=safe_text, headers=safe_headers)
@settings(max_examples=300, deadline=5000)
def test_no_secret_findings_for_non_matching_alphabet(body, headers):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 15: Secret scan
    no-match safety**
    **Validates: Requirements 30.7**

    FOR ALL bodies and headers drawn from a digit-only alphabet (which contains
    no letter able to form any configured pattern's required literal or keyword),
    ``scan_for_secrets`` returns zero ``SecretFinding`` records.
    """
    findings = scan_for_secrets(
        body=body,
        headers=headers,
        patterns=DEFAULT_SECRET_PATTERNS,
        endpoint="/digits",
        method="GET",
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Representative example-based cases pinning the documented behaviour.
# ---------------------------------------------------------------------------


def test_empty_body_and_headers_yield_no_findings():
    """
    **Validates: Requirement 30.7**

    An empty body with no headers produces no findings.
    """
    assert scan_for_secrets(body="", headers={}) == []


def test_digit_only_payload_yields_no_findings():
    """
    **Validates: Requirement 30.7**

    A long digit-only body and digit-only headers -- even though they contain
    16+ character runs -- never trigger the keyword-gated generic patterns.
    """
    body = "0123456789" * 20  # 200-char digit run, no keyword precedes it
    headers = {"1234567890": "0987654321" * 5}

    assert scan_for_secrets(body=body, headers=headers) == []
