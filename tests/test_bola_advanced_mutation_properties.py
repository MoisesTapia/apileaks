"""
Property-based tests for the advanced request-mutation techniques of the BOLA
module (verb tampering, parameter pollution, identifier placement, and encoded
identifier variants).

Feature: owasp-auth-modules-hardening

Property 11: Advanced mutations preserve every other request component.
For all generated base requests, ``_build_verb_tampering_probes``,
``_build_parameter_pollution_probe`` and ``_build_placement_probes`` each mutate
a SINGLE dimension of the request (the HTTP method / override header, one
duplicated query parameter, or one identifier placement) while preserving every
other request component (method, URL, params, headers, body/json) unchanged.

Property 12: Encoded identifier formats round-trip to the original value.
For all identifier values, decoding the base64 form, URL-decoding the
url_encoded form, and unwrapping the object-wrapped form produced by
``encode_identifier_variants`` each yield the original identifier's string form.

**Validates: Requirements 31.1, 31.3, 31.4, 31.5, 36.3**
"""

import base64
import string
import urllib.parse
from urllib.parse import urlparse, parse_qs
from unittest.mock import Mock, AsyncMock

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from utils.http_client import HTTPRequestEngine, Request
from core.config import BOLAConfig


# ---------------------------------------------------------------------------
# Shared helpers / strategies
# ---------------------------------------------------------------------------

# Safe token alphabet: no URL/query delimiters, survives urlencode round-trips
# exactly so preservation comparisons are unambiguous.
_SAFE_ALPHABET = string.ascii_letters + string.digits + "-_"
_safe_text = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=10)

# Header keys that never collide with the method-override header, keeping the
# direct-vs-override variant classification unambiguous.
_header_key = _safe_text.filter(
    lambda k: k.lower() != "x-http-method-override"
)

_headers = st.dictionaries(_header_key, _safe_text, max_size=4)
_params = st.dictionaries(_safe_text, _safe_text, max_size=4)
# Body (json) is a plain dict of safe scalar fields.
_json_body = st.dictionaries(
    _safe_text,
    st.one_of(_safe_text, st.integers(min_value=-1000, max_value=1000),
              st.booleans()),
    max_size=4,
)

_HTTP_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]


def _make_module(*, safe_mode=False, allow_destructive=True):
    """Build a BOLATestingModule whose mutation builders can be exercised fully.

    The builders under test are pure request-descriptor constructors, so a stub
    HTTP client and empty auth contexts suffice. Safe_Mode is OFF and the
    destructive opt-in is present by default so state-changing probes are
    actually emitted and the preservation invariant is exercised across every
    method (including PUT/PATCH/DELETE).
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    config = BOLAConfig(
        enabled=True,
        safe_mode=safe_mode,
        allow_destructive=allow_destructive,
        destructive_methods={"PATCH", "PUT", "POST", "DELETE"},
    )
    return BOLATestingModule(config, client, [])


def _base_url(draw):
    """Build an https URL with a numeric id path segment and optional query."""
    id_value = draw(st.integers(min_value=1, max_value=1_000_000).map(str))
    query_pairs = draw(
        st.lists(
            st.tuples(_safe_text, _safe_text),
            min_size=0, max_size=3,
            unique_by=lambda kv: kv[0],
        )
    )
    url = f"https://api.example.com/users/{id_value}/orders"
    if query_pairs:
        url += "?" + "&".join(f"{k}={v}" for k, v in query_pairs)
    return url, id_value


@st.composite
def _base_request(draw):
    """Generate a fully-populated base Request plus its embedded id value."""
    url, id_value = _base_url(draw)
    method = draw(st.sampled_from(_HTTP_METHODS))
    return (
        Request(
            method=method,
            url=url,
            headers=draw(_headers),
            params=draw(_params),
            data=draw(st.one_of(st.none(), _safe_text)),
            json=draw(_json_body),
        ),
        id_value,
    )


# ===========================================================================
# Property 11 - verb tampering preserves every other component
# ===========================================================================


@settings(max_examples=200, deadline=None)
@given(_base_request())
def test_verb_tampering_preserves_all_other_components(case):
    # Feature: owasp-auth-modules-hardening, Property 11: Advanced mutations preserve every other request component
    base, _id_value = case
    module = _make_module()

    probes = module._build_verb_tampering_probes(base)

    # Destructive opt-in is present and Safe_Mode is off, so every candidate
    # method yields both a direct and an override variant.
    assert len(probes) > 0

    override_header = module.METHOD_OVERRIDE_HEADER
    base_method = base.method.upper()

    for probe in probes:
        # URL, params and body are ALWAYS preserved for verb tampering.
        assert probe.url == base.url
        assert probe.params == base.params
        assert probe.data == base.data
        assert probe.json == base.json

        if probe.method.upper() != base_method:
            # Direct variant: only the wire method changed to a candidate; every
            # header (and every other component) is identical to the base.
            assert probe.method.upper() in module.VERB_TAMPERING_METHODS
            assert probe.headers == base.headers
        else:
            # Override variant: the wire method is preserved and the ONLY header
            # change is the added X-HTTP-Method-Override carrying a candidate.
            assert override_header in probe.headers
            candidate = probe.headers[override_header]
            assert candidate in module.VERB_TAMPERING_METHODS
            assert candidate != base_method
            expected_headers = dict(base.headers)
            expected_headers[override_header] = candidate
            assert probe.headers == expected_headers


# ===========================================================================
# Property 11 - parameter pollution preserves every other component
# ===========================================================================


@st.composite
def _pollution_case(draw):
    base, _id_value = draw(_base_request())
    parameter_name = draw(_safe_text)
    own_id = draw(st.one_of(st.integers(min_value=1, max_value=100000),
                            _safe_text))
    victim_id = draw(st.one_of(st.integers(min_value=1, max_value=100000),
                               _safe_text))
    return base, parameter_name, own_id, victim_id


@settings(max_examples=200, deadline=None)
@given(_pollution_case())
def test_parameter_pollution_preserves_all_other_components(case):
    # Feature: owasp-auth-modules-hardening, Property 11: Advanced mutations preserve every other request component
    base, parameter_name, own_id, victim_id = case
    module = _make_module()

    probe = module._build_parameter_pollution_probe(
        base, parameter_name, own_id, victim_id
    )
    # Safe_Mode is off, so a probe is always produced.
    assert probe is not None

    # Method, headers, params and body are preserved unchanged.
    assert probe.method == base.method
    assert probe.headers == base.headers
    assert probe.params == base.params
    assert probe.data == base.data
    assert probe.json == base.json

    base_parsed = urlparse(base.url)
    probe_parsed = urlparse(probe.url)

    # Only the query string is touched: scheme/netloc/path/fragment preserved.
    assert probe_parsed.scheme == base_parsed.scheme
    assert probe_parsed.netloc == base_parsed.netloc
    assert probe_parsed.path == base_parsed.path
    assert probe_parsed.fragment == base_parsed.fragment

    base_qs = parse_qs(base_parsed.query, keep_blank_values=True)
    probe_qs = parse_qs(probe_parsed.query, keep_blank_values=True)

    # The targeted identifier parameter is duplicated own-id-then-victim-id.
    assert probe_qs[parameter_name] == [str(own_id), str(victim_id)]

    # Every OTHER query parameter is preserved unchanged.
    base_others = {k: v for k, v in base_qs.items() if k != parameter_name}
    probe_others = {k: v for k, v in probe_qs.items() if k != parameter_name}
    assert probe_others == base_others


# ===========================================================================
# Property 11 - placement variation preserves every other component
# ===========================================================================


@st.composite
def _placement_case(draw):
    base, id_value = draw(_base_request())
    identifier = ObjectIdentifier(
        value=id_value,
        type="sequential",
        endpoint=base.url,
        parameter_name=draw(_safe_text),
        location="path",
    )
    candidate_id = draw(st.one_of(st.integers(min_value=1, max_value=100000),
                                  _safe_text))
    return base, identifier, candidate_id


@settings(max_examples=200, deadline=None)
@given(_placement_case())
def test_placement_probes_preserve_all_other_components(case):
    # Feature: owasp-auth-modules-hardening, Property 11: Advanced mutations preserve every other request component
    base, identifier, candidate_id = case
    module = _make_module()
    param_name = identifier.parameter_name

    probes = module._build_placement_probes(base, identifier, candidate_id)

    # Safe_Mode is off, so all four placements are produced.
    assert set(probes.keys()) == {"path", "query", "body", "header"}

    base_parsed = urlparse(base.url)

    # --- path placement: ONLY the URL path may change ------------------
    path_probe = probes["path"]
    assert path_probe.method == base.method
    assert path_probe.headers == base.headers
    assert path_probe.params == base.params
    assert path_probe.data == base.data
    assert path_probe.json == base.json
    path_parsed = urlparse(path_probe.url)
    assert path_parsed.scheme == base_parsed.scheme
    assert path_parsed.netloc == base_parsed.netloc
    assert path_parsed.query == base_parsed.query
    assert path_parsed.fragment == base_parsed.fragment

    # --- query placement: ONLY the URL query may change ----------------
    query_probe = probes["query"]
    assert query_probe.method == base.method
    assert query_probe.headers == base.headers
    assert query_probe.params == base.params
    assert query_probe.data == base.data
    assert query_probe.json == base.json
    query_parsed = urlparse(query_probe.url)
    assert query_parsed.scheme == base_parsed.scheme
    assert query_parsed.netloc == base_parsed.netloc
    assert query_parsed.path == base_parsed.path
    assert query_parsed.fragment == base_parsed.fragment

    # --- body placement: ONLY the json body may change -----------------
    body_probe = probes["body"]
    assert body_probe.method == base.method
    assert body_probe.url == base.url
    assert body_probe.headers == base.headers
    assert body_probe.params == base.params
    assert body_probe.data == base.data
    assert body_probe.json[param_name] == str(candidate_id)
    # Every other body field is preserved.
    other_body = {k: v for k, v in body_probe.json.items() if k != param_name}
    base_body_others = {k: v for k, v in (base.json or {}).items()
                        if k != param_name}
    assert other_body == base_body_others

    # --- header placement: ONLY the headers may change -----------------
    header_probe = probes["header"]
    assert header_probe.method == base.method
    assert header_probe.url == base.url
    assert header_probe.params == base.params
    assert header_probe.data == base.data
    assert header_probe.json == base.json
    assert header_probe.headers[param_name] == str(candidate_id)
    # Every other header is preserved.
    other_headers = {k: v for k, v in header_probe.headers.items()
                     if k != param_name}
    base_header_others = {k: v for k, v in base.headers.items()
                          if k != param_name}
    assert other_headers == base_header_others


# ===========================================================================
# Property 11 - Safe_Mode variant: probes stay restricted to Safe_Methods
# ===========================================================================


@settings(max_examples=100, deadline=None)
@given(_base_request())
def test_verb_tampering_safe_mode_emits_only_safe_effective_methods(case):
    # Feature: owasp-auth-modules-hardening, Property 11: Advanced mutations preserve every other request component
    base, _id_value = case
    module = _make_module(safe_mode=True, allow_destructive=False)
    safe_methods = {"GET", "HEAD", "OPTIONS"}
    override_header = module.METHOD_OVERRIDE_HEADER

    probes = module._build_verb_tampering_probes(base)

    for probe in probes:
        # Preservation still holds in Safe_Mode.
        assert probe.url == base.url
        assert probe.params == base.params
        assert probe.data == base.data
        assert probe.json == base.json
        # Effective method must be a Safe_Method.
        if override_header in probe.headers:
            effective = probe.headers[override_header].upper()
            # The wire method that still reaches the server must also be safe.
            assert probe.method.upper() in safe_methods
        else:
            effective = probe.method.upper()
        assert effective in safe_methods


# ===========================================================================
# Property 12 - encoded identifier variants round-trip to the original value
# ===========================================================================

# Identifier values covering ints, uuids, booleans, and arbitrary (non-surrogate)
# text - surrogate code points are excluded because they are not valid UTF-8
# identifiers and never appear in real URLs/JSON.
_identifier_value = st.one_of(
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.booleans(),
    st.uuids().map(str),
    st.text(st.characters(blacklist_categories=("Cs",)), min_size=0,
            max_size=40),
)


@settings(max_examples=200, deadline=None)
@given(_identifier_value)
def test_encoded_identifier_variants_round_trip(value):
    # Feature: owasp-auth-modules-hardening, Property 12: Encoded identifier formats round-trip to the original value
    module = _make_module()
    expected = str(value)

    result = module.encode_identifier_variants(value)

    # base64 decodes back to the original string form.
    assert base64.b64decode(result["base64"]).decode("utf-8") == expected
    # URL-encoding round-trips via unquote.
    assert urllib.parse.unquote(result["url_encoded"]) == expected
    # The object-wrapped variant exposes the original value under "id".
    assert result["object_wrapped"]["id"] == expected


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
