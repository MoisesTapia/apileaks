"""
Property-Based Tests for URL Normalization and Deduplication (Requirement 38).

**Feature: owasp-complete-purple-teaming-cicd**
  - **Property 23: URL normalization idempotence**
  - **Property 24: Deduplication idempotence and collapse**

Property 23 (from design.md):
    FOR ALL URLs, applying ``normalize_url`` twice in succession produces the
    same canonical URL as applying it once:
    ``normalize_url(normalize_url(u)) == normalize_url(u)``; and a URL already in
    canonical form is returned unchanged.

    **Validates: Requirements 38.5, 38.4, 38.2**

Property 24 (from design.md):
    FOR ALL URL sets, deduplicating a set whose members are already pairwise
    distinct after ``URL_Normalization`` returns that same set unchanged; and any
    two URLs that are equal after ``URL_Normalization`` collapse to a single
    tested-and-stored entry (one ``tested_urls`` membership and one stored
    ``Discovery_Result``).

    **Validates: Requirements 38.6, 38.3, 38.1**

Property 23 exercises the real pure ``normalize_url`` helper in
``utils.url_normalize`` (task 42.1). Two complementary generators feed it:

  - a *structured adversarial* generator that assembles realistic URLs which
    stress every documented normalization dimension -- mixed-case scheme/host,
    default and non-default ports, userinfo, bracketed IPv6 literals, mixed-case
    ``%XX`` percent escapes, ``.``/``..`` dot segments, empty segments, trailing
    slashes, queries and fragments;
  - a *free-form* generator drawn from a URL-ish alphabet, to catch idempotence
    breaks the structured shapes miss.

Property 24 exercises the real deduplication wired into ``EndpointFuzzer`` (task
42.2): ``_fuzz_wordlist`` canonicalizes each candidate before the ``tested_urls``
membership check, and ``_test_endpoint`` stores under the canonical URL. The
tests drive the real orchestrator against a deterministic in-memory fake
``HTTPRequestEngine`` (no network), mirroring ``test_url_normalization_wiring.py``
and ``test_request_budget_bound_properties.py``.

Equivalence-class variants below are built only from transforms the documented
canonical form explicitly collapses (scheme/host case, default-port insertion,
``%XX`` hex case, dot-segment injection, trailing slash). Each generated variant
is asserted to be equal-after-normalization to its canonical base, so the
collapse contract is genuinely stressed rather than vacuously satisfied.
"""

import asyncio
import string

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite
from urllib.parse import urlsplit, urlunsplit

from modules.fuzzing.orchestrator import EndpointFuzzer
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from utils.http_client import Response
from utils.url_normalize import normalize_url


# ---------------------------------------------------------------------------
# Generators for Property 23 (idempotence of normalize_url)
# ---------------------------------------------------------------------------

# Path/query/fragment segment alphabet: ordinary characters plus a few that are
# meaningful to normalization (none of these are themselves percent-encoded by
# normalize_url, keeping the structured shapes predictable).
_SEG_ALPHABET = string.ascii_letters + string.digits + "-._~"

# Hex digits in BOTH cases so generated %XX escapes exercise the hex-case
# normalization (e.g. %2f -> %2F).
_HEX = "0123456789abcdefABCDEF"


@composite
def _percentish_text(draw, min_size=0, max_size=8):
    """Draw text mixing ordinary chars, mixed-case %XX escapes, and lone '%'.

    The lone-'%' and ``%X`` (single-hex) fragments are deliberately included:
    they are NOT well-formed escapes, so ``normalize_url`` must leave them
    untouched -- a classic idempotence trap.
    """
    pieces = draw(
        st.lists(
            st.one_of(
                st.text(alphabet=_SEG_ALPHABET, min_size=1, max_size=4),
                st.builds(lambda a, b: f"%{a}{b}", st.sampled_from(_HEX), st.sampled_from(_HEX)),
                st.just("%"),
                st.builds(lambda a: f"%{a}", st.sampled_from(_HEX)),
                st.just("."),
                st.just(".."),
            ),
            min_size=min_size,
            max_size=max_size,
        )
    )
    return "".join(pieces)


@composite
def _host(draw):
    """Draw a host: a dotted name (mixed case) or a bracketed IPv6 literal."""
    if draw(st.booleans()):
        labels = draw(
            st.lists(
                st.text(alphabet=string.ascii_letters + string.digits + "-", min_size=1, max_size=6),
                min_size=1,
                max_size=3,
            )
        )
        return ".".join(labels)
    # A small set of bracketed IPv6 literals (host contents must be preserved).
    return draw(st.sampled_from(["[::1]", "[2001:db8::1]", "[fe80::1]"]))


@composite
def structured_url(draw):
    """Assemble a realistic URL that stresses every normalization dimension."""
    scheme = draw(st.sampled_from(["http", "https", "HTTP", "HTTPS", "HtTpS", "ftp"]))

    host = draw(_host())
    # Optional userinfo (case-sensitive; only its %-escapes are normalized).
    userinfo = draw(
        st.one_of(
            st.none(),
            st.builds(lambda u: f"{u}@", _percentish_text(min_size=1, max_size=6)),
            st.builds(lambda u, p: f"{u}:{p}@", _percentish_text(min_size=1, max_size=5),
                      _percentish_text(min_size=1, max_size=5)),
        )
    )
    # Optional port: default, non-default, or empty (bare trailing colon).
    port = draw(st.sampled_from(["", "", ":80", ":443", ":8080", ":", ":0"]))
    netloc = f"{userinfo or ''}{host}{port}"

    # Path: leading slash + dot/empty/percent segments, optional trailing slash.
    nseg = draw(st.integers(min_value=0, max_value=4))
    segs = [draw(_percentish_text(min_size=0, max_size=6)) for _ in range(nseg)]
    path = "/" + "/".join(segs) if segs else draw(st.sampled_from(["", "/"]))
    if path and path != "/" and draw(st.booleans()):
        path = path + "/"

    query = draw(st.one_of(st.just(""), _percentish_text(min_size=1, max_size=10)))
    fragment = draw(st.one_of(st.just(""), _percentish_text(min_size=1, max_size=8)))

    return urlunsplit((scheme, netloc, path, query, fragment))


@composite
def freeform_url(draw):
    """Draw a free-form URL-ish string from a broad URL alphabet."""
    alphabet = string.ascii_letters + string.digits + ":/?#[]@!$&'()*+,;=-._~%"
    body = draw(st.text(alphabet=alphabet, min_size=0, max_size=40))
    scheme = draw(st.sampled_from(["http://", "https://", "HTTP://", "//", ""]))
    return scheme + body


def _is_parseable_url(url):
    """True if urlsplit accepts ``url`` (filters out non-URL inputs).

    The input space for normalization is parseable URLs -- candidates are built
    via ``urljoin`` from wordlist words, so they always parse. Free-form
    generation can emit malformed strings (e.g. a lone ``[`` opening an
    unterminated IPv6 literal) that ``urlsplit`` itself rejects; those are not
    URLs and are excluded here.
    """
    try:
        urlsplit(url)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Generators for Property 24 (canonical bases + equivalence-class variants)
# ---------------------------------------------------------------------------

_HOST_ALPHABET = string.ascii_lowercase + string.digits
_PLAIN_SEG = string.ascii_lowercase + string.digits + "_-"


@composite
def canonical_url(draw):
    """Draw a URL already in canonical form (a ``normalize_url`` fixed point).

    Lower-case scheme/host, no port, no userinfo, dot-free/escape-free path
    segments, no trailing slash on non-root paths, no query/fragment. Such a URL
    must be returned unchanged by ``normalize_url`` (Requirement 38.4).
    """
    scheme = draw(st.sampled_from(["http", "https"]))
    labels = draw(
        st.lists(st.text(alphabet=_HOST_ALPHABET, min_size=1, max_size=6), min_size=1, max_size=3)
    )
    host = ".".join(labels)
    nseg = draw(st.integers(min_value=0, max_value=4))
    segs = [draw(st.text(alphabet=_PLAIN_SEG, min_size=1, max_size=6)) for _ in range(nseg)]
    path = "/" + "/".join(segs) if segs else "/"
    return f"{scheme}://{host}{path}"


@composite
def equivalent_variants(draw, canonical):
    """Draw 1-4 raw spellings that all normalize to ``canonical``.

    Each variant applies a random subset of equivalence-preserving transforms
    the documented canonical form collapses (Requirement 38.2):
      - upper-case scheme (scheme is lower-cased);
      - upper-case host (host is lower-cased);
      - append the scheme's default port (default port is removed);
      - inject ``.``/``..`` dot segments that resolve away (dot-segment removal);
      - append a single trailing slash to a non-root path (trailing-slash strip).
    """
    scheme, rest = canonical.split("://", 1)
    if "/" in rest:
        host, tail = rest.split("/", 1)
        path = "/" + tail
    else:
        host, path = rest, "/"
    default_port = "80" if scheme == "http" else "443"
    segs = [s for s in path.split("/") if s]

    n = draw(st.integers(min_value=1, max_value=4))
    variants = []
    for _ in range(n):
        s = scheme.upper() if draw(st.booleans()) else scheme
        h = host.upper() if draw(st.booleans()) else host
        if draw(st.booleans()):
            h = f"{h}:{default_port}"

        p = path
        if segs and draw(st.booleans()):
            # Inject dot segments that resolve back to the same path:
            #   /a/b -> /./a/zz/../b   (remove_dot_segments => /a/b)
            injected = ["", "."] + [segs[0], "zz", ".."] + segs[1:] if len(segs) >= 1 else segs
            p = "/" + "/".join(injected[1:])  # drop leading "" placeholder
        if segs and draw(st.booleans()):
            p = p + "/"
        variants.append(f"{s}://{h}{p}")
    return variants


@composite
def url_pool_with_collisions(draw):
    """Build (raw_urls, base_set): variants of distinct canonical bases, shuffled."""
    bases = draw(st.lists(canonical_url(), min_size=1, max_size=6, unique=True))
    raw = []
    for b in bases:
        raw.extend(draw(equivalent_variants(b)))
    raw = list(draw(st.permutations(raw)))
    return raw, set(bases)


# ---------------------------------------------------------------------------
# Deterministic in-memory orchestrator harness (no network)
# ---------------------------------------------------------------------------

class RecordingFakeClient:
    """Fake HTTPRequestEngine recording every (method, url) request; answers 200."""

    def __init__(self):
        self.calls = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)
        return Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b'{"ok": true}',
            text='{"ok": true}',
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config() -> FuzzingConfig:
    """Minimal discovery-enabled config: single method, no extensions/budget."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=None,
        concurrency=50,
    )


# Absolute candidate URLs are passed as wordlist entries; urljoin(base, abs) == abs,
# so the seed base only needs to be a valid absolute URL.
_SEED_BASE = "http://seed.example/"


async def _run_wordlist(words):
    """Run a single _fuzz_wordlist pass over absolute candidate URLs."""
    fake_client = RecordingFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_config())
    await fuzzer._fuzz_wordlist(_SEED_BASE, list(words), depth=0)
    return fake_client, fuzzer


# ---------------------------------------------------------------------------
# Property 23: URL normalization idempotence
# ---------------------------------------------------------------------------

@given(url=st.one_of(structured_url(), freeform_url()).filter(_is_parseable_url))
@settings(max_examples=400, deadline=None)
def test_normalize_url_is_idempotent(url):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 23: URL normalization
    idempotence**
    **Validates: Requirements 38.5, 38.4, 38.2**

    FOR ALL URLs ``u`` (structured adversarial and free-form):

      - 38.5: applying normalization twice equals applying it once --
        ``normalize_url(normalize_url(u)) == normalize_url(u)``.
      - 38.4: the once-normalized value is a fixed point -- normalizing a URL
        already in canonical form returns it unchanged.
    """
    once = normalize_url(url)
    twice = normalize_url(once)
    assert twice == once, (
        f"normalize_url not idempotent for {url!r}: once={once!r} twice={twice!r}"
    )


@given(url=canonical_url())
@settings(max_examples=300, deadline=None)
def test_canonical_url_returned_unchanged(url):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 23: URL normalization
    idempotence (canonical fixed point)**
    **Validates: Requirements 38.4, 38.2**

    FOR ALL URLs already in canonical form, ``normalize_url`` returns the same
    URL unchanged (Requirement 38.4). The generator only emits lower-case
    scheme/host, no default ports, dot-free escape-free segments, and no
    non-root trailing slash, i.e. URLs that already satisfy the canonical form
    of Requirement 38.2.
    """
    assert normalize_url(url) == url, f"canonical URL {url!r} was altered"


# ---------------------------------------------------------------------------
# Property 24: Deduplication idempotence and collapse
# ---------------------------------------------------------------------------

@given(bases=st.lists(canonical_url(), min_size=0, max_size=8, unique=True))
@settings(max_examples=300, deadline=None)
def test_distinct_after_normalization_dedup_is_identity(bases):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 24: Deduplication
    idempotence**
    **Validates: Requirements 38.6, 38.1, 38.3**

    FOR ALL URL sets whose members are already pairwise distinct after
    normalization, deduplication returns that same set unchanged -- no collapse
    occurs:

      - the candidate set survives one-to-one (one tested_urls entry per URL,
        one Discovery_Request per URL);
      - no logical endpoint is dropped or invented.
    """
    # Precondition the generator guarantees: distinct canonical forms.
    canon = {normalize_url(b) for b in bases}
    assert len(canon) == len(bases)

    fake_client, fuzzer = asyncio.run(_run_wordlist(bases))

    # Dedup is the identity here: every distinct URL is tested and stored once.
    assert fuzzer.tested_urls == set(bases)
    assert fake_client.call_count == len(bases)
    assert set(fuzzer.discovered_endpoints.keys()) == set(bases)


@given(pool=url_pool_with_collisions())
@settings(max_examples=300, deadline=None)
def test_equivalent_urls_collapse_to_single_entry(pool):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 24: Deduplication
    collapse**
    **Validates: Requirements 38.6, 38.3, 38.1**

    FOR ALL URL sets containing members that are equal after normalization, each
    equivalence class collapses to exactly one tested-and-stored entry:

      - every generated variant is equal-after-normalization to its canonical
        base (the collision is real, not vacuous);
      - 38.1/38.3: equivalent candidates add a single tested_urls entry and
        issue a single Discovery_Request (no duplicate request for the others);
      - 38.6: equal-after-normalization URLs collapse to one stored
        Discovery_Result keyed by the canonical URL.
    """
    raw, expected_canonical = pool

    # The collision is genuine: each variant normalizes to a canonical base, and
    # the bases are exactly the distinct canonical forms present in the input.
    assert {normalize_url(u) for u in raw} == expected_canonical

    fake_client, fuzzer = asyncio.run(_run_wordlist(raw))

    # 38.1 / 38.3 / 38.6: collapse to one entry / request / stored result per
    # canonical URL, regardless of how many equivalent spellings appeared.
    assert fuzzer.tested_urls == expected_canonical
    assert fake_client.call_count == len(expected_canonical)
    assert set(fuzzer.discovered_endpoints.keys()) == expected_canonical
