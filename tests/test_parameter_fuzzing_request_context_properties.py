"""Property-based tests for request-context application in the ``par`` flow.

# Feature: parameter-fuzzing, Property 8: Request context is applied to every request

Property 8 (from design.md / tasks.md task 11.7):
    FOR ALL combinations of custom headers, a cookie, and basic-auth credentials
    supplied to ``par``, every HTTP request issued during the run SHALL carry all
    provided headers, the cookie (as a ``Cookie`` header), and the basic-auth
    ``Authorization`` header.

How this is exercised offline
    The test threads the request-context options through the *same* production
    path the ``par`` command uses: ``parse_header_options`` (with the cookie
    carried as a ``Cookie`` header) and ``parse_basic_auth`` feed
    ``create_default_config(..., "par", extra_headers=..., basic_auth=...)``,
    which is loaded into the real ``APILeakConfig`` and driven through
    ``APILeakCore._execute_fuzzing_phase``. That phase's
    ``_ensure_fuzzing_orchestrator`` is the production code under test: it derives
    the engine-level ``default_headers`` from the threaded custom headers/cookie
    and wires the basic-auth context onto the HTTP client.

Why a thin stub subclass
    The shared task-1.1 stub (:mod:`tests.support.http_stub`) records exactly the
    kwargs the fuzzer passes to ``request`` and deliberately does NOT model the
    engine-level default-header merge or auth application — those are a
    ``HTTPRequestEngine`` responsibility performed inside ``request`` (via
    ``setdefault`` for ``default_headers`` and ``_apply_authentication`` for the
    active auth context). To exercise Property 8 end-to-end offline, this module
    uses a minimal subclass that reproduces exactly those two engine steps and
    otherwise reuses the base stub's recording. The engine construction code that
    *feeds* those steps (deriving ``default_headers`` and setting the auth
    context) is the genuine production code exercised here; the mechanical merge
    itself is already pinned against the real engine in
    ``tests/test_dir_headers_auth_cli.py``.

**Validates: Requirements 7.1, 7.2, 7.3**
"""

from __future__ import annotations

import asyncio
import base64
import os
import tempfile
from typing import Dict, Optional, Tuple
from unittest.mock import patch

from hypothesis import given, settings, strategies as st

import utils.http_client as hc
from apileaks import create_default_config, parse_basic_auth, parse_header_options
from core.config import ConfigurationManager
from core.engine import APILeakCore
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


TARGET = "https://api.example.test"

# A couple of candidate parameter names so the run issues a baseline request plus
# per-candidate (and boundary) requests -- every one of which must carry context.
_WORDLIST_NAMES = ["alpha", "beta"]

# Header names/values that would collide with the engine-level context headers
# are excluded from the generated custom headers so the assertions are
# unambiguous (the ``X-`` prefix already avoids these, but keep it explicit).
_RESERVED = {"cookie", "authorization", "content-type", "user-agent", "host"}


# --------------------------------------------------------------------------- #
# Context-applying stub (reproduces the two engine-level request() steps)
# --------------------------------------------------------------------------- #

def _apply_auth_context(auth, headers: Dict[str, str]) -> None:
    """Mirror ``HTTPRequestEngine._apply_authentication`` onto ``headers``.

    Faithful to the real engine: bearer/jwt -> ``Bearer`` token, basic ->
    ``Basic <base64(user:pass)>``, api-key -> ``X-API-Key``; then any
    context-supplied headers are merged.
    """
    if auth is None:
        return
    atype = getattr(auth, "type", None)
    tval = getattr(atype, "value", atype)
    if tval in ("bearer", "jwt"):
        token = getattr(auth, "token", None)
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif tval == "basic":
        username = getattr(auth, "username", None)
        password = getattr(auth, "password", None)
        if username and password:
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
    elif tval == "api_key":
        token = getattr(auth, "token", None)
        if token and "X-API-Key" not in headers:
            headers["X-API-Key"] = token
    extra = getattr(auth, "headers", None)
    if extra:
        headers.update(extra)


class _ContextApplyingStub(HTTPRequestEngineStub):
    """Offline stub that applies engine-level request context like the real engine.

    Reproduces the two steps ``HTTPRequestEngine.request`` performs before
    dispatch: (1) merge engine-level ``default_headers`` via ``setdefault`` (never
    overriding a per-request header), and (2) apply the active auth context. The
    base stub's recording of the resulting request is reused unchanged.
    """

    def __init__(self, *, default_headers: Optional[Dict[str, str]] = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._engine_default_headers: Dict[str, str] = dict(default_headers or {})

    async def request(self, method: str, url: str, **kwargs):
        headers = dict(kwargs.get("headers", {}) or {})
        # (1) engine-level default headers: setdefault, never override.
        for name, value in self._engine_default_headers.items():
            headers.setdefault(name, value)
        # (2) active auth context -> Authorization / api-key header.
        _apply_auth_context(self.current_auth_context, headers)
        kwargs["headers"] = headers
        return await super().request(method, url, **kwargs)


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #

# Header names are ``X-`` prefixed so they are valid and never collide with the
# reserved context headers. Values are non-empty, whitespace-free printable ASCII
# (no colon) so they round-trip through ``parse_header_options`` verbatim.
_header_name = st.from_regex(r"X-[A-Za-z][A-Za-z0-9-]{0,15}", fullmatch=True)
_header_value = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters=":"),
    min_size=1,
    max_size=20,
)
_headers = st.dictionaries(_header_name, _header_value, max_size=5).filter(
    lambda d: all(name.lower() not in _RESERVED for name in d)
)

# A cookie string carried verbatim as the ``Cookie`` header.
_cookie = st.one_of(
    st.none(),
    st.from_regex(
        r"[a-zA-Z0-9_]{1,8}=[a-zA-Z0-9_]{1,8}(; [a-zA-Z0-9_]{1,8}=[a-zA-Z0-9_]{1,8}){0,2}",
        fullmatch=True,
    ),
)

# Basic-auth ``user:pass`` (neither part contains a colon so parsing is exact).
_basic_user = st.from_regex(r"[A-Za-z0-9_]{1,10}", fullmatch=True)
_basic_pass = st.from_regex(r"[A-Za-z0-9_!@#$%^&*]{1,12}", fullmatch=True)
_basic_auth = st.one_of(st.none(), st.tuples(_basic_user, _basic_pass))


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

def _write_wordlist() -> str:
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write("\n".join(_WORDLIST_NAMES) + "\n")
    handle.close()
    return handle.name


def _run_par_flow(
    headers: Dict[str, str],
    cookie: Optional[str],
    basic_auth: Optional[Tuple[str, str]],
) -> _ContextApplyingStub:
    """Drive the ``par`` parameter-fuzzing phase fully offline and return the stub.

    Threads the request-context options exactly as the ``par`` command does, then
    substitutes the context-applying stub at the single ``HTTPRequestEngine``
    construction point ``_ensure_fuzzing_orchestrator`` imports.
    """
    # Mirror `par`'s request-context threading verbatim.
    header_strings = [f"{name}: {value}" for name, value in headers.items()]
    extra_headers = parse_header_options(header_strings)
    if cookie:
        extra_headers["Cookie"] = cookie
    basic_auth_str = f"{basic_auth[0]}:{basic_auth[1]}" if basic_auth else None
    basic_auth_creds = parse_basic_auth(basic_auth_str)

    wordlist_path = _write_wordlist()
    stub_holder: Dict[str, _ContextApplyingStub] = {}

    def _engine_factory(*args, **kwargs):
        stub = _ContextApplyingStub(
            default=ScriptedResponse(status_code=200, body={"ok": True}),
            default_headers=kwargs.get("default_headers"),
        )
        stub_holder["stub"] = stub
        return stub

    try:
        config_dict = create_default_config(
            TARGET, wordlist_path, "par",
            extra_headers=extra_headers, basic_auth=basic_auth_creds,
        )
        apileak_config = ConfigurationManager().load_config_from_dict(config_dict)

        core = APILeakCore(apileak_config)
        core.target = TARGET

        with patch.object(hc, "HTTPRequestEngine", _engine_factory):
            asyncio.run(core._execute_fuzzing_phase())
    finally:
        os.unlink(wordlist_path)

    return stub_holder["stub"]


# --------------------------------------------------------------------------- #
# Property 8
# --------------------------------------------------------------------------- #

@given(headers=_headers, cookie=_cookie, basic_auth=_basic_auth)
@settings(max_examples=120, deadline=None)
def test_request_context_applied_to_every_request(headers, cookie, basic_auth):
    """Request context is applied to every request.

    # Feature: parameter-fuzzing, Property 8: Request context is applied to every request
    **Validates: Requirements 7.1, 7.2, 7.3**
    """
    stub = _run_par_flow(headers, cookie, basic_auth)

    # The run must actually issue requests (baseline + per-candidate tests),
    # otherwise "every request carries context" would be vacuously true.
    assert stub.requests, "the par flow issued no HTTP requests"

    expected_authorization = None
    if basic_auth is not None:
        creds = f"{basic_auth[0]}:{basic_auth[1]}"
        expected_authorization = "Basic " + base64.b64encode(creds.encode()).decode()

    for recorded in stub.requests:
        # R7.1: every provided custom header rides every request, unchanged.
        for name, value in headers.items():
            assert recorded.headers.get(name) == value, (
                f"header {name!r} missing/altered on {recorded.method} "
                f"{recorded.url}: got {recorded.headers.get(name)!r}"
            )

        # R7.2: the cookie is applied as a Cookie header on every request.
        if cookie is not None:
            assert recorded.headers.get("Cookie") == cookie, (
                f"Cookie header missing/altered on {recorded.method} "
                f"{recorded.url}: got {recorded.headers.get('Cookie')!r}"
            )

        # R7.3: basic-auth is applied as an Authorization header on every request.
        if expected_authorization is not None:
            assert recorded.headers.get("Authorization") == expected_authorization, (
                f"basic-auth Authorization missing/altered on {recorded.method} "
                f"{recorded.url}: got {recorded.headers.get('Authorization')!r}"
            )


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
