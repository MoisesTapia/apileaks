"""
Unit tests for threading the optional merged Spec_Schema into the three
hardened OWASP modules (BOLA, Auth, Property) via ``core/engine.py``.

**Feature: owasp-auth-modules-hardening, Task 43.2**

These tests confirm the additive, backward-compatible wiring:
* each module ``__init__`` accepts an optional ``spec_schema=`` keyword that
  defaults to ``None`` and is stored on ``self.spec_schema`` (Requirements
  49.2, 49.5, 52.6, 53.2, 54.3, 55.5);
* omitting the keyword (the existing 3-positional-arg construction) leaves
  ``self.spec_schema is None`` so the no-spec path is unchanged (Req 49.3);
* ``APILeakCore._initialize_owasp_modules`` reads
  ``owasp_testing.spec_schema`` and threads it into the ``bola`` / ``auth`` /
  ``property`` modules while preserving those registration keys.
"""

import asyncio
from unittest.mock import Mock, AsyncMock

import pytest

from modules.owasp.bola_testing import BOLATestingModule
from modules.owasp.auth_testing import AuthenticationTestingModule
from modules.owasp.property_level_auth import PropertyLevelAuthModule
from utils.http_client import HTTPRequestEngine
from core.config import (
    APILeakConfig,
    TargetConfig,
    BOLAConfig,
    AuthTestingConfig,
    PropertyTestingConfig,
    AuthContext,
    AuthType,
)
from core.engine import APILeakCore


def _engine_config():
    return APILeakConfig(target=TargetConfig(base_url="https://example.test"))


def _http_client():
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    client.add_auth_context = Mock()
    return client


def _auth_contexts():
    return [
        AuthContext(name="user1", type=AuthType.BEARER, token="t1", privilege_level=1),
    ]


# ---------------------------------------------------------------------------
# Per-module __init__ accepts and stores spec_schema (additive keyword)
# ---------------------------------------------------------------------------

def test_bola_module_defaults_spec_schema_to_none():
    """Constructing without the keyword leaves spec_schema None (Req 49.3)."""
    module = BOLATestingModule(BOLAConfig(), _http_client(), _auth_contexts())
    assert module.spec_schema is None


def test_auth_module_defaults_spec_schema_to_none():
    """Constructing without the keyword leaves spec_schema None (Req 49.3)."""
    module = AuthenticationTestingModule(
        AuthTestingConfig(), _http_client(), _auth_contexts()
    )
    assert module.spec_schema is None


def test_property_module_defaults_spec_schema_to_none():
    """Constructing without the keyword leaves spec_schema None (Req 49.3)."""
    module = PropertyLevelAuthModule(
        PropertyTestingConfig(), _http_client(), _auth_contexts()
    )
    assert module.spec_schema is None


def test_bola_module_stores_supplied_spec_schema():
    """A supplied spec_schema is stored on the module (Reqs 49.2, 53.2)."""
    sentinel = object()
    module = BOLATestingModule(
        BOLAConfig(), _http_client(), _auth_contexts(), spec_schema=sentinel
    )
    assert module.spec_schema is sentinel


def test_auth_module_stores_supplied_spec_schema():
    """A supplied spec_schema is stored on the module (Reqs 49.2, 54.3)."""
    sentinel = object()
    module = AuthenticationTestingModule(
        AuthTestingConfig(), _http_client(), _auth_contexts(), spec_schema=sentinel
    )
    assert module.spec_schema is sentinel


def test_property_module_stores_supplied_spec_schema():
    """A supplied spec_schema is stored on the module (Reqs 49.2, 52.6, 55.5)."""
    sentinel = object()
    module = PropertyLevelAuthModule(
        PropertyTestingConfig(), _http_client(), _auth_contexts(), spec_schema=sentinel
    )
    assert module.spec_schema is sentinel


# ---------------------------------------------------------------------------
# Engine threads owasp_testing.spec_schema into the three modules
# ---------------------------------------------------------------------------

def test_engine_threads_spec_schema_and_preserves_keys():
    """_initialize_owasp_modules threads spec_schema into bola/auth/property.

    Also confirms the engine registration keys are preserved (Req 23.1).
    """
    config = _engine_config()
    sentinel = object()
    config.owasp_testing.spec_schema = sentinel

    core = APILeakCore(config)
    asyncio.run(core._initialize_owasp_modules())

    for key in ("bola", "auth", "property"):
        assert key in core.owasp_modules, f"registration key {key!r} missing"
        assert core.owasp_modules[key].spec_schema is sentinel


def test_engine_leaves_spec_schema_none_when_unset():
    """No spec attached -> modules carry spec_schema None (Req 49.3)."""
    config = _engine_config()
    assert config.owasp_testing.spec_schema is None

    core = APILeakCore(config)
    asyncio.run(core._initialize_owasp_modules())

    for key in ("bola", "auth", "property"):
        assert core.owasp_modules[key].spec_schema is None
