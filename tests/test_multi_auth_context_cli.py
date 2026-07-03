"""
Unit tests for multi-user Auth_Context threading in the ``full`` command.

**Feature: owasp-auth-modules-hardening, Task 12.3**

These tests lock in the behavior added by Task 12.1: the repeatable
``--auth-context user:token[:privilege]`` option is parsed into one
``AuthContext`` per value and threaded into ``authentication.contexts`` for the
OWASP modules, while a lone ``--jwt`` (with NO ``--auth-context``) preserves the
existing single-context behavior — i.e. no extra Auth_Contexts are appended and
the configuration still carries exactly the one default (anonymous) context.

They mirror the CLI-testing patterns in ``tests/test_dir_headers_auth_cli.py``
(``CliRunner`` invocation, capturing the threaded config via a patch, and
patching so no real network scan runs). Here the multi-user threading happens
*after* ``load_config_from_dict`` (it mutates the loaded ``apileak_config``),
so we capture ``apileak_config`` at the ``run_enhanced_apileak`` boundary — the
first consumer of the fully threaded configuration.

Covered behavior:

- A single ``--jwt`` with no ``--auth-context`` leaves ``authentication.contexts``
  as the single default context (Requirements 20.4, 26.2).
- ``parse_auth_context_option(())`` yields an empty list so the single-``--jwt``
  path is preserved unchanged (Requirements 20.4, 26.2).
- For contrast, supplying ``--auth-context`` appends the parsed contexts with
  their privilege levels (Requirements 20.1, 20.2, 20.3).
"""

from unittest.mock import patch

from click.testing import CliRunner

import apileaks
from apileaks import cli, parse_auth_context_option
from core.config import AuthType


TARGET = "https://api.example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke_full_capturing_config(args):
    """Invoke ``full`` and capture the fully threaded ``apileak_config``.

    ``run_enhanced_apileak`` is the first consumer of the loaded and
    auth-context-threaded configuration, so replacing it lets us inspect the
    effective ``authentication.contexts`` without performing a real scan. The
    configuration validation step is stubbed to isolate the auth-context
    threading behavior from unrelated file-system checks (e.g. wordlist paths).
    """
    captured = {}

    def _capture(config, *rest, **kwargs):
        captured["config"] = config

        async def _noop():
            return None

        # Returned coroutine is what asyncio.run(...) drives; it is a no-op so
        # the command completes cleanly after we have captured the config.
        return _noop()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "validate_configuration", return_value=[]
    ), patch.object(apileaks, "run_enhanced_apileak", _capture):
        result = runner.invoke(
            cli,
            ["--no-banner", "full", "--target", TARGET, *args],
        )
    return result, captured.get("config")


# ---------------------------------------------------------------------------
# Single --jwt (no --auth-context) preserves one-context behavior (20.4, 26.2)
# ---------------------------------------------------------------------------

def test_single_jwt_without_auth_context_preserves_one_context():
    """A lone ``--jwt`` appends no extra Auth_Context (one-context preserved).

    **Validates: Requirements 20.4, 26.2**
    """
    result, config = _invoke_full_capturing_config(
        ["--jwt", "header.payload.signature"]
    )

    assert result.exit_code == 0, result.output
    assert config is not None

    contexts = config.authentication.contexts
    # The multi-context threading path never fired: only the single default
    # (anonymous) context remains.
    assert len(contexts) == 1
    assert contexts[0].name == "anonymous"


def test_no_auth_options_keeps_single_default_context():
    """With neither ``--jwt`` nor ``--auth-context`` the one default persists.

    **Validates: Requirements 20.4, 26.2**
    """
    result, config = _invoke_full_capturing_config([])

    assert result.exit_code == 0, result.output
    assert config is not None
    assert len(config.authentication.contexts) == 1
    assert config.authentication.contexts[0].name == "anonymous"


def test_parse_auth_context_option_empty_preserves_single_jwt_behavior():
    """An empty option set yields no contexts, so ``--jwt`` stays one-context.

    ``parse_auth_context_option`` is the gate for the multi-user threading: it
    returns an empty list when no ``--auth-context`` value is supplied, which is
    what preserves the existing single-``--jwt`` behavior at the call site.

    **Validates: Requirements 20.4, 26.2**
    """
    assert parse_auth_context_option(()) == []
    assert parse_auth_context_option(None) == []


# ---------------------------------------------------------------------------
# Contrast: --auth-context appends the parsed contexts (20.1, 20.2, 20.3)
# ---------------------------------------------------------------------------

def test_auth_context_options_append_parsed_contexts():
    """Supplying ``--auth-context`` appends one context per value.

    This contrasts with the single-``--jwt`` case above: the two supplied
    identities are threaded on top of the default anonymous context, each with
    its parsed token and privilege level.

    **Validates: Requirements 20.1, 20.2, 20.3**
    """
    result, config = _invoke_full_capturing_config(
        [
            "--auth-context", "alice:alice-token:2",
            "--auth-context", "bob:bob-token:5",
        ]
    )

    assert result.exit_code == 0, result.output
    assert config is not None

    contexts = config.authentication.contexts
    # Default anonymous context plus the two supplied identities.
    assert len(contexts) == 3
    assert contexts[0].name == "anonymous"

    by_name = {ctx.name: ctx for ctx in contexts}
    assert by_name["alice"].token == "alice-token"
    assert by_name["alice"].type == AuthType.BEARER
    assert by_name["alice"].privilege_level == 2
    assert by_name["bob"].token == "bob-token"
    assert by_name["bob"].privilege_level == 5


def test_single_auth_context_without_privilege_defaults_privilege_one():
    """A ``--auth-context`` without a privilege suffix defaults privilege to 1.

    **Validates: Requirements 20.1, 20.2, 20.3**
    """
    result, config = _invoke_full_capturing_config(
        ["--auth-context", "carol:carol-token"]
    )

    assert result.exit_code == 0, result.output
    assert config is not None

    contexts = config.authentication.contexts
    assert len(contexts) == 2
    carol = {ctx.name: ctx for ctx in contexts}["carol"]
    assert carol.token == "carol-token"
    assert carol.privilege_level == 1
