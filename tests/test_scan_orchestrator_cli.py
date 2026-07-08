"""Orchestrator and backward-compatibility tests for the CLI restructure (task 7.1).

These tests exercise the ``scan`` orchestrator and its deprecated ``full`` alias
and hidden ``main`` command built in task 7 (``apileaks.py``). ``scan`` resolves
the ``--modules`` selection (default: all registered engine keys) and routes
through the shared ``_build_and_run`` execution core; ``full`` and ``main`` are
thin wrappers that emit a stderr Deprecation_Notice and ``ctx.forward(scan)`` so
they run identically.

They anchor two correctness properties and several acceptance criteria:

* Property 5 (single-vs-composed config equivalence): for a module key ``k`` and
  fixed option values ``V``, ``owasp k V`` and ``scan --modules k V`` build an
  identical config in ``k``'s module field and in every transversal-derived
  field, differing only in ``enabled_modules`` cardinality (R2.5, R3.5, R4.3).
* Property 6 (alias run equivalence): ``full A``, ``main A``, and ``scan A``
  execute the same module set, build the same config, and return the same exit
  code; ``full``/``main`` additionally write exactly one stderr Deprecation_Notice
  and leave stdout unchanged (R6.2, R6.4, R6.7).
* R4.2 / R4.6 / R4.7: ``scan`` with no ``--modules`` runs all descriptor keys;
  ``scan --modules bola,auth`` runs exactly those; an unknown key exits nonzero
  before any run.
* R6.3: hidden ``main`` is absent from top-level help but invokable.
* R6.6: ``full --modules bola`` emits a notice naming ``apileaks owasp bola``.
* R5.4: ``--safe-mode`` propagates to every composed module.

The engine boundary (``run_enhanced_apileak``) is patched so no real scan runs,
capturing the fully assembled ``APILeakConfig`` (the first consumer of every
resolved setting). Configuration validation is stubbed so routing/equivalence
behavior is isolated from unrelated filesystem checks. This mirrors the capture
pattern in ``tests/test_owasp_group_cli.py``.
"""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

import apileaks
from apileaks import cli
from cli.owasp_descriptors import OWASP_MODULE_DESCRIPTORS, all_keys


TARGET = "http://example.com"

# Descriptor keys other than "bola" (for isolation assertions).
_NON_BOLA_KEYS = {desc.key for desc in OWASP_MODULE_DESCRIPTORS if desc.key != "bola"}


# --------------------------------------------------------------------------- #
# Capture helpers
# --------------------------------------------------------------------------- #

def _invoke_capturing_config(args):
    """Invoke the top-level ``cli`` with ``args``, capturing the engine config.

    ``run_enhanced_apileak`` is the first consumer of the fully built config, so
    replacing it captures ``owasp_testing.enabled_modules`` and every resolved
    transversal/module field without running a real scan. Configuration
    validation is stubbed so the behavior under test is isolated from unrelated
    filesystem checks. Returns ``(result, config, mock_run)``.
    """
    captured = {}

    def _capture(config, *rest, **kwargs):
        captured["config"] = config

        async def _noop():
            return None

        return _noop()

    runner = CliRunner(mix_stderr=False)
    with patch.object(
        apileaks.ConfigurationManager, "validate_configuration", return_value=[]
    ), patch.object(
        apileaks, "run_enhanced_apileak", MagicMock(side_effect=_capture)
    ) as mock_run:
        result = runner.invoke(cli, ["--no-banner", *args])
    return result, captured.get("config"), mock_run


def _deprecation_lines(stderr):
    """Return the ``[DEPRECATION]`` notice lines present in stderr."""
    return [line for line in stderr.splitlines() if "[DEPRECATION]" in line]


# --------------------------------------------------------------------------- #
# R4.2 / R4.6 / R4.7: module selection resolution.
# --------------------------------------------------------------------------- #

def test_scan_without_modules_runs_all_descriptor_keys():
    """``scan`` with no ``--modules`` enables every registered engine key (R4.2).

    **Validates: Requirements 4.2**
    """
    result, config, _ = _invoke_capturing_config(["scan", "--target", TARGET])

    assert result.exit_code == 0, result.output
    assert config is not None
    assert config.owasp_testing.enabled_modules == all_keys()
    # Sanity: all ten modules are composed.
    assert len(config.owasp_testing.enabled_modules) == len(OWASP_MODULE_DESCRIPTORS)


def test_scan_with_modules_subset_runs_exactly_those():
    """``scan --modules bola,auth`` enables exactly those keys, in order (R4.6).

    **Validates: Requirements 4.6**
    """
    result, config, _ = _invoke_capturing_config(
        ["scan", "--target", TARGET, "--modules", "bola,auth"]
    )

    assert result.exit_code == 0, result.output
    assert config is not None
    assert config.owasp_testing.enabled_modules == ["bola", "auth"]


def test_scan_unknown_module_exits_nonzero_before_any_run():
    """An unregistered ``--modules`` key aborts nonzero before any run (R4.7).

    The error names the offending key and no engine call is made.

    **Validates: Requirements 4.7**
    """
    result, _, mock_run = _invoke_capturing_config(
        ["scan", "--target", TARGET, "--modules", "bola,definitely-not-a-module"]
    )

    assert result.exit_code != 0
    assert "definitely-not-a-module" in result.stderr
    mock_run.assert_not_called()


# --------------------------------------------------------------------------- #
# Property 5: single (owasp k) vs composed (scan --modules k) config equivalence.
# --------------------------------------------------------------------------- #

# A fixed, representative set of BOLA-specific + transversal option values used
# by both invocations so the assembled configs must be identical.
_EQUIVALENCE_ARGS = [
    "--target", TARGET,
    "--bola-composite",
    "--bola-id-leakage",
    "--allow-write-bola",
    "--bola-destructive-methods", "patch,put,delete",
    "--timeout", "20",
    "--rate-limit", "7",
    "--safe-mode",
]


def test_owasp_bola_and_scan_modules_bola_build_identical_bola_config():
    """``owasp bola V`` and ``scan --modules bola V`` build an identical config.

    The BOLA module field and every transversal-derived field match; the two
    differ only in ``enabled_modules`` cardinality (here both resolve to the
    single key ``bola``, so even that matches) (Property 5 / R2.5, R3.5, R4.3).

    **Validates: Requirements 2.5, 3.5, 4.3**
    """
    single_result, single_cfg, _ = _invoke_capturing_config(
        ["owasp", "bola", *_EQUIVALENCE_ARGS]
    )
    composed_result, composed_cfg, _ = _invoke_capturing_config(
        ["scan", "--modules", "bola", *_EQUIVALENCE_ARGS]
    )

    assert single_result.exit_code == 0, single_result.output
    assert composed_result.exit_code == 0, composed_result.output
    assert single_cfg is not None and composed_cfg is not None

    # Both compose exactly the one selected module (equal cardinality here).
    assert single_cfg.owasp_testing.enabled_modules == ["bola"]
    assert composed_cfg.owasp_testing.enabled_modules == ["bola"]

    # The BOLA module config field is identical (dataclass equality).
    assert (
        single_cfg.owasp_testing.bola_testing
        == composed_cfg.owasp_testing.bola_testing
    )
    # Spot-check the values the options threaded, to catch a silent equality gap.
    bola_cfg = composed_cfg.owasp_testing.bola_testing
    assert bola_cfg.allow_destructive is True
    assert bola_cfg.enable_composite is True
    assert bola_cfg.enable_id_leakage is True
    assert bola_cfg.destructive_methods == {"PATCH", "PUT", "DELETE"}


def test_owasp_bola_and_scan_modules_bola_match_transversal_fields():
    """Transversal-derived fields match between single and composed runs.

    Target, per-request timeout, rate limit, and safe-mode resolve identically
    regardless of whether the module runs alone or via the orchestrator
    (Property 5 / R3.5).

    **Validates: Requirements 3.5, 4.3**
    """
    _, single_cfg, _ = _invoke_capturing_config(["owasp", "bola", *_EQUIVALENCE_ARGS])
    _, composed_cfg, _ = _invoke_capturing_config(
        ["scan", "--modules", "bola", *_EQUIVALENCE_ARGS]
    )

    assert single_cfg is not None and composed_cfg is not None
    assert single_cfg.target.base_url == composed_cfg.target.base_url == TARGET
    assert single_cfg.target.timeout == composed_cfg.target.timeout == 20
    assert (
        single_cfg.rate_limiting.requests_per_second
        == composed_cfg.rate_limiting.requests_per_second
        == 7
    )
    assert single_cfg.safe_mode == composed_cfg.safe_mode is True


# --------------------------------------------------------------------------- #
# Property 6: full / main / scan run equivalence.
# --------------------------------------------------------------------------- #

_ALIAS_ARGS = ["--target", TARGET, "--modules", "bola,auth", "--timeout", "15"]


def test_full_main_scan_produce_identical_enabled_modules():
    """``full A``, ``main A`` (via --modules on scan's surface), and ``scan A``
    compose the same module set and build an equivalent config (R6.2).

    ``main`` exposes only a subset of options, so it is compared on the module
    selection it supports; ``full`` and ``scan`` are compared on the full arg set.

    **Validates: Requirements 6.2**
    """
    _, scan_cfg, _ = _invoke_capturing_config(["scan", *_ALIAS_ARGS])
    _, full_cfg, _ = _invoke_capturing_config(["full", *_ALIAS_ARGS])

    assert scan_cfg is not None and full_cfg is not None
    # Same module set.
    assert (
        full_cfg.owasp_testing.enabled_modules
        == scan_cfg.owasp_testing.enabled_modules
        == ["bola", "auth"]
    )
    # Equivalent transversal-derived config.
    assert full_cfg.target.base_url == scan_cfg.target.base_url
    assert full_cfg.target.timeout == scan_cfg.target.timeout == 15
    assert full_cfg.owasp_testing.bola_testing == scan_cfg.owasp_testing.bola_testing


def test_main_forwards_to_scan_with_same_modules():
    """Hidden ``main --modules bola,auth`` forwards to ``scan`` identically (R6.2).

    **Validates: Requirements 6.2, 6.3**
    """
    _, scan_cfg, _ = _invoke_capturing_config(
        ["scan", "--target", TARGET, "--modules", "bola,auth"]
    )
    result, main_cfg, mock_run = _invoke_capturing_config(
        ["main", "--target", TARGET, "--modules", "bola,auth"]
    )

    assert result.exit_code == 0, result.output
    assert main_cfg is not None and scan_cfg is not None
    assert (
        main_cfg.owasp_testing.enabled_modules
        == scan_cfg.owasp_testing.enabled_modules
        == ["bola", "auth"]
    )


def test_full_emits_exactly_one_deprecation_notice_and_unchanged_stdout():
    """``full`` writes exactly one stderr notice and leaves stdout unchanged (R6.4).

    Compared against the equivalent ``scan`` run: stdout is byte-identical and
    ``scan`` writes no deprecation notice, while ``full`` writes exactly one.

    **Validates: Requirements 6.4**
    """
    scan_result, _, _ = _invoke_capturing_config(["scan", "--target", TARGET])
    full_result, _, _ = _invoke_capturing_config(["full", "--target", TARGET])

    assert scan_result.exit_code == 0, scan_result.output
    assert full_result.exit_code == 0, full_result.output

    # scan emits no deprecation notice; full emits exactly one.
    assert _deprecation_lines(scan_result.stderr) == []
    full_notices = _deprecation_lines(full_result.stderr)
    assert len(full_notices) == 1
    assert "full" in full_notices[0] and "scan" in full_notices[0]

    # The notice never alters standard output (R6.4): stdout is unchanged.
    assert full_result.stdout == scan_result.stdout


def test_main_emits_exactly_one_deprecation_notice():
    """Hidden ``main`` writes exactly one stderr Deprecation_Notice (R6.4).

    **Validates: Requirements 6.4**
    """
    result, _, _ = _invoke_capturing_config(["main", "--target", TARGET])

    assert result.exit_code == 0, result.output
    notices = _deprecation_lines(result.stderr)
    assert len(notices) == 1
    assert "main" in notices[0] and "scan" in notices[0]


def test_full_main_scan_same_exit_code_for_valid_and_invalid_args():
    """``full``/``main``/``scan`` return the identical exit code (R6.7).

    Checked for a valid invocation (exit 0) and an invalid one (unknown module
    key → nonzero), so the emitted notice never alters the exit code.

    **Validates: Requirements 6.7**
    """
    # Valid: all three exit 0.
    scan_ok, _, _ = _invoke_capturing_config(["scan", "--target", TARGET])
    full_ok, _, _ = _invoke_capturing_config(["full", "--target", TARGET])
    main_ok, _, _ = _invoke_capturing_config(["main", "--target", TARGET])
    assert scan_ok.exit_code == full_ok.exit_code == main_ok.exit_code == 0

    # Invalid: unknown module key aborts nonzero on every entry point.
    bad = ["--target", TARGET, "--modules", "bola,nope"]
    scan_bad, _, scan_mock = _invoke_capturing_config(["scan", *bad])
    full_bad, _, full_mock = _invoke_capturing_config(["full", *bad])
    main_bad, _, main_mock = _invoke_capturing_config(["main", *bad])

    assert scan_bad.exit_code != 0
    assert scan_bad.exit_code == full_bad.exit_code == main_bad.exit_code
    scan_mock.assert_not_called()
    full_mock.assert_not_called()
    main_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# R6.6: full --modules emits a notice naming the owasp <module> equivalent.
# --------------------------------------------------------------------------- #

def test_full_modules_single_key_emits_notice_naming_owasp_bola():
    """``full --modules bola`` names ``apileaks owasp bola`` as the replacement.

    **Validates: Requirements 6.6**
    """
    result, config, _ = _invoke_capturing_config(
        ["full", "--target", TARGET, "--modules", "bola"]
    )

    assert result.exit_code == 0, result.output
    # Runs only the selected module (R6.5).
    assert config.owasp_testing.enabled_modules == ["bola"]

    notices = _deprecation_lines(result.stderr)
    # Two notices: the full->scan alias notice and the module-selection notice.
    assert any("apileaks owasp bola" in line for line in notices), result.stderr


def test_full_modules_multiple_keys_emits_scan_replacement():
    """``full --modules bola,auth`` names ``scan --modules`` as the replacement.

    A multi-key selection has no single ``owasp <module>`` equivalent, so the
    notice points at ``apileaks scan --modules ...`` (R6.6).

    **Validates: Requirements 6.6**
    """
    result, _, _ = _invoke_capturing_config(
        ["full", "--target", TARGET, "--modules", "bola,auth"]
    )

    assert result.exit_code == 0, result.output
    notices = _deprecation_lines(result.stderr)
    assert any(
        "apileaks scan --modules bola,auth" in line for line in notices
    ), result.stderr


# --------------------------------------------------------------------------- #
# R6.3: hidden main is absent from top-level help but invokable.
# --------------------------------------------------------------------------- #

def test_main_hidden_from_top_level_help_but_invokable():
    """``main`` is omitted from the top-level help listing yet still runs (R6.3).

    **Validates: Requirements 6.3**
    """
    runner = CliRunner()
    help_result = runner.invoke(cli, ["--no-banner", "--help"])

    assert help_result.exit_code == 0, help_result.output
    # The command line in the help listing (avoid matching prose that could
    # contain the substring "main"): no listed command is named ``main``.
    listed_commands = set()
    for line in help_result.output.splitlines():
        stripped = line.strip()
        # Command listing rows begin with the command name followed by 2+ spaces.
        if stripped and not stripped.startswith("-"):
            parts = stripped.split()
            if parts:
                listed_commands.add(parts[0])
    assert "main" not in listed_commands
    # scan and full ARE listed (full is deprecated but visible).
    assert "scan" in listed_commands

    # Despite being hidden, main is invokable.
    result, config, _ = _invoke_capturing_config(["main", "--target", TARGET])
    assert result.exit_code == 0, result.output
    assert config is not None


# --------------------------------------------------------------------------- #
# R5.4: --safe-mode propagates to every composed module.
# --------------------------------------------------------------------------- #

def test_safe_mode_propagates_to_every_composed_module():
    """``scan --safe-mode`` sets Safe_Mode for a run composing every module (R5.4).

    All ten modules are composed and the run's Safe_Mode flag is set, so every
    composed module runs in Safe_Mode.

    **Validates: Requirements 5.4**
    """
    result, config, _ = _invoke_capturing_config(
        ["scan", "--target", TARGET, "--safe-mode"]
    )

    assert result.exit_code == 0, result.output
    assert config is not None
    # Every registered module is composed for this run...
    assert config.owasp_testing.enabled_modules == all_keys()
    # ...and Safe_Mode is enabled for the run.
    assert config.safe_mode is True


def test_safe_mode_off_by_default():
    """Without ``--safe-mode`` the run's Safe_Mode flag stays off (baseline)."""
    result, config, _ = _invoke_capturing_config(["scan", "--target", TARGET])

    assert result.exit_code == 0, result.output
    assert config is not None
    assert config.safe_mode is False
