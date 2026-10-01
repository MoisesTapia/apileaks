"""
CLI input parsers and validation helpers.

Pure helpers extracted from ``apileaks.py`` (the CLI entrypoint) as part of the
monolith decomposition. These functions parse/validate command-line inputs and
have no dependency on the rest of ``apileaks`` beyond the standard library and
Click, so they live here and are re-imported by ``apileaks.py`` to preserve the
public surface (including test monkeypatch targets).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click


def parse_response_codes(response_filter: str) -> list:
    """Parse response code filter string into list of integers"""
    if not response_filter:
        return []

    codes = []
    parts = response_filter.split(",")

    for part in parts:
        part = part.strip()
        if "-" in part:
            # Range like 200-300
            try:
                start, end = part.split("-")
                codes.extend(range(int(start), int(end) + 1))
            except ValueError:
                click.echo(f"Warning: Invalid range format '{part}', ignoring", err=True)
        else:
            # Single code like 200
            try:
                codes.append(int(part))
            except ValueError:
                click.echo(f"Warning: Invalid response code '{part}', ignoring", err=True)

    return sorted(set(codes))  # Remove duplicates and sort


def parse_status_codes(status_filter: str) -> list:
    """Parse status code filter string into list of integers for HTTP output filtering"""
    if not status_filter:
        return []

    codes = []
    parts = status_filter.split(",")

    for part in parts:
        part = part.strip()
        if "-" in part:
            # Range like 200-300
            try:
                start, end = part.split("-")
                codes.extend(range(int(start), int(end) + 1))
            except ValueError:
                click.echo(
                    f"Warning: Invalid status code range format '{part}', ignoring", err=True
                )
        else:
            # Single code like 200
            try:
                codes.append(int(part))
            except ValueError:
                click.echo(f"Warning: Invalid status code '{part}', ignoring", err=True)

    return sorted(set(codes))  # Remove duplicates and sort

    return sorted(set(codes))  # Remove duplicates and sort


def _validate_confirm_hits(ctx, param, value):
    """Click callback: reject a --confirm-hits below 1, naming the value.

    Click's ``type=int`` already rejects non-integers; this guards the lower
    bound so no Endpoint_Discovery runs on an invalid Hit_Confirmation count.
    ``default=None`` keeps Hit_Confirmation disabled; any supplied value must
    request at least one confirmation re-request (Requirement 35.7).
    """
    if value is not None and value < 1:
        raise click.BadParameter(f"--confirm-hits must be >= 1 (got {value})")
    return value


def _assert_readable(path, option_name):
    """Raise click.BadParameter naming the path when it is missing/unreadable.

    Shared by the --client-cert and --ca-bundle validators so an unreadable path
    is rejected before any Endpoint_Discovery runs (Requirement 29.6).
    """
    if not os.path.exists(path):
        raise click.BadParameter(f"{option_name} path does not exist: {path}")
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        raise click.BadParameter(f"{option_name} path cannot be read: {path}")


def validate_header_options(header):
    """Validate repeatable ``--header``/``-H`` values are in ``Name: Value`` form.

    A provided custom-header option that does not contain a ``:`` separating a
    name from a value is malformed; this rejects it with a descriptive error
    naming the offending header and exits BEFORE any request is issued
    (Requirement 7.5). Well-formed values are left for :func:`parse_header_options`
    to split; this only guards the colon-separator precondition.
    """
    for raw in header or ():
        if ":" not in raw:
            click.echo(
                f"Error: Malformed --header value '{raw}': expected 'Name: Value' "
                "with a ':' separating the header name from its value.",
                err=True,
            )
            sys.exit(1)


def load_user_agents_from_file(file_path):
    """Load user agents from file, filtering out empty lines and comments"""
    try:
        user_agents = []
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    user_agents.append(line)

        if not user_agents:
            click.echo(f"Error: No valid user agents found in file: {file_path}", err=True)
            sys.exit(1)

        return user_agents
    except Exception as e:
        click.echo(f"Error reading user agent file {file_path}: {e}", err=True)
        sys.exit(1)


def validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file):
    """Validate that only one user agent option is specified"""
    options_count = sum([bool(user_agent_random), bool(user_agent_custom), bool(user_agent_file)])

    if options_count > 1:
        click.echo("Error: Only one user agent option can be specified at a time:", err=True)
        click.echo("  --user-agent-random", err=True)
        click.echo("  --user-agent-custom", err=True)
        click.echo("  --user-agent-file", err=True)
        sys.exit(1)

    # Validate user agent file exists if specified
    if user_agent_file:
        if not Path(user_agent_file).exists():
            click.echo(f"Error: User agent file not found: {user_agent_file}", err=True)
            sys.exit(1)


def parse_target_file(path: str) -> list:
    """Read a target-file and return a list of normalised target URLs.

    Each non-empty, non-comment line becomes one target.  Lines that do not
    start with ``http://`` or ``https://`` are auto-prefixed with ``https://``
    so bare hostnames (``api.example.com``) and port-only specs
    (``api.example.com:8443``) work without decoration.

    Raises :class:`click.BadParameter` when the file cannot be read.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except OSError as exc:
        raise click.BadParameter(f"--target-file cannot be read: {path} ({exc})") from exc

    targets: list[str] = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("http://") and not stripped.startswith("https://"):
            stripped = "https://" + stripped
        targets.append(stripped)
    return targets


def prepare_output_filename(output_param):
    """Prepare output filename, ensuring it goes to reports directory"""
    if not output_param:
        return None

    # Extract just the filename, ignore any path components
    filename = Path(output_param).name

    # Remove any extension as the system will add appropriate extensions
    if "." in filename:
        filename = filename.rsplit(".", 1)[0]

    return filename


def _parse_selection_indices(selection, count):
    """Parse a multi-index/range triage selection into sorted 1-based indices.

    Accepts comma-separated indices and inclusive ranges, e.g. ``"1,3,5"`` or
    ``"2-4"`` (and combinations like ``"1,3-5"``). Every index must fall within
    ``[1, count]``. Returns a sorted list of unique indices, or ``None`` when the
    selection is empty or contains any malformed/out-of-range token (so the
    caller treats it as an invalid selection and re-prompts).
    """
    selection = (selection or "").strip()
    if not selection:
        return None

    indices = set()
    for token in selection.split(","):
        token = token.strip()
        if not token:
            return None
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                return None
            start_raw, end_raw = parts[0].strip(), parts[1].strip()
            if not (start_raw.isdigit() and end_raw.isdigit()):
                return None
            start, end = int(start_raw), int(end_raw)
            if start > end:
                return None
            for index in range(start, end + 1):
                if not 1 <= index <= count:
                    return None
                indices.add(index)
        else:
            if not token.isdigit():
                return None
            index = int(token)
            if not 1 <= index <= count:
                return None
            indices.add(index)

    if not indices:
        return None
    return sorted(indices)


def _require_target_or_config(opts, config_path):
    """Fail before any request when no target and no config file are supplied.

    Mirrors the ``full`` command guard (Requirement 1.5): a Module_Subcommand or
    the Orchestrator_Command invoked without a target and without a ``--config``
    file runs no OWASP module, writes an error to standard error, and exits with
    a nonzero status before any request is issued.

    The requirement is satisfied by the target-resolution precedence
    command-line option -> Environment_Override -> config file: a ``--target``
    option, a ``--target-file`` file, a non-empty ``APILEAK_TARGET``
    Environment_Override, or a ``--config`` file each supply the target, so only
    the complete absence of all four aborts the run (Requirements 1.5, 10.2–10.4).
    """
    if config_path:
        return
    if opts.get("target"):
        return
    if opts.get("target_file"):
        return
    # Environment_Override: a non-empty APILEAK_TARGET satisfies the target
    # requirement when no --target option is supplied (Requirements 10.2, 10.3).
    if os.getenv("APILEAK_TARGET"):
        return
    click.echo(
        "Error: --target or --target-file is required when no config file is provided",
        err=True,
    )
    sys.exit(1)


def _parse_custom_headers(header):
    """Parse repeatable ``Name: Value`` header options into a dict.

    Exits with an error on a malformed header, matching prior CLI behavior.
    """
    custom_headers = {}
    for h in header:
        if ":" not in h:
            click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
            sys.exit(1)
        name, value = h.split(":", 1)
        custom_headers[name.strip()] = value.strip()
    return custom_headers


def _count_by_severity(findings):
    """Count findings by severity name for the CI severity gate.

    Args:
        findings: Iterable of Finding objects.

    Returns:
        A mapping of ``{"critical": int, "high": int, "medium": int, "low": int}``.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = getattr(finding, "severity", None)
        name = getattr(severity, "value", severity)
        if isinstance(name, str):
            name = name.lower()
        if name in counts:
            counts[name] += 1
    return counts
