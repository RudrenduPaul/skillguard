#!/usr/bin/env python3
"""
Thin argument-parsing wrapper over skillguard.scan.index (see that module
for the full data-flow diagram). This module owns: flag parsing, the
WHAT/WHY/FIX error surface for bad CLI input, and the process exit-code
contract. Console entry point: `skillguard scan <path> [options]`, installed
via the `skillguard` console-script defined in python/pyproject.toml.

Ported from src/cli.ts (which uses `commander`); this port uses the stdlib
`argparse` to avoid a CLI-framework dependency. Flags, defaults, and the
WHAT/WHY/FIX validation messages are kept identical to the npm CLI's
`--help` output and error text.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, NoReturn

from .errors import format_what_why_fix
from .output.formatters import format_result, format_set_result
from .scan.index import scan_skill
from .scan.skill_set import scan_skill_set
from .types import ScanOptions

_SEVERITIES = ["HIGH", "MEDIUM", "LOW"]
_FORMATS = ["human", "json", "sarif"]
_VERSION = "0.2.0"


def _fail(what: str, why: str, fix: str) -> NoReturn:
    sys.stderr.write(format_what_why_fix(what, why, fix) + "\n")
    sys.exit(2)


def _parse_severity(value: str) -> str:
    upper = value.upper()
    if upper not in _SEVERITIES:
        _fail(
            f'Invalid --severity-threshold value "{value}".',
            f"--severity-threshold must be one of {', '.join(_SEVERITIES)}.",
            f"Pass one of: {', '.join(_SEVERITIES)}, e.g. --severity-threshold MEDIUM",
        )
    return upper


def _parse_format(value: str) -> str:
    if value not in _FORMATS:
        _fail(
            f'Invalid --format value "{value}".',
            f"--format must be one of {', '.join(_FORMATS)}.",
            f"Pass one of: {', '.join(_FORMATS)}, e.g. --format sarif",
        )
    return value


def _parse_timeout(value: str) -> int:
    try:
        ms = float(value)
    except ValueError:
        ms = float("nan")
    if ms != ms or ms <= 0:  # ms != ms is the portable NaN check
        _fail(
            f'Invalid --timeout value "{value}".',
            "--timeout must be a positive number of milliseconds.",
            "Pass a positive number, e.g. --timeout 10000 for a 10-second per-file timeout.",
        )
    return int(ms)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description=(
            "Security scanner for third-party AI agent-skill files: SKILL.md "
            "manifests, hooks, and bundled scripts."
        ),
    )
    parser.add_argument("--version", action="version", version=f"skillguard-cli {_VERSION}")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a skill directory for known attack patterns")
    scan_parser.add_argument("path", help="path to the skill directory to scan")
    scan_parser.add_argument(
        "-f", "--format", default="human", help="output format: human, json, or sarif"
    )
    scan_parser.add_argument(
        "-s",
        "--severity-threshold",
        default="HIGH",
        help="minimum severity that fails the scan (HIGH, MEDIUM, or LOW)",
    )
    scan_parser.add_argument(
        "-t", "--timeout", default="10000", help="per-file scan timeout in milliseconds"
    )
    scan_parser.add_argument(
        "--skillguardignore",
        default=None,
        help=(
            "path to a .skillguardignore file (must be explicit -- never "
            "auto-loaded from inside the scan target, for security)"
        ),
    )
    scan_parser.add_argument(
        "--allow-inline-suppression",
        action="store_true",
        default=False,
        help=(
            'honor "# skillguard-ignore: SGxx" comments found inside the scanned '
            "files themselves. Off by default -- only enable this for a target you "
            "already trust, e.g. self-scanning your own skill before publishing."
        ),
    )

    subparsers.add_parser(
        "mcp",
        help=(
            "Start SkillGuard as an MCP (Model Context Protocol) server on stdio, exposing "
            "a scan_skill tool so another agent can call SkillGuard directly instead of "
            "shelling out to this CLI. Requires the optional `mcp` extra -- see "
            "docs/integrations/mcp.md."
        ),
    )

    scan_set_parser = subparsers.add_parser(
        "scan-set",
        help=(
            "Scan a directory of skill subdirectories for cross-skill privilege "
            "chaining (SG09), in addition to each skill's own findings"
        ),
    )
    scan_set_parser.add_argument(
        "dir",
        help="path to a directory whose immediate children are each a skill directory (SKILL.md plus hooks/scripts)",
    )
    scan_set_parser.add_argument(
        "-f", "--format", default="human", help="output format: human, json, or sarif"
    )
    scan_set_parser.add_argument(
        "-s",
        "--severity-threshold",
        default="HIGH",
        help="minimum severity that fails the scan (HIGH, MEDIUM, or LOW)",
    )
    scan_set_parser.add_argument(
        "-t", "--timeout", default="10000", help="per-file scan timeout in milliseconds"
    )
    scan_set_parser.add_argument(
        "--skillguardignore",
        default=None,
        help=(
            "path to a .skillguardignore file, applied to every skill in the set "
            "(must be explicit -- never auto-loaded from inside any scan target, "
            "for security)"
        ),
    )
    scan_set_parser.add_argument(
        "--allow-inline-suppression",
        action="store_true",
        default=False,
        help=(
            'honor "# skillguard-ignore: SGxx" comments found inside the scanned '
            "files themselves, for every skill in the set. Off by default -- only "
            "enable this for a set you already trust."
        ),
    )

    return parser


def run_cli(argv: List[str]) -> int:
    """
    `argv` follows the sys.argv convention: argv[0] is the program name,
    the real arguments start at argv[1]. Returns the process exit code
    (0 clean / 1 findings at/above threshold / 2 target/config error);
    invalid CLI input calls sys.exit(2) directly via _fail(), matching the
    documented exit-code contract.
    """
    parser = build_parser()
    args = parser.parse_args(argv[1:])

    if args.command == "mcp":
        from .mcp_server import run_mcp_server

        try:
            run_mcp_server()
        except ImportError as err:
            _fail(
                "`skillguard mcp` requires the optional `mcp` dependency, which is not installed.",
                str(err),
                'Install it with: pip install "skillguard-cli[mcp]" (requires Python >=3.10), '
                "then rerun `skillguard mcp`.",
            )
        return 0

    if args.command not in ("scan", "scan-set"):
        parser.print_help()
        return 0

    fmt = _parse_format(args.format)
    severity_threshold = _parse_severity(args.severity_threshold)
    timeout_ms = _parse_timeout(args.timeout)

    if fmt != "json":
        # First-run friction fix: the pattern engine is bundled, but scans
        # of a new target can still take a moment on a large directory --
        # tell the user SkillGuard is working, not hung.
        sys.stderr.write("Loading SkillGuard rule packs...\n")

    options = ScanOptions(
        severity_threshold=severity_threshold,
        timeout_ms=timeout_ms,
        ignore_file_path=args.skillguardignore,
        allow_inline_suppression=bool(args.allow_inline_suppression),
    )

    if args.command == "scan-set":
        set_result = scan_skill_set(args.dir, options)
        sys.stdout.write(format_set_result(set_result, fmt) + "\n")
        return set_result.exit_code

    result = scan_skill(args.path, options)
    sys.stdout.write(format_result(result, fmt) + "\n")
    return result.exit_code


def main() -> None:
    try:
        code = run_cli(sys.argv)
    except SystemExit:
        raise
    except Exception as err:  # noqa: BLE001 -- top-level crash guard, mirrors src/cli.ts's catch-all
        sys.stderr.write(
            format_what_why_fix(
                "skillguard-cli crashed unexpectedly.",
                str(err),
                "Please open an issue at https://github.com/RudrenduPaul/skillguard/issues "
                "with the command you ran.",
            )
            + "\n"
        )
        sys.exit(2)
    else:
        sys.exit(code)


if __name__ == "__main__":
    main()
