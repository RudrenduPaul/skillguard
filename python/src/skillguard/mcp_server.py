"""
Agent-native MCP entry point, run via `skillguard mcp` (see skillguard/cli.py).
Python counterpart of src/mcp/server.ts -- see that module's docstring for
the full rationale; this port keeps the same tool name, the same
scanSkill()-only data path, and the same security guarantees, adapted to
Python's snake_case option naming (severity_threshold, timeout_ms) to match
this package's own ScanOptions/CLI flag convention rather than the
TypeScript package's camelCase.

This exposes the exact same `scan_skill()` used by `skillguard scan` as a
single MCP tool, `scan_skill`, so another agent (Claude Code, Cursor, an
orchestrator, ...) can call SkillGuard directly as a tool instead of
shelling out to the CLI binary and parsing stdout.

Optional dependency: the `mcp` package (official Python MCP SDK) is NOT a
hard dependency of `skillguard-cli` -- it requires Python >=3.10, while the
base package supports >=3.9, and most installs never use MCP mode at all.
Install it via the `mcp` extra: `pip install "skillguard-cli[mcp]"`. The
import is deferred to create_server() (not module level) so importing this
module, or importing `skillguard` itself, never requires `mcp` to be
installed -- only actually starting the server does.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .errors import format_what_why_fix
from .output.formatters import format_json
from .scan.index import scan_skill
from .types import ScanOptions, Severity

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_SEVERITIES = ["HIGH", "MEDIUM", "LOW"]
_DEFAULT_TIMEOUT_MS = 10_000


def _parse_severity(value: Optional[str]) -> Severity:
    if value is None:
        return "HIGH"
    upper = value.upper()
    if upper not in _SEVERITIES:
        raise ValueError(
            format_what_why_fix(
                f'Invalid severity_threshold value "{value}".',
                f"severity_threshold must be one of {', '.join(_SEVERITIES)}.",
                f'Pass one of: {", ".join(_SEVERITIES)}, e.g. severity_threshold="MEDIUM"',
            )
        )
    return upper  # type: ignore[return-value]


def _parse_timeout(value: Optional[int]) -> int:
    if value is None:
        return _DEFAULT_TIMEOUT_MS
    if value <= 0:
        raise ValueError(
            format_what_why_fix(
                f'Invalid timeout_ms value "{value}".',
                "timeout_ms must be a positive number of milliseconds.",
                "Pass a positive number, e.g. timeout_ms=10000 for a 10-second per-file timeout.",
            )
        )
    return value


def create_server() -> "FastMCP":
    """
    Builds the MCP server and registers the scan_skill tool. Exported
    separately from run_mcp_server() so tests can exercise tool calls
    in-process (via mcp.shared.memory.create_connected_server_and_client_session)
    without spawning a child process.

    Raises ImportError if the optional `mcp` package is not installed --
    callers (skillguard/cli.py) turn that into a WHAT/WHY/FIX message
    pointing at `pip install "skillguard-cli[mcp]"`.
    """
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("skillguard")

    @server.tool(
        name="scan_skill",
        description=(
            "Scans a third-party AI agent-skill directory (a SKILL.md manifest plus its "
            "bundled hooks/scripts) for known attack patterns before that skill is "
            "installed or executed: remote-code-execution hooks (SG02), file-scope "
            "escalation (SG03), supply-chain-risky install hooks (SG04), obfuscated "
            "payloads (SG05), credential harvesting (SG06), frontmatter spoofing (SG07), "
            "prompt injection in the skill's own instructional text (SG08), and "
            "marketplace typosquatting (SG10). Call this before installing or running any "
            "agent skill you did not author yourself -- the same way you would not execute "
            "an unreviewed shell script from a stranger; it has nothing useful to do on "
            "skills you already trust.\n\n"
            "This is a read-only, offline, side-effect-free operation: every rule pack "
            "ships inside the installed wheel, so no network call happens at scan time, "
            "and the target's own files are only ever read and pattern-matched, never "
            "eval()'d, exec()'d, or imported. Re-running it on an unchanged target is "
            "idempotent. Two suppression mechanisms exist in the underlying CLI "
            "(.skillguardignore and inline \"# skillguard-ignore: SGxx\" comments) but "
            "this tool never honors either, even if the target ships its own "
            ".skillguardignore -- every call runs at full strictness since the target is "
            "by definition untrusted. One coverage gap: SG09 (cross-skill privilege "
            "chaining across a set of skills) only runs through the separate "
            "scan_skill_set()/scan-set CLI path, not through this single-directory tool. "
            "An invalid path or unreadable target raises an error rather than returning a "
            "silently-clean result.\n\n"
            "Parameters: path (string, required) is the filesystem path to the skill "
            "directory to scan, e.g. \"/skills/pdf-tools\" containing SKILL.md plus its "
            "hooks/. severity_threshold (string, optional, one of HIGH/MEDIUM/LOW, "
            "default HIGH) is the minimum finding severity that flips the result's exit "
            "code to non-zero -- lower it to MEDIUM or LOW for a stricter review. "
            "timeout_ms (integer, optional, default 10000) caps the per-file scan time in "
            "milliseconds; files that exceed it land in the result's timeouts list "
            "instead of failing the whole scan. Example calls: "
            '{"path": "/skills/pdf-tools"} for a default HIGH-severity scan; '
            '{"path": "/skills/pdf-tools", "severity_threshold": "LOW"} to surface every '
            'finding; {"path": "/skills/pdf-tools", "timeout_ms": 30000} for a larger '
            "skill that needs more per-file time.\n\n"
            "Returns a JSON string with: target (the scanned path), filesScanned, "
            "severityThreshold, exitCode (0 = clean, 1 = a finding at/above threshold "
            "was found, 2 = target/config error), summary (finding counts by severity), "
            "findings (a list of {ruleId, category, severity, message, file, line, "
            "snippet?}), timeouts (files that hit the per-file limit), unscannedFiles "
            "(recognized-but-unsupported-language files), and warnings ({code, message} "
            "entries, e.g. for an invalid rule pack). A non-zero exitCode means the skill "
            "tripped a finding at or above the configured threshold and should not be "
            "trusted without human review."
        ),
    )
    def scan_skill_tool(
        path: str,
        severity_threshold: Optional[str] = None,
        timeout_ms: Optional[int] = None,
    ) -> str:
        severity = _parse_severity(severity_threshold)
        timeout = _parse_timeout(timeout_ms)

        # SECURITY: ignore_file_path and allow_inline_suppression are
        # deliberately never passed here -- see the module-level docstring
        # above and the SECURITY comments in skillguard/scan/index.py. A
        # calling agent has no way to make this tool honor a
        # .skillguardignore file or inline suppression comments; both stay
        # at scan_skill()'s safest default.
        result = scan_skill(
            path,
            ScanOptions(severity_threshold=severity, timeout_ms=timeout),
        )
        return format_json(result)

    return server


def run_mcp_server() -> None:
    """
    Starts the MCP server on stdio and blocks until the client disconnects.
    `FastMCP.run()` is itself a blocking call (it wraps its own event loop),
    so by the time this function returns, the server has already finished
    serving -- unlike a naive "connect and return immediately" wiring, there
    is no risk of the caller (skillguard/cli.py's `main()`) exiting the
    process out from under a server that has barely started.
    """
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    run_mcp_server()
