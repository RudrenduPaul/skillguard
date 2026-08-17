"""
Subprocess-based MCP server that wraps the *Node/TypeScript* SkillGuard CLI
(`skillguard-cli`, built from ../../src/cli.ts) rather than this Python
package's own native scan engine.

This is deliberately a SECOND, separate MCP server from
`skillguard/mcp_server.py`. That module already exposes a `scan_skill` MCP
tool backed directly by this package's own native `scan_skill()` -- no
subprocess involved at all, which is architecturally better for production
use (no process-spawn cost, no stdout/JSON parsing surface, no dependency on
Node being installed). This module exists to satisfy a specific ask: a
thin wrapper that shells out to the *Node* CLI binary, e.g. to validate that
the Node and Python implementations agree, or in a context where the Node
CLI is the source of truth and only Node is installed.

Command resolution (env var controlled, mirroring the pattern used for
other repos in this batch):
  - If SKILLGUARD_NODE_CLI_PATH is set, run `node <that path> <args>`. This
    is for local/dev testing against a freshly built `dist/cli.js` before
    it is published.
  - Otherwise, default to `npx skillguard-cli <args>` (the real published
    npm package name -- note the base name "skillguard" is NOT the
    published package; `package.json` publishes as "skillguard-cli" with a
    "skillguard-cli" bin entry, not a "skillguard" bin entry).

Optional dependency: reuses this package's existing `mcp` extra
(`pip install "skillguard-cli[mcp]"`), which already pins `mcp>=1.28,<2` --
see skillguard/mcp_server.py's docstring for the same rationale. The import
of `mcp.server.fastmcp` is deferred to create_server() so importing this
module never requires `mcp` to be installed.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_FALLBACK_DESCRIPTION = (
    "Runs the SkillGuard Node CLI (skillguard-cli) as a subprocess with the given "
    "argument list and returns its parsed JSON output as a dict. Pass args like "
    '["scan", "<path-to-skill-dir>", "--format", "json"] to scan a single skill, or '
    '["scan-set", "<dir>", "--format", "json"] to scan a directory of skills for '
    "cross-skill privilege chaining. Always include --format json so the output is "
    "machine-parseable -- human/sarif output will not parse as JSON and this tool "
    "will return a structured error dict instead of raising."
)


def _resolve_base_command() -> List[str]:
    """
    SKILLGUARD_NODE_CLI_PATH switches this wrapper from the production
    default (`npx skillguard-cli`) to a local build (`node <path>`), e.g.
    SKILLGUARD_NODE_CLI_PATH=/path/to/skillguard/dist/cli.js for testing
    against a freshly built dist/ before it is published.
    """
    local_path = os.environ.get("SKILLGUARD_NODE_CLI_PATH")
    if local_path:
        return ["node", local_path]
    return ["npx", "skillguard-cli"]


def _build_description() -> str:
    """
    Built at server-start time from a real `--help` subprocess call so the
    tool description an agent sees always reflects the actual installed
    CLI's real flags/subcommands, not a hand-maintained copy that can drift.
    Falls back to a safe static description if the subprocess call fails
    for any reason (Node/npx not on PATH, CLI not built yet, timeout, ...).
    """
    try:
        cmd = _resolve_base_command() + ["--help"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        help_text = (proc.stdout or "").strip()
        if not help_text:
            return _FALLBACK_DESCRIPTION
        return (
            "Runs the SkillGuard Node CLI (skillguard-cli) as a subprocess with the "
            "given argument list and returns its parsed JSON output as a dict. Always "
            "include --format json. Real `skillguard-cli --help` output:\n\n" + help_text
        )
    except Exception:
        return _FALLBACK_DESCRIPTION


def create_server() -> "FastMCP":
    """
    Builds the MCP server and registers the `run` tool. Exported separately
    from main() so tests can exercise tool calls without spawning a server
    process, matching the pattern in skillguard/mcp_server.py.

    Raises ImportError if the optional `mcp` package is not installed.
    """
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("skillguard-node-cli")
    description = _build_description()

    @server.tool(name="run", description=description)
    def run(args: List[str]) -> dict:
        # Top-level guard: this handler must never raise -- any failure
        # (bad args, missing binary, non-JSON output, timeout) is reported
        # back as a structured {"error": ...} dict instead of an exception
        # escaping into the MCP transport.
        try:
            cmd = _resolve_base_command() + list(args)

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except Exception as exc:  # noqa: BLE001 -- subprocess launch failure
                return {
                    "error": f"failed to execute skillguard CLI: {exc}",
                    "command": cmd,
                }

            # Exit code contract (matches src/cli.ts / skillguard/cli.py):
            # 0 = clean scan, 1 = findings at/above severity threshold --
            # both are a *successful* invocation with valid JSON on stdout.
            # Anything else (2 = bad CLI input/target, or an uncaught
            # crash) is an unexpected status worth surfacing distinctly.
            if proc.returncode not in (0, 1):
                return {
                    "error": "skillguard CLI exited with an unexpected status.",
                    "returncode": proc.returncode,
                    "command": cmd,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                }

            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                return {
                    "error": f"failed to parse skillguard CLI output as JSON: {exc}",
                    "returncode": proc.returncode,
                    "command": cmd,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                }
        except Exception as exc:  # noqa: BLE001 -- absolute last-resort guard
            return {"error": f"unexpected error running skillguard CLI tool: {exc}"}

    return server


def main() -> None:
    """
    Starts the MCP server on stdio and blocks until the client disconnects.
    stdout is reserved for the JSON-RPC stdio transport -- this module never
    calls print(); any diagnostics would go to stderr.
    """
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
