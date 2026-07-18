# MCP (agent-native) integration

CI integrations (see [ci.md](ci.md)) gate a scan on a human's pipeline. This
is the other half: letting an *agent* -- Claude Code, Cursor, an
orchestrator, or any MCP-speaking client -- call SkillGuard directly as a
tool call, before it installs or runs a third-party agent skill, without
shelling out to the CLI binary and parsing stdout.

## Why this matters

Agent frameworks are starting to let one agent install or fetch skills for
another agent to run -- a marketplace, an orchestrator pulling in a
sub-agent's toolset, a plugin registry. None of that has a scan step wired
in by default: an agent that fetches a `SKILL.md` plus its hooks has no
built-in way to ask "is this safe?" before executing it. `skillguard-cli mcp`
closes that gap by exposing the same `scanSkill()` pipeline the CLI and
GitHub Action already use as a single MCP tool, `scan_skill`, so an agent's
own tool-use loop can call it the same way it calls any other tool -- no
subprocess, no stdout parsing, no separate install step for the calling
agent.

Both distributions ship this: the npm CLI's tool input is
`{ path, severityThreshold?, timeoutMs? }` (camelCase, matching that
package's own `ScanOptions` naming); the Python CLI's is
`{ path, severity_threshold?, timeout_ms? }` (snake_case, matching *its*
own `ScanOptions` naming). Both wrap the identical `scan_skill`/`scanSkill`
pipeline and return the identical JSON `ScanResult` shape either CLI's
`--format json` produces.

## Starting the server

npm CLI:

```bash
npx skillguard-cli mcp
```

Python CLI (requires the optional `mcp` extra, Python >=3.10 -- see
[Python setup](#python-setup) below):

```bash
skillguard mcp
```

Either way, this starts a stdio-transport MCP server and blocks, serving
tool calls over stdin/stdout until the client disconnects. There is nothing
to configure -- no port, no auth -- the server only exposes the one
`scan_skill` tool.

## Python setup

The Python distribution's `mcp` mode is an optional extra, not part of the
base install -- the official `mcp` Python SDK requires Python >=3.10, while
`skillguard-cli` itself supports >=3.9, and most installs never use MCP
mode:

```bash
pip install "skillguard-cli[mcp]"
```

Running `skillguard mcp` without the extra installed fails with a
WHAT/WHY/FIX message pointing at the command above, rather than a bare
`ModuleNotFoundError` traceback.

## Client setup

### Claude Code

Add to your MCP server config (`.mcp.json`, or via `claude mcp add`):

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "npx",
      "args": ["skillguard-cli", "mcp"]
    }
  }
}
```

Or, for the Python distribution:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "skillguard",
      "args": ["mcp"]
    }
  }
}
```

### Generic MCP client

Any client that launches an MCP server as a stdio subprocess uses the same
shape:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "npx",
      "args": ["skillguard-cli", "mcp"]
    }
  }
}
```

If SkillGuard is already installed as a project dependency rather than run
via `npx`, point `command`/`args` at the installed binary directly (e.g.
`"command": "skillguard-cli", "args": ["mcp"]`, or
`"command": "node", "args": ["node_modules/.bin/skillguard-cli", "mcp"]`).

## The `scan_skill` tool

| Field (npm) | Field (Python) | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `path` | `path` | string | yes | Filesystem path to the skill directory to scan (a directory containing a `SKILL.md` manifest plus any hooks/scripts). |
| `severityThreshold` | `severity_threshold` | string | no | Minimum severity that fails the scan: `HIGH`, `MEDIUM`, or `LOW`. Defaults to `HIGH`, same as either CLI's `--severity-threshold`. |
| `timeoutMs` | `timeout_ms` | number | no | Per-file scan timeout in milliseconds. Defaults to `10000`, same as either CLI's `--timeout`. |

The tool returns the same structured `ScanResult` the CLI's `--format json`
output produces (`target`, `filesScanned`, `severityThreshold`, `exitCode`,
`summary`, `findings`, `timeouts`, `unscannedFiles`, `warnings`) as a single
JSON text content block, so a calling agent can parse it exactly the way it
would parse `skillguard-cli scan <path> --format json` output.

Example call and response shape:

```jsonc
// tool call
{ "name": "scan_skill", "arguments": { "path": "./some-downloaded-skill" } }

// tool result (content[0].text, parsed)
{
  "target": "/abs/path/to/some-downloaded-skill",
  "filesScanned": 5,
  "severityThreshold": "HIGH",
  "exitCode": 1,
  "summary": { "HIGH": 5, "MEDIUM": 5, "LOW": 1 },
  "findings": [
    {
      "ruleId": "sg04-postinstall-remote-fetch",
      "category": "SG04",
      "severity": "HIGH",
      "message": "A postinstall/preinstall hook downloads and executes a remote script...",
      "file": "hooks/postinstall.js",
      "line": 5
    }
  ],
  "timeouts": [],
  "unscannedFiles": [],
  "warnings": []
}
```

An `exitCode` of `1` means a finding at or above the configured severity
threshold was found -- treat that the same way you'd treat a failing CI
gate: do not install or run the skill without human review. `isError: true`
on the MCP response itself (distinct from `exitCode` in the returned JSON)
is reserved for a call that could not be validated at all -- an invalid
`severityThreshold`/`timeoutMs` argument. It is *not* set just because the
scan itself found something, or even because the target path didn't exist:
a missing target still returns a normal (`isError: false`) tool result
whose JSON body reports `exitCode: 2` -- `scan_skill()`/`scanSkill()` never
throws for a missing target, it always returns a structured `ScanResult`,
and the MCP layer passes that through unchanged. (The npm SDK path
additionally sets `isError: true` on that `exitCode: 2` case as a
convenience for the calling agent, since raising there costs nothing extra
in TypeScript; the Python path does not add this, since its own convention
is `isError` maps to protocol/argument failures only. Either way, always
check the JSON body's `exitCode`, not just `isError`, for the authoritative
scan verdict.)

## Security

The MCP tool calls `scanSkill()`/`scan_skill()` directly -- the exact same
function the CLI and library entry point use -- with no shortcut around it.
In particular:

- **No `.skillguardignore` exposure.** The tool's input schema only accepts
  `path`, `severityThreshold`/`severity_threshold`, and
  `timeoutMs`/`timeout_ms`. There is no way for a caller to pass an
  ignore-file path through this tool, so every MCP-triggered scan runs with
  zero path suppressions, same as calling the library function with no
  `ignoreFilePath`/`ignore_file_path` option set.
- **No inline-suppression opt-in.** `allowInlineSuppression`/
  `allow_inline_suppression` is never passed either, so
  `# skillguard-ignore: SGxx` comments inside the scanned skill's own files
  are never honored via this path. This matters specifically *because* the
  scan target is untrusted third-party content: a malicious skill cannot
  silence its own findings just because an agent is scanning it through MCP
  instead of the CLI.
- **A bad call doesn't take down the server.** Unlike the one-shot CLI
  (where invalid input exits the process), the MCP server is long-running --
  invalid `severityThreshold`/`timeoutMs` on one tool call returns a
  structured `isError: true` result for that call only, and the server keeps
  serving subsequent calls.

See the SECURITY comment in `src/scan/index.ts` (TypeScript) or
`skillguard/scan/index.py` (Python) for the full rationale behind both
defaults.

## Testing it yourself

```bash
git clone https://github.com/RudrenduPaul/skillguard.git
cd skillguard && npm install && npm run build
npx skillguard-cli mcp
```

Then point any MCP inspector or client at
`{ "command": "node", "args": ["dist/cli.js", "mcp"] }` from the repo root,
call `scan_skill` with `{ "path": "examples/known-bad-skill" }`, and expect
`exitCode: 1` with findings across multiple categories -- the same fixture
`docs/integrations/ci.md` and the README's own benchmark section use.

Python distribution:

```bash
cd python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"
skillguard mcp
```

Point an MCP inspector or client at `{ "command": "skillguard", "args":
["mcp"] }`, call `scan_skill` with
`{ "path": "../examples/known-bad-skill" }`, and expect the same
`exitCode: 1` result.
