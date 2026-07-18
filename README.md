# SkillGuard

[![npm version](https://img.shields.io/npm/v/skillguard-cli.svg)](https://www.npmjs.com/package/skillguard-cli)
[![PyPI version](https://img.shields.io/pypi/v/skillguard-cli.svg)](https://pypi.org/project/skillguard-cli/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-59%2F59%20passing-brightgreen.svg)](./CHANGELOG.md)

36% of published agent skills have exploitable flaws per Snyk. SkillGuard scans SKILL.md, hooks, and scripts for known attack patterns before they run, and gates your CI on the result.

Third-party AI agent-skill files (`SKILL.md` manifests, hooks, and bundled
scripts) run with real tool, file, and network permissions the moment
they're installed. Most marketplaces and frameworks have no scan step
between "someone published a skill" and "a user's agent runs it." SkillGuard
is that scan step: a CLI, a library, and a GitHub Action, all reading the
same seven bundled rule packs.

## Try it now

```bash
npx skillguard-cli scan ./examples/known-bad-skill
```

This runs against a fixture bundled with the repo, safe, non-functional,
and deliberately pattern-matchable, and returns real findings with
file:line citations. Every scan prints a "Loading SkillGuard rule packs..."
message to stderr before it starts; that's expected, not a hang.

Compare it against a clean fixture:

```bash
npx skillguard-cli scan ./examples/clean-skill
```

which returns zero findings and exit code 0.

## Benchmarks

Every number below is something we actually ran, with the command shown
next to it, so you can reproduce it yourself: no extrapolation, no
rounding in SkillGuard's favor.

**Time to first scan** (fresh clone, `npm install`, build, first scan against
the bundled fixture), timed on 2026-07-13 against `build/v0.1`:

```bash
git clone --branch build/v0.1 https://github.com/RudrenduPaul/skillguard.git
cd skillguard && npm install && npm run build
node dist/cli.js scan ./examples/known-bad-skill
```

| Stage | Time |
| --- | --- |
| `git clone` | 0.9s |
| `npm install` | 1.3s |
| `npm run build` | 1.0s |
| first scan | 0.2s |
| **Total** | **~3.3s** |

This is a single real, timestamped run on a warm local npm cache and a
fast network connection, no averaging across multiple runs. Treat it as
a lower bound: a cold cache or a slower connection will push the total
higher. `npx skillguard-cli` (once published) adds npm's own
resolve-and-download time on top of the "first scan" row above.

**Known-bad fixture**, `node dist/cli.js scan ./examples/known-bad-skill`:
11 findings (5 HIGH, 5 MEDIUM, 1 LOW) spanning all 7 rule categories
(SG01 through SG07), across the fixture's 5 hook/script files, exit code 1,
wall time 0.155s. This number was re-verified after a change to default
suppression behavior; the finding count and severity split are unchanged
from before that fix.

**Clean fixtures**, `node dist/cli.js scan ./examples/clean-skill` and
`node dist/cli.js scan ./examples/clean-skill-python`: 0 findings, exit
code 0, on both. This confirms the rule packs stay quiet on two
intentionally well-behaved skills. Treat it as a 2-fixture sanity check:
SkillGuard hasn't been run against a large corpus of real-world skills
yet, so this isn't a general
"0% false positive rate" claim.

**Test suite**: 59/59 passing (`npm test`), including a real, non-mocked
wall-clock regression test for the per-file ReDoS timeout.

**Rule coverage**: 7 first-party categories (SG01 through SG07), documented
rule-by-rule in [CHANGELOG.md](./CHANGELOG.md).

## How SkillGuard compares

SkillGuard is purpose-built for the agent-skill threat model: frontmatter
declared scope versus actual behavior, hook-level supply-chain risk, and
credential-harvesting patterns specific to how skills are packaged and
installed. That is a narrower job than a general-purpose scanner, and this
table says so plainly rather than implying SkillGuard beats tools built for
a different job.

| | SkillGuard | Snyk Agent Scan | Semgrep (CE) | Socket CLI | Snyk (Open Source/Code) |
| --- | --- | --- | --- | --- | --- |
| What it scans | Agent-skill files: SKILL.md, hooks, scripts | Agent skills and MCP server configs | General source code, 30+ languages | npm/PyPI/etc. package installs | Manifest-declared dependencies, source code |
| Agent-skill-specific ruleset | Yes, all 7 categories purpose-built for this threat model | Yes, its whole focus (prompt injection, tool poisoning, toxic flows, skill malware) | No, general SAST rules only | No, supply-chain focused, not skill-file focused | No, general SCA/SAST |
| Auth required for a basic scan | None (`npx skillguard-cli scan <path>`) | Yes, requires a Snyk account and `SNYK_TOKEN` before any scan | None for Community Edition local scans | Yes, `SOCKET_CLI_API_TOKEN` needed for full functionality | Yes, `snyk auth` required |
| Runtime | Node.js, zero external binary | Python via `uvx` | Own binary (Python-based CLI) | Node.js | Own CLI |
| License | Apache 2.0 | Apache 2.0 | LGPL-2.1 | MIT | Proprietary CLI, free tier |
| Maturity (GitHub stars, checked 2026-07-13) | New (v0.1.0, pre-launch) | 2.8k stars, 246 forks, 100+ releases | 15.9k stars | 295 stars | not a single OSS repo; commercial product |

Sources for the comparison rows above: [semgrep/semgrep](https://github.com/semgrep/semgrep)
and [Semgrep CLI docs](https://docs.semgrep.dev/getting-started/cli) (languages,
license, no-auth local scans); [SocketDev/socket-cli](https://github.com/SocketDev/socket-cli)
(license, token requirement); [snyk/agent-scan](https://github.com/snyk/agent-scan)
(scope, auth requirement, stars); [Snyk CLI docs](https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli-for-open-source)
(what Snyk Open Source scans).

A few honest notes, since a security tool's credibility depends on saying
the unflattering parts out loud:

- **Snyk Agent Scan is the closest real competitor.** It scans the same
  kind of target (agent skills, plus MCP servers, which SkillGuard does not
  cover) and detects more categories overall (15+ versus SkillGuard's 7).
  It is also more mature: 2.8k stars versus SkillGuard's pre-launch v0.1.0.
  The real difference is the install and auth story: Snyk Agent Scan needs
  a Snyk account, an API token, and a Python/`uv` toolchain before it
  scans anything, where `npx skillguard-cli scan <path>` runs with zero
  signup, zero token, and zero non-Node runtime dependency. If you already
  have a Snyk account and want MCP-server coverage too, Agent Scan covers
  more ground. If you want a zero-auth, zero-config check to drop into an
  existing Node-based CI pipeline, that is what SkillGuard is for.
- **SkillGuard does not wrap Semgrep.** An earlier design pass planned to
  invoke Semgrep as the underlying engine, but no official npm-native
  Semgrep package exists to bundle, and depending on the Python/PyPI
  distribution would have broken the zero-config `npx` install this tool
  is built around. `src/scan/semgrep-runner.ts` documents this deviation
  directly in the source: SkillGuard ships its own small, in-process
  pattern engine that consumes the same rule-pack shape (a manifest plus a
  rules file), Semgrep-inspired but not Semgrep. If you need true
  multi-language, general-purpose static analysis with a mature rule
  ecosystem across 30+ languages, Semgrep is the better and more
  battle-tested tool for that job; SkillGuard is not trying to replace it.
- **Socket CLI is the closest adjacent category, not a direct competitor.**
  It is excellent at what it does (typosquats, malicious install scripts,
  suspicious package behavior across npm/PyPI/etc.) but it scans installed
  *packages*, not the shape of a skill's own SKILL.md frontmatter, hooks,
  and declared-versus-actual behavior that SkillGuard targets.
- **Snyk itself is the category leader for dependency and code
  vulnerabilities generally**, with broad language support and an
  established enterprise track record neither SkillGuard nor Snyk Agent
  Scan can claim yet. It has no skill-file-specific ruleset of its own;
  that gap is exactly what Snyk's own team built Agent Scan to cover.

## Install

SkillGuard ships two independent, equally first-class packages -- pick
whichever fits your toolchain, or install both. Neither is deprecated in
favor of the other; they read the same seven bundled rule packs and produce
the same findings against the same target.

```bash
# npm -- JavaScript/TypeScript CLI + library
npm install --save-dev skillguard-cli

# PyPI -- Python CLI + library (genuine port, not a wrapper around the Node binary)
pip install skillguard-cli
```

No separate install step, no external binary to fetch either way:
SkillGuard's seven rule packs and pattern-matching engine ship inside the
npm package and the Python wheel alike. The Python package's CLI entry
point is `skillguard` (e.g. `skillguard scan ./my-skill`); see
[`python/README.md`](./python/README.md) and
[docs/getting-started.md](./docs/getting-started.md) for the Python-specific
walkthrough, and [CHANGELOG.md](./CHANGELOG.md) for each distribution's
version history.

## CLI usage

```bash
npx skillguard-cli scan <path> [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--format <human\|json\|sarif>` | `human` | Output format. |
| `--severity-threshold <HIGH\|MEDIUM\|LOW>` | `HIGH` | Minimum severity that fails the scan (exit code 1). |
| `--timeout <ms>` | `10000` | Per-file scan timeout in milliseconds. |
| `--skillguardignore <path>` | none, must be passed explicitly | Path to a suppression file. Never auto-loaded from inside the scan target, see [Suppressing findings](#suppressing-findings). |
| `--allow-inline-suppression` | `false` | Honor inline `# skillguard-ignore: SGxx` comments found inside the scanned files. Off by default, see below. |

**Exit codes**: `0`, clean scan. `1`, a finding at or above the severity
threshold. `2`, the target path doesn't exist or no skill files were found.

## Library usage (agent-native)

```ts
import { scanSkill } from 'skillguard-cli';

const result = await scanSkill('./my-skill', { severityThreshold: 'HIGH' });

if (result.exitCode === 1) {
  console.log(`${result.findings.length} finding(s) at or above HIGH`);
}
```

`scanSkill()` runs the same scan logic as the CLI and returns a structured
`ScanResult` (findings, timeouts, warnings, exit code), useful for agent
frameworks that want to call SkillGuard in-process instead of shelling out.

## MCP server (agent-native, tool-call)

```bash
npx skillguard-cli mcp
```

Starts SkillGuard as a stdio MCP server exposing one tool, `scan_skill`
(`{ path, severityThreshold?, timeoutMs? }`), so another agent -- Claude
Code, Cursor, an orchestrator -- can scan a third-party skill directly as a
tool call before installing or running it, instead of shelling out to the
CLI and parsing stdout. Client config example:

```json
{ "mcpServers": { "skillguard": { "command": "npx", "args": ["skillguard-cli", "mcp"] } } }
```

Full setup, the tool's input/output schema, and the security guarantees this
path preserves (same `.skillguardignore`/inline-suppression defaults as the
CLI) are in [docs/integrations/mcp.md](./docs/integrations/mcp.md).

## GitHub Action

```yaml
- name: SkillGuard
  uses: RudrenduPaul/skillguard@main
  with:
    path: ./my-skill
    severity-threshold: HIGH
```

The Action defaults to `--format sarif` and uploads results straight to
GitHub code scanning, no configuration required. The bare CLI keeps a
human-readable default, since a terminal and a CI log want different things.

## Rule packs

Every rule pack lives under `rulepacks/` and ships inside the npm package,
nothing is fetched over the network at scan time.

| Category | Name | Severity | What it catches |
| --- | --- | --- | --- |
| SG01 | network mismatch | MEDIUM | Raw sockets, netcat, `/dev/tcp`, network primitives that bypass a typical HTTP-only scope. |
| SG02 | remote code execution | HIGH | `curl \| bash`, `eval()`/`exec()` of a fetched response, shelling out with remote-influenced content. |
| SG03 | file-scope escalation | MEDIUM | Writes/deletes/`chmod` reaching outside the skill's own directory. |
| SG04 | hook supply-chain | HIGH | Install-time hooks or dependencies that fetch and run remote code, or pin to a mutable branch. |
| SG05 | obfuscated payloads | LOW | base64/string-concat/dynamic-`Function` idioms used to hide a payload. See the note below. |
| SG06 | credential harvesting | HIGH | Reads of credential-shaped env vars or credential files, especially near a network call. |
| SG07 | frontmatter spoofing | MEDIUM | SKILL.md's declared network/filesystem scope vs. what the hooks/scripts actually do. |

**SG05 known limitation**: obfuscation detection under pure static analysis
has a materially higher false-negative rate than the other six categories.
SG05 catches known, common encoding/eval idioms. Treat it as best-effort
coverage, not a complete answer to obfuscation.

## Suppressing findings

**Trust model:** SkillGuard's job is to vet directories you did *not* write.
Both suppression mechanisms below can silence a finding, so neither is ever
trusted automatically from inside the thing being scanned. Each requires an
explicit, deliberate opt-in from whoever runs the scan.

A `.skillguardignore` file suppresses whole files by glob, same mental model
as `.gitignore`:

```
# .skillguardignore
vendor/**
*.generated.js
```

It is **only honored when you pass `--skillguardignore <path>`** (or the
`ignoreFilePath` library option). SkillGuard never reads a
`.skillguardignore` living inside the scan target on its own. A malicious
skill submission that ships its own `.skillguardignore` cannot silence
findings about itself unless you explicitly point SkillGuard at that file.
If you maintain a skill yourself and want self-suppression, keep your
`.skillguardignore` and pass its path explicitly:

```bash
npx skillguard-cli scan ./my-skill --skillguardignore ./my-skill/.skillguardignore
```

An inline `# skillguard-ignore: SG02` comment (on the same line as the match,
or the line directly above it) suppresses a single finding in place. This is
**off by default** and requires `--allow-inline-suppression`, for the same
reason: the comment lives inside the exact untrusted content being vetted,
so by default nothing in a scan target can silence a finding about itself.
Only enable it for a target you already trust, e.g. self-scanning your own
skill before publishing.

## Known Limitations

SkillGuard v0.1 documents its gaps in the open, on purpose.
The full list, including the residual single-pattern ReDoS risk and the
symlinks-are-unscanned-not-followed policy, both closed as far as they can
be in a synchronous, worker-free v0.1 and tracked for a real fix in v0.2,
lives in [CHANGELOG.md](./CHANGELOG.md). Read it before wiring SkillGuard
into a CI gate you plan to trust.

## Development

```bash
npm install
npm run build
npm test
```

## License

Apache 2.0, see [LICENSE](./LICENSE).
