# SkillGuard

36% of published agent skills have exploitable flaws per Snyk — SkillGuard scans SKILL.md, hooks, and scripts for known attack patterns before they run, and gates your CI on the result.

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

This runs against a fixture bundled with the repo — safe, non-functional,
and deliberately pattern-matchable — and returns a real HIGH-severity
finding with a file:line citation. Every scan prints a
"Loading SkillGuard rule packs..." message to stderr before it starts;
that's expected, not a hang.

Compare it against a clean fixture:

```bash
npx skillguard-cli scan ./examples/clean-skill
```

which returns zero findings and exit code 0.

## Install

```bash
npm install --save-dev skillguard-cli
```

No separate install step, no external binary to fetch: SkillGuard's seven
rule packs and pattern-matching engine ship inside the npm package.

## CLI usage

```bash
npx skillguard-cli scan <path> [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--format <human\|json\|sarif>` | `human` | Output format. |
| `--severity-threshold <HIGH\|MEDIUM\|LOW>` | `HIGH` | Minimum severity that fails the scan (exit code 1). |
| `--timeout <ms>` | `10000` | Per-file scan timeout in milliseconds. |
| `--skillguardignore <path>` | none (must be passed explicitly) | Path to a suppression file. Never auto-loaded from inside the scan target — see [Suppressing findings](#suppressing-findings). |
| `--allow-inline-suppression` | `false` | Honor inline `# skillguard-ignore: SGxx` comments found inside the scanned files. Off by default — see below. |

**Exit codes**: `0` — clean scan, `1` — a finding at or above the severity
threshold, `2` — the target path doesn't exist or no skill files were found.

## Library usage (agent-native)

```ts
import { scanSkill } from 'skillguard-cli';

const result = await scanSkill('./my-skill', { severityThreshold: 'HIGH' });

if (result.exitCode === 1) {
  console.log(`${result.findings.length} finding(s) at or above HIGH`);
}
```

`scanSkill()` runs the same scan logic as the CLI and returns a structured
`ScanResult` (findings, timeouts, warnings, exit code) — useful for agent
frameworks that want to call SkillGuard in-process instead of shelling out.

## GitHub Action

```yaml
- name: SkillGuard
  uses: RudrenduPaul/skillguard@main
  with:
    path: ./my-skill
    severity-threshold: HIGH
```

The Action defaults to `--format sarif` and uploads results straight to
GitHub code scanning — no configuration required. The bare CLI keeps a
human-readable default, since a terminal and a CI log want different things.

## Rule packs

Every rule pack lives under `rulepacks/` and ships inside the npm package —
nothing is fetched over the network at scan time.

| Category | Name | Severity | What it catches |
| --- | --- | --- | --- |
| SG01 | network mismatch | MEDIUM | Raw sockets, netcat, `/dev/tcp` — network primitives that bypass a typical HTTP-only scope. |
| SG02 | remote code execution | HIGH | `curl \| bash`, `eval()`/`exec()` of a fetched response, shelling out with remote-influenced content. |
| SG03 | file-scope escalation | MEDIUM | Writes/deletes/`chmod` reaching outside the skill's own directory. |
| SG04 | hook supply-chain | HIGH | Install-time hooks or dependencies that fetch and run remote code, or pin to a mutable branch. |
| SG05 | obfuscated payloads | LOW | base64/string-concat/dynamic-`Function` idioms used to hide a payload. See the note below. |
| SG06 | credential harvesting | HIGH | Reads of credential-shaped env vars or credential files, especially near a network call. |
| SG07 | frontmatter spoofing | MEDIUM | SKILL.md's declared network/filesystem scope vs. what the hooks/scripts actually do. |

**SG05 known limitation**: obfuscation detection under pure static analysis
has a materially higher false-negative rate than the other six categories.
SG05 catches known, common encoding/eval idioms — treat it as best-effort
coverage, not a complete answer to obfuscation.

## Suppressing findings

**Trust model:** SkillGuard's job is to vet directories you did *not* write.
Both suppression mechanisms below can silence a finding, so neither is ever
trusted automatically from inside the thing being scanned — each requires an
explicit, deliberate opt-in from whoever runs the scan.

A `.skillguardignore` file suppresses whole files by glob, same mental model
as `.gitignore`:

```
# .skillguardignore
vendor/**
*.generated.js
```

It is **only honored when you pass `--skillguardignore <path>`** (or the
`ignoreFilePath` library option) — SkillGuard never reads a
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
**off by default** and requires `--allow-inline-suppression` — for the same
reason: the comment lives inside the exact untrusted content being vetted,
so by default nothing in a scan target can silence a finding about itself.
Only enable it for a target you already trust, e.g. self-scanning your own
skill before publishing.

## Development

```bash
npm install
npm run build
npm test
```

## License

Apache 2.0 — see [LICENSE](./LICENSE).
