# Changelog

All notable changes to SkillGuard are documented in this file, so a rule-pack
change never breaks a CI gate with no explanation. This changelog covers
both distributions -- the npm package (`skillguard-cli`, JS/TS) and the
PyPI package (`skillguard-cli`, Python) -- since they ship the same rule
packs and scan semantics; entries note which distribution they apply to.

## [Python 0.1.2] - 2026-07-17

Metadata-only release. Added Sourav Nandy as a listed co-author in
`pyproject.toml` (`authors`) and `project.urls`, matching the attribution
already used on this account's other PyPI packages (`memtrust`,
`agent-eval`, `agent-observability`, `ownvoice`). No code changes.

## [Python 0.1.1] - 2026-07-16

Initial public release of the Python port, published to PyPI as
`skillguard-cli` (`pip install skillguard-cli`). Complementary to, not a
replacement for, the existing npm package -- both are first-class and
maintained together. See `python/README.md` for Python-specific usage.

0.1.1 follows 0.1.0 same-day: a post-publish dependency review tightened
the `PyYAML` dependency to a pinned upper bound (`>=6.0,<7` instead of an
open-ended `>=6.0`). 0.1.0 remains installable on PyPI but 0.1.1 is the
version this changelog entry and `python/README.md` describe; install
`skillguard-cli` (unpinned) to always get the latest.

### Added

- `skillguard scan <path>` CLI (console script `skillguard`, package
  `skillguard`) with the same flags as the npm CLI: `--format`
  (human/json/sarif), `--severity-threshold` (default HIGH), `--timeout`
  (default 10000ms), `--skillguardignore`, and `--allow-inline-suppression`.
- Programmatic library API: `from skillguard import scan_skill, ScanOptions`,
  returning the same structured result shape (`ScanResult` dataclass with
  `findings`, `timeouts`, `unscanned_files`, `warnings`, `exit_code`).
- All seven first-party rule packs (SG01 through SG07) reimplemented as
  genuine Python logic -- the same rule contract (pack.json manifest +
  rules.yml pattern rules for SG01-SG06, a first-party structural module for
  SG07's frontmatter/behavior diff), bundled inside the wheel, no
  cross-language dependency on the Node/npm package at runtime.
- A first-party glob compiler for `.skillguardignore` suppression (no
  third-party glob-matching dependency), implementing the same
  brace-expansion-disabled, extglob-disabled semantics as the npm package's
  `minimatch` usage, for the same ReDoS-avoidance reason documented in that
  package's source.
- Full pytest suite (54 tests) ported from the TypeScript vitest suite,
  covering every rule pack, the walker, suppression, rule-pack loader,
  output formatters (human/json/sarif), the CLI, and an end-to-end pass
  against the same bundled `examples/` fixtures the npm package's tests use.

### Notes

- Verified byte-for-byte parity against the npm package's own documented
  benchmark: scanning `examples/known-bad-skill` with both CLIs produces
  the same 11 findings (5 HIGH, 5 MEDIUM, 1 LOW) across the same rule
  categories.
- `examples/clean-skill` and `examples/clean-skill-python` both scan clean
  (0 findings, exit code 0) under the Python CLI, matching the npm CLI.

## [0.1.0] - 2026-07-12

Initial release.

### Added

- `skillguard-cli scan <path>` CLI with `--format` (human/json/sarif),
  `--severity-threshold` (default HIGH), `--timeout` (default 10000ms), and
  `--skillguardignore` flags.
- Programmatic library export: `import { scanSkill } from 'skillguard-cli'`.
- `.skillguardignore` glob-based path suppression, plus inline
  `# skillguard-ignore: SGxx` comment suppression.
- In-repo GitHub Action (`action.yml`) that scans a path and uploads SARIF to
  GitHub code scanning by default.
- Seven first-party, bundled rule packs (no remote fetch):
  - **SG01 — network mismatch**: raw/low-level network primitives (sockets,
    netcat, `/dev/tcp`) that bypass a skill's typical HTTP-only scope.
  - **SG02 — remote code execution**: `curl | bash` style pipelines, `eval`/
    `exec` of a fetched network response, and shelling out with
    remote-influenced content.
  - **SG03 — file-scope escalation**: writes, deletes, or permission changes
    that reach outside a skill's own working directory.
  - **SG04 — hook supply-chain**: install-time hooks or dependency
    declarations that fetch and run remote code, or pin to a mutable branch
    ref instead of a fixed version/commit.
  - **SG05 — obfuscated payloads**: known base64/string-concatenation/
    dynamic-`Function` idioms used to hide a payload from plain-text review.
    Documented, intentional higher false-negative rate under static
    analysis alone — see `rulepacks/sg05-obfuscated-payloads/rules.yml`.
  - **SG06 — credential harvesting**: reads of credential-shaped environment
    variables or well-known credential files, especially combined with a
    nearby outbound network call.
  - **SG07 — frontmatter spoofing**: structural comparison of SKILL.md's
    declared network/filesystem scope against the actual behavior of its
    hooks/scripts (`src/ast/frontmatter-behavior-diff.ts`).
- `examples/known-bad-skill` and `examples/clean-skill` fixtures for the
  README demo command and end-to-end tests.

### Security (before v0.1 ships)

- **Fixed: suppression trust boundary.** `.skillguardignore` was previously
  auto-loaded from `<target>/.skillguardignore` by default, and inline
  `# skillguard-ignore: SGxx` comments were always honored — both read from
  inside the exact untrusted directory SkillGuard exists to vet. A malicious
  skill submission could ship its own `.skillguardignore` (a single line was
  enough) or annotate its own malicious lines with a suppression comment and
  flip a scan with real HIGH findings to a clean exit-0 PASS, in the default
  GitHub Action configuration — a complete bypass of the scanner's core
  promise, verified live against the bundled `known-bad-skill` fixture.
  **Fix:** `.skillguardignore` is now only loaded when explicitly passed
  (`--skillguardignore <path>` / `ignoreFilePath` option); inline suppression
  now requires an explicit `--allow-inline-suppression` flag /
  `allowInlineSuppression` option, off by default. Both remain fully
  supported for the legitimate self-scan use case (an author suppressing
  known false positives in their own skill pre-publish) — they just require
  a deliberate opt-in instead of being auto-trusted from untrusted content.
- **Fixed: unbounded ReDoS via `.skillguardignore` glob patterns.**
  minimatch's brace-expansion (`{a,b}`) and extglob (`@(...)` etc.) syntax
  can compile to a catastrophically backtracking regex — confirmed locally:
  `{a,a}` repeated ~22 times (about 110 bytes) took 3.5+ seconds just to
  *compile*, growing exponentially with each repetition, with zero timeout
  protection anywhere in the suppression-matching code path (the existing
  per-file timeout only covers rule-pattern matching, not path suppression).
  Since `.skillguardignore` is read from the scan target, this was a
  directly attacker-controlled, unbounded hang, worse than the documented
  single-pattern ReDoS residual risk below. **Fix:** suppression-glob
  matching now runs with brace expansion and extglob syntax disabled
  (`nobrace`/`noext`), plus a 512-character cap on individual suppression
  lines as defense in depth. Neither feature is meaningful for a
  `.gitignore`-style suppression file, so this is not a capability loss.
- **Fixed: terminal/ANSI-escape injection in the human-readable CLI output.**
  A finding's `file` path and `snippet` (a raw slice of matched file
  content) both originate in the scan target and were printed verbatim to
  `formatHuman()`'s terminal-facing output. A crafted filename or source
  line containing raw ESC/ANSI escape sequences, or embedded CR/LF bytes,
  could conceal or rewrite what a human sees when running
  `skillguard-cli scan` locally -- hiding the incriminating part of a
  flagged line, overwriting a display line via a bare CR, or forging a fake
  extra report line via an embedded LF. **Fix:** `file`, `snippet`, and
  suppression/warning text derived from the scan target are now stripped of
  ASCII control characters before being printed in human format. This does
  not affect the JSON/SARIF machine-readable formats or the exit code --
  the automated CI-gate decision was never affected by this gap, only a
  human directly reading terminal output.

### Known Limitations (tracked for v0.2)

- **Single-pattern ReDoS residual risk.** The per-file timeout (default
  10000ms) is enforced between matches, closing the practical case of a scan
  hanging across many files or many matches (verified: a 3M-line adversarial
  file now completes or times out in under 300ms). A single pathological
  regex causing catastrophic backtracking inside one match attempt can still
  block that file's scan synchronously before the next timeout check runs.
  Fully closing this requires moving rule evaluation to a worker thread with
  `terminate()`, tracked as a v0.2 item, not shipped silently as solved.
- **Symlinks are surfaced as unscanned, never followed.** This is the safe
  default (no path-traversal or symlink-cycle risk) but means a skill
  directory that legitimately shares files via symlinks will show those
  paths as coverage gaps rather than being scanned. Safe symlink-following
  needs a containment + cycle-detection policy, tracked as a future
  enhancement, not a v0.1 blocker.
