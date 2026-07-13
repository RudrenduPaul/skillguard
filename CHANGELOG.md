# Changelog

All notable changes to SkillGuard are documented in this file, so a rule-pack
change never breaks a CI gate with no explanation.

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
