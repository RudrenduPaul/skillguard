# Security Policy

SkillGuard is a security tool: its entire purpose is running against
untrusted, potentially malicious third-party content (agent-skill
directories). A vulnerability in SkillGuard itself -- something that lets a
malicious scan target escape the scanner's intended read-only, no-eval
sandboxing, or that lets a crafted target silence findings about itself
outside the documented suppression mechanisms -- is taken seriously and
handled as a priority.

## Supported versions

| Package | Version | Supported |
| --- | --- | --- |
| `skillguard-cli` (npm) | 0.1.x | Yes |
| `skillguard-cli` (PyPI) | 0.1.x | Yes |

Both distributions are pre-1.0 and under active development. Security fixes
land on the latest `0.1.x` release of each; there is no older supported line
to backport to yet.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report it privately via
[GitHub Security Advisories](https://github.com/RudrenduPaul/skillguard/security/advisories/new)
for this repository. Include:

- Which distribution is affected (npm package, PyPI package, or both).
- A minimal reproduction: the scan target content (or a description of the
  shape of it) and the command/library call that triggers the issue.
- What you expected SkillGuard to do, and what it actually did.
- Your assessment of impact -- e.g. "a crafted `.skillguardignore` inside
  the scan target silences findings without the caller opting in" is a
  trust-boundary bypass of exactly the kind this project has fixed before
  (see [CHANGELOG.md](./CHANGELOG.md)'s "Security" section for the v0.1.0
  suppression-trust-boundary and ReDoS fixes).

## What counts as in scope

- Any code path where content read from the *scan target* (file contents,
  filenames, `.skillguardignore` contents, SKILL.md frontmatter) is
  executed, evaluated, or dynamically imported/required, rather than only
  read and pattern-matched.
- Any suppression mechanism (`.skillguardignore`, inline
  `# skillguard-ignore:` comments) that takes effect without the caller's
  explicit, documented opt-in (`--skillguardignore <path>` /
  `ignore_file_path`, `--allow-inline-suppression` / `allow_inline_suppression`).
  Suppression is designed to require deliberate action from whoever runs
  the scan -- a scan target silencing itself by default is the bug class
  this project has already fixed once and does not want to reintroduce.
- A crafted scan target that causes unbounded resource consumption (ReDoS,
  unbounded memory, an unbounded hang) bypassing the documented per-file
  timeout.
- A crafted scan target's filenames or matched content that can manipulate
  what a human sees in the default human-readable CLI output (terminal/ANSI
  injection) in a way the existing control-character sanitization doesn't
  already cover.

## What is out of scope

- Findings that are false negatives of a best-effort detection rule
  (particularly SG05, obfuscated payloads) -- these are documented, known
  limitations of static pattern matching, not vulnerabilities in SkillGuard
  itself. Open a normal issue for these (or better, a PR with a new rule).
- Vulnerabilities in a scan *target* itself (i.e. the thing SkillGuard is
  scanning) -- report those to the target's own maintainers.

## Response

We aim to acknowledge a report within 5 business days and to have a fix or
a mitigation plan within 30 days for a confirmed, in-scope vulnerability.
Credit is given in the release notes unless you ask to remain anonymous.
