# Contributing to SkillGuard

SkillGuard ships two independently maintained, equally first-class
distributions of the same scanner: an npm package (`skillguard-cli`,
TypeScript, repo root) and a PyPI package (`skillguard-cli`, Python,
`python/`). Both read the same seven rule packs (`rulepacks/` at the repo
root for the npm package; `python/src/skillguard/rulepacks/data/` for the
Python package, kept in sync by hand since they're separate language
runtimes) and are expected to produce the same findings against the same
target. Please read this whole file before opening a PR -- which section
applies depends on which codebase you're touching.

## Ground rules

- Every change lands with tests. Neither test suite is optional scaffolding
  -- both are the mechanism that keeps the two implementations in parity.
- A rule-pack change (a new rule, a changed regex, a changed severity) must
  be made in **both** `rulepacks/` (TypeScript) and
  `python/src/skillguard/rulepacks/data/` (Python), with equivalent test
  coverage added to both suites. A rule pack that only exists in one
  language is a silent behavior gap between the two CLIs -- avoid it.
- Findings, exit codes, and warning message text (the WHAT/WHY/FIX format)
  should read identically between the two CLIs wherever the underlying
  behavior is the same. If you intentionally diverge the two (e.g. a
  Python-only convenience flag), say so explicitly in the PR description.
- No `eval`/`exec`/dynamic `require`/`import` of anything read from a scan
  target, in either codebase. SkillGuard's entire premise is that it's safe
  to run against untrusted third-party skill directories; a fix that breaks
  that invariant is not a fix.

## Working on the TypeScript package (repo root)

```bash
npm install
npm run build
npm test
npm run typecheck
```

- Source lives under `src/`; rule packs under `rulepacks/`; fixtures used by
  both the README demo and the end-to-end tests under `examples/`.
- Tests use `vitest` (`src/**/*.test.ts`, one file per module).
- `npm run build` compiles to `dist/`, which is what the `bin` entry
  (`skillguard-cli`) and the library export (`skillguard-cli` as an npm
  import) both resolve to. Run it before manually testing `dist/cli.js`.

## Working on the Python package (`python/`)

```bash
cd python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

- Source lives under `python/src/skillguard/`, laid out to mirror the
  TypeScript module structure 1:1 (`scan/`, `rulepacks/`, `structural/`
  for SG07, `output/`, `suppress/`, `cli.py`, `types.py`, `errors.py`,
  `walker.py`) so a change in one codebase has an obvious counterpart to
  check in the other.
- Rule pack data (`pack.json` + `rules.yml`, verbatim from the TypeScript
  originals where the rule is shared) lives under
  `python/src/skillguard/rulepacks/data/` and ships inside the wheel.
- Tests use `pytest` (`python/tests/test_*.py`), including an end-to-end
  suite that runs against the same `examples/` fixtures at the repo root
  the TypeScript suite uses -- no fixture duplication.
- Build and verify a real install before opening a PR that touches
  packaging:
  ```bash
  python3 -m build python --outdir python/dist
  python3 -m venv /tmp/sg-verify && /tmp/sg-verify/bin/pip install python/dist/*.whl
  /tmp/sg-verify/bin/skillguard scan examples/known-bad-skill
  ```

## Adding or changing a rule

1. Decide the category (SG01-SG07) and severity per the locked taxonomy:
   HIGH for confirmed executable impact (e.g. remote code execution,
   credential exfiltration), MEDIUM for a declared-scope violation without a
   confirmed exploit path, LOW for best-effort/higher-false-negative
   detection (currently only SG05).
2. Add the rule to `rulepacks/<pack>/rules.yml` (TypeScript) and the
   matching `python/src/skillguard/rulepacks/data/<pack>/rules.yml`
   (Python) with the same `id`, `severity`, `languages`, and an equivalent
   `regex` (JS regex syntax and Python `re` syntax are close but not
   identical -- verify the translated pattern actually matches the same
   inputs, don't assume).
3. Add a positive test case (the rule fires) and, where practical, a
   negative test case (a similar-looking but benign snippet does not fire)
   to both test suites.
4. Run both test suites and both CLIs against `examples/known-bad-skill`
   and `examples/clean-skill` to confirm the finding counts you'd expect.

## Reporting a security issue

Do not open a public issue for a security vulnerability. See
[SECURITY.md](./SECURITY.md).

## License

By contributing, you agree your contribution is licensed under the same
Apache License, Version 2.0 that covers the rest of this repository (see
[LICENSE](./LICENSE)).
