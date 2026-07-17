# CI integrations

SkillGuard is meant to be a CI gate on any pipeline that installs or
publishes third-party agent skills. Both packages support the same
`--severity-threshold`/`--format` contract, so pick whichever matches your
pipeline's existing toolchain.

## GitHub Actions -- npm CLI, bundled composite Action

The repo ships a composite GitHub Action (`action.yml`) that wraps the npm
CLI, defaults to `--format sarif`, and uploads results straight to GitHub
code scanning:

```yaml
- name: SkillGuard
  uses: RudrenduPaul/skillguard@main
  with:
    path: ./my-skill
    severity-threshold: HIGH
```

Under the hood this runs `npx --yes skillguard-cli scan <path> --format
sarif ...`, uploads the SARIF file via `github/codeql-action/upload-sarif`,
then gates the job on the scan's real exit code (so a failing scan still
shows up in the Security tab before the job fails, instead of the SARIF
upload being skipped). Full inputs:

| Input | Default | Description |
| --- | --- | --- |
| `path` | *(required)* | Path to the skill directory to scan. |
| `severity-threshold` | `HIGH` | Minimum severity that fails the check. |
| `timeout` | `10000` | Per-file scan timeout in milliseconds. |
| `skillguardignore` | *(unset)* | Path to a `.skillguardignore` file. |
| `allow-inline-suppression` | `false` | Honor inline suppression comments. |
| `sarif-output` | `skillguard-results.sarif` | Where to write the SARIF report. |

## GitHub Actions -- Python CLI, plain step

The Python package has no bundled composite Action (SARIF upload needs the
same `github/codeql-action/upload-sarif` step either way), but the
equivalent pipeline is a few lines:

```yaml
name: SkillGuard (Python)
on: [pull_request]

jobs:
  skillguard-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for the SARIF upload step
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install skillguard-cli
      - name: Run SkillGuard
        run: |
          skillguard scan ./my-skill --format sarif --severity-threshold HIGH \
            > skillguard-results.sarif
          echo "exit-code=$?" >> "$GITHUB_ENV"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard-results.sarif
      - name: Gate on SkillGuard result
        run: |
          if [ "$exit-code" != "0" ]; then
            echo "SkillGuard found findings at or above the configured severity threshold."
            exit 1
          fi
```

(Note the `> file` redirect captures stdout only, so the exit code has to
be captured explicitly, same as the npm Action's own script does
internally -- see `action.yml` in the repo root for the exact pattern this
mirrors.)

## Pre-commit hook (Python CLI)

For a local/pre-push gate rather than CI, wire the Python CLI into
[pre-commit](https://pre-commit.com/):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skillguard
        name: SkillGuard scan
        entry: skillguard scan skills/my-skill --severity-threshold HIGH
        language: system
        pass_filenames: false
```

This assumes `skillguard` is already on `PATH` (installed via `pip install
skillguard-cli` in your dev environment, or add a `language: python` /
`additional_dependencies: [skillguard-cli]` hook instead if you want
pre-commit to manage the install itself).

## Choosing a severity threshold

`HIGH` (the default for both CLIs) only fails a scan on confirmed
executable-impact findings (SG02 remote code execution, SG04 hook
supply-chain, SG06 credential harvesting). Lowering the threshold to
`MEDIUM` also gates on declared-scope violations without a confirmed
exploit path (SG01, SG03, SG07) -- reasonable for a stricter internal
marketplace, noisier for a first rollout against skills you didn't author.
`LOW` additionally gates on SG05's best-effort obfuscation heuristics,
which has a documented higher false-negative *and* false-positive
trade-off; see [concepts.md](../concepts.md#sg05----obfuscated-payloads-low).
