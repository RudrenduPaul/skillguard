# Python examples

Each numbered subdirectory is a real, runnable script against the actual
`skillguard` Python library (`from skillguard import scan_skill, ...`), not
pseudocode. They scan the repo's own bundled fixtures under `../../examples/`
(`known-bad-skill`, `clean-skill`), so nothing external is required.

Install the package first (editable install from this checkout, or `pip
install skillguard-cli` from PyPI both work identically):

```bash
cd python
pip install -e .
```

Then run any example directly:

```bash
python3 examples/01-basic-scan/scan.py
python3 examples/02-ci-gate/gate.py
python3 examples/03-agent-native-json/agent_report.py
```

| Example | What it demonstrates |
| --- | --- |
| [01-basic-scan](./01-basic-scan/) | The core library call: `scan_skill()`, reading back `findings`/`exit_code`, printing a human-readable summary. |
| [02-ci-gate](./02-ci-gate/) | Using `scan_skill()` as a CI gate: a custom severity threshold, real process exit-code propagation, suitable to drop into a CI script directly. |
| [03-agent-native-json](./03-agent-native-json/) | The agent-native use case: calling SkillGuard in-process (no CLI subprocess), serializing structured findings to JSON, and demonstrating the two suppression mechanisms (`.skillguardignore` and inline `# skillguard-ignore:` comments). |
