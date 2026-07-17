#!/usr/bin/env python3
"""
01 -- basic scan.

The simplest possible use of the skillguard library: call scan_skill()
against a directory, look at result.exit_code and result.findings. This
scans the repo's own bundled fixtures (../../../examples/known-bad-skill
and ../../../examples/clean-skill), so it runs standalone with no setup
beyond `pip install -e .` (or `pip install skillguard-cli`) from the
python/ directory.

Run:
    python3 examples/01-basic-scan/scan.py
"""
from pathlib import Path

from skillguard import scan_skill

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES_DIR = REPO_ROOT / "examples"


def main() -> None:
    for fixture in ("known-bad-skill", "clean-skill"):
        target = EXAMPLES_DIR / fixture
        result = scan_skill(str(target))

        print(f"--- {fixture} ---")
        print(f"target:        {result.target}")
        print(f"files scanned: {result.files_scanned}")
        print(f"exit code:     {result.exit_code}")
        print(f"findings:      {len(result.findings)}")

        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.category} {finding.file}:{finding.line} ({finding.rule_id})")

        print()


if __name__ == "__main__":
    main()
