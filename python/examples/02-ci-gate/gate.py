#!/usr/bin/env python3
"""
02 -- CI gate.

Demonstrates using scan_skill() as an actual CI gate script: takes a target
path and a severity threshold from the command line (falling back to the
repo's known-bad-skill fixture and HIGH so it's runnable with zero
arguments), prints a summary, and propagates the real scan exit code as the
process exit code -- exactly what you'd drop into a CI pipeline step (see
../../../docs/integrations/ci.md for the GitHub Actions version of this
same pattern).

Run:
    python3 examples/02-ci-gate/gate.py
    python3 examples/02-ci-gate/gate.py ../../../examples/clean-skill MEDIUM
"""
import sys
from pathlib import Path

from skillguard import ScanOptions, scan_skill

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TARGET = REPO_ROOT / "examples" / "known-bad-skill"


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_TARGET)
    severity_threshold = sys.argv[2] if len(sys.argv) > 2 else "HIGH"

    result = scan_skill(target, ScanOptions(severity_threshold=severity_threshold))

    if result.exit_code == 0:
        print(f"PASS: {target} -- no findings at or above {severity_threshold}.")
        return 0

    if result.exit_code == 2:
        print(f"ERROR: could not scan {target} -- see warnings below.", file=sys.stderr)
        for warning in result.warnings:
            print(warning.message, file=sys.stderr)
        return 2

    print(
        f"FAIL: {target} -- {len(result.findings)} finding(s) at or above "
        f"{severity_threshold}:",
        file=sys.stderr,
    )
    for finding in result.findings:
        print(
            f"  [{finding.severity}] {finding.category} {finding.file}:{finding.line}: {finding.message}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
