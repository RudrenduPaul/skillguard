"""
End-to-end tests against the same bundled fixtures the TypeScript suite uses
(examples/clean-skill, examples/clean-skill-python, examples/known-bad-skill
at the repo root -- shared between both language implementations, not
duplicated here).
"""
from pathlib import Path

import pytest

from skillguard import scan_skill

# Shared with the TypeScript test suite -- examples/ lives at the repo root,
# not duplicated per language.
EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"


def test_clean_skill_scans_with_exit_0_and_no_findings():
    result = scan_skill(str(EXAMPLES_DIR / "clean-skill"))
    assert result.exit_code == 0
    assert result.findings == []


def test_clean_skill_python_scans_with_exit_0():
    result = scan_skill(str(EXAMPLES_DIR / "clean-skill-python"))
    assert result.exit_code == 0
    assert result.findings == []


def test_known_bad_skill_scans_with_exit_1_and_cites_high_finding():
    result = scan_skill(str(EXAMPLES_DIR / "known-bad-skill"))
    assert result.exit_code == 1

    high_findings = [f for f in result.findings if f.severity == "HIGH"]
    assert len(high_findings) > 0

    cited = high_findings[0]
    assert cited.file.endswith((".sh", ".js", ".py"))
    assert cited.line > 0

    invalid_pack_warnings = [w for w in result.warnings if w.code == "invalid-pack"]
    assert invalid_pack_warnings == []


def test_known_bad_skill_trips_multiple_distinct_rule_categories():
    result = scan_skill(str(EXAMPLES_DIR / "known-bad-skill"))
    categories = {f.category for f in result.findings}
    assert len(categories) >= 3


@pytest.mark.skipif(not EXAMPLES_DIR.exists(), reason="repo-root examples/ fixtures not present")
def test_examples_dir_exists():
    assert EXAMPLES_DIR.exists()
