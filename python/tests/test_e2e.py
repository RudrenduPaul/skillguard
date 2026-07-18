"""
End-to-end tests against the same bundled fixtures the TypeScript suite uses
(examples/clean-skill, examples/clean-skill-python, examples/known-bad-skill
at the repo root -- shared between both language implementations, not
duplicated here).
"""
from pathlib import Path

import pytest

from skillguard import scan_skill, scan_skill_set

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


def test_sg10_typosquat_skill_fixture_is_flagged_high_exit_1():
    result = scan_skill(str(EXAMPLES_DIR / "typosquat-skill"))

    assert result.exit_code == 1
    sg10_findings = [f for f in result.findings if f.category == "SG10"]
    assert len(sg10_findings) == 1
    assert sg10_findings[0].rule_id == "sg10-typosquat-suspected"
    assert sg10_findings[0].severity == "HIGH"
    assert sg10_findings[0].file == "SKILL.md"
    assert sg10_findings[0].line > 0
    assert "numpi" in sg10_findings[0].message
    assert "numpy" in sg10_findings[0].message


def test_sg10_known_name_legit_skill_fixture_is_not_flagged_exit_0():
    result = scan_skill(str(EXAMPLES_DIR / "known-name-legit-skill"))

    assert result.exit_code == 0
    assert result.findings == []


def test_sg10_unrelated_legitimately_named_clean_fixtures_are_not_flagged():
    clean = scan_skill(str(EXAMPLES_DIR / "clean-skill"))
    clean_python = scan_skill(str(EXAMPLES_DIR / "clean-skill-python"))

    assert [f for f in clean.findings if f.category == "SG10"] == []
    assert [f for f in clean_python.findings if f.category == "SG10"] == []


def test_skill_set_cross_privilege_fixture_trips_sg09():
    result = scan_skill_set(str(EXAMPLES_DIR / "skill-set-cross-privilege"))

    assert sorted(s.name for s in result.skills) == ["report-uploader", "vault-reader"]
    for skill in result.skills:
        assert skill.result.exit_code == 0

    assert len(result.findings) == 1
    sg09 = result.findings[0]
    assert sg09.category == "SG09"
    assert sg09.severity == "HIGH"
    assert "vault-reader" in sg09.message
    assert "report-uploader" in sg09.message

    assert result.exit_code == 1


def test_skill_set_clean_fixture_has_no_cross_skill_findings():
    result = scan_skill_set(str(EXAMPLES_DIR / "skill-set-clean"))

    assert sorted(s.name for s in result.skills) == ["formatter", "greeter"]
    for skill in result.skills:
        assert skill.result.findings == []
        assert skill.result.exit_code == 0
    assert result.findings == []
    assert result.exit_code == 0


@pytest.mark.skipif(not EXAMPLES_DIR.exists(), reason="repo-root examples/ fixtures not present")
def test_examples_dir_exists():
    assert EXAMPLES_DIR.exists()
