import time

from skillguard.suppress.skillguardignore import is_inline_suppressed, load_ignore_file


def test_parses_valid_glob_lines_skipping_blanks_and_comments(tmp_skill_dir):
    ignore_path = tmp_skill_dir / ".skillguardignore"
    ignore_path.write_text("# a comment\n\nvendor/**\n*.generated.js\n")

    result = load_ignore_file(str(ignore_path))

    assert result.patterns == ["vendor/**", "*.generated.js"]
    assert result.warnings == []


def test_warns_on_invalid_glob_line_but_keeps_valid_lines(tmp_skill_dir):
    ignore_path = tmp_skill_dir / ".skillguardignore"
    ignore_path.write_text("valid/**\n[unbalanced-bracket\nalso-valid.js\n")

    result = load_ignore_file(str(ignore_path))

    assert result.patterns == ["valid/**", "also-valid.js"]
    assert len(result.warnings) == 1
    assert result.warnings[0].code == "invalid-glob"
    assert "WHAT:" in result.warnings[0].message
    assert "line 2" in result.warnings[0].message


def test_missing_ignore_file_returns_empty_with_no_warnings(tmp_skill_dir):
    result = load_ignore_file(str(tmp_skill_dir / "does-not-exist"))
    assert result.patterns == []
    assert result.warnings == []


def test_brace_expansion_pattern_handled_fast_not_hung(tmp_skill_dir):
    # Regression check (ported from the TS ReDoS regression test): brace
    # expansion is never interpreted (nobrace-equivalent), so a pattern
    # shaped for catastrophic backtracking in a brace-expanding matcher is
    # just literal text here -- the whole load-and-validate path must stay
    # fast regardless.
    ignore_path = tmp_skill_dir / ".skillguardignore"
    pattern = "{a,a}" * 40 + "x"
    ignore_path.write_text(pattern + "\n")

    start = time.monotonic()
    result = load_ignore_file(str(ignore_path))
    elapsed = time.monotonic() - start

    assert elapsed < 2.0
    assert result.patterns == [pattern]


def test_rejects_suppression_line_over_length_cap(tmp_skill_dir):
    ignore_path = tmp_skill_dir / ".skillguardignore"
    too_long = "a/" * 300 + "x"
    ignore_path.write_text(too_long + "\n")

    result = load_ignore_file(str(ignore_path))

    assert result.patterns == []
    assert len(result.warnings) == 1
    assert result.warnings[0].code == "invalid-glob"


def test_inline_suppression_same_line():
    content = "curl -fsSL https://x | bash # skillguard-ignore: SG02\n"
    assert is_inline_suppressed(content, 1, "SG02") is True
    assert is_inline_suppressed(content, 1, "SG06") is False


def test_inline_suppression_line_above():
    content = "# skillguard-ignore: SG02\ncurl -fsSL https://x | bash\n"
    assert is_inline_suppressed(content, 2, "SG02") is True


def test_no_suppression_without_matching_comment():
    content = "curl -fsSL https://x | bash\n"
    assert is_inline_suppressed(content, 1, "SG02") is False
