import pytest

from skillguard.cli import run_cli


def test_exits_2_when_target_path_does_not_exist(tmp_skill_dir, capsys):
    missing = tmp_skill_dir / "does-not-exist"
    exit_code = run_cli(["skillguard", "scan", str(missing)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.out


def test_exits_0_for_clean_target_with_no_findings(tmp_skill_dir, capsys):
    (tmp_skill_dir / "SKILL.md").write_text(
        "---\nname: x\nnetwork: false\nfilesystem: none\n---\n"
    )
    hooks = tmp_skill_dir / "hooks"
    hooks.mkdir()
    (hooks / "greet.js").write_text("console.log('hi');\n")

    exit_code = run_cli(["skillguard", "scan", str(tmp_skill_dir)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "No findings." in captured.out


def test_rejects_invalid_severity_threshold_with_what_why_fix(tmp_skill_dir, capsys):
    (tmp_skill_dir / "SKILL.md").write_text("---\nname: x\n---\n")
    with pytest.raises(SystemExit) as exc_info:
        run_cli(["skillguard", "scan", str(tmp_skill_dir), "--severity-threshold", "NOT_A_LEVEL"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "WHAT:" in captured.err
    assert "WHY:" in captured.err
    assert "FIX:" in captured.err


def test_severity_threshold_override_fails_scan_on_medium_finding(tmp_skill_dir):
    (tmp_skill_dir / "SKILL.md").write_text(
        "---\nname: x\nnetwork: false\nfilesystem: none\n---\n"
    )
    hooks = tmp_skill_dir / "hooks"
    hooks.mkdir()
    (hooks / "cleanup.sh").write_text("rm -rf /etc/config\n")

    exit_code = run_cli(
        ["skillguard", "scan", str(tmp_skill_dir), "--severity-threshold", "MEDIUM"]
    )
    assert exit_code == 1


def test_rejects_invalid_format_value(tmp_skill_dir):
    (tmp_skill_dir / "SKILL.md").write_text("---\nname: x\n---\n")
    with pytest.raises(SystemExit) as exc_info:
        run_cli(["skillguard", "scan", str(tmp_skill_dir), "--format", "yaml"])
    assert exc_info.value.code == 2
