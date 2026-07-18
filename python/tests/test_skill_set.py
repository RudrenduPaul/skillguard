from pathlib import Path

from skillguard.scan.skill_set import compute_cross_skill_findings, discover_skill_dirs, scan_skill_set
from skillguard.types import Finding, ScanOptions, ScanResult, SkillEntry

CLEAN_SKILL_MD = "---\nname: x\nnetwork: false\nfilesystem: none\n---\n"
NETWORK_SKILL_MD = "---\nname: net\nnetwork: true\nfilesystem: none\n---\n"
SANDBOXED_NETWORK_SKILL_MD = "---\nname: net\nnetwork: true\nfilesystem: none\nsandbox: true\n---\n"

RAW_SOCKET_PY = "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
PATH_TRAVERSAL_SH = "cat ../../../../.env\n"


def _write_skill(root: Path, name: str, skill_md_body: str, hook_files: dict) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(skill_md_body)
    hooks_dir = skill_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    for file_name, content in hook_files.items():
        (hooks_dir / file_name).write_text(content)
    return skill_dir


def test_discover_skill_dirs_finds_immediate_subdirs_with_skill_md(tmp_path):
    _write_skill(tmp_path, "skill-a", CLEAN_SKILL_MD, {})
    _write_skill(tmp_path, "skill-b", CLEAN_SKILL_MD, {})
    not_a_skill = tmp_path / "not-a-skill"
    not_a_skill.mkdir()
    (not_a_skill / "README.md").write_text("hello\n")

    found = discover_skill_dirs(str(tmp_path))
    assert [f.name for f in found] == ["skill-a", "skill-b"]
    assert found[0].skill_md_path == str(tmp_path / "skill-a" / "SKILL.md")


def test_discover_skill_dirs_matches_skill_md_case_insensitively(tmp_path):
    skill_dir = tmp_path / "skill-a"
    skill_dir.mkdir()
    (skill_dir / "skill.md").write_text(CLEAN_SKILL_MD)

    found = discover_skill_dirs(str(tmp_path))
    assert len(found) == 1
    assert found[0].name == "skill-a"


def test_discover_skill_dirs_ignores_git_and_node_modules(tmp_path):
    _write_skill(tmp_path, ".git", CLEAN_SKILL_MD, {})
    _write_skill(tmp_path, "node_modules", CLEAN_SKILL_MD, {})
    _write_skill(tmp_path, "real-skill", CLEAN_SKILL_MD, {})

    found = discover_skill_dirs(str(tmp_path))
    assert [f.name for f in found] == ["real-skill"]


def test_discover_skill_dirs_returns_empty_for_missing_directory(tmp_path):
    assert discover_skill_dirs(str(tmp_path / "nope")) == []


def test_discover_skill_dirs_does_not_recurse(tmp_path):
    nested = tmp_path / "wrapper" / "actual-skill"
    nested.mkdir(parents=True)
    (nested / "SKILL.md").write_text(CLEAN_SKILL_MD)

    assert discover_skill_dirs(str(tmp_path)) == []


def test_exit_code_2_when_targets_dir_does_not_exist(tmp_path):
    result = scan_skill_set(str(tmp_path / "nope"))
    assert result.exit_code == 2
    assert result.warnings[0].code == "targets-dir-not-found"
    assert result.skills == []


def test_exit_code_2_when_no_skill_subdirectories(tmp_path):
    (tmp_path / "just-a-folder").mkdir()
    result = scan_skill_set(str(tmp_path))
    assert result.exit_code == 2
    assert any(w.code == "no-skills-found-in-set" for w in result.warnings)


def test_scans_each_skill_using_the_same_machinery_as_scan_skill(tmp_path):
    _write_skill(tmp_path, "clean-one", CLEAN_SKILL_MD, {"greet.js": "console.log('hi');\n"})
    _write_skill(tmp_path, "noisy-one", CLEAN_SKILL_MD, {"cleanup.sh": "rm -rf /etc/config\n"})

    result = scan_skill_set(str(tmp_path), ScanOptions(severity_threshold="MEDIUM"))
    assert len(result.skills) == 2

    clean_one = next(s for s in result.skills if s.name == "clean-one")
    assert clean_one.result.findings == []
    assert clean_one.result.exit_code == 0

    noisy_one = next(s for s in result.skills if s.name == "noisy-one")
    assert any(f.category == "SG03" for f in noisy_one.result.findings)
    assert noisy_one.result.exit_code == 1


def test_sg09_fires_for_fs_read_plus_network_egress_neither_sandboxed(tmp_path):
    _write_skill(tmp_path, "fs-reader", CLEAN_SKILL_MD, {"read.sh": PATH_TRAVERSAL_SH})
    _write_skill(tmp_path, "net-sender", NETWORK_SKILL_MD, {"send.py": RAW_SOCKET_PY})

    result = scan_skill_set(str(tmp_path))

    for skill in result.skills:
        assert skill.result.exit_code == 0

    assert len(result.findings) == 1
    sg09 = result.findings[0]
    assert sg09.category == "SG09"
    assert sg09.severity == "HIGH"
    assert sg09.rule_id == "sg09-cross-skill-privilege-chaining"
    assert "fs-reader" in sg09.message
    assert "net-sender" in sg09.message
    assert sg09.file == "fs-reader/hooks/read.sh"

    assert result.exit_code == 1


def test_sg09_does_not_fire_with_only_one_capability_present(tmp_path):
    _write_skill(tmp_path, "fs-reader", CLEAN_SKILL_MD, {"read.sh": PATH_TRAVERSAL_SH})
    _write_skill(tmp_path, "harmless", CLEAN_SKILL_MD, {"greet.js": "console.log('hi');\n"})

    result = scan_skill_set(str(tmp_path))
    assert result.findings == []
    assert result.exit_code == 0


def test_sg09_does_not_fire_when_network_skill_declares_sandboxing(tmp_path):
    _write_skill(tmp_path, "fs-reader", CLEAN_SKILL_MD, {"read.sh": PATH_TRAVERSAL_SH})
    _write_skill(tmp_path, "net-sender", SANDBOXED_NETWORK_SKILL_MD, {"send.py": RAW_SOCKET_PY})

    result = scan_skill_set(str(tmp_path))
    assert result.findings == []
    assert result.exit_code == 0


def test_clean_skill_set_has_no_sg09_finding(tmp_path):
    _write_skill(tmp_path, "skill-a", CLEAN_SKILL_MD, {"greet.js": "console.log('hi');\n"})
    _write_skill(tmp_path, "skill-b", CLEAN_SKILL_MD, {"format.py": "print('hello')\n"})

    result = scan_skill_set(str(tmp_path))
    assert result.findings == []
    assert result.exit_code == 0


def _make_entry(name: str, path: str, findings) -> SkillEntry:
    return SkillEntry(
        name=name,
        path=path,
        result=ScanResult(
            target=path,
            findings=findings,
            timeouts=[],
            unscanned_files=[],
            warnings=[],
            files_scanned=1,
            severity_threshold="HIGH",
            exit_code=0,
        ),
    )


def test_compute_cross_skill_findings_same_skill_combines_both_capabilities(tmp_path):
    skill_dir = _write_skill(tmp_path, "combo", CLEAN_SKILL_MD, {})

    from skillguard.scan.skill_set import DiscoveredSkillDir

    discovered = [
        DiscoveredSkillDir(
            name="combo", path=str(skill_dir), skill_md_path=str(skill_dir / "SKILL.md")
        )
    ]
    skills = [
        _make_entry(
            "combo",
            str(skill_dir),
            [
                Finding(
                    rule_id="sg03-path-traversal",
                    category="SG03",
                    severity="MEDIUM",
                    message="traversal",
                    file="hooks/read.sh",
                    line=3,
                ),
                Finding(
                    rule_id="sg01-raw-socket-python",
                    category="SG01",
                    severity="MEDIUM",
                    message="socket",
                    file="hooks/send.py",
                    line=5,
                ),
            ],
        )
    ]

    findings = compute_cross_skill_findings(discovered, skills)
    assert len(findings) == 1
    assert "alone combines" in findings[0].message


def test_compute_cross_skill_findings_empty_set_returns_empty_list():
    assert compute_cross_skill_findings([], []) == []
