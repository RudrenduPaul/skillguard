import json

from skillguard.rulepacks.loader import load_rule_packs

VALID_RULES_YAML = """
rules:
  - id: test-rule
    message: "test message"
    severity: HIGH
    languages: [javascript]
    regex: "console\\\\.log"
"""


def _write_pack(rulepacks_dir, name, manifest, rules_yaml=None):
    pack_dir = rulepacks_dir / name
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "pack.json").write_text(json.dumps(manifest, indent=2))
    if rules_yaml is not None:
        (pack_dir / "rules.yml").write_text(rules_yaml)


def test_loads_valid_pack(tmp_skill_dir):
    _write_pack(
        tmp_skill_dir,
        "sg-test",
        {
            "name": "sg-test",
            "version": "0.1.0",
            "category": "SG01",
            "minCoreVersion": "0.1.0",
            "description": "test pack",
            "kind": "pattern",
            "rulesFile": "rules.yml",
        },
        VALID_RULES_YAML,
    )

    result = load_rule_packs(str(tmp_skill_dir), "0.1.0")

    assert result.warnings == []
    assert len(result.packs) == 1
    assert result.packs[0].manifest.name == "sg-test"
    assert len(result.packs[0].rules) == 1
    assert result.packs[0].rules[0].id == "test-rule"


def test_critical_skips_malformed_manifest_but_loads_remaining_valid_packs(tmp_skill_dir):
    _write_pack(tmp_skill_dir, "broken-pack", {"name": "broken-pack"})  # missing required fields
    _write_pack(
        tmp_skill_dir,
        "good-pack",
        {
            "name": "good-pack",
            "version": "0.1.0",
            "category": "SG02",
            "minCoreVersion": "0.1.0",
            "description": "a valid pack",
            "kind": "pattern",
            "rulesFile": "rules.yml",
        },
        VALID_RULES_YAML,
    )

    result = load_rule_packs(str(tmp_skill_dir), "0.1.0")

    assert len(result.packs) == 1
    assert result.packs[0].manifest.name == "good-pack"

    assert len(result.warnings) == 1
    assert result.warnings[0].code == "invalid-pack"
    assert "WHAT:" in result.warnings[0].message
    assert "WHY:" in result.warnings[0].message
    assert "FIX:" in result.warnings[0].message
    assert "broken-pack" in result.warnings[0].message


def test_skips_pack_with_invalid_json(tmp_skill_dir):
    pack_dir = tmp_skill_dir / "bad-json-pack"
    pack_dir.mkdir(parents=True)
    (pack_dir / "pack.json").write_text("{ not valid json")

    result = load_rule_packs(str(tmp_skill_dir), "0.1.0")

    assert result.packs == []
    assert len(result.warnings) == 1
    assert result.warnings[0].code == "invalid-pack"


def test_skips_pack_whose_min_core_version_exceeds_running_core(tmp_skill_dir):
    _write_pack(
        tmp_skill_dir,
        "future-pack",
        {
            "name": "future-pack",
            "version": "0.1.0",
            "category": "SG03",
            "minCoreVersion": "99.0.0",
            "description": "requires a future core",
            "kind": "pattern",
            "rulesFile": "rules.yml",
        },
        VALID_RULES_YAML,
    )

    result = load_rule_packs(str(tmp_skill_dir), "0.1.0")

    assert result.packs == []
    assert len(result.warnings) == 1
    assert result.warnings[0].code == "invalid-pack"
    assert "future-pack" in result.warnings[0].message


def test_loads_structural_pack_without_rules_file(tmp_skill_dir):
    _write_pack(
        tmp_skill_dir,
        "sg07-frontmatter-spoofing",
        {
            "name": "sg07-frontmatter-spoofing",
            "version": "0.1.0",
            "category": "SG07",
            "minCoreVersion": "0.1.0",
            "description": "structural pack",
            "kind": "structural",
        },
    )

    result = load_rule_packs(str(tmp_skill_dir), "0.1.0")

    assert result.warnings == []
    assert len(result.packs) == 1
    assert result.packs[0].rules == []


def test_loads_all_seven_bundled_first_party_rule_packs():
    from skillguard.scan.index import _bundled_rulepacks_dir

    result = load_rule_packs(_bundled_rulepacks_dir(), "0.1.0")

    assert result.warnings == []
    categories = {p.manifest.category for p in result.packs}
    assert categories == {"SG01", "SG02", "SG03", "SG04", "SG05", "SG06", "SG07"}
