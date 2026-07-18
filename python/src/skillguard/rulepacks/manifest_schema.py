"""
The rule-pack plugin contract: a rule pack is a directory with a pack.json
manifest plus its .yml pattern-rule file (for "pattern" packs) or a
reference to a first-party structural module (for "structural" packs -- v0.1
only ships one, SG07's frontmatter/behavior diff).

Every manifest is validated against this schema before its pack is allowed
to run. An invalid manifest causes that single pack to be skipped with a
warning -- it never hard-fails the whole scan.

Ported from src/rulepacks/manifest-schema.ts, which uses the `zod` npm
library. This module reimplements the same validation rules by hand rather
than pulling in a schema-validation dependency, since the schema is small
and fixed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

VALID_CATEGORIES = {"SG01", "SG02", "SG03", "SG04", "SG05", "SG06", "SG07", "SG08", "SG09", "SG10"}
VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}
VALID_LANGUAGES = {"javascript", "typescript", "python", "shell"}
VALID_KINDS = {"pattern", "structural"}


class ValidationError(Exception):
    def __init__(self, issues: List[str]) -> None:
        super().__init__("; ".join(issues))
        self.issues = issues


@dataclass
class PackManifest:
    name: str
    version: str
    category: str
    min_core_version: str
    description: str
    kind: str = "pattern"
    rules_file: Optional[str] = None


def parse_pack_manifest(raw: Dict[str, Any]) -> PackManifest:
    issues: List[str] = []

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        issues.append("name: name must be a non-empty string")

    version = raw.get("version")
    if not isinstance(version, str) or not _SEMVER_RE.match(version):
        issues.append('version: version must be semver, e.g. "0.1.0"')

    category = raw.get("category")
    if category not in VALID_CATEGORIES:
        issues.append("category: category must be one of SG01..SG10")

    min_core_version = raw.get("minCoreVersion")
    if not isinstance(min_core_version, str) or not _SEMVER_RE.match(min_core_version):
        issues.append('minCoreVersion: minCoreVersion must be semver, e.g. "0.1.0"')

    description = raw.get("description")
    if not isinstance(description, str) or not description.strip():
        issues.append("description: description must be a non-empty string")

    kind = raw.get("kind", "pattern")
    if kind not in VALID_KINDS:
        issues.append('kind: kind must be one of "pattern", "structural"')

    rules_file = raw.get("rulesFile")
    if kind == "pattern" and not rules_file:
        issues.append('rulesFile: rulesFile is required when kind is "pattern"')

    if issues:
        raise ValidationError(issues)

    return PackManifest(
        name=name,
        version=version,
        category=category,
        min_core_version=min_core_version,
        description=description,
        kind=kind,
        rules_file=rules_file,
    )


@dataclass
class PatternRule:
    id: str
    message: str
    severity: str
    languages: List[str]
    regex: str
    flags: str = "gi"


def parse_rules_file(raw: Dict[str, Any]) -> List[PatternRule]:
    issues: List[str] = []
    rules_raw = raw.get("rules") if isinstance(raw, dict) else None
    if not isinstance(rules_raw, list) or len(rules_raw) == 0:
        raise ValidationError(["rules: rules must be a non-empty array"])

    rules: List[PatternRule] = []
    for idx, entry in enumerate(rules_raw):
        if not isinstance(entry, dict):
            issues.append(f"rules.{idx}: rule must be an object")
            continue

        entry_issues: List[str] = []

        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            entry_issues.append(f"rules.{idx}.id: id must be a non-empty string")

        message = entry.get("message")
        if not isinstance(message, str) or not message:
            entry_issues.append(f"rules.{idx}.message: message must be a non-empty string")

        severity = entry.get("severity")
        if severity not in VALID_SEVERITIES:
            entry_issues.append(f"rules.{idx}.severity: severity must be one of HIGH, MEDIUM, LOW")

        languages = entry.get("languages")
        if (
            not isinstance(languages, list)
            or len(languages) == 0
            or any(lang not in VALID_LANGUAGES for lang in languages)
        ):
            entry_issues.append(f"rules.{idx}.languages: languages must be a non-empty array of valid languages")

        regex = entry.get("regex")
        if not isinstance(regex, str) or not regex:
            entry_issues.append(f"rules.{idx}.regex: regex must be a non-empty string")

        flags = entry.get("flags", "gi")

        if entry_issues:
            issues.extend(entry_issues)
            continue

        rules.append(
            PatternRule(
                id=rule_id,
                message=message,
                severity=severity,
                languages=languages,
                regex=regex,
                flags=flags,
            )
        )

    if issues:
        raise ValidationError(issues)

    return rules


def semver_gte(a: str, b: str) -> bool:
    """Compares two semver strings (a >= b). No pre-release/build-metadata support -- not needed for this contract."""
    pa = [int(part) for part in a.split(".")]
    pb = [int(part) for part in b.split(".")]
    for i in range(3):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va != vb:
            return va > vb
    return True
