"""
SG07 -- frontmatter spoofing. Parses SKILL.md's YAML frontmatter for its
declared network/filesystem scope, then compares it against the actual
behavior implied by the skill's hooks/scripts (a read-only structural scan
-- this module never executes anything from the scan target, only reads
file bytes and pattern-matches, same invariant as
skillguard/scan/semgrep_runner.py).

Declared scope schema (SKILL.md frontmatter):
  ---
  name: my-skill
  network: false          # boolean -- does this skill need network access?
  filesystem: none        # "none" | "read-only" | "read-write"
  ---

A mismatch (declared narrower than actual) is a MEDIUM finding: declared-
scope violation without a confirmed exploit path, as distinct from SG02/
SG06's confirmed executable impact.

Ported from src/ast/frontmatter-behavior-diff.ts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, TypedDict

import yaml

from ..types import Finding
from ..walker import ScannableFile

_FRONTMATTER_RE = re.compile(r"^---\r?\n([\s\S]*?)\r?\n---")
_NAME_KEY_RE = re.compile(r"^name:[ \t]*(.+)$", re.MULTILINE)


@dataclass
class DeclaredScope:
    network: bool
    filesystem_write: bool
    name: Optional[str] = None
    """The frontmatter's declared `name:` field, trimmed, or None if absent/blank.
    Consumed by SG10 (structural/typosquatting_check.py) in addition to SG07."""
    name_line: Optional[int] = None
    """1-indexed line of the `name:` key within skill_md_content, or None if
    there's no name field. Lets SG10 cite a real file:line for its finding."""


def _line_number_at(content: str, index: int) -> int:
    return 1 + content.count("\n", 0, index)


def parse_frontmatter(skill_md_content: str) -> Optional[DeclaredScope]:
    match = _FRONTMATTER_RE.match(skill_md_content)
    if not match:
        return None

    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return None

    if not isinstance(data, dict):
        return None

    network = data.get("network") is True
    filesystem = data.get("filesystem") if isinstance(data.get("filesystem"), str) else "none"
    filesystem_write = filesystem == "read-write"

    raw_name = data.get("name")
    name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else None

    # _FRONTMATTER_RE.match() anchors at the start of the string, so
    # match.start() is always 0 -- the frontmatter block always begins at
    # the top of the file. The captured group's offset within the full match
    # is found once via find(), rather than re-deriving it from span math.
    name_line: Optional[int] = None
    if name is not None:
        block = match.group(1)
        name_key_match = _NAME_KEY_RE.search(block)
        if name_key_match:
            block_offset = match.group(0).find(block)
            name_line = _line_number_at(skill_md_content, block_offset + name_key_match.start())

    return DeclaredScope(
        network=network, filesystem_write=filesystem_write, name=name, name_line=name_line
    )


_NETWORK_EVIDENCE_RE = re.compile(
    r"\b(fetch|axios|http\.request|https\.request|requests\.(get|post|put|delete)"
    r"|urllib\.request|urlopen|socket\.socket|curl\s|wget\s)\b",
    re.IGNORECASE,
)

_FS_WRITE_EVIDENCE_RE = re.compile(
    r"\b(fs\.writeFile|fs\.writeFileSync|fs\.appendFile|fs\.unlink|open\([^)]*['\"]w"
    r"|os\.remove|os\.rmdir|shutil\.rmtree)\b|>\s*/|rm\s+-rf",
    re.IGNORECASE,
)


class _Evidence(TypedDict):
    file: str
    line: int


@dataclass
class BehaviorEvidence:
    network: bool = False
    filesystem_write: bool = False
    network_evidence: List[_Evidence] = field(default_factory=list)
    fs_evidence: List[_Evidence] = field(default_factory=list)


def _first_match_line(content: str, pattern: "re.Pattern[str]") -> Optional[int]:
    match = pattern.search(content)
    if not match:
        return None
    return _line_number_at(content, match.start())


def infer_actual_behavior(scripts: List[ScannableFile]) -> BehaviorEvidence:
    evidence = BehaviorEvidence()

    for script in scripts:
        try:
            with open(script.abs_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        net_line = _first_match_line(content, _NETWORK_EVIDENCE_RE)
        if net_line is not None:
            evidence.network = True
            evidence.network_evidence.append({"file": script.rel_path, "line": net_line})

        fs_line = _first_match_line(content, _FS_WRITE_EVIDENCE_RE)
        if fs_line is not None:
            evidence.filesystem_write = True
            evidence.fs_evidence.append({"file": script.rel_path, "line": fs_line})

    return evidence


def diff_frontmatter_behavior(declared: DeclaredScope, actual: BehaviorEvidence) -> List[Finding]:
    findings: List[Finding] = []

    if not declared.network and actual.network:
        for ev in actual.network_evidence:
            findings.append(
                Finding(
                    rule_id="sg07-network-scope-mismatch",
                    category="SG07",
                    severity="MEDIUM",
                    message=(
                        'SKILL.md frontmatter declares "network: false" but this script '
                        "performs a network call — the declared permission scope does not "
                        "match actual behavior."
                    ),
                    file=ev["file"],
                    line=ev["line"],
                )
            )

    if not declared.filesystem_write and actual.filesystem_write:
        for ev in actual.fs_evidence:
            findings.append(
                Finding(
                    rule_id="sg07-filesystem-scope-mismatch",
                    category="SG07",
                    severity="MEDIUM",
                    message=(
                        'SKILL.md frontmatter does not declare "filesystem: read-write" but '
                        "this script writes or deletes files — the declared permission scope "
                        "does not match actual behavior."
                    ),
                    file=ev["file"],
                    line=ev["line"],
                )
            )

    return findings
