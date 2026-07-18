"""
SG10 -- marketplace typosquatting detection. Extracts the declared `name`
field from SKILL.md's YAML frontmatter (via structural/frontmatter_behavior_diff.py's
shared parse_frontmatter -- not a second YAML-frontmatter parser) and compares
it against rulepacks/data/sg10-marketplace-typosquatting/known-names.json, a
small bundled starter list of well-known package/tool names (not a live or
comprehensive marketplace registry -- see that pack's pack.json). A near-miss
(edit distance 1-2, not an exact match) suggests the declared name may be
impersonating a popular tool.

This module never executes anything from the scan target, only reads
SKILL.md content already handed to it and pattern-matches -- same read-only
invariant as structural/frontmatter_behavior_diff.py.

Ported from src/ast/typosquatting-check.ts.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import List, Optional

from .frontmatter_behavior_diff import parse_frontmatter


@dataclass
class DeclaredName:
    name: str
    line: int
    """1-based line number within skill_md_content where the `name:` field appears."""


def parse_declared_name(skill_md_content: str) -> Optional[DeclaredName]:
    """
    Extracts the declared `name` field (and the line it appears on) from
    SKILL.md's YAML frontmatter. Returns None when there is no frontmatter
    block, the frontmatter isn't valid YAML, or no non-empty `name` field is
    declared -- in every case there is nothing to compare. A thin wrapper
    around parse_frontmatter()'s `name`/`name_line` fields (added there
    specifically so this module didn't need its own duplicate frontmatter
    parser), narrowing its `Optional[str]` name to this module's
    name-required DeclaredName shape.
    """
    declared = parse_frontmatter(skill_md_content)
    if declared is None or declared.name is None:
        return None

    return DeclaredName(name=declared.name, line=declared.name_line or 1)


def levenshtein_distance(a: str, b: str) -> int:
    """Pure Levenshtein edit-distance implementation (insertions, deletions,
    substitutions each cost 1) -- no dependency, single-row DP."""
    m, n = len(a), len(b)
    if m == 0:
        return n
    if n == 0:
        return m

    prev_row = list(range(n + 1))
    curr_row = [0] * (n + 1)

    for i in range(1, m + 1):
        curr_row[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr_row[j] = min(
                prev_row[j] + 1,  # deletion
                curr_row[j - 1] + 1,  # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row, curr_row = curr_row, prev_row

    return prev_row[n]


@dataclass
class TyposquatMatch:
    known_name: str
    distance: int


# Names shorter than this are excluded from comparison -- too easy to false-positive on.
_MIN_NAME_LENGTH_FOR_CHECK = 4


def find_typosquat_matches(declared_name: str, known_names: List[str]) -> List[TyposquatMatch]:
    """
    Compares declared_name against every entry in known_names. A known name
    is flagged when it is not an exact match (case-insensitive) but its edit
    distance from declared_name is 1 or 2, and both names clear a minimum
    length (short names produce too many coincidental near-misses to be
    meaningful).
    """
    normalized_declared = declared_name.lower()
    if len(normalized_declared) < _MIN_NAME_LENGTH_FOR_CHECK:
        return []

    matches: List[TyposquatMatch] = []
    for known_name in known_names:
        normalized_known = known_name.lower()
        if len(normalized_known) < _MIN_NAME_LENGTH_FOR_CHECK:
            continue
        if normalized_declared == normalized_known:
            continue  # exact match is presumably the real thing

        # A 1-2 edit distance can't span a larger length gap than that, but
        # checking it up front skips the DP for obviously unrelated pairs.
        if abs(len(normalized_declared) - len(normalized_known)) > 2:
            continue

        distance = levenshtein_distance(normalized_declared, normalized_known)
        if 1 <= distance <= 2:
            matches.append(TyposquatMatch(known_name=known_name, distance=distance))

    return matches


def _default_known_names_path() -> str:
    # structural/typosquatting_check.py -> ../rulepacks/data/sg10-marketplace-typosquatting/known-names.json
    # (bundled inside the installed package via pyproject.toml's wheel
    # packaging, same as every other rule pack's data -- see
    # python/pyproject.toml -- mirrors DEFAULT_KNOWN_NAMES_PATH in
    # src/ast/typosquatting-check.ts, one directory name different since the
    # Python distribution bundles rule-pack data under rulepacks/data/ rather
    # than a top-level rulepacks/ dir).
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(
        package_root, "rulepacks", "data", "sg10-marketplace-typosquatting", "known-names.json"
    )


def load_known_names(known_names_path: Optional[str] = None) -> List[str]:
    """
    Loads the bundled known-names seed list. Fail-soft: a missing or corrupt
    file yields an empty list (no findings, no crash) rather than raising --
    same philosophy as load_rule_packs().
    """
    path = known_names_path or _default_known_names_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            parsed = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(parsed, list):
        return []
    return [entry for entry in parsed if isinstance(entry, str)]
