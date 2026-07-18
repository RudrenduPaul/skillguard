"""
scan_skill_set() -- SkillGuard's cross-skill entry point, additive alongside
scan_skill(). Where scan_skill() vets one skill directory, scan_skill_set()
vets a directory whose immediate children are each a skill (a marketplace
bundle, a project's .claude/skills/ folder, etc.) and adds one thing a
single-skill scan structurally cannot see: SG09, cross-skill privilege
chaining -- two skills that are individually clean-looking but, combined in
the same unsandboxed execution context, let one skill's filesystem read
feed another skill's network egress.

Data flow:

  targets dir
       |
       v
  discover_skill_dirs()      -> immediate subdirs containing a SKILL.md,
       |                        same case-insensitive "SKILL.MD" basename
       |                        match walker.py already uses
       v
  scan_skill() per subdir    -> the EXISTING single-skill pipeline, reused
       |                        verbatim (this module never re-implements
       |                        walking, rule loading, or pattern matching)
       v
  compute_cross_skill_findings() -> SG09: reads each skill's own findings
                                     (already produced above) for a
                                     network-egress signal and a sensitive-
                                     file-read signal, plus each skill's own
                                     SKILL.md frontmatter for a
                                     "sandbox: true" declaration -- no new
                                     pattern engine.

Ported from src/scan/skill-set.ts.

NOTE ON RULE-PACK WIRING: this SG09 check deliberately ships with no
rulepacks/data manifest. skillguard's structural-check dispatch (see
scan/index.py's has_structural_sg07-style gating) is scoped to a single
skill's own SKILL.md/files and runs once per scan_skill() call -- including
plain single-skill `scan` calls -- so a pack entry here would have no
effect on that per-skill dispatch (Python has no structural-analyzer
registry yet; each category is gated individually) but would still be
misleading manifest clutter for a check that only ever runs inside
scan_skill_set() itself, which is always an explicit, deliberate call.
Findings still carry category "SG09" (same locked taxonomy number as
skillguard's other cross-skill-privilege-chaining heuristic on the
TypeScript side) with a distinct rule_id
("sg09-cross-skill-privilege-chaining") so the two are never confused.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional

import yaml

from ..structural.frontmatter_behavior_diff import FRONTMATTER_RE
from ..types import Finding, ScanOptions, ScanWarning, SkillEntry, SkillSetScanResult, meets_threshold
from ..errors import format_what_why_fix
from .index import scan_skill

_DEFAULT_SEVERITY_THRESHOLD = "HIGH"

_ALWAYS_IGNORED_DIRS = {".git", "node_modules", ".skillguard-cache"}


@dataclass
class DiscoveredSkillDir:
    name: str
    """The subdirectory's own name under the targets directory."""
    path: str
    """Absolute path to the subdirectory."""
    skill_md_path: str
    """Absolute path to the SKILL.md found directly inside it."""


def discover_skill_dirs(targets_dir: str) -> List[DiscoveredSkillDir]:
    """
    Finds every immediate subdirectory of `targets_dir` that looks like a
    skill -- i.e. contains a SKILL.md directly inside it (not nested
    deeper). Uses the exact same case-insensitive "SKILL.MD" basename
    convention skillguard/walker.py uses for the single-skill case, so a
    directory that would be recognized as a skill by scan_skill() is
    recognized the same way here. Returned in a stable (alphabetical by
    name) order so scan output is deterministic across runs.
    """
    try:
        entries = list(os.scandir(targets_dir))
    except OSError:
        return []

    found: List[DiscoveredSkillDir] = []
    for entry in entries:
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if not is_dir or entry.name in _ALWAYS_IGNORED_DIRS:
            continue

        try:
            children = os.listdir(entry.path)
        except OSError:
            continue

        skill_md_name = next((name for name in children if name.upper() == "SKILL.MD"), None)
        if skill_md_name:
            found.append(
                DiscoveredSkillDir(
                    name=entry.name,
                    path=entry.path,
                    skill_md_path=os.path.join(entry.path, skill_md_name),
                )
            )

    return sorted(found, key=lambda d: d.name)


# SG09's network-egress signal: either an SG01 (network-mismatch) finding
# -- raw sockets, netcat, /dev/tcp -- or any existing finding whose own
# rule_id/message/snippet already names a network-egress primitive (e.g.
# SG02's "curl-pipe-shell", SG06's "credential-network-send"). This reads
# only findings scan_skill() already produced; it adds no new file-content
# pattern matching of its own.
_NETWORK_EGRESS_KEYWORD_RE = re.compile(
    r"\b(curl|wget|fetch|requests\.(get|post|put|delete)|axios|urlopen)\b", re.IGNORECASE
)


def _is_network_egress_finding(finding: Finding) -> bool:
    if finding.category == "SG01":
        return True
    if _NETWORK_EGRESS_KEYWORD_RE.search(finding.rule_id):
        return True
    if _NETWORK_EGRESS_KEYWORD_RE.search(finding.message):
        return True
    if finding.snippet and _NETWORK_EGRESS_KEYWORD_RE.search(finding.snippet):
        return True
    return False


# SG09's sensitive-file-read signal: any SG03 (file-scope-escalation) or
# SG06 (credential-harvesting) finding -- e.g. an SSH private key read, a
# cloud credentials file read, a credential-shaped env var read, or a
# path-traversal/system-path write. Same rationale as above: reuse the
# findings scan_skill() already produced, no parallel detector.
def _is_sensitive_file_read_finding(finding: Finding) -> bool:
    return finding.category in ("SG03", "SG06")


def _is_sandbox_declared(skill_md_content: str) -> bool:
    """
    True when a skill's own SKILL.md frontmatter declares `sandbox: true`,
    meaning that skill is meant to run in its own isolated execution
    context rather than sharing one with the rest of the set. Deliberately
    separate from structural/frontmatter_behavior_diff.py's
    parse_frontmatter()/DeclaredScope (whose exact shape is asserted in its
    own test suite) -- this only reuses that module's public FRONTMATTER_RE
    block-extraction regex, not its declared-scope schema.
    """
    match = FRONTMATTER_RE.match(skill_md_content)
    if not match:
        return False
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    return data.get("sandbox") is True


@dataclass
class _CapabilityProfile:
    name: str
    sandboxed: bool
    network_egress_evidence: Optional[Finding]
    sensitive_file_read_evidence: Optional[Finding]


def compute_cross_skill_findings(
    discovered: List[DiscoveredSkillDir], skills: List[SkillEntry]
) -> List[Finding]:
    """
    SG09 -- cross-skill privilege chaining. Builds a lightweight capability
    profile per skill from findings scan_skill() already produced (plus
    each skill's own SKILL.md frontmatter), then checks: does the set
    contain at least one non-sandboxed skill with a sensitive-file-read
    capability AND at least one non-sandboxed skill (the same one, or a
    different one) with a network-egress capability? If so, both run in
    the same execution context by default (no per-skill sandboxing
    declared), so the set as a whole can read a sensitive file and
    exfiltrate it -- a capability neither skill's own standalone scan would
    have flagged.

    Reports at most one representative HIGH finding per scan_skill_set()
    run (the first qualifying pair, in discovery order) rather than every
    pairwise combination, to keep the signal a single clear flag rather
    than combinatorial noise across a large skill set.
    """
    profiles: List[_CapabilityProfile] = []
    for i, skill in enumerate(skills):
        sandboxed = False
        try:
            with open(discovered[i].skill_md_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            sandboxed = _is_sandbox_declared(content)
        except OSError:
            sandboxed = False

        network_egress_evidence = next(
            (f for f in skill.result.findings if _is_network_egress_finding(f)), None
        )
        sensitive_file_read_evidence = next(
            (f for f in skill.result.findings if _is_sensitive_file_read_finding(f)), None
        )
        profiles.append(
            _CapabilityProfile(
                name=skill.name,
                sandboxed=sandboxed,
                network_egress_evidence=network_egress_evidence,
                sensitive_file_read_evidence=sensitive_file_read_evidence,
            )
        )

    fs_candidate = next(
        (p for p in profiles if not p.sandboxed and p.sensitive_file_read_evidence), None
    )
    net_candidate = next(
        (p for p in profiles if not p.sandboxed and p.network_egress_evidence), None
    )

    if fs_candidate is None or net_candidate is None:
        return []

    fs_ev = fs_candidate.sensitive_file_read_evidence
    net_ev = net_candidate.network_egress_evidence
    same_skill = fs_candidate.name == net_candidate.name

    if same_skill:
        message = (
            f'Cross-skill privilege chaining: skill "{fs_candidate.name}" alone combines '
            f"filesystem-read-of-sensitive-paths capability ({fs_ev.rule_id} at "
            f"{fs_candidate.name}/{fs_ev.file}:{fs_ev.line}) and network-egress capability "
            f"({net_ev.rule_id} at {net_candidate.name}/{net_ev.file}:{net_ev.line}) with no "
            f'per-skill sandboxing declared ("sandbox: true" in SKILL.md frontmatter) -- it can '
            "read a sensitive credential/file and exfiltrate it over the network on its own, and "
            "any other skill sharing its unsandboxed execution context inherits the same risk."
        )
    else:
        message = (
            f'Cross-skill privilege chaining: skill "{fs_candidate.name}" has '
            f"filesystem-read-of-sensitive-paths capability ({fs_ev.rule_id} at "
            f"{fs_candidate.name}/{fs_ev.file}:{fs_ev.line}) and skill \"{net_candidate.name}\" has "
            f"network-egress capability ({net_ev.rule_id} at {net_candidate.name}/{net_ev.file}:"
            f'{net_ev.line}). Neither skill declares per-skill sandboxing ("sandbox: true" in '
            "SKILL.md frontmatter), so both are assumed to run in the same execution context by "
            f'default -- combined, this skill set can read a sensitive credential/file with "'
            f'{fs_candidate.name}" and exfiltrate it over the network with "{net_candidate.name}", '
            "a capability neither skill exposes on its own."
        )

    return [
        Finding(
            rule_id="sg09-cross-skill-privilege-chaining",
            category="SG09",
            severity="HIGH",
            message=message,
            file=f"{fs_candidate.name}/{fs_ev.file}",
            line=fs_ev.line,
        )
    ]


def scan_skill_set(targets_dir: str, options: Optional[ScanOptions] = None) -> SkillSetScanResult:
    options = options or ScanOptions()
    severity_threshold = options.severity_threshold or _DEFAULT_SEVERITY_THRESHOLD
    abs_targets_dir = os.path.abspath(targets_dir)

    if not os.path.exists(abs_targets_dir):
        return SkillSetScanResult(
            targets_dir=abs_targets_dir,
            skills=[],
            findings=[],
            severity_threshold=severity_threshold,
            warnings=[
                ScanWarning(
                    code="targets-dir-not-found",
                    message=format_what_why_fix(
                        f'Targets directory "{abs_targets_dir}" does not exist.',
                        "scan_skill_set() scans a directory whose immediate children are each a "
                        "skill directory (SKILL.md plus hooks/scripts) and needs a real path to "
                        "start from.",
                        "Pass a valid directory path, e.g. skillguard scan-set ./my-skills-dir",
                    ),
                )
            ],
            exit_code=2,
        )

    discovered = discover_skill_dirs(abs_targets_dir)

    if not discovered:
        return SkillSetScanResult(
            targets_dir=abs_targets_dir,
            skills=[],
            findings=[],
            severity_threshold=severity_threshold,
            warnings=[
                ScanWarning(
                    code="no-skills-found-in-set",
                    message=format_what_why_fix(
                        f'No skill subdirectories found under "{abs_targets_dir}".',
                        "scan_skill_set() looks for immediate subdirectories that each contain a "
                        "SKILL.md file, and found none.",
                        "Point scan_skill_set at a directory whose immediate children are skill "
                        "directories, e.g. skillguard scan-set "
                        "./examples/skill-set-cross-privilege",
                    ),
                )
            ],
            exit_code=2,
        )

    skills: List[SkillEntry] = []
    for d in discovered:
        # Reuses the EXISTING single-skill scan machinery verbatim -- same
        # options (severity threshold, timeout, ignore file, inline
        # suppression, rule packs dir) applied per skill, exactly as if
        # each subdirectory had been passed to scan_skill() directly.
        result = scan_skill(d.path, options)
        skills.append(SkillEntry(name=d.name, path=d.path, result=result))

    cross_skill_findings = compute_cross_skill_findings(discovered, skills)

    any_per_skill_error = any(s.result.exit_code == 2 for s in skills)
    any_per_skill_fail = any(s.result.exit_code == 1 for s in skills)
    cross_skill_fail = any(meets_threshold(f.severity, severity_threshold) for f in cross_skill_findings)

    if any_per_skill_error:
        exit_code = 2
    elif any_per_skill_fail or cross_skill_fail:
        exit_code = 1
    else:
        exit_code = 0

    return SkillSetScanResult(
        targets_dir=abs_targets_dir,
        skills=skills,
        findings=cross_skill_findings,
        severity_threshold=severity_threshold,
        warnings=[],
        exit_code=exit_code,
    )
