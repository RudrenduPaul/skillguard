"""
Data flow (reproduced here for anyone reading this file first):

  target path
       |
       v
  .skillguardignore loaded  -> ignore globs (+ warnings for invalid lines).
       |                       Only loaded when the caller explicitly
       |                       supplies a path -- never auto-derived from
       |                       inside the (untrusted) scan target.
       v
  walker.py                 -> SKILL.md path, scannable files, unscanned files
       |
       v
  rulepacks/loader.py       -> loaded packs (invalid packs skipped + warned)
       |
   +---+-----------------------------+
   v                                 v
 scan/semgrep_runner.py (SG01-06,  structural/frontmatter_behavior_diff.py
 partial SG05), per-file           (SG07: declared vs actual scope),
 timeout enforced                  structural/prompt_injection_scan.py
                                    (SG08: override phrasing / hidden
                                    Unicode / encoded blocks in SKILL.md's
                                    body text), and
                                    structural/typosquatting_check.py
                                    (SG10: declared name vs
                                    known-names.json) -- all read-only,
                                    sharing one SKILL.md read (SG07/SG10
                                    also share one parse_frontmatter() call;
                                    SG08 works from the raw content and
                                    strips its own frontmatter internally)
   |                                 |
   +-----------------+---------------+
                      v
             inline suppression filter (# skillguard-ignore: SGxx),
             off by default -- opt in via allow_inline_suppression
                      v
             severity threshold -> exit code (0 clean / 1 fail / 2 error)

Ported from src/scan/index.ts. NOTE: the TypeScript original moved its
structural dispatch to a directory-discovered analyzer registry
(src/scan/structural/index.ts); this Python port keeps the simpler,
explicit per-category dispatch style (_find_structural_pack()) it already
had for SG07/SG10 and extends it for SG08 rather than also porting that
registry mechanism, since doing so is a larger architecture change than
adding one new detection category.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

from ..errors import format_what_why_fix
from ..rulepacks.loader import CORE_VERSION, LoadedPack, load_rule_packs
from ..structural.frontmatter_behavior_diff import (
    diff_frontmatter_behavior,
    infer_actual_behavior,
    parse_frontmatter,
)
from ..structural.prompt_injection_scan import scan_prompt_injection
from ..structural.typosquatting_check import (
    find_typosquat_matches,
    load_known_names,
    parse_declared_name,
)
from ..suppress.skillguardignore import IgnoreFileResult, is_inline_suppressed, load_ignore_file
from ..types import Finding, ScanOptions, ScanResult, ScanWarning, meets_threshold
from ..walker import walk

_DEFAULT_SEVERITY_THRESHOLD = "HIGH"
_DEFAULT_TIMEOUT_MS = 10_000


def _bundled_rulepacks_dir() -> str:
    # skillguard/scan/index.py -> ../rulepacks/data (bundled inside the
    # installed package via pyproject.toml's wheel packaging, so it's
    # present in the published distribution -- see python/pyproject.toml).
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(package_root, "rulepacks", "data")


def scan_skill(target: str, options: Optional[ScanOptions] = None) -> ScanResult:
    options = options or ScanOptions()
    severity_threshold = options.severity_threshold or _DEFAULT_SEVERITY_THRESHOLD
    timeout_ms = options.timeout_ms or _DEFAULT_TIMEOUT_MS
    rulepacks_dir = options.rulepacks_dir or _bundled_rulepacks_dir()

    abs_target = os.path.abspath(target)

    if not os.path.exists(abs_target):
        return ScanResult(
            target=abs_target,
            findings=[],
            timeouts=[],
            unscanned_files=[],
            files_scanned=0,
            severity_threshold=severity_threshold,
            warnings=[
                ScanWarning(
                    code="target-not-found",
                    message=format_what_why_fix(
                        f'Target path "{abs_target}" does not exist.',
                        "SkillGuard scans a directory containing a skill (SKILL.md plus "
                        "hooks/scripts) and needs a real path to start from.",
                        "Pass a valid directory path, e.g. skillguard scan ./my-skill",
                    ),
                )
            ],
            exit_code=2,
        )

    # SECURITY: .skillguardignore is only loaded when the caller explicitly
    # supplies a path (CLI --skillguardignore flag, or the ignore_file_path
    # library option) -- never auto-derived from inside the scan target. See
    # ScanOptions.ignore_file_path for the full rationale (same invariant as
    # the TypeScript original).
    ignore_result: IgnoreFileResult = (
        load_ignore_file(options.ignore_file_path) if options.ignore_file_path else IgnoreFileResult([], [])
    )

    walk_result = walk(abs_target, ignore_result.patterns)

    if not walk_result.skill_md_path and len(walk_result.files) == 0:
        return ScanResult(
            target=abs_target,
            findings=[],
            timeouts=[],
            unscanned_files=walk_result.unscanned_files,
            files_scanned=0,
            severity_threshold=severity_threshold,
            warnings=[
                *ignore_result.warnings,
                ScanWarning(
                    code="no-skill-files-found",
                    message=format_what_why_fix(
                        f'No skill files found under "{abs_target}".',
                        "SkillGuard looks for a SKILL.md manifest plus hooks/scripts, and "
                        "found neither.",
                        "Point SkillGuard at a directory that contains a SKILL.md file, e.g. "
                        "skillguard scan ./examples/known-bad-skill",
                    ),
                ),
            ],
            exit_code=2,
        )

    packs_result = load_rule_packs(rulepacks_dir, CORE_VERSION)

    pattern_packs = [p for p in packs_result.packs if p.manifest.kind == "pattern"]

    # Local import avoids a module-import cycle at package-init time.
    from .semgrep_runner import compile_rules, run_rules

    compiled_rules = compile_rules(pattern_packs)
    run_result = run_rules(walk_result.files, compiled_rules, timeout_ms, options.clock)

    def _find_structural_pack(category: str) -> Optional[LoadedPack]:
        # Finds the loaded structural pack for a category, or None if that
        # pack wasn't loaded (missing/invalid pack.json, minCoreVersion
        # mismatch, etc. -- see load_rule_packs). Generalizes what was a
        # one-off SG07 boolean check so SG10 can share it instead of
        # duplicating the same `any(...)`.
        for p in packs_result.packs:
            if p.manifest.category == category and p.manifest.kind == "structural":
                return p
        return None

    structural_findings: List[Finding] = []
    structural_warnings: List[ScanWarning] = []
    sg07_pack = _find_structural_pack("SG07")
    sg08_pack = _find_structural_pack("SG08")
    sg10_pack = _find_structural_pack("SG10")
    if (sg07_pack or sg08_pack or sg10_pack) and walk_result.skill_md_path:
        try:
            with open(walk_result.skill_md_path, "r", encoding="utf-8", errors="replace") as fh:
                skill_md_content = fh.read()
            # Parsed once, shared by both SG07 and SG10 -- they both need
            # the same declared-frontmatter view (SG07 reads
            # network/filesystem_write, SG10 reads name/name_line), so
            # there's no reason to re-read the file or re-run the YAML
            # parse twice per scan (the TypeScript port's structural-
            # analyzer-registry architecture re-parses per analyzer module
            # instead, a deliberate trade-off of that plugin design --
            # Python's direct-dispatch scan pipeline doesn't have that
            # constraint, so it shares the one parse). SG08 doesn't need
            # the parsed frontmatter at all -- it works from the raw
            # content and strips its own frontmatter block internally
            # (scan_prompt_injection()) -- so it runs unconditionally on
            # `skill_md_content`, independent of whether `declared` parses.
            if sg08_pack:
                sg08_findings = scan_prompt_injection(skill_md_content)
                if sg08_findings:
                    rel_skill_md = os.path.relpath(walk_result.skill_md_path, abs_target).replace(
                        os.sep, "/"
                    )
                    structural_findings.extend(
                        Finding(
                            rule_id=f.rule_id,
                            category=f.category,
                            severity=f.severity,
                            message=f.message,
                            file=rel_skill_md,
                            line=f.line,
                            snippet=f.snippet,
                        )
                        for f in sg08_findings
                    )

            declared = parse_frontmatter(skill_md_content)
            if declared:
                if sg07_pack:
                    actual = infer_actual_behavior(walk_result.files)
                    structural_findings.extend(diff_frontmatter_behavior(declared, actual))
                if sg10_pack and declared.name:
                    known_names = load_known_names()
                    if known_names:
                        matches = find_typosquat_matches(declared.name, known_names)
                        rel_file = os.path.relpath(walk_result.skill_md_path, abs_target).replace(
                            os.sep, "/"
                        )
                        for match in matches:
                            structural_findings.append(
                                Finding(
                                    rule_id="sg10-typosquat-suspected",
                                    category="SG10",
                                    # HIGH, not MEDIUM: an edit-distance-1-2
                                    # near-miss of a well-known name
                                    # (excluding the exact match itself,
                                    # already filtered out by
                                    # find_typosquat_matches) is the
                                    # textbook typosquat pattern -- a
                                    # dropped/doubled/swapped/substituted
                                    # character intended to trick a human
                                    # or agent into installing the wrong
                                    # skill.
                                    severity="HIGH",
                                    message=(
                                        f'SKILL.md declares name "{declared.name}", which closely '
                                        f'resembles the well-known name "{match.known_name}" (edit '
                                        f"distance {match.distance}) — this may be an attempt to "
                                        "impersonate a popular skill or tool via typosquatting."
                                    ),
                                    file=rel_file,
                                    line=declared.name_line or 1,
                                )
                            )
        except OSError as err:
            structural_warnings.append(
                ScanWarning(
                    code="skill-md-unreadable",
                    message=format_what_why_fix(
                        f'Could not read "{walk_result.skill_md_path}" for the SG07/SG08/SG10 '
                        "structural checks.",
                        str(err),
                        "SG07/SG08/SG10 were skipped for this scan; the rest of the scan still "
                        "ran. Check the file exists and is readable.",
                    ),
                )
            )

    all_findings: List[Finding] = [*run_result.findings, *structural_findings]

    # Inline suppression: "# skillguard-ignore: SGxx" on the finding's own
    # line or the line directly above it. SECURITY: off by default (see
    # ScanOptions.allow_inline_suppression) -- these comments live inside
    # the exact untrusted scan-target content being vetted, so by default
    # nothing in that content can silence a finding about itself.
    file_content_cache: Dict[str, str] = {}

    def _is_suppressed(finding: Finding) -> bool:
        abs_path = os.path.join(abs_target, finding.file)
        content = file_content_cache.get(abs_path)
        if content is None:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                content = ""
            file_content_cache[abs_path] = content
        return is_inline_suppressed(content, finding.line, finding.category)

    if options.allow_inline_suppression:
        suppressed_findings = [f for f in all_findings if not _is_suppressed(f)]
    else:
        suppressed_findings = all_findings

    exit_code = 1 if any(meets_threshold(f.severity, severity_threshold) for f in suppressed_findings) else 0

    return ScanResult(
        target=abs_target,
        findings=suppressed_findings,
        timeouts=run_result.timed_out_files,
        unscanned_files=walk_result.unscanned_files,
        files_scanned=len(walk_result.files),
        severity_threshold=severity_threshold,
        warnings=[*ignore_result.warnings, *packs_result.warnings, *structural_warnings],
        exit_code=exit_code,
    )
