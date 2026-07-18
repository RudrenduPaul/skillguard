"""
Programmatic / agent-native entry point.

    from skillguard import scan_skill, ScanOptions

    result = scan_skill("./my-skill")
    if result.exit_code == 1:
        print(f"{len(result.findings)} finding(s) at or above HIGH")

Returns the same structured ScanResult the CLI formats for human/json/sarif
output -- an agent framework can call this in-process instead of shelling
out to the CLI. Same core scan logic as `skillguard scan`; skillguard/cli.py
is a thin argument-parsing wrapper over this function.

This is the Python port of the skillguard-cli npm package
(https://www.npmjs.com/package/skillguard-cli). Both distributions ship the
same bundled rule packs and read the same rule-pack contract; see
https://github.com/RudrenduPaul/skillguard for the canonical
documentation, benchmarks, and the original TypeScript source.

Additive alongside scan_skill(): scan_skill_set() scans a directory whose
immediate children are each a skill directory (a marketplace bundle, a
project's .claude/skills/ folder, etc.) and layers a skill-set-level
structural check (SG09 -- cross-skill privilege chaining) on top of each
skill's own scan_skill()-equivalent result.

    from skillguard import scan_skill_set
    set_result = scan_skill_set("./my-skills-dir")
"""
from .scan.index import scan_skill
from .scan.skill_set import compute_cross_skill_findings, discover_skill_dirs, scan_skill_set
from .types import (
    Finding,
    OutputFormat,
    RuleCategory,
    ScanOptions,
    ScanResult,
    ScanWarning,
    Severity,
    SkillEntry,
    SkillSetScanResult,
)

__version__ = "0.2.0"

__all__ = [
    "scan_skill",
    "scan_skill_set",
    "discover_skill_dirs",
    "compute_cross_skill_findings",
    "Finding",
    "ScanOptions",
    "ScanResult",
    "ScanWarning",
    "Severity",
    "OutputFormat",
    "RuleCategory",
    "SkillEntry",
    "SkillSetScanResult",
    "__version__",
]
