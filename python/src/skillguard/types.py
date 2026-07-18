"""
Shared types for SkillGuard's scan pipeline. Used by both the CLI
(skillguard/cli.py) and the programmatic library API (skillguard/__init__.py).

This is a Python port of the TypeScript original's src/types.ts. Field names
follow Python (snake_case) convention; the JSON/SARIF output layer
(skillguard/output/formatters.py) re-serializes to the same camelCase keys
the npm package's `--format json`/`--format sarif` output uses, so the two
CLIs stay wire-compatible even though the in-process Python objects use
snake_case attributes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Literal, Optional

Severity = Literal["HIGH", "MEDIUM", "LOW"]
OutputFormat = Literal["human", "json", "sarif"]

# SG01 through SG10 -- see rulepacks/data/ for the corresponding rule packs.
RuleCategory = Literal[
    "SG01", "SG02", "SG03", "SG04", "SG05", "SG06", "SG07", "SG08", "SG09", "SG10"
]

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


@dataclass
class Finding:
    rule_id: str
    """e.g. "sg02-curl-pipe-shell" """
    category: RuleCategory
    severity: Severity
    message: str
    file: str
    """Path relative to the scan target."""
    line: int
    snippet: Optional[str] = None


@dataclass
class ScanWarning:
    code: str
    """Machine-readable code, e.g. "invalid-pack", "invalid-glob"."""
    message: str
    """Human-readable WHAT/WHY/FIX formatted message."""


@dataclass
class ScanResult:
    target: str
    findings: List[Finding]
    timeouts: List[str]
    """Files that hit the per-file scan timeout; scan continued past them."""
    unscanned_files: List[str]
    """Files with a recognized script role but an unsupported language."""
    warnings: List[ScanWarning]
    files_scanned: int
    severity_threshold: Severity
    exit_code: int
    """0 = clean, 1 = finding(s) at/above threshold, 2 = target/config error."""


@dataclass
class ScanOptions:
    severity_threshold: Severity = "HIGH"
    """Minimum severity that causes a non-zero (1) exit code."""
    timeout_ms: int = 10_000
    """Hard per-file scan timeout in milliseconds."""
    ignore_file_path: Optional[str] = None
    """
    Path to a .skillguardignore file. NOT auto-derived from the scan target
    (security: the target directory is untrusted third-party content
    SkillGuard exists to vet, so an ignore file shipped inside it must never
    be trusted implicitly -- only an explicit, deliberate caller-supplied
    path is honored). Leave as None to scan with no path suppressions.
    """
    rulepacks_dir: Optional[str] = None
    """Directory containing first-party (and any local) rule packs."""
    allow_inline_suppression: bool = False
    """
    Honor inline `# skillguard-ignore: SGxx` comments found inside the scan
    target's own files. Default False (security: those comments live inside
    the exact untrusted content being scanned, so by default nothing in the
    scan target can silence a finding about itself -- opt in only when the
    caller already trusts the content, e.g. an author self-scanning their
    own skill pre-publish).
    """
    clock: Optional[Callable[[], float]] = None
    """Injectable clock (milliseconds), used by tests to simulate slow scans deterministically."""
