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
same seven bundled rule packs (SG01 through SG07) and read the same
rule-pack contract; see https://github.com/RudrenduPaul/skillguard for the
canonical documentation, benchmarks, and the original TypeScript source.
"""
from .scan.index import scan_skill
from .types import (
    Finding,
    OutputFormat,
    RuleCategory,
    ScanOptions,
    ScanResult,
    ScanWarning,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "scan_skill",
    "Finding",
    "ScanOptions",
    "ScanResult",
    "ScanWarning",
    "Severity",
    "OutputFormat",
    "RuleCategory",
    "__version__",
]
